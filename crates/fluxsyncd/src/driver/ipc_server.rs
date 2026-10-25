//! Local IPC server: accept loop, NDJSON framing, per-client channels.

use super::*;

pub(super) async fn ipc_accept_loop(server: IpcServer, sh: Arc<Shared>) -> Result<()> {
    let Shared {
        cmd_tx,
        logs_bcast_tx,
        log_tail,
        shutdown,
        ..
    } = &*sh;
    let mut clients = JoinSet::new();
    // Bounds the number of concurrently-connected IPC clients so N local
    // processes can't each hold a up-to-64-MiB in-flight line and scale the
    // daemon's memory with connection count. Acquiring blocks (backpressure)
    // once the bound is hit rather than dropping the connection — this is a
    // local trusted socket, so a slow-to-accept client is preferable to a
    // rejected one.
    let accept_permits = Arc::new(Semaphore::new(32));
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            // Acquiring the permit and accepting the connection live in the
            // same arm so a shutdown mid-wait (whether blocked on the
            // semaphore or on the accept itself) still cancels promptly.
            accepted = async {
                let permit = accept_permits.clone().acquire_owned().await.expect("semaphore never closed");
                let conn = server.accept().await?;
                Ok::<_, std::io::Error>((permit, conn))
            } => {
                let (permit, conn) = match accepted {
                    Ok(pc) => pc,
                    Err(e) => { tracing::warn!(error = %e, "ipc accept"); continue; }
                };
                let cmd_tx = cmd_tx.clone();
                let state_rx = sh.state_watch_tx.subscribe();
                let logs_bcast_rx = logs_bcast_tx.subscribe();
                let log_tail = log_tail.clone();
                let client_shutdown = shutdown.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_ipc_client(conn, cmd_tx, state_rx, logs_bcast_rx, log_tail, client_shutdown).await {
                        tracing::debug!(error = %e, "ipc client end");
                    }
                });
            }
        }
    }
    while clients.join_next().await.is_some() {}
    Ok(())
}

/// Cap on a single IPC NDJSON line. The largest legitimate request is a
/// base64 image push (~4/3 of `MAX_PAYLOAD`); 64 MiB leaves headroom while
/// bounding a malicious/buggy local client that streams a newline-less line
/// (which would otherwise let `read_line` buffer unbounded → OOM the daemon).
pub(super) const MAX_IPC_LINE: usize = 64 * 1024 * 1024;

/// Like `AsyncBufReadExt::read_line` but refuses to buffer more than `max`
/// bytes for one line. Reads via `fill_buf`/`consume` so accumulation is
/// bounded; returns `InvalidData` once the line would exceed the cap. Bytes
/// are decoded lossily once the whole line is collected, so multi-byte UTF-8
/// never splits across an internal buffer boundary.
pub(super) async fn read_line_capped<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    out: &mut String,
    max: usize,
) -> std::io::Result<usize> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            break; // EOF
        }
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if bytes.len() + take > max {
            reader.consume(take);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IPC line exceeds max length",
            ));
        }
        bytes.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        if done {
            break;
        }
    }
    out.push_str(&String::from_utf8_lossy(&bytes));
    Ok(bytes.len())
}

pub(super) async fn handle_ipc_client(
    conn: IpcConn,
    cmd_tx: mpsc::UnboundedSender<DriverCmd>,
    mut state_rx: watch::Receiver<State>,
    mut logs_bcast_rx: broadcast::Receiver<LogEntry>,
    _log_tail: Arc<LogTail>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (read_half, mut write_half) = conn.split();
    let mut reader = BufReader::new(read_half);

    let mut opening = String::new();
    read_line_capped(&mut reader, &mut opening, MAX_IPC_LINE).await?;
    let sub: Subscribe = serde_json::from_str(opening.trim())
        .map_err(|e| anyhow!("opening line not a Subscribe: {e}"))?;

    match sub.subscribe {
        Channel::Cmd => {
            let mut line = String::new();
            loop {
                line.clear();
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    res = read_line_capped(&mut reader, &mut line, MAX_IPC_LINE) => {
                        let n = res?;
                        if n == 0 { return Ok(()); }
                        let req: CmdRequest = match serde_json::from_str(line.trim()) {
                            Ok(r) => r,
                            Err(e) => {
                                let resp = CmdResponse::err(0, format!("bad json: {e}"));
                                write_json_line(&mut write_half, &resp).await?;
                                continue;
                            }
                        };
                        let (reply_tx, reply_rx) = oneshot::channel();
                        cmd_tx.send(DriverCmd::Run { op: req.op, reply: reply_tx, req_id: req.id })
                            .map_err(|_| anyhow!("driver gone"))?;
                        let resp = reply_rx.await.map_err(|_| anyhow!("driver dropped reply"))?;
                        write_json_line(&mut write_half, &resp).await?;
                    }
                }
            }
        }
        Channel::State => {
            // Serialize under the watch borrow instead of cloning the State
            // (its history carries every item's full text) for each client
            // on each change. `borrow_and_update` marks the opening snapshot
            // as seen: with a plain `borrow`, `changed()` fired immediately
            // and every new subscriber received that first snapshot twice.
            let line = json_line(&*state_rx.borrow_and_update())?;
            write_line(&mut write_half, &line).await?;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    changed = state_rx.changed() => {
                        if changed.is_err() { return Ok(()); }
                        let line = json_line(&*state_rx.borrow_and_update())?;
                        write_line(&mut write_half, &line).await?;
                    }
                }
            }
        }
        Channel::Logs => loop {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                entry = logs_bcast_rx.recv() => {
                    match entry {
                        Ok(e) => write_json_line(&mut write_half, &e).await?,
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            let warn = LogEntry { level: LogLevel::Warn, msg: String::from("(some log lines were dropped)") };
                            write_json_line(&mut write_half, &warn).await?;
                        }
                    }
                }
            }
        },
    }
}

pub(super) async fn write_json_line<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: serde::Serialize,
{
    write_line(writer, &json_line(value)?).await
}

/// One NDJSON line (`value` + `\n`), built synchronously so callers can
/// serialize while holding a `watch` borrow and drop it before awaiting.
pub(super) fn json_line<T: serde::Serialize>(value: &T) -> Result<String> {
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    Ok(s)
}

pub(super) async fn write_line<W>(writer: &mut W, line: &str) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}
