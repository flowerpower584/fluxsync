// Pair window. Daemon's `pair_show` IPC payload (re-shaped by the
// Tauri command in `src-tauri/src/lib.rs`) carries a ready-rendered
// `qr_svg` field — no JS QR library needed.

const { invoke } = window.__TAURI__.core;
const { getCurrentWindow } = window.__TAURI__.window;
const { listen } = window.__TAURI__.event;

// The tray boots the daemon on first launch. If the user opens the
// pair window the millisecond the app appears in the menu bar, the
// daemon may still be coming up — retry a few times before surfacing
// the error to the user.
async function pairShowWithRetry({ tries = 8, delayMs = 400 } = {}) {
  let lastErr = null;
  for (let i = 0; i < tries; i++) {
    try {
      const info = await invoke('fluxsync_pair_show');
      if (info) return info;
      lastErr = new Error('empty pair info');
    } catch (e) {
      lastErr = e;
    }
    await new Promise(r => setTimeout(r, delayMs));
  }
  throw lastErr ?? new Error('pair_show failed after retries');
}

// Listen for the `pairing-success` event the tray's setup() emits when
// the daemon's state stream reports a non-empty peer_name. Replaces the
// prior 1s polling loop, which was racy: the tray's IPC client only
// opened the daemon's `cmd` channel, never the `state` channel, so a
// dropped/late status reply could leave the QR up after handshake
// already completed in Rust.
//
// Capture the initial peer_name BEFORE arming the listener so that
// re-opening the QR window after a prior successful pair doesn't
// auto-close on a stale handshake. Without this, opening the window
// calls `pair_show` on the daemon which bumps the FSM into Discovering;
// mDNS rediscovers the still-trusted peer in <1s and re-handshakes
// before the user has a chance to scan a fresh device.
let unlistenPair = null;
async function watchForPair() {
  if (unlistenPair) { unlistenPair(); unlistenPair = null; }
  let initialPeerName = '';
  try {
    const seed = await invoke('fluxsync_status');
    initialPeerName = (seed && seed.data && seed.data.peer_name) || '';
  } catch (_) {
    initialPeerName = '';
  }
  // After 3 seconds, clear the stale-peer guard so a re-handshake
  // with the same device still dismisses the QR window. Without this,
  // mDNS rediscovery of a still-trusted peer could re-handshake but
  // the event would be filtered out because name === initialPeerName.
  setTimeout(() => { initialPeerName = ''; }, 3000);

  unlistenPair = await listen('pairing-success', (event) => {
    const name = event.payload || 'peer';
    if (unlistenPair) { unlistenPair(); unlistenPair = null; }
    showPaired(name === 'pending' ? 'your device' : name);
    setTimeout(() => {
      getCurrentWindow().close();
    }, 400);
  });
}

function showPaired(peerName) {
  const card = document.getElementById('qr-card');
  card.innerHTML =
    `<div style="display:flex;flex-direction:column;align-items:center;gap:12px;` +
    `font-family:'Inter Tight','Inter',sans-serif;color:#0A0A0A">` +
    `<div style="font-size:48px;line-height:1">✓</div>` +
    `<div style="font-size:14px;font-weight:600">Paired with ${escapeHtml(peerName)}</div>` +
    `</div>`;
}

// Fetch `pair_show` and render the QR (or a URI/error fallback). Split
// out of `main` so the unpair button can regenerate the QR after it
// clears the stale pairing that was blocking `pair_show`.
async function generateQr() {
  const card = document.getElementById('qr-card');
  const err = document.getElementById('pair-error');
  err.style.display = 'none';
  err.textContent = '';
  card.innerHTML =
    `<span style="color:#71717A;font-family:'JetBrains Mono',monospace;font-size:11px">Generating…</span>`;

  try {
    const info = await pairShowWithRetry();

    if (info.qr_svg) {
      card.innerHTML = info.qr_svg;
    } else if (info.uri) {
      // Fallback: monospace URI the user can copy into the peer device.
      card.innerHTML =
        `<pre style="margin:0;font-family:'JetBrains Mono',monospace;` +
        `font-size:10px;color:#0A0A0A;white-space:pre-wrap;word-break:break-all">` +
        escapeHtml(info.uri) + `</pre>`;
    } else {
      card.innerHTML =
        `<span style="color:#71717A;font-family:'JetBrains Mono',monospace;font-size:11px">` +
        `No URI returned by daemon.</span>`;
    }

    document.getElementById('fp-words').textContent =
      (info.fingerprint_words || []).join(' ');
    document.getElementById('addr-hint').textContent =
      `REACHABLE AT ${info.addr_hint || '—'}`;
  } catch (e) {
    err.style.display = 'block';
    err.textContent = `Pair info unavailable: ${e?.message || e}`;
  }
}

// Unpair-all button. The daemon's `pair_show` refuses with
// `already_paired` while a trusted peer exists, so the QR can't render
// until pairing is cleared. First click arms a confirm; the second
// click within 4s clears every trusted peer (daemon `unpair` op) and
// regenerates the QR. Reversible — just pair again.
function setupUnpairButton() {
  const btn = document.getElementById('unpair-btn');
  if (!btn) return;
  const idle = 'Unpair all devices';
  let armed = false;
  let armTimer = null;

  function disarm() {
    armed = false;
    btn.textContent = idle;
    btn.classList.remove('armed');
    if (armTimer) { clearTimeout(armTimer); armTimer = null; }
  }

  btn.addEventListener('click', async () => {
    if (!armed) {
      armed = true;
      btn.textContent = 'Click again to confirm';
      btn.classList.add('armed');
      armTimer = setTimeout(disarm, 4000);
      return;
    }
    disarm();
    btn.disabled = true;
    btn.textContent = 'Unpairing…';
    try {
      await invoke('fluxsync_unpair');
      btn.textContent = 'Unpaired ✓';
      await watchForPair(); // re-arm so a fresh scan still closes the window
      await generateQr();
    } catch (e) {
      const err = document.getElementById('pair-error');
      err.style.display = 'block';
      err.textContent = `Unpair failed: ${e?.message || e}`;
    } finally {
      setTimeout(() => { btn.disabled = false; btn.textContent = idle; }, 1200);
    }
  });
}

(async function main() {
  // Arm the listener BEFORE generating the QR so handshakes that complete
  // during the `pair_show` retry window are not lost. Tauri events are not
  // queued for late subscribers — `listen()` only catches events fired
  // after registration returns.
  await watchForPair();
  setupUnpairButton();
  await generateQr();
})();

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
