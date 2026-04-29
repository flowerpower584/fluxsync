// FluxSync — Friendly logs view
// Terminal feel, but plain English messages and color-coded levels.
// No cryptic IDs unless explicitly toggled.

function LogsView({ state, theme = 'dark' }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  const [filter, setFilter] = React.useState('all');
  const [showRaw, setShowRaw] = React.useState(false);

  const allLogs = [
    { time: '14:32:07', level: 'OK',   msg: 'Clipboard updated — text copied from S21 Ultra (38 chars).' },
    { time: '14:32:01', level: 'INFO', msg: 'Galaxy S21 Ultra came back online.' },
    { time: '14:31:48', level: 'SYNC', msg: 'Sent URL to peer: github.com/...  (encrypted, 0.2 KB).' },
    { time: '14:30:12', level: 'WARN', msg: 'Peer battery dropped to 14%. Sync paused automatically.' },
    { time: '14:28:45', level: 'INFO', msg: 'Connection healthy. Round-trip 11ms.' },
    { time: '14:25:03', level: 'OK',   msg: 'Handshake successful. Session key rotated.' },
    { time: '14:24:58', level: 'INFO', msg: 'Discovered peer "Galaxy S21 Ultra" via mDNS.' },
    { time: '14:24:55', level: 'INFO', msg: 'Daemon started. Listening on UDP/41889.' },
    { time: '14:18:22', level: 'ERR',  msg: 'Could not reach peer (timeout). Will retry in 30s.' },
    { time: '14:18:11', level: 'INFO', msg: 'Network changed: wifi-home → wifi-cafe.' },
  ];

  const filtered = filter === 'all' ? allLogs : allLogs.filter(l => l.level.toLowerCase() === filter);

  const counts = {
    ok: allLogs.filter(l => l.level === 'OK').length,
    info: allLogs.filter(l => l.level === 'INFO').length,
    warn: allLogs.filter(l => l.level === 'WARN').length,
    err: allLogs.filter(l => l.level === 'ERR').length,
    sync: allLogs.filter(l => l.level === 'SYNC').length,
  };

  return (
    <div style={{
      width: 640,
      background: t.surface,
      border: `1px solid ${t.border}`,
      borderRadius: 4,
      color: t.fg,
      overflow: 'hidden',
    }}>
      {/* Toolbar */}
      <div style={{
        padding: '10px 14px',
        borderBottom: `1px solid ${t.border}`,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: theme === 'dark' ? '#0F0F12' : '#FBFBFA',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontWeight: 600, fontSize: 13 }}>Activity</span>
          <span className="mono" style={{ color: t.subtle, fontSize: 10 }} data-uppercase>
            live · {allLogs.length} events
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {[
            { k: 'all', label: 'All', n: allLogs.length },
            { k: 'ok', label: 'OK', n: counts.ok, c: FS.ok },
            { k: 'sync', label: 'Sync', n: counts.sync, c: FS.crit },
            { k: 'warn', label: 'Warn', n: counts.warn, c: FS.warn },
            { k: 'err', label: 'Errors', n: counts.err, c: FS.crit },
          ].map(f => (
            <button
              key={f.k}
              onClick={() => setFilter(f.k)}
              style={{
                padding: '3px 8px',
                fontSize: 11,
                border: `1px solid ${filter === f.k ? (f.c || t.fg) : t.border}`,
                color: filter === f.k ? (f.c || t.fg) : t.muted,
                background: filter === f.k ? `${(f.c || t.fg)}11` : 'transparent',
                borderRadius: 2,
                display: 'flex', alignItems: 'center', gap: 5,
              }}
            >
              {f.label}
              <span className="mono" style={{ fontSize: 9, opacity: 0.7 }}>{f.n}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Friendly mode banner — explains what this view is */}
      <div style={{
        padding: '8px 14px',
        background: theme === 'dark' ? 'rgba(91,127,191,0.08)' : 'rgba(91,127,191,0.06)',
        borderBottom: `1px solid ${t.border}`,
        fontSize: 11,
        color: t.muted,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
          <span>
            <span style={{ color: FS.info, marginRight: 6 }}>ℹ</span>
            Plain-English log of what FluxSync is doing. Nothing technical to read here.
          </span>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10 }} className="mono">
          <input
            type="checkbox"
            checked={showRaw}
            onChange={(e) => setShowRaw(e.target.checked)}
            style={{ accentColor: FS.crit }}
          />
          <span data-uppercase>Show raw</span>
        </label>
      </div>

      {/* Log stream */}
      <div className="mono" style={{
        padding: '8px 14px',
        maxHeight: 320,
        overflowY: 'auto',
        fontSize: 11,
        background: theme === 'dark' ? '#08080A' : '#FFFFFF',
      }}>
        {filtered.map((entry, i) => {
          const levelColor = {
            OK: FS.ok, INFO: FS.info, WARN: FS.warn, ERR: FS.crit, SYNC: FS.crit,
          }[entry.level];
          return (
            <div key={i} style={{
              display: 'grid',
              gridTemplateColumns: '64px 56px 1fr',
              gap: 10,
              padding: '4px 0',
              borderBottom: i < filtered.length - 1 ? `1px solid ${theme === 'dark' ? '#15151A' : '#F4F4F5'}` : 'none',
              alignItems: 'baseline',
            }}>
              <span style={{ color: t.subtle, fontSize: 10 }}>{entry.time}</span>
              <span style={{ color: levelColor, fontWeight: 500, fontSize: 10 }} data-uppercase>
                ● {entry.level}
              </span>
              <span style={{
                color: t.fg,
                fontFamily: showRaw ? FS.mono.split(',')[0].replace(/'/g, '') : FS.ui,
                fontSize: showRaw ? 10.5 : 11.5,
                lineHeight: 1.5,
              }}>
                {showRaw
                  ? `[${entry.level}] ts=${entry.time} ${entry.msg.replace(/\.$/, '')}`
                  : entry.msg}
              </span>
            </div>
          );
        })}
      </div>

      {/* Footer — quick actions */}
      <div style={{
        padding: '8px 14px',
        borderTop: `1px solid ${t.border}`,
        display: 'flex',
        justifyContent: 'space-between',
        fontSize: 10,
        color: t.muted,
        background: theme === 'dark' ? '#0F0F12' : '#FBFBFA',
      }} className="mono">
        <div style={{ display: 'flex', gap: 14 }}>
          <span data-uppercase>↓ export</span>
          <span data-uppercase>⌫ clear</span>
          <span data-uppercase>⏸ pause stream</span>
        </div>
        <span data-uppercase>auto-scroll on</span>
      </div>
    </div>
  );
}

Object.assign(window, { LogsView });
