// FluxSync — macOS tray dropdown
// Lives in the menu bar. Soft blur, 8px radius, subtle 1px border.

function MacOSMenuBar({ theme = 'light', active }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  return (
    <div style={{
      height: 24,
      background: theme === 'dark' ? 'rgba(28,28,30,0.85)' : 'rgba(255,255,255,0.7)',
      backdropFilter: 'blur(20px)',
      borderBottom: `1px solid ${t.border}`,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 10px',
      fontSize: 12,
      color: t.fg,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <span style={{ fontWeight: 600, fontSize: 13 }}></span>
        <span style={{ fontWeight: 600 }}>Finder</span>
        <span style={{ color: t.muted }}>File</span>
        <span style={{ color: t.muted }}>Edit</span>
        <span style={{ color: t.muted }}>View</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* the FluxSync tray icon, highlighted */}
        <span style={{
          padding: '2px 5px',
          background: theme === 'dark' ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.06)',
          borderRadius: 3,
          display: 'flex', alignItems: 'center', gap: 5,
        }}>
          <TrayGlyph active={active} theme={theme} />
        </span>
        <span style={{ color: t.muted, fontSize: 11 }} className="mono">14:32</span>
        <span style={{ color: t.muted, fontSize: 11 }}>📶</span>
        <span style={{ color: t.muted, fontSize: 11 }}>🔋</span>
      </div>
    </div>
  );
}

// The actual tray icon — a stylized "clip + sync" mark
function TrayGlyph({ active = true, theme = 'light', size = 13 }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  const c = active ? FS.crit : t.muted;
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none">
      {/* Two stacked rounded rects (clipboard layers) */}
      <rect x="2.5" y="3" width="8" height="9" stroke={c} strokeWidth="1.3" />
      <rect x="5.5" y="6" width="8" height="9" stroke={c} strokeWidth="1.3" fill={theme === 'dark' ? '#1c1c1e' : '#fff'} />
      {active && <circle cx="13.5" cy="3" r="1.5" fill={FS.ok} />}
    </svg>
  );
}

function MacOSTray({ state, setState, focused = false }) {
  const theme = 'light';
  const t = FS.light;
  const { on, batteryLevel, batteryThreshold, charging, history, peerName, peerBattery, peerCharging } = state;

  const peerBelow = peerBattery <= batteryThreshold;
  const peerCritical = peerBattery <= 5;
  const syncPaused = on && peerBelow && !peerCharging;
  const effectiveStatus = !on ? 'off' : peerCritical ? 'crit' : syncPaused ? 'warn' : 'ok';
  const statusLabel = !on ? 'INACTIVE' : peerCritical ? 'CRITICAL' : syncPaused ? 'PAUSED · LOW BATTERY' : 'SYNCHRONIZING';

  return (
    <div style={{
      width: 360,
      background: t.surface,
      border: `1px solid ${t.border}`,
      borderRadius: 8,
      boxShadow: '0 12px 40px rgba(0,0,0,0.12), 0 2px 6px rgba(0,0,0,0.06)',
      overflow: 'hidden',
      color: t.fg,
      fontSize: 12,
    }}>
      {/* Header — brand + version */}
      <div style={{
        padding: '12px 14px 10px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottom: `1px solid ${t.border}`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <TrayGlyph active={on} size={16} />
          <span style={{ fontWeight: 600, letterSpacing: '-0.01em' }}>FluxSync</span>
          <span className="mono" style={{ color: t.subtle, fontSize: 10 }}>v0.4.2</span>
        </div>
        <E2EBadge compact />
      </div>

      {/* Master toggle */}
      <div style={{
        padding: '14px 14px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: `1px solid ${t.border}`,
        background: on ? '#FBFBFA' : 'transparent',
      }}>
        <div>
          <div style={{ fontWeight: 500, fontSize: 13 }}>Clipboard sync</div>
          <div className="mono" style={{ color: t.muted, fontSize: 10, marginTop: 2 }}>
            <Dot status={effectiveStatus} pulse={effectiveStatus === 'ok'} style={{ marginRight: 5, verticalAlign: 'middle' }} />
            <span data-uppercase>{statusLabel}</span>
          </div>
        </div>
        <Toggle on={on} onChange={(v) => setState({ ...state, on: v })} />
      </div>

      {/* Peer device card */}
      <div style={{ padding: '10px 14px 12px', borderBottom: `1px solid ${t.border}` }}>
        <SectionLabel right={<span><Dot status={on ? 'ok' : 'off'} size={5} style={{ marginRight: 4 }} />{on ? 'LINKED' : 'STANDBY'}</span>}>
          Peer device
        </SectionLabel>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 28, height: 28,
              border: `1px solid ${t.border}`, borderRadius: 4,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <svg width="11" height="16" viewBox="0 0 11 16" fill="none">
                <rect x="0.5" y="0.5" width="10" height="15" rx="1.5" stroke={t.muted} />
                <circle cx="5.5" cy="13" r="0.7" fill={t.muted} />
              </svg>
            </div>
            <div>
              <div style={{ fontWeight: 500 }}>{peerName}</div>
              <div className="mono" style={{ color: t.subtle, fontSize: 10 }}>android · 192.168.1.42</div>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3 }}>
            <Battery level={peerBattery} charging={peerCharging} threshold={batteryThreshold} />
            <span className="mono" style={{ fontSize: 10, color: peerCritical ? FS.crit : peerBelow ? FS.warn : t.muted }}>
              {peerBattery}%{peerCharging ? ' ⚡' : ''}
            </span>
          </div>
        </div>

        {syncPaused && (
          <div style={{
            marginTop: 8,
            padding: '6px 8px',
            background: FS.warnSoft,
            borderLeft: `2px solid ${FS.warn}`,
            fontSize: 11,
            color: '#7A5A1F',
            display: 'flex', gap: 6, alignItems: 'flex-start',
          }}>
            <span>⏸</span>
            <span>Sync auto-paused. Peer below {batteryThreshold}% threshold.</span>
          </div>
        )}
        {peerCritical && (
          <div style={{
            marginTop: 8,
            padding: '6px 8px',
            background: FS.critSoft,
            borderLeft: `2px solid ${FS.crit}`,
            fontSize: 11,
            color: FS.crit,
          }}>
            Peer battery critical ({peerBattery}%) — sync halted.
          </div>
        )}
      </div>

      {/* History */}
      <div style={{ padding: '10px 14px 8px' }}>
        <SectionLabel right={<span className="mono">{history.length} ITEMS</span>}>
          Recent clipboard
        </SectionLabel>
        <div>
          {history.slice(0, 5).map((h, i) => (
            <button
              key={i}
              style={{
                width: '100%', textAlign: 'left',
                padding: '6px 8px',
                margin: '0 -8px',
                display: 'flex', alignItems: 'center', gap: 8,
                fontSize: 11.5,
                borderRadius: 3,
                color: t.fg,
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = t.hover}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <span className="mono" style={{ color: t.subtle, fontSize: 9, width: 28, flexShrink: 0 }} data-uppercase>{h.kind}</span>
              <span style={{
                flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                fontFamily: h.kind === 'text' ? 'inherit' : FS.mono.split(',')[0].replace(/'/g, ''),
              }}>
                {h.preview}
              </span>
              <span className="mono" style={{ color: t.subtle, fontSize: 9 }}>{h.time}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Footer actions */}
      <div style={{
        borderTop: `1px solid ${t.border}`,
        padding: '8px 14px',
        display: 'flex', justifyContent: 'space-between',
        fontSize: 11,
        background: '#FBFBFA',
      }}>
        <button style={{ color: t.muted }} onMouseEnter={e => e.currentTarget.style.color = t.fg} onMouseLeave={e => e.currentTarget.style.color = t.muted}>
          Settings…
        </button>
        <span className="mono" style={{ color: t.subtle, fontSize: 10 }}>⌘⇧V to paste from peer</span>
      </div>
    </div>
  );
}

Object.assign(window, { MacOSTray, MacOSMenuBar, TrayGlyph });
