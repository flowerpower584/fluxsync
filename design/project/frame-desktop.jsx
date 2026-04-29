// FluxSync — Windows tray flyout + Linux/Arch tray
// Windows: square corners, denser, system tray bottom-right
// Linux: tiling-WM aesthetic, monospace-heavy, bordered

// ── WINDOWS ──────────────────────────────────────────────────
function WindowsTaskbar({ active }) {
  const t = FS.dark; // Windows mock in dark
  return (
    <div style={{
      height: 36,
      background: 'rgba(32,32,32,0.95)',
      backdropFilter: 'blur(40px)',
      borderTop: `1px solid #333`,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 8px',
      color: '#fff',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {/* Start + Search + pinned */}
        <div style={{ width: 28, height: 28, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ width: 14, height: 14, display: 'grid', gridTemplateColumns: '1fr 1fr', gridTemplateRows: '1fr 1fr', gap: 1 }}>
            {[0, 1, 2, 3].map(i => <div key={i} style={{ background: '#fff' }} />)}
          </div>
        </div>
        {[1, 2, 3].map(i => (
          <div key={i} style={{ width: 28, height: 28, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ width: 14, height: 14, border: '1px solid #888', borderRadius: 2 }} />
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 6px', fontSize: 11 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '2px 5px', background: 'rgba(255,255,255,0.08)', borderRadius: 2 }}>
          <TrayGlyph active={active} theme="dark" size={12} />
        </span>
        <span style={{ color: '#aaa' }}>📶</span>
        <span style={{ color: '#aaa' }}>🔊</span>
        <div style={{ textAlign: 'right', lineHeight: 1.1, fontSize: 10, color: '#ccc' }} className="mono">
          <div>14:32</div>
          <div>04/25/2026</div>
        </div>
      </div>
    </div>
  );
}

function WindowsTray({ state, setState }) {
  const t = FS.dark;
  const { on, batteryThreshold, history, peerName, peerBattery, peerCharging } = state;
  const peerBelow = peerBattery <= batteryThreshold;
  const peerCritical = peerBattery <= 5;
  const syncPaused = on && peerBelow && !peerCharging;
  const effectiveStatus = !on ? 'off' : peerCritical ? 'crit' : syncPaused ? 'warn' : 'ok';
  const statusLabel = !on ? 'INACTIVE' : peerCritical ? 'CRITICAL' : syncPaused ? 'PAUSED' : 'SYNCING';

  return (
    <div style={{
      width: 340,
      background: '#1C1C1E',
      border: `1px solid ${t.borderStrong}`,
      borderRadius: 4,
      color: t.fg,
      fontSize: 12,
      overflow: 'hidden',
    }}>
      {/* Window-style header strip */}
      <div style={{
        padding: '10px 12px',
        borderBottom: `1px solid ${t.border}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <TrayGlyph active={on} theme="dark" size={14} />
          <span style={{ fontWeight: 600 }}>FluxSync</span>
        </div>
        <span className="mono" style={{ color: t.subtle, fontSize: 9 }} data-uppercase>0.4.2 · WIN-AMD64</span>
      </div>

      {/* Toggle */}
      <div style={{
        padding: '12px',
        borderBottom: `1px solid ${t.border}`,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <div>
          <div style={{ fontWeight: 500 }}>Sync</div>
          <div className="mono" style={{ color: t.muted, fontSize: 10, marginTop: 2 }}>
            <Dot status={effectiveStatus} pulse={effectiveStatus === 'ok'} style={{ marginRight: 5 }} />
            <span data-uppercase>{statusLabel}</span>
          </div>
        </div>
        <Toggle on={on} onChange={(v) => setState({ ...state, on: v })} theme="dark" />
      </div>

      {/* Network grid (peer info) */}
      <div style={{ padding: '10px 12px', borderBottom: `1px solid ${t.border}` }}>
        <SectionLabel theme="dark" right={<span className="mono"><Dot status={on ? 'ok' : 'off'} size={5} style={{ marginRight: 4 }} />UDP/41889</span>}>
          Mesh
        </SectionLabel>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }} className="mono">
          <tbody>
            <tr style={{ color: t.muted, fontSize: 9 }} data-uppercase>
              <td style={{ padding: '3px 0' }}>Host</td>
              <td>Net</td>
              <td>Batt</td>
              <td style={{ textAlign: 'right' }}>RTT</td>
            </tr>
            <tr style={{ borderTop: `1px solid ${t.border}` }}>
              <td style={{ padding: '5px 0', color: t.fg }}>this-pc</td>
              <td style={{ color: t.muted }}>lan</td>
              <td style={{ color: FS.ok }}>—</td>
              <td style={{ textAlign: 'right', color: t.muted }}>self</td>
            </tr>
            <tr style={{ borderTop: `1px solid ${t.border}` }}>
              <td style={{ padding: '5px 0', color: t.fg }}>{peerName.toLowerCase().replace(/\s/g, '-')}</td>
              <td style={{ color: t.muted }}>wlan</td>
              <td style={{ color: peerCritical ? FS.crit : peerBelow ? FS.warn : FS.ok }}>
                {peerBattery}%{peerCharging ? '⚡' : ''}
              </td>
              <td style={{ textAlign: 'right', color: t.muted }}>12ms</td>
            </tr>
          </tbody>
        </table>
        {syncPaused && (
          <div style={{
            marginTop: 8, padding: '5px 7px',
            background: FS.warnSoft, borderLeft: `2px solid ${FS.warn}`,
            fontSize: 10.5, color: '#E6BC6E',
          }}>
            Sync paused — peer battery below {batteryThreshold}%.
          </div>
        )}
      </div>

      {/* Compact history */}
      <div style={{ padding: '8px 12px' }}>
        <SectionLabel theme="dark" right={<span className="mono">LAST {Math.min(history.length, 5)}</span>}>
          Clipboard buffer
        </SectionLabel>
        {history.slice(0, 5).map((h, i) => (
          <div key={i} style={{
            padding: '4px 0',
            display: 'grid', gridTemplateColumns: '32px 1fr 36px',
            gap: 8, fontSize: 11, alignItems: 'center',
            borderBottom: i < 4 ? `1px solid ${t.border}` : 'none',
          }}>
            <span className="mono" style={{ color: t.subtle, fontSize: 9 }} data-uppercase>{h.kind}</span>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.preview}</span>
            <span className="mono" style={{ color: t.subtle, fontSize: 9, textAlign: 'right' }}>{h.time}</span>
          </div>
        ))}
      </div>

      <div style={{
        borderTop: `1px solid ${t.border}`,
        padding: '7px 12px',
        display: 'flex', justifyContent: 'space-between',
        fontSize: 10,
        background: '#161618',
      }} className="mono">
        <span style={{ color: t.muted }}>Settings</span>
        <span style={{ color: t.subtle }} data-uppercase>Ctrl+Shift+V</span>
      </div>
    </div>
  );
}

// ── LINUX / ARCH (tiling WM aesthetic) ───────────────────────
function LinuxBar({ active }) {
  const t = FS.dark;
  return (
    <div className="mono" style={{
      height: 22,
      background: '#0d0d0e',
      borderBottom: `1px solid #222`,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 8px',
      color: '#bbb',
      fontSize: 11,
    }}>
      <div style={{ display: 'flex', gap: 4 }}>
        {['1:web', '2:term', '3:fs', '4:dev'].map((w, i) => (
          <span key={i} style={{
            padding: '0 6px',
            background: i === 2 ? FS.crit : 'transparent',
            color: i === 2 ? '#fff' : '#888',
          }}>{w}</span>
        ))}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span><TrayGlyph active={active} theme="dark" size={11} /></span>
        <span>cpu 14%</span>
        <span>mem 3.2/16G</span>
        <span style={{ color: '#fff' }}>14:32:07</span>
      </div>
    </div>
  );
}

function LinuxTray({ state, setState }) {
  const t = FS.dark;
  const { on, batteryThreshold, history, peerName, peerBattery, peerCharging } = state;
  const peerBelow = peerBattery <= batteryThreshold;
  const peerCritical = peerBattery <= 5;
  const syncPaused = on && peerBelow && !peerCharging;
  const statusLabel = !on ? 'inactive' : peerCritical ? 'critical' : syncPaused ? 'paused' : 'syncing';
  const statusColor = !on ? t.subtle : peerCritical ? FS.crit : syncPaused ? FS.warn : FS.ok;

  return (
    <div className="mono" style={{
      width: 360,
      background: '#0d0d0e',
      border: `1px solid ${FS.crit}`,
      color: '#d4d4d8',
      fontSize: 11,
      overflow: 'hidden',
    }}>
      {/* Title bar — dwm/i3 style */}
      <div style={{
        padding: '4px 9px',
        borderBottom: `1px solid #222`,
        display: 'flex', justifyContent: 'space-between',
        background: '#141416',
      }}>
        <span><span style={{ color: FS.crit }}>▍</span> fluxsync — ~/fluxsyncd</span>
        <span style={{ color: '#666' }} data-uppercase>v0.4.2</span>
      </div>

      <div style={{ padding: '10px 12px' }}>
        {/* Status block */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div>
            <div style={{ color: '#888', fontSize: 9 }} data-uppercase>fluxsyncd.service</div>
            <div style={{ marginTop: 3, color: statusColor }}>
              <span style={{ marginRight: 4 }}>●</span>{statusLabel}
              <span style={{ color: '#666', marginLeft: 6 }}>(systemd · pid 1247)</span>
            </div>
          </div>
          <Toggle on={on} onChange={(v) => setState({ ...state, on: v })} theme="dark" />
        </div>

        {/* Peer block, terminal table */}
        <div style={{ borderTop: `1px dashed #333`, paddingTop: 8, marginBottom: 8 }}>
          <div style={{ color: '#666', fontSize: 9, marginBottom: 4 }} data-uppercase>$ fluxctl peers</div>
          <div style={{ display: 'grid', gridTemplateColumns: '14px 1fr auto auto', gap: 8, alignItems: 'center', padding: '2px 0' }}>
            <span style={{ color: FS.ok }}>↔</span>
            <span style={{ color: '#fff' }}>{peerName.toLowerCase().replace(/\s/g, '-')}.local</span>
            <span style={{ color: peerCritical ? FS.crit : peerBelow ? FS.warn : FS.ok }}>
              batt={peerBattery}{peerCharging ? '+' : ''}
            </span>
            <span style={{ color: '#666' }}>12ms</span>
          </div>
        </div>

        {/* Conditions */}
        <div style={{ borderTop: `1px dashed #333`, paddingTop: 8, marginBottom: 8 }}>
          <div style={{ color: '#666', fontSize: 9, marginBottom: 4 }} data-uppercase>conditions</div>
          <div style={{ color: '#aaa' }}>
            <span style={{ color: '#666' }}>threshold</span> = {batteryThreshold}%<br/>
            <span style={{ color: '#666' }}>charge_override</span> = <span style={{ color: FS.ok }}>true</span><br/>
            <span style={{ color: '#666' }}>cipher</span> = <span style={{ color: FS.ok }}>chacha20-poly1305</span>
          </div>
        </div>

        {/* History */}
        <div style={{ borderTop: `1px dashed #333`, paddingTop: 8 }}>
          <div style={{ color: '#666', fontSize: 9, marginBottom: 4 }} data-uppercase>$ fluxctl tail -n 5</div>
          {history.slice(0, 5).map((h, i) => (
            <div key={i} style={{ display: 'flex', gap: 8, padding: '2px 0', color: '#aaa' }}>
              <span style={{ color: '#555', width: 38, flexShrink: 0 }}>{h.time}</span>
              <span style={{ color: FS.crit, width: 32, flexShrink: 0 }} data-uppercase>{h.kind}</span>
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{h.preview}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{
        background: '#141416',
        borderTop: `1px solid #222`,
        padding: '4px 9px',
        color: '#666',
        display: 'flex', justifyContent: 'space-between',
      }}>
        <span><span style={{ color: FS.crit }}>:</span>q to close</span>
        <span data-uppercase>e2e · linked</span>
      </div>
    </div>
  );
}

Object.assign(window, { WindowsTaskbar, WindowsTray, LinuxBar, LinuxTray });
