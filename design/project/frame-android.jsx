// FluxSync — Android app (full screen, single page)

function AndroidStatusBar({ active }) {
  return (
    <div style={{
      height: 28,
      background: '#0B0B0C',
      color: '#fff',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 14px',
      fontSize: 11,
    }} className="mono">
      <span>14:32</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10 }}>
        {active && <span style={{ color: FS.ok }}>●</span>}
        <span>4G</span>
        <span>📶</span>
        <span>87%</span>
      </div>
    </div>
  );
}

function AndroidApp({ state, setState }) {
  const t = FS.dark;
  const {
    on, batteryLevel, batteryThreshold, charging,
    peerName, peerBattery, peerCharging,
    history,
  } = state;

  const myBelow = batteryLevel <= batteryThreshold;
  const myCritical = batteryLevel <= 5;
  const syncPaused = on && myBelow && !charging;
  const effectiveStatus = !on ? 'off' : myCritical ? 'crit' : syncPaused ? 'warn' : 'ok';
  const statusLabel = !on ? 'INACTIVE' : myCritical ? 'CRITICAL' : syncPaused ? 'PAUSED' : 'SYNCHRONIZING';

  return (
    <div style={{
      width: 360, height: 760,
      background: t.bg, color: t.fg,
      display: 'flex', flexDirection: 'column',
      fontSize: 13,
    }}>
      <AndroidStatusBar active={on} />

      {/* Top app bar */}
      <div style={{
        padding: '18px 20px 14px',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        borderBottom: `1px solid ${t.border}`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <TrayGlyph active={on} theme="dark" size={18} />
          <div>
            <div style={{ fontWeight: 600, fontSize: 16, letterSpacing: '-0.01em' }}>FluxSync</div>
            <div className="mono" style={{ color: t.subtle, fontSize: 10, marginTop: 1 }} data-uppercase>v0.4.2 · android</div>
          </div>
        </div>
        <button style={{ width: 32, height: 32, border: `1px solid ${t.border}`, borderRadius: 4, color: t.muted, fontSize: 16 }}>≡</button>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px 20px' }}>
        {/* Hero status card */}
        <div style={{
          padding: 18,
          border: `1px solid ${effectiveStatus === 'ok' ? FS.ok : effectiveStatus === 'warn' ? FS.warn : effectiveStatus === 'crit' ? FS.crit : t.border}`,
          borderRadius: 4,
          background: effectiveStatus === 'crit' ? FS.critSoft : effectiveStatus === 'warn' ? FS.warnSoft : t.surface,
          marginBottom: 14,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="mono" style={{ color: t.muted, fontSize: 10 }} data-uppercase>
                <Dot status={effectiveStatus} pulse={effectiveStatus === 'ok'} style={{ marginRight: 6 }} />
                {statusLabel}
              </div>
              <div style={{ fontSize: 24, fontWeight: 600, letterSpacing: '-0.02em', marginTop: 8 }}>
                {on ? (syncPaused ? 'On hold' : myCritical ? 'Halted' : 'Live') : 'Offline'}
              </div>
              <div style={{ color: t.muted, fontSize: 12, marginTop: 4 }}>
                {!on
                  ? 'Tap the switch to start sharing your clipboard.'
                  : syncPaused
                  ? `Battery below ${batteryThreshold}%. Resumes when you charge.`
                  : myCritical
                  ? 'Battery critical. All sync stopped.'
                  : `Linked with ${peerName}.`}
              </div>
            </div>
            <Toggle on={on} onChange={(v) => setState({ ...state, on: v })} theme="dark" size="md" />
          </div>
        </div>

        {/* Hardware row: this device + peer */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 14 }}>
          {[
            { label: 'This device', name: 'Galaxy S21 Ultra', batt: batteryLevel, charging, mine: true },
            { label: 'Peer', name: peerName, batt: peerBattery, charging: peerCharging, mine: false },
          ].map((d, i) => {
            const below = d.batt <= batteryThreshold;
            const critical = d.batt <= 5;
            return (
              <div key={i} style={{
                padding: '10px 12px',
                border: `1px solid ${t.border}`,
                borderRadius: 4,
                background: t.surface,
              }}>
                <div className="mono" style={{ color: t.subtle, fontSize: 9 }} data-uppercase>{d.label}</div>
                <div style={{ marginTop: 4, fontSize: 12, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.name}</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8 }}>
                  <Battery level={d.batt} charging={d.charging} threshold={batteryThreshold} theme="dark" width={24} />
                  <span className="mono" style={{
                    fontSize: 11,
                    color: critical ? FS.crit : below ? FS.warn : t.fg,
                  }}>{d.batt}%{d.charging ? '⚡' : ''}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Conditions panel */}
        <div style={{ marginBottom: 14 }}>
          <SectionLabel theme="dark" right={<E2EBadge theme="dark" compact />}>
            Conditions
          </SectionLabel>
          <div style={{
            padding: '14px 14px 16px',
            border: `1px solid ${t.border}`,
            borderRadius: 4,
            background: t.surface,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
              <div>
                <div className="mono" style={{ color: t.muted, fontSize: 10 }} data-uppercase>Pause sync below</div>
                <div style={{ fontSize: 22, fontWeight: 600, marginTop: 2, letterSpacing: '-0.02em' }}>
                  {batteryThreshold}<span style={{ color: t.muted, fontWeight: 400 }}>%</span>
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div className="mono" style={{ fontSize: 10, color: t.subtle }} data-uppercase>Status</div>
                <div className="mono" style={{ fontSize: 11, color: myBelow ? FS.warn : FS.ok, marginTop: 2 }}>
                  {myBelow ? `${batteryLevel - batteryThreshold}% below` : `${batteryLevel - batteryThreshold}% above`}
                </div>
              </div>
            </div>
            <div style={{ marginTop: 12 }}>
              <Slider value={batteryThreshold} onChange={(v) => setState({ ...state, batteryThreshold: v })} min={5} max={50} theme="dark" />
              <div className="mono" style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: t.subtle, marginTop: 4 }}>
                <span>5%</span><span>20%</span><span>35%</span><span>50%</span>
              </div>
            </div>
            <div style={{
              marginTop: 12, paddingTop: 12, borderTop: `1px solid ${t.border}`,
              display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12,
            }}>
              <div>
                <div>Resume while charging</div>
                <div style={{ color: t.muted, fontSize: 11 }}>Override threshold when plugged in</div>
              </div>
              <Toggle on={true} onChange={() => {}} theme="dark" size="sm" />
            </div>
          </div>
        </div>

        {/* Recent clipboard */}
        <div>
          <SectionLabel theme="dark" right={<span className="mono">{history.length} ITEMS</span>}>
            Recent
          </SectionLabel>
          <div style={{ border: `1px solid ${t.border}`, borderRadius: 4, background: t.surface }}>
            {history.slice(0, 4).map((h, i) => (
              <div key={i} style={{
                padding: '10px 12px',
                borderBottom: i < 3 ? `1px solid ${t.border}` : 'none',
                display: 'flex', alignItems: 'center', gap: 10,
              }}>
                <span className="mono" style={{ color: t.subtle, fontSize: 9, width: 28 }} data-uppercase>{h.kind}</span>
                <span style={{ flex: 1, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.preview}</span>
                <span className="mono" style={{ color: t.subtle, fontSize: 9 }}>{h.time}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom nav rail */}
      <div style={{
        borderTop: `1px solid ${t.border}`,
        background: t.surface,
        padding: '8px 20px 14px',
        display: 'flex', justifyContent: 'space-around',
        fontSize: 10,
      }}>
        {[
          { l: 'Home', a: true },
          { l: 'Devices' },
          { l: 'Logs' },
          { l: 'Settings' },
        ].map((n, i) => (
          <div key={i} style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3,
            color: n.a ? FS.crit : t.muted,
          }}>
            <div style={{ width: 16, height: 16, border: `1px solid currentColor`, borderRadius: 2, opacity: n.a ? 1 : 0.6 }} />
            <span className="mono" data-uppercase style={{ fontSize: 9 }}>{n.l}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

Object.assign(window, { AndroidApp, AndroidStatusBar });
