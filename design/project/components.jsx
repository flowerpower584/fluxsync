// FluxSync — shared primitives
// All components push to window at end so other Babel scripts can use them.

const FS = {
  // Light tokens
  light: {
    bg: '#FAFAF9',
    surface: '#FFFFFF',
    fg: '#0A0A0A',
    muted: '#71717A',
    subtle: '#A1A1AA',
    border: '#E4E4E7',
    borderStrong: '#D4D4D8',
    hover: '#F4F4F5',
  },
  dark: {
    bg: '#0B0B0C',
    surface: '#131316',
    fg: '#FAFAFA',
    muted: '#A1A1AA',
    subtle: '#71717A',
    border: '#1F1F22',
    borderStrong: '#2A2A2E',
    hover: '#1A1A1D',
  },
  // Status — intentionally desaturated
  ok: '#3FAE5A',
  okSoft: 'rgba(63,174,90,0.12)',
  warn: '#D9A441',
  warnSoft: 'rgba(217,164,65,0.14)',
  crit: '#D43F3F', // rouge sénégalais
  critSoft: 'rgba(212,63,63,0.12)',
  info: '#5B7FBF',
  ui: "'Inter Tight', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
  mono: "'JetBrains Mono', 'SF Mono', ui-monospace, monospace",
};

// Inject base font + reset, scoped to .fs-root.
if (typeof document !== 'undefined' && !document.getElementById('fs-styles')) {
  const s = document.createElement('style');
  s.id = 'fs-styles';
  s.textContent = `
    @import url('https://fonts.googleapis.com/css2?family=Inter+Tight:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap');
    .fs-root, .fs-root *{box-sizing:border-box;font-family:${FS.ui};-webkit-font-smoothing:antialiased;}
    .fs-root .mono{font-family:${FS.mono};font-feature-settings:"calt" 0;}
    .fs-root button{font-family:inherit;cursor:pointer;border:0;background:none;padding:0;color:inherit;}
    .fs-root [data-uppercase]{text-transform:uppercase;letter-spacing:0.06em;}
    @keyframes fs-pulse{0%,100%{opacity:1}50%{opacity:.45}}
    @keyframes fs-blink{0%,49%{opacity:1}50%,100%{opacity:.25}}
    .fs-pulse{animation:fs-pulse 1.6s ease-in-out infinite;}
    .fs-blink{animation:fs-blink 1.1s steps(1) infinite;}
    .fs-root ::selection{background:${FS.crit};color:#fff;}
  `;
  document.head.appendChild(s);
}

// ── Status dot ────────────────────────────────────────────────
function Dot({ status = 'ok', size = 6, pulse = false, style }) {
  const colors = { ok: FS.ok, warn: FS.warn, crit: FS.crit, off: '#52525B', info: FS.info };
  return (
    <span
      className={pulse ? 'fs-pulse' : ''}
      style={{
        display: 'inline-block',
        width: size,
        height: size,
        borderRadius: '50%',
        background: colors[status],
        boxShadow: status !== 'off' ? `0 0 0 3px ${colors[status]}22` : 'none',
        flexShrink: 0,
        ...style,
      }}
    />
  );
}

// ── Toggle switch (square, 1px, no gradient) ──────────────────
function Toggle({ on, onChange, size = 'md', theme = 'light', disabled }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  const dims = size === 'sm' ? { w: 28, h: 16, k: 12 } : { w: 36, h: 20, k: 16 };
  return (
    <button
      onClick={() => !disabled && onChange?.(!on)}
      style={{
        width: dims.w,
        height: dims.h,
        border: `1px solid ${on ? FS.crit : t.borderStrong}`,
        background: on ? FS.crit : 'transparent',
        borderRadius: 2,
        position: 'relative',
        transition: 'all .15s ease',
        opacity: disabled ? 0.4 : 1,
        cursor: disabled ? 'not-allowed' : 'pointer',
      }}
    >
      <span style={{
        position: 'absolute',
        top: 1,
        left: on ? dims.w - dims.k - 3 : 1,
        width: dims.k,
        height: dims.k,
        background: on ? '#fff' : t.muted,
        borderRadius: 1,
        transition: 'left .15s ease, background .15s ease',
      }} />
    </button>
  );
}

// ── Battery glyph ─────────────────────────────────────────────
function Battery({ level = 80, charging = false, threshold = 15, theme = 'light', width = 28 }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  const below = level <= threshold;
  const critical = level <= 5;
  const color = critical ? FS.crit : below ? FS.warn : FS.ok;
  const h = width * 0.45;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span style={{ position: 'relative', width, height: h, border: `1px solid ${t.borderStrong}`, borderRadius: 2 }}>
        <span style={{
          position: 'absolute', top: 1, left: 1, bottom: 1,
          width: `calc(${Math.max(0, level)}% - 2px)`,
          background: color,
          transition: 'all .3s',
        }} />
        {charging && (
          <span style={{
            position: 'absolute', inset: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 9, color: '#fff', fontWeight: 600, mixBlendMode: 'difference',
          }}>⚡</span>
        )}
        <span style={{
          position: 'absolute', right: -3, top: '25%', bottom: '25%', width: 2,
          background: t.borderStrong, borderRadius: '0 1px 1px 0',
        }} />
      </span>
    </span>
  );
}

// ── Row (label / value) ───────────────────────────────────────
function Row({ label, children, theme = 'light', dense = false }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: dense ? '5px 0' : '8px 0',
      fontSize: 12,
    }}>
      <span className="mono" data-uppercase style={{ color: t.muted, fontSize: 10 }}>{label}</span>
      <span style={{ color: t.fg, display: 'flex', alignItems: 'center', gap: 6 }}>{children}</span>
    </div>
  );
}

// ── Section header ────────────────────────────────────────────
function SectionLabel({ children, theme = 'light', right }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '6px 0',
      borderBottom: `1px solid ${t.border}`,
      marginBottom: 6,
    }}>
      <span className="mono" data-uppercase style={{ color: t.subtle, fontSize: 9 }}>{children}</span>
      {right && <span className="mono" style={{ color: t.subtle, fontSize: 9 }}>{right}</span>}
    </div>
  );
}

// ── Slider ────────────────────────────────────────────────────
function Slider({ value, onChange, min = 5, max = 50, theme = 'light' }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  const pct = ((value - min) / (max - min)) * 100;
  const trackRef = React.useRef(null);
  const drag = (e) => {
    const r = trackRef.current.getBoundingClientRect();
    const x = (e.touches ? e.touches[0].clientX : e.clientX) - r.left;
    const v = Math.round(min + (Math.max(0, Math.min(r.width, x)) / r.width) * (max - min));
    onChange?.(v);
  };
  return (
    <div
      ref={trackRef}
      onMouseDown={(e) => { drag(e); const m = (ev) => drag(ev); const u = () => { window.removeEventListener('mousemove', m); window.removeEventListener('mouseup', u); }; window.addEventListener('mousemove', m); window.addEventListener('mouseup', u); }}
      style={{
        position: 'relative', height: 24, cursor: 'pointer', display: 'flex', alignItems: 'center',
      }}
    >
      <div style={{ position: 'absolute', left: 0, right: 0, height: 2, background: t.border }} />
      <div style={{ position: 'absolute', left: 0, width: `${pct}%`, height: 2, background: FS.crit }} />
      <div style={{
        position: 'absolute', left: `calc(${pct}% - 6px)`, width: 12, height: 12,
        background: t.surface, border: `1px solid ${FS.crit}`, borderRadius: 1,
      }} />
    </div>
  );
}

// ── E2E lock indicator ────────────────────────────────────────
function E2EBadge({ theme = 'light', compact = false }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: compact ? '2px 5px' : '3px 7px',
      border: `1px solid ${t.border}`,
      borderRadius: 2,
      fontSize: 9,
    }}>
      <svg width="9" height="10" viewBox="0 0 9 10" fill="none">
        <rect x="1" y="4" width="7" height="5" stroke={FS.ok} strokeWidth="1" />
        <path d="M2.5 4V2.5a2 2 0 014 0V4" stroke={FS.ok} strokeWidth="1" fill="none" />
      </svg>
      <span className="mono" data-uppercase style={{ color: t.muted, letterSpacing: '0.08em' }}>E2E · X25519</span>
    </span>
  );
}

// ── Mini histogram (for connection strength etc.) ─────────────
function Bars({ values = [3, 5, 4, 6, 5, 7, 6, 8, 7, 6], color = FS.ok, height = 14 }) {
  const max = Math.max(...values, 1);
  return (
    <span style={{ display: 'inline-flex', alignItems: 'flex-end', gap: 1.5, height }}>
      {values.map((v, i) => (
        <span key={i} style={{
          width: 2, height: `${(v / max) * 100}%`, background: color, opacity: 0.4 + 0.6 * (v / max),
        }} />
      ))}
    </span>
  );
}

// ── Friendly logs view ────────────────────────────────────────
// Beginner-readable, but still terminal-styled. Uses plain language for the
// message and shows the [LEVEL] tag in color.
function LogLine({ entry, theme = 'light' }) {
  const t = theme === 'dark' ? FS.dark : FS.light;
  const levelColor = {
    OK: FS.ok, INFO: FS.info, WARN: FS.warn, ERR: FS.crit, SYNC: FS.crit,
  }[entry.level] || t.muted;
  return (
    <div className="mono" style={{
      display: 'grid',
      gridTemplateColumns: '54px 56px 1fr',
      gap: 8,
      padding: '3px 0',
      fontSize: 11,
      lineHeight: 1.5,
      color: t.fg,
    }}>
      <span style={{ color: t.subtle }}>{entry.time}</span>
      <span style={{ color: levelColor, fontWeight: 500 }} data-uppercase>[{entry.level}]</span>
      <span style={{ color: t.muted }}>{entry.msg}</span>
    </div>
  );
}

Object.assign(window, {
  FS, Dot, Toggle, Battery, Row, SectionLabel, Slider, E2EBadge, Bars, LogLine,
});
