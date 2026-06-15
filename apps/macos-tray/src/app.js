// Menu-bar popup logic — mirrors Android LinkedScreen.
// Talks to fluxsyncd via Tauri's `invoke()` → Rust commands
// declared in `src-tauri/src/lib.rs`. Live state arrives via the
// `state-update` Tauri event the daemon-bridge emits on every push;
// a 5s safety poll keeps the UI honest if the event stream stalls.

const { invoke } = window.__TAURI__.core;
const { getCurrentWindow } = window.__TAURI__.window;
const { listen } = window.__TAURI__.event;
const { exit } = window.__TAURI__.process || {};

let pollHandle = null;
let unlistenState = null;

// Tag the body with the host OS so the stylesheet can paint a Windows
// backdrop (WebView2 ignores `transparent: true` on ARM64). Also rewrite
// the "Pair this Mac" headline so the popup says the right device word
// regardless of where it is running.
(function tagHostOS() {
  const ua = navigator.userAgent;
  const os = /Windows/i.test(ua) ? 'windows'
    : /Macintosh|Mac OS/i.test(ua) ? 'macos'
    : /Linux/i.test(ua) ? 'linux'
    : 'unknown';
  document.body.dataset.os = os;
  const label = { windows: 'PC', macos: 'Mac', linux: 'Linux' }[os] || 'device';
  const osName = { windows: 'Windows', macos: 'macOS', linux: 'Linux' }[os] || '—';
  const selfName = document.getElementById('self-name');
  const selfMeta = document.getElementById('self-meta');
  if (selfName) selfName.textContent = 'This ' + label;
  if (selfMeta) selfMeta.textContent = osName + ' · this device';
})();

// ── Authoritative sync state (avoids DOM-as-source-of-truth race) ──
let syncOn = false;
let isToggling = false;
let daemonReachable = true;

// Apply a state snapshot to the DOM. Called both from the safety poll
// (`refreshState`) and the `state-update` Tauri event listener.
function applyState(s) {
  if (isToggling) return;
  daemonReachable = true;
  if (s) syncOn = !!s.on;

  const isPaired = s && s.peer_name && s.peer_name.trim() !== "" && s.peer_name !== "pending";
  // Single-window UX: this menu is the only window. Show the dashboard +
  // history when linked, or an inline "Pair a device" CTA when not — never
  // auto-spawn the separate pair window (that left two windows at launch).
  document.getElementById('tray-container').style.display = 'flex';
  document.getElementById('dashboard-body').style.display = isPaired ? 'flex' : 'none';
  document.querySelector('.history-section').style.display = isPaired ? 'block' : 'none';
  const fwSection = document.getElementById('firewall-section');
  if (fwSection) fwSection.style.display = isPaired ? 'block' : 'none';
  document.getElementById('pairing-entry').style.display = isPaired ? 'none' : 'flex';

  if (isPaired) {
    renderHero(s);
    renderPeer(s);
    renderMesh(s);
    renderSelf(s);
    renderRecent(s.history || []);
    renderFirewall(s);
    maybePulse(s);
  } else {
    setHero('off', 'NO DEVICE PAIRED');
    renderRecent([]);
  }
  renderLink(s, isPaired);
  renderMetrics(s);
  renderFooter(true, s);
}

async function refreshState() {
  if (isToggling) return;
  try {
    const resp = await invoke('fluxsync_status');
    const s = resp && resp.data ? resp.data : null;
    applyState(s);
  } catch (e) {
    // Daemon unreachable — distinguish from a daemon that is up but
    // toggled off, so the user knows whether the daemon failed to spawn
    // or they just need to hit the toggle.
    daemonReachable = false;
    syncOn = false;
    setHero('off', 'DAEMON OFFLINE');
    renderLink(null, false);
    renderMetrics(null);
    renderFooter(false, null);
  }
}

function setHero(state, label) {
  const hero = document.getElementById('hero');
  hero.setAttribute('data-state', state);
  document.getElementById('hero-label').textContent = label;

  const t = document.getElementById('toggle');
  t.classList.toggle('on', state === 'ok' || state === 'warn');

  const glyph = document.getElementById('brand-glyph');
  const dot = glyph.querySelector('.active-dot');
  if (dot) dot.style.display = state !== 'off' ? 'block' : 'none';
}

function renderHero(s) {
  if (!s) {
    setHero('off', 'INACTIVE');
    return;
  }
  const on = !!s.on;
  const below = (s.battery_level ?? 0) <= (s.battery_threshold ?? 20);
  const critical = (s.battery_level ?? 0) <= 5;
  const charging = !!s.charging;
  const paused = on && below && !charging;

  if (!on) return setHero('off', 'INACTIVE');
  if (critical) return setHero('crit', 'CRITICAL');
  if (paused) return setHero('warn', 'PAUSED · LOW BATTERY');
  return setHero('ok', 'SYNCHRONIZING');
}

function renderPeer(s) {
  const peerBat = s ? (s.peer_battery ?? 0) : 0;
  const peerCharging = s ? !!s.peer_charging : false;
  const threshold = s ? (s.battery_threshold ?? 20) : 20;
  const peerName = s ? (s.peer_name || '—') : '—';
  const on = !!s.on;

  const peerSection = document.getElementById('dashboard-body');
  peerSection.setAttribute('data-active', on ? 'true' : 'false');

  document.getElementById('peer-name-pill').textContent = peerName;
  renderPeerDevice(s ? s.peer_platform : '');
  document.getElementById('peer-status-text').textContent = on ? 'LINKED' : 'STANDBY';
  
  const bar = document.getElementById('peer-battery-bar');
  const text = document.getElementById('peer-battery-text');
  
  const color = peerBat <= 5 ? 'var(--fs-crit)' :
                peerBat <= threshold ? 'var(--fs-warn)' : 'var(--fs-ok)';
  
  bar.style.width = `${Math.min(peerBat, 100)}%`;
  bar.style.background = color;
  text.textContent = `${peerBat}%${peerCharging ? '⚡' : ''}`;
  text.style.color = peerBat <= 5 ? 'var(--fs-crit)' : peerBat <= threshold ? 'var(--fs-warn)' : 'var(--fs-muted)';

  document.getElementById('pause-banner').style.display = (on && peerBat <= threshold && !peerCharging) ? 'flex' : 'none';
}

// Phone vs computer icon driven by the peer's OS family (s.peer_platform,
// from Msg::Hello). The HTML ships a phone placeholder; without this every
// peer — even a Mac/PC — rendered as a phone.
const PEER_ICON_PHONE =
  '<svg width="11" height="16" viewBox="0 0 11 16" fill="none">' +
  '<rect x="0.5" y="0.5" width="10" height="15" rx="1.5" stroke="var(--fs-muted)"/>' +
  '<circle cx="5.5" cy="13" r="0.7" fill="var(--fs-muted)"/></svg>';
const PEER_ICON_COMPUTER =
  '<svg width="16" height="14" viewBox="0 0 16 14" fill="none">' +
  '<rect x="0.5" y="0.5" width="15" height="10" rx="1" stroke="var(--fs-muted)"/>' +
  '<path d="M5 13h6M8 10.5V13" stroke="var(--fs-muted)" stroke-linecap="round"/></svg>';

function renderPeerDevice(platform) {
  const p = (platform || '').toLowerCase();
  const isMobile = p === 'android' || p === 'ios';
  const label = { macos: 'macOS', windows: 'Windows', linux: 'Linux',
                  android: 'Android', ios: 'iOS' }[p] || (p ? p : '—');
  const iconEl = document.getElementById('peer-device-icon');
  if (iconEl) iconEl.innerHTML = isMobile ? PEER_ICON_PHONE : PEER_ICON_COMPUTER;
  const metaEl = document.getElementById('peer-meta');
  if (metaEl) metaEl.textContent = label;
}

const PLATFORM_LABELS = { macos: 'macOS', windows: 'Windows', linux: 'Linux', android: 'Android', ios: 'iOS' };

// FluxMesh Phase 3: list secondary peers below the primary card when more
// than one device is linked (the primary stays in the main peer card).
// Built with textContent (never innerHTML) so a peer-controlled name can't
// inject markup. The container is created lazily, so index.html needs no
// change and the card is unchanged for the single-peer case.
function renderMesh(s) {
  const peers = (s && Array.isArray(s.peers)) ? s.peers : [];
  const body = document.getElementById('dashboard-body');
  let box = document.getElementById('mesh-peers');
  if (peers.length <= 1) {
    if (box) box.style.display = 'none';
    return;
  }
  if (!box) {
    box = document.createElement('div');
    box.id = 'mesh-peers';
    box.style.cssText = 'display:flex;flex-direction:column;gap:6px;margin-top:10px;padding-top:10px;border-top:1px solid var(--fs-line,rgba(255,255,255,0.08));';
    body.appendChild(box);
  }
  box.style.display = 'flex';
  box.replaceChildren();

  const head = document.createElement('div');
  head.style.cssText = 'font-size:10px;letter-spacing:0.08em;color:var(--fs-muted);text-transform:uppercase;';
  head.textContent = `Mesh · ${peers.length} devices`;
  box.appendChild(head);

  for (const p of peers) {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:12px;';

    const left = document.createElement('span');
    const name = (p.name && p.name.trim()) ? p.name : '(unknown)';
    const label = PLATFORM_LABELS[(p.platform || '').toLowerCase()] || (p.platform || '');
    left.textContent = `${p.primary ? '★ ' : ''}${name}${label ? ' · ' + label : ''}`;

    const right = document.createElement('span');
    right.style.cssText = 'display:flex;align-items:center;gap:8px;color:var(--fs-muted);';

    const batt = document.createElement('span');
    batt.textContent = `${p.battery ?? 100}%${p.charging ? '⚡' : ''}`;
    right.appendChild(batt);

    // Secondaries get a per-peer unpair button (the primary uses the main
    // card's Unpair). The daemon `revoke` op drops just this peer, leaving
    // every other paired device linked.
    if (!p.primary) {
      const hex = peerIdHex(p.peer_id);
      if (hex) {
        const btn = document.createElement('button');
        btn.className = 'mesh-unpair';
        btn.textContent = 'Unpair';
        btn.addEventListener('click', () => unpairPeer(hex, name));
        right.appendChild(btn);
      }
    }

    row.appendChild(left);
    row.appendChild(right);
    box.appendChild(row);
  }
}

// peer_id rides the State DTO as a 32-byte array (serde `[u8;32]`); the
// daemon `revoke` op wants the full hex string. Returns '' if malformed.
function peerIdHex(id) {
  if (!Array.isArray(id) || id.length !== 32) return '';
  return id.map((b) => (b & 0xff).toString(16).padStart(2, '0')).join('');
}

async function unpairPeer(peerHex, name) {
  if (!confirm(`Unpair ${name || 'this device'}? It will be disconnected and removed.`)) return;
  try {
    await invoke('fluxsync_revoke_peer', { peerId: peerHex });
    showToast('Device unpaired.');
    await refreshState();
  } catch (err) {
    showToast(`Unpair failed: ${err}`);
  }
}

// Inline RTT pill next to the E2E badge. Hidden until daemon reports a
// non-zero last_rtt_ms (no peer linked → no RTT to show).
function renderMetrics(s) {
  const badge = document.querySelector('.e2e-badge');
  if (!badge) return;
  let pill = document.getElementById('rtt-pill');
  const rtt = s && s.metrics && typeof s.metrics.last_rtt_ms === 'number' ? s.metrics.last_rtt_ms : null;
  if (rtt == null || rtt === 0) {
    if (pill) pill.style.display = 'none';
    return;
  }
  if (!pill) {
    pill = document.createElement('span');
    pill.id = 'rtt-pill';
    pill.className = 'rtt-pill mono';
    badge.parentElement.insertBefore(pill, badge);
  }
  pill.style.display = 'inline-flex';
  pill.textContent = `${rtt}MS`;
}

// Self side of the connection card: the daemon reports this device's own
// battery via `battery_level` / `charging` (SetSelfBattery on mobile, host
// watcher on desktop). Colors mirror the peer-side thresholds.
function renderSelf(s) {
  const fill = document.getElementById('self-batt-fill');
  const pc = document.getElementById('self-batt-pc');
  const box = document.getElementById('self-batt');
  if (!fill || !pc || !box) return;
  const lvl = s.battery_level ?? 0;
  const threshold = s.battery_threshold ?? 20;
  fill.style.width = `${Math.min(lvl, 100)}%`;
  fill.style.background = lvl <= 5 ? 'var(--fs-crit)' : lvl <= threshold ? 'var(--fs-warn)' : 'var(--fs-ok)';
  pc.textContent = `${lvl}%`;
  box.classList.toggle('chg', !!s.charging);
}

// Beam between the two devices. `data-link` on the container drives the
// CSS: on (solid green), paused (amber dashes), searching (gray crawl,
// radar rings on the peer icon), off (inert). Phase comes straight from
// the FSM (`s.phase`), pause mirrors the hero/pause-banner policy.
function renderLink(s, isPaired) {
  const c = document.getElementById('tray-container');
  if (!c) return;
  if (!s || !s.on || !isPaired) { c.dataset.link = 'off'; return; }
  const phase = (s.phase || '').toLowerCase();
  if (phase === 'discovering' || phase === 'handshaking') { c.dataset.link = 'searching'; return; }
  const threshold = s.battery_threshold ?? 20;
  const selfLow = (s.battery_level ?? 0) <= threshold && !s.charging;
  const peerLow = (s.peer_battery ?? 0) <= threshold && !s.peer_charging;
  c.dataset.link = (phase === 'paused' || selfLow || peerLow) ? 'paused' : 'on';
}

// Fire a pulse along the beam when a new item lands at the top of the
// history. Direction follows `HistoryItem.source`: local → tx (out),
// remote → rx (in). Keyed on the content hash so re-renders don't re-fire.
let lastTopKey = null;
function maybePulse(s) {
  const top = s && s.history && s.history[0];
  const key = top ? (top.hash || String(top.lamport)) : null;
  if (key && lastTopKey && key !== lastTopKey) {
    const pulse = document.getElementById('beam-pulse');
    if (pulse) {
      pulse.classList.remove('tx', 'rx');
      void pulse.offsetWidth; // restart the CSS animation
      pulse.classList.add(top.source === 'remote' ? 'rx' : 'tx');
    }
    const first = document.querySelector('#recent .history-item');
    if (first) first.classList.add('new');
  }
  lastTopKey = key;
}

function renderFooter(up, s) {
  const dot = document.getElementById('daemon-dot');
  const lb = document.getElementById('daemon-label');
  if (dot) dot.classList.toggle('down', !up);
  if (lb) lb.textContent = up ? 'fluxsyncd active' : 'daemon unreachable';
  if (up && s && s.version) {
    const v = document.getElementById('brand-version');
    if (v) v.textContent = `v${s.version}`;
  }
}

const KIND_ICONS = {
  text: '<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M2 2.5h8M2 6h8M2 9.5h5"/></svg>',
  url: '<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M4.5 7.5l3-3M3.2 8.8L2 10a2 2 0 102.8 2.8L6 11.5M8.8 3.2L10 2a2 2 0 10-2.8-2.8L6 .5" transform="translate(0 .4)"/></svg>',
  image: '<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2"><circle cx="4" cy="4.5" r="1.2"/><path d="M0 9.5l3.5-3.5L12 12" stroke-linejoin="round"/></svg>',
};
const LOCK_ICON =
  '<svg width="10" height="11" viewBox="0 0 9 10" fill="none">' +
  '<rect x="1" y="4" width="7" height="5" stroke="currentColor" stroke-width="1.2"/>' +
  '<path d="M2.5 4V2.5a2 2 0 014 0V4" stroke="currentColor" stroke-width="1.2" fill="none"/></svg>';

// Copy a history item's text back to the OS clipboard. The async Clipboard
// API is tried first; WKWebView sometimes rejects it, so fall back to the
// legacy execCommand path, which still works on a user gesture.
async function copyText(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch {}
    ta.remove();
  }
  showToast('Copied');
}

// History rows render every `HistoryItem` field the daemon sends: kind
// (icon), sensitive (masked preview + lock), source (local/peer badge),
// time (HH:MM from the daemon's wall clock).
function renderRecent(history) {
  const list = document.getElementById('recent');
  document.getElementById('recent-count').textContent = `${history.length} items`;
  list.innerHTML = '';
  if (!history.length) {
    const empty = document.createElement('div');
    empty.className = 'history-empty';
    empty.textContent = 'Nothing copied yet.';
    list.append(empty);
    return;
  }
  history.forEach(h => {
    const item = document.createElement('button');
    item.className = 'history-item';

    const kind = (h.kind || 'text').toLowerCase();
    const ic = document.createElement('span');
    ic.className = 'kind-ic' + (kind === 'image' ? ' thumb' : '');
    ic.innerHTML = KIND_ICONS[kind] || KIND_ICONS.text;

    const p = document.createElement('span');
    if (h.sensitive) {
      p.className = 'preview masked';
      p.textContent = '••••••••••••';
    } else {
      p.className = 'preview';
      p.textContent = h.preview || '';
    }

    item.append(ic, p);

    if (h.sensitive) {
      const lock = document.createElement('span');
      lock.className = 'lock';
      lock.title = 'Marked sensitive — masked';
      lock.innerHTML = LOCK_ICON;
      item.append(lock);
    }

    const src = document.createElement('span');
    const remote = h.source === 'remote';
    src.className = 'src ' + (remote ? 'remote' : 'local');
    src.textContent = remote ? 'peer' : 'local';
    item.append(src);

    // FluxVault: pin/unpin star. Pinned items survive the vault TTL + cap.
    // It lives inside the history button, so stop the click from also
    // triggering the row's copy handler.
    const fav = document.createElement('span');
    fav.className = 'fav' + (h.favorite ? ' on' : '');
    fav.textContent = h.favorite ? '★' : '☆';
    fav.title = h.favorite ? 'Unpin' : 'Pin — keep past history limit';
    fav.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleFavorite(h.hash, !h.favorite);
    });
    item.append(fav);

    // Text rows carry their full payload in `preview` (only the CSS clips it),
    // so clicking copies it straight back. Image previews are just a "N KB"
    // label — the bytes aren't in the snapshot — so those rows aren't copyable.
    if (kind !== 'image' && h.preview) {
      item.classList.add('copyable');
      item.title = 'Click to copy';
      const hint = document.createElement('span');
      hint.className = 'copy-hint';
      hint.textContent = 'Copy';
      item.append(hint);
      item.addEventListener('click', () => copyText(h.preview));
    } else {
      item.style.cursor = 'default';
    }

    const t = document.createElement('span');
    t.className = 'time';
    t.textContent = h.time || '—';
    item.append(t);

    list.append(item);
  });
}

// ── FluxVault favorites ────────────────────────────────────────────────
async function toggleFavorite(hash, favorite) {
  if (!hash) return;
  try {
    await invoke('fluxsync_set_favorite', { hash, favorite });
    await refreshState();
  } catch (err) {
    showToast(`${favorite ? 'Pin' : 'Unpin'} failed: ${err}`);
  }
}

// ── FluxFirewall ───────────────────────────────────────────────────────
// Per-content-type Allow/Ask/Deny policy + the Ask "pending decisions"
// queue. Reads `State.firewall` + `State.pending`, drives `set_firewall`
// and `resolve_pending`. Built fresh into #firewall-body each snapshot.
const FW_RULES = ['allow', 'ask', 'deny'];
const FW_KINDS = [
  ['text', 'Text', 'Plain text snippets'],
  ['url', 'Links', 'URLs on the clipboard'],
  ['code', 'Code', 'Code-shaped content'],
  ['image', 'Images', 'PNG image payloads'],
  ['sensitive', 'Secrets', 'Detected keys & tokens'],
];

function defaultFirewall() {
  return { enabled: false, text: 'allow', url: 'allow', code: 'allow', image: 'allow', sensitive: 'ask' };
}

async function pushFirewall(policy) {
  try {
    await invoke('fluxsync_set_firewall', { policy });
    await refreshState();
  } catch (err) {
    showToast(`Firewall update failed: ${err}`);
  }
}

async function resolvePending(hash, allow) {
  try {
    await invoke('fluxsync_resolve_pending', { hash, allow });
    await refreshState();
  } catch (err) {
    showToast(`${allow ? 'Approve' : 'Reject'} failed: ${err}`);
  }
}

function renderFirewall(s) {
  const body = document.getElementById('firewall-body');
  if (!body) return;
  const fw = Object.assign(defaultFirewall(), s.firewall || {});
  const pending = s.pending || [];
  body.innerHTML = '';

  // Pending decisions first — they're time-sensitive.
  if (pending.length) {
    const head = document.createElement('div');
    head.className = 'fw-subhead';
    head.textContent = 'Pending decisions';
    body.append(head);
    pending.forEach(p => body.append(buildPendingCard(p)));
  }

  // Master switch.
  const master = document.createElement('div');
  master.className = 'fw-master';
  const mLabel = document.createElement('div');
  mLabel.className = 'fw-master-text';
  const mTitle = document.createElement('span');
  mTitle.className = 'fw-master-title';
  mTitle.textContent = 'Clipboard firewall';
  const mHint = document.createElement('span');
  mHint.className = 'fw-master-hint';
  mHint.textContent = fw.enabled ? 'Rules below are enforced' : 'Off — every item passes';
  mLabel.append(mTitle, mHint);
  const mToggle = document.createElement('button');
  mToggle.className = 'fw-switch' + (fw.enabled ? ' on' : '');
  mToggle.setAttribute('aria-label', 'Toggle firewall');
  mToggle.addEventListener('click', () => {
    pushFirewall(Object.assign({}, fw, { enabled: !fw.enabled }));
  });
  master.append(mLabel, mToggle);
  body.append(master);

  // Per-kind rule rows.
  const rules = document.createElement('div');
  rules.className = 'fw-rules' + (fw.enabled ? '' : ' disabled');
  FW_KINDS.forEach(([field, label, hint]) => {
    rules.append(buildRuleRow(fw, field, label, hint));
  });
  body.append(rules);
}

function buildPendingCard(p) {
  const card = document.createElement('div');
  card.className = 'fw-pending';
  const meta = document.createElement('div');
  meta.className = 'fw-pending-meta';
  const tag = document.createElement('span');
  tag.className = 'fw-pending-tag';
  const dir = p.direction === 'outbound' ? 'OUTGOING' : 'INCOMING';
  tag.textContent = dir + ' · ' + String(p.kind || 'text').toUpperCase();
  meta.append(tag);
  if (p.sensitive) {
    const sec = document.createElement('span');
    sec.className = 'fw-pending-secret';
    sec.textContent = 'SECRET';
    meta.append(sec);
  }
  const prev = document.createElement('div');
  prev.className = 'fw-pending-preview';
  prev.textContent = p.sensitive ? '••••••••••••' : (p.preview || '(no preview)');
  const actions = document.createElement('div');
  actions.className = 'fw-pending-actions';
  const reject = document.createElement('button');
  reject.className = 'fw-btn reject';
  reject.textContent = 'Reject';
  reject.addEventListener('click', () => resolvePending(p.hash, false));
  const approve = document.createElement('button');
  approve.className = 'fw-btn approve';
  approve.textContent = 'Approve';
  approve.addEventListener('click', () => resolvePending(p.hash, true));
  actions.append(reject, approve);
  card.append(meta, prev, actions);
  return card;
}

function buildRuleRow(fw, field, label, hint) {
  const row = document.createElement('div');
  row.className = 'fw-rule';
  const text = document.createElement('div');
  text.className = 'fw-rule-text';
  const t = document.createElement('span');
  t.className = 'fw-rule-label';
  t.textContent = label;
  const h = document.createElement('span');
  h.className = 'fw-rule-hint';
  h.textContent = hint;
  text.append(t, h);
  const seg = document.createElement('div');
  seg.className = 'fw-seg';
  const current = fw[field] || 'allow';
  FW_RULES.forEach(rule => {
    const b = document.createElement('button');
    b.className = 'fw-seg-btn ' + rule + (current === rule ? ' active' : '');
    b.textContent = rule.toUpperCase();
    b.addEventListener('click', () => {
      if (!fw.enabled || current === rule) return;
      pushFirewall(Object.assign({}, fw, { [field]: rule }));
    });
    seg.append(b);
  });
  row.append(text, seg);
  return row;
}

// ── Wire up controls ─────────────────────────────────────────────
document.getElementById('toggle').addEventListener('click', async () => {
  if (isToggling) return;
  const willBeOn = !syncOn;
  isToggling = true;
  syncOn = willBeOn;
  const t = document.getElementById('toggle');
  t.classList.toggle('on', willBeOn);
  try {
    await invoke('fluxsync_toggle', { on: willBeOn });
  } catch (err) {
    // Backend rejected — revert visual state and tell the user why.
    syncOn = !willBeOn;
    t.classList.toggle('on', !willBeOn);
    showToast(daemonReachable ? `Toggle failed: ${err}` : 'Daemon unreachable. Toggle reverted.');
  } finally {
    isToggling = false;
  }
  refreshState();
});

// Toast singleton — slide-in bottom, auto-dismiss. Re-uses one DOM node
// so rapid failures collapse into one visible message.
let toastTimer = null;
function showToast(message) {
  let el = document.getElementById('fs-toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'fs-toast';
    el.className = 'fs-toast';
    document.body.appendChild(el);
  }
  el.textContent = message;
  el.classList.add('visible');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('visible'), 3000);
}

const headerSettings = document.getElementById('header-settings');
if (headerSettings) headerSettings.addEventListener('click', () => invoke('fluxsync_open_settings'));

// Pair CTA (unpaired state) — opens the dedicated pair window, which hides
// this menu so only one window is ever on screen.
document.getElementById('pair-cta').addEventListener('click', () => {
  invoke('fluxsync_open_pair');
});

// entry-show-qr removed — pair window owns the entry now.

document.getElementById('unpair-btn').addEventListener('click', async () => {
  if (!confirm('This will disconnect and unpair your device. Continue?')) return;
  try {
    await invoke('fluxsync_unpair');
    showToast('Device unpaired.');
    refreshState();
    // Stay on this window — refreshState swaps in the inline pair CTA.
  } catch (err) {
    showToast(`Unpair failed: ${err}`);
  }
});

async function openPair() {
  try {
    await invoke('fluxsync_open_pair');
  } catch (_) { /* surface in popup next refresh */ }
  // Don't hide the popup — let the user see both windows
}

// (No threshold slider in the tray popup — it lives on the Settings
// window. The previous listener referenced an element that never
// existed in `index.html` and silently threw at boot.)

// ── Lifecycle ────────────────────────────────────────────────────
async function onShow() {
  await refreshState();
  // Live updates via Tauri event from `subscribe_state` in
  // `src-tauri/src/lib.rs`. Polling becomes a 5s safety net only —
  // catches the (rare) case where the event stream wedges.
  if (!unlistenState) {
    unlistenState = await listen('state-update', (event) => {
      applyState(event.payload);
    });
  }
  if (pollHandle) clearInterval(pollHandle);
  pollHandle = setInterval(refreshState, 5000);
}
function onHide() {
  if (pollHandle) clearInterval(pollHandle);
  pollHandle = null;
  if (unlistenState) { unlistenState(); unlistenState = null; }
}

// ── Universal Draggable Window (Long Click) ──────────────────────
let dragTimer = null;
let dragActive = false;

document.addEventListener('mousedown', (e) => {
  // Only trigger if we're NOT clicking an interactive element
  const isInteractive = e.target.closest('button, input, a, .toggle, .footer-btn, .history-item');
  if (isInteractive) return;

  console.log("[FluxSync-UI] Mousedown on safe area, starting drag timer...");
  dragActive = false;
  dragTimer = setTimeout(async () => {
    console.log("[FluxSync-UI] Drag threshold reached, starting Tauri drag...");
    dragActive = true;
    try {
      await window.__TAURI__.window.getCurrentWindow().startDragging();
    } catch (err) {
      console.error("[FluxSync-UI] Drag failed:", err);
    }
  }, 150); // Very fast: 150ms
});

document.addEventListener('mouseup', () => {
  if (dragTimer) {
    clearTimeout(dragTimer);
    dragTimer = null;
  }
});

document.addEventListener('contextmenu', (e) => {
  if (dragActive) {
    e.preventDefault();
    dragActive = false;
  }
});

const win = getCurrentWindow();
win.onFocusChanged(({ payload }) => {
  // Refresh on focus. Do NOT auto-hide on blur: this is a normal dock
  // window now (closing it quits the app), and the old `win.hide()` here
  // also blanked the WebView on the next show.
  if (payload) onShow();
});
// First load when the window is created visible (during `tauri dev`).
onShow();
