// Menu-bar popup logic — mirrors Android LinkedScreen.
// Talks to fluxsyncd via Tauri's `invoke()` → Rust commands declared in
// `src-tauri/src/lib.rs`. Live state arrives via the `state-update` Tauri
// event the daemon bridge emits on every push; a 5 s safety poll keeps the
// UI honest if the event stream stalls.
//
// Rendering model: the daemon re-publishes the whole State on every
// heartbeat (~3 s per peer) even when nothing visible changed, and a
// history row's `preview` carries the item's full text. So:
//   * updates are coalesced to one render per animation frame;
//   * every section keeps a cheap signature and skips work when unchanged;
//   * history rows are keyed (hash + lamport) and patched in place —
//     never rebuilt — so hover, focus and scroll survive every push;
//   * only a bounded prefix of each preview ever reaches the DOM (laying
//     out a 20 KB single-line text node per row was the main cost).

import {
  IS_MAC, tagHostOS, OS_NAMES, OS_DEVICE_WORD, PLATFORM_LABELS, TOFU_PLACEHOLDER,
  isRealPeerName, peerIdHex, batteryKnown, setText, setAttr, showToast, confirmDialog,
} from './ui.js';

const { invoke } = window.__TAURI__.core;
const { getCurrentWindow } = window.__TAURI__.window;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const el = {
  tray: $('tray-container'),
  hero: $('hero'),
  heroLabel: $('hero-label'),
  heroSub: $('hero-sub'),
  toggle: $('toggle'),
  link: $('dashboard-body'),
  selfName: $('self-name'),
  selfMeta: $('self-meta'),
  peerName: $('peer-name-pill'),
  peerMeta: $('peer-meta'),
  peerIcon: $('peer-device-icon'),
  packet: $('beam-pulse'),
  pauseBanner: $('pause-banner'),
  pauseText: $('pause-text'),
  offline: $('offline-state'),
  pairing: $('pairing-entry'),
  onboarding: $('onboarding-steps'),
  pairTitle: $('pair-empty-title'),
  pairHint: $('pair-empty-hint'),
  pairCta: $('pair-cta'),
  pairCtaSub: $('pair-cta-sub'),
  tabs: $('tabs'),
  views: $('tray-scroll'),
  pendingStrip: $('pending-strip'),
  pendingStripText: $('pending-strip-text'),
  pendingBadge: $('pending-badge'),
  pending: $('pending-section'),
  recent: $('recent'),
  recentCount: $('recent-count'),
  search: $('history-search'),
  filters: $('history-filters'),
  clearBtn: $('clear-history-btn'),
  fwToggle: $('fw-toggle'),
  fwSub: $('fw-sub'),
  fwRules: $('fw-rules'),
  devices: $('device-list'),
  devicesCount: $('devices-count'),
  rtt: $('rtt-pill'),
  version: $('brand-version'),
  daemonDot: $('daemon-dot'),
  daemonLabel: $('daemon-label'),
};

// ── Host OS ──────────────────────────────────────────────────────
const HOST_OS = tagHostOS();
const HOST_WORD = OS_DEVICE_WORD[HOST_OS] || 'device';
setText(el.selfName, 'This ' + HOST_WORD);
const MOD_LABEL = IS_MAC ? '⌘' : 'Ctrl';
setText($('kbd-mod'), MOD_LABEL);

// ── Icons (inline SVG: Plex's Latin-1 cut has no arrows/stars) ───
const svg = (w, h, vb, body, extra = '') =>
  `<svg width="${w}" height="${h}" viewBox="${vb}" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" ${extra}>${body}</svg>`;
const ICON = {
  phone: svg(12, 17, '0 0 11 16', '<rect x="0.6" y="0.6" width="9.8" height="14.8" rx="2"/><path d="M4.4 13h2.2"/>', 'stroke-width="1.2"'),
  computer: svg(17, 14, '0 0 16 14', '<rect x="0.6" y="0.6" width="14.8" height="9.8" rx="1.4"/><path d="M5 13h6M8 10.5V13"/>', 'stroke-width="1.2"'),
  text: svg(13, 13, '0 0 12 12', '<path d="M2 2.5h8M2 6h8M2 9.5h5"/>', 'stroke-width="1.25"'),
  url: svg(13, 13, '0 0 24 24', '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>', 'stroke-width="2"'),
  code: svg(14, 14, '0 0 24 24', '<path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/>', 'stroke-width="2"'),
  image: svg(13, 13, '0 0 24 24', '<rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="9" cy="9" r="2"/><path d="M21 15l-5-5L5 21"/>', 'stroke-width="2"'),
  inArrow: svg(10, 10, '0 0 10 10', '<path d="M8.5 1.5L2 8M2 3.5V8h4.5"/>', 'stroke-width="1.5"'),
  outArrow: svg(10, 10, '0 0 10 10', '<path d="M1.5 8.5L8 2M3.5 2H8v4.5"/>', 'stroke-width="1.5"'),
  star: svg(14, 14, '0 0 24 24', '<path d="M12 2.8l2.8 5.7 6.3.9-4.55 4.43 1.07 6.27L12 17.13 6.38 20.1l1.07-6.27L2.9 9.4l6.3-.9z"/>', 'stroke-width="1.8"'),
  open: svg(12, 12, '0 0 12 12', '<path d="M5 2H2.5A.5.5 0 0 0 2 2.5v7a.5.5 0 0 0 .5.5h7a.5.5 0 0 0 .5-.5V7M7 2h3v3M10 2L5.5 6.5"/>', 'stroke-width="1.3"'),
  lock: svg(9, 10, '0 0 9 10', '<rect x="1" y="4" width="7" height="5" rx="1"/><path d="M2.5 4V2.5a2 2 0 014 0V4"/>', 'stroke-width="1.2"'),
  pinMini: '<svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2.8l2.8 5.7 6.3.9-4.55 4.43 1.07 6.27L12 17.13 6.38 20.1l1.07-6.27L2.9 9.4l6.3-.9z"/></svg>',
  bolt: '<svg width="7" height="10" viewBox="0 0 7 10" fill="currentColor" aria-hidden="true"><path d="M4 0L0 6h2.5L3 10l4-6H4.5L4 0z"/></svg>',
};

// ── Authoritative sync state (avoids DOM-as-source-of-truth race) ──
let syncOn = false;
let isToggling = false;
let daemonReachable = true;
let lastStateAt = 0;

// DIR-P3-12: first-run onboarding is dismissed forever once the user pairs
// a device, or hides it — persisted so it never resurfaces after an unpair.
const ONBOARDING_KEY = 'fs.onboardingDismissed';
function onboardingDismissed() {
  try { return localStorage.getItem(ONBOARDING_KEY) === '1'; } catch (_) { return false; }
}
function dismissOnboarding() {
  try { localStorage.setItem(ONBOARDING_KEY, '1'); } catch (_) {}
  el.onboarding.hidden = true;
}

// ── Coalesced state application ──────────────────────────────────
// Both the safety poll and the `state-update` listener funnel through
// here; only the newest snapshot per frame is rendered. A hidden window
// gets no animation frames, so it does no work until it is shown again.
let queuedState;
let frameQueued = false;
function applyState(s) {
  if (isToggling) return;
  lastStateAt = Date.now();
  queuedState = s;
  if (!frameQueued) {
    frameQueued = true;
    requestAnimationFrame(flushState);
  }
}
function flushState() {
  frameQueued = false;
  const s = queuedState;
  queuedState = undefined;
  if (s !== undefined) render(s);
}

let currentView = 'loading';
function setView(view) {
  if (view === currentView) return;
  currentView = view;
  el.tray.dataset.view = view;
  el.offline.hidden = view !== 'offline';
  el.pairing.hidden = view !== 'unpaired';
  el.tabs.hidden = view !== 'paired';
  el.views.hidden = view !== 'paired';
  el.link.hidden = view !== 'paired';
  if (view !== 'paired') el.pauseBanner.hidden = true;
  el.toggle.disabled = view === 'offline';
}

function render(s) {
  daemonReachable = true;
  if (s) syncOn = !!s.on;

  // Bug C: an unverified SAS pairing must not unlock the main UI. `sas_phase`
  // is the authoritative "a fresh pairing is in flight" signal — NOT
  // `s.pending`, which is the FluxFirewall Ask-queue (unrelated to SAS).
  // Folding it in would hide the dashboard (and the approve/reject buttons
  // themselves) whenever a linked peer has an ordinary Ask item queued.
  const activeSas = !!s && ['showing', 'peer_confirmed', 'local_confirmed'].includes(s.sas_phase);
  // Only gate when the unverified pairing is the ONLY connection: with a
  // second peer already linked (`peers.length >= 2`), the dashboard for the
  // confirmed primary must keep showing while a second device verifies.
  const soleUnverified = activeSas && (!s.peers || s.peers.length <= 1);
  const isPaired = !!s && !!s.peer_name && s.peer_name.trim() !== '' && s.peer_name !== 'pending' &&
    s.peer_name !== TOFU_PLACEHOLDER && !soleUnverified;

  // Single-window UX: dashboard + history when linked, or an inline "Pair a
  // device" CTA when not — never auto-spawn the separate pair window.
  setView(isPaired ? 'paired' : 'unpaired');

  if (isPaired) {
    dismissOnboarding();
    renderHero(s);
    renderPeer(s);
    renderSelf(s);
    renderDevices(s);
    renderPending(s);
    setHistory(s);
    renderFirewall(s);
    maybePulse(s);
  } else {
    renderUnpaired(soleUnverified);
    if (soleUnverified) setHero('warn', 'Verifying', 'Compare the 6 words on both devices');
    else setHero('off', 'Not paired', 'Pair a device to start syncing');
    if (historyItems.length) setHistory(null);
  }
  renderLink(s, isPaired);
  renderMetrics(s);
  renderFooter(true, s);
}

function renderUnpaired(soleUnverified) {
  // While the only connection is an unverified SAS flow, the empty state
  // must not read "pair a device" next to the verify window — swap it for
  // a verification prompt whose CTA lands on the words.
  if (soleUnverified) {
    setText(el.pairTitle, 'Check the 6 words');
    setText(el.pairHint, 'A device is pairing. Make sure both screens show the same 6 words, then confirm on each one.');
    setText(el.pairCta, 'Show verification words');
    el.pairCtaSub.hidden = true;
  } else {
    setText(el.pairTitle, 'One clipboard, all your devices');
    setText(el.pairHint, 'Copy here, paste there. Straight across your network, end-to-end encrypted — no cloud, no account.');
    setText(el.pairCta, 'Pair a device');
    el.pairCtaSub.hidden = false;
  }
  el.onboarding.hidden = soleUnverified || onboardingDismissed();
}

async function refreshState() {
  if (isToggling) return;
  try {
    const resp = await invoke('fluxsync_status');
    applyState(resp && resp.data ? resp.data : null);
  } catch (e) {
    setOffline();
  }
}

// Daemon unreachable — distinguished from a daemon that is up but toggled
// off, so the user knows whether the service failed or they just need to
// hit the toggle.
function setOffline() {
  daemonReachable = false;
  syncOn = false;
  queuedState = undefined;
  setView('offline');
  setHero('crit', 'Offline', 'The FluxSync service isn’t answering');
  renderLink(null, false);
  renderMetrics(null);
  renderFooter(false, null);
}

// ── Hero ─────────────────────────────────────────────────────────
function setHero(state, label, sub) {
  setAttr(el.hero, 'data-state', state);
  setText(el.heroLabel, label);
  setText(el.heroSub, sub || ' ');
  if (!isToggling) {
    const on = daemonReachable && syncOn;
    el.toggle.classList.toggle('on', on);
    setAttr(el.toggle, 'aria-checked', String(on));
  }
}

function renderHero(s) {
  const peer = s.peer_name || 'your device';
  if (!s.on) return setHero('off', 'Off', `Your clipboard stays on this ${HOST_WORD}`);

  // 255 = battery not read yet (desktop / boot) → not "low"; only a real
  // 0-100 reading can trip the low/critical hero states.
  const threshold = s.battery_threshold ?? 20;
  const known = batteryKnown(s.battery_level);
  if (known && s.battery_level <= 5) return setHero('crit', 'Battery critical', 'Sync is paused to save power');
  if (known && s.battery_level <= threshold && !s.charging) {
    return setHero('warn', 'Paused', `Battery under ${threshold}% — resumes on charge`);
  }

  // Connection truth comes from the FSM phase, never the on-toggle: with
  // sync enabled but no live peer the hero must NOT claim "Linked".
  switch (s.phase) {
    case 'linked':       return setHero('ok', 'Linked', `Syncing with ${peer}`);
    case 'paused':
    case 'halted':       return setHero('warn', 'Paused', `${peer}'s battery is low — resumes on charge`);
    case 'handshaking':  return setHero('warn', 'Connecting', `Securing the link with ${peer}`);
    case 'discovering':
    case 'reconnecting': return setHero('warn', 'Searching', `Looking for ${peer} on your network`);
    default:             return setHero('off', 'Standby', `Waiting for ${peer}`);
  }
}

// ── The two ends of the link ─────────────────────────────────────
// Battery tail for a meta line: "76%" (+ bolt when charging), coloured
// when low. Desktops report 255 = no battery → nothing.
function setMeta(target, label, level, charging, threshold) {
  const key = `${label}|${level}|${charging}|${threshold}`;
  if (target.dataset.key === key) return;
  target.dataset.key = key;
  target.replaceChildren(document.createTextNode(label));
  if (!batteryKnown(level)) return;
  const b = document.createElement('span');
  b.textContent = `${level}%`;
  if (level <= 5) b.className = 'crit';
  else if (level <= threshold && !charging) b.className = 'low';
  target.append(document.createTextNode(' · '), b);
  if (charging) b.insertAdjacentHTML('beforeend', ICON.bolt);
}

let lastPeerPlatform = null;
function renderPeer(s) {
  const threshold = s.battery_threshold ?? 20;
  setText(el.peerName, s.peer_name || '—');
  el.peerName.title = s.peer_name || '';

  const p = (s.peer_platform || '').toLowerCase();
  if (p !== lastPeerPlatform) {
    lastPeerPlatform = p;
    // Phone vs computer icon from the peer's OS family (Hello).
    el.peerIcon.innerHTML = (p === 'android' || p === 'ios') ? ICON.phone : ICON.computer;
  }
  const platform = PLATFORM_LABELS[p] || (p || 'Peer');

  // Show the % whenever the peer is connected (linked OR battery-paused —
  // the link is still up, the value is still live) AND a real reading has
  // arrived. 255 = not read yet → hidden, never a fake 100%.
  const connected = s.phase === 'linked' || s.phase === 'paused' || s.phase === 'halted';
  setMeta(el.peerMeta, platform, connected ? s.peer_battery : 255, !!s.peer_charging, threshold);

  const peerLow = connected && batteryKnown(s.peer_battery) && s.peer_battery <= threshold && !s.peer_charging;
  el.pauseBanner.hidden = !peerLow;
  if (peerLow) setText(el.pauseText, `Paused — ${s.peer_name || 'the other device'} is under ${threshold}% battery. Resumes on charge.`);
}

// Self side: desktops without a battery report 255 — just the OS then.
function renderSelf(s) {
  setMeta(el.selfMeta, OS_NAMES[HOST_OS] || 'This device', s.battery_level, !!s.charging, s.battery_threshold ?? 20);
}

// RTT next to the gear; hidden until the daemon reports one.
function renderMetrics(s) {
  const rtt = s && s.metrics && typeof s.metrics.last_rtt_ms === 'number' ? s.metrics.last_rtt_ms : 0;
  el.rtt.hidden = !rtt;
  if (rtt) setText(el.rtt, `${rtt} ms`);
}

// The wire between the two devices. `data-link` drives the CSS: on (solid
// green), paused (amber dashes), searching (crawling dashes), off (inert).
function renderLink(s, isPaired) {
  let link = 'off';
  if (s && s.on && isPaired) {
    const phase = (s.phase || '').toLowerCase();
    if (phase === 'discovering' || phase === 'handshaking' || phase === 'reconnecting') {
      link = 'searching';
    } else {
      const threshold = s.battery_threshold ?? 20;
      const selfLow = batteryKnown(s.battery_level) && s.battery_level <= threshold && !s.charging;
      const peerLow = batteryKnown(s.peer_battery) && s.peer_battery <= threshold && !s.peer_charging;
      link = (phase === 'paused' || phase === 'halted' || selfLow || peerLow) ? 'paused' : (phase === 'linked' ? 'on' : 'off');
    }
  }
  setAttr(el.tray, 'data-link', link);
}

// A coral packet crosses the wire when a new item lands at the top of the
// history: local → out (tx), remote → in (rx).
let lastTopKey = null;
function maybePulse(s) {
  const top = s && s.history && s.history[0];
  const key = top ? itemKey(top) : null;
  if (key && lastTopKey && key !== lastTopKey) {
    el.packet.classList.remove('tx', 'rx');
    void el.packet.offsetWidth; // restart the CSS animation
    el.packet.classList.add(top.source === 'remote' ? 'rx' : 'tx');
    const entry = rowCache.get(key);
    if (entry) {
      entry.el.classList.add('new');
      entry.el.addEventListener('animationend', () => entry.el.classList.remove('new'), { once: true });
    }
  }
  lastTopKey = key;
}

function renderFooter(up, s) {
  el.daemonDot.classList.toggle('down', !up);
  setText(el.daemonLabel, up ? 'fluxsyncd · running' : 'fluxsyncd · unreachable');
  if (up && s && s.version) setText(el.version, s.version);
}

// ── Tabs ─────────────────────────────────────────────────────────
const TAB_KEY = 'fs.trayTab';
const TABS = ['clipboard', 'firewall', 'devices'];
let activeTab = 'clipboard';
try { const t = localStorage.getItem(TAB_KEY); if (TABS.includes(t)) activeTab = t; } catch (_) {}

function selectTab(view, focus) {
  if (!TABS.includes(view)) return;
  activeTab = view;
  try { localStorage.setItem(TAB_KEY, view); } catch (_) {}
  for (const t of el.tabs.querySelectorAll('.tab')) {
    const on = t.dataset.view === view;
    setAttr(t, 'aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
    if (on && focus) t.focus();
  }
  for (const id of TABS) $(`view-${id}`).hidden = id !== view;
  paintPendingStrip();
}
el.tabs.addEventListener('click', (e) => {
  const t = e.target.closest('.tab');
  if (t) selectTab(t.dataset.view);
});
el.tabs.addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
  e.preventDefault();
  const i = TABS.indexOf(activeTab);
  selectTab(TABS[(i + (e.key === 'ArrowRight' ? 1 : -1) + TABS.length) % TABS.length], true);
});

// ── History ──────────────────────────────────────────────────────
const FILTERS = [
  ['all', 'All'],
  ['pinned', 'Pinned'],
  ['text', 'Text'],
  ['url', 'Links'],
  ['code', 'Code'],
  ['image', 'Images'],
];
// Upper bound on preview characters put in the DOM. CSS clips to one line
// anyway; the full text stays in memory for copy + search.
const PREVIEW_DOM_CHARS = 220;

let historyItems = [];          // newest-first, as sent by the daemon
let historySig = null;          // cheap identity of `historyItems` (null = never rendered)
let renderedSig = null;         // historySig + filters at last DOM sync
let searchQuery = '';
let kindFilter = 'all';
const rowCache = new Map();     // key -> row entry (see createRow)
const searchIndex = new Map();  // key -> lower-cased searchable text
let peerNames = new Map();      // peer hex id -> display name

function itemKey(h) {
  return `${h.hash || ''}:${h.lamport}`;
}
function itemKind(h) {
  const k = (h.kind || 'text').toLowerCase();
  return ['text', 'url', 'code', 'image'].includes(k) ? k : 'text';
}

function setHistory(s) {
  const items = (s && Array.isArray(s.history)) ? s.history : [];
  if (s) {
    peerNames = new Map();
    for (const p of (Array.isArray(s.peers) ? s.peers : [])) {
      const hex = peerIdHex(p.peer_id);
      if (hex && p.name) peerNames.set(hex, p.name);
    }
    const primaryHex = peerIdHex(s.peer_id);
    if (primaryHex && s.peer_name && !peerNames.has(primaryHex)) peerNames.set(primaryHex, s.peer_name);
    peerNames.set('', s.peer_name || 'peer');
  }
  // Rows only change on add/remove/pin/peer rename — never on heartbeats.
  let sig = '';
  for (const h of items) sig += itemKey(h) + (h.favorite ? '*' : '') + (h.sensitive ? '!' : '') + originLabel(h) + '\n';
  if (sig === historySig) return;
  historySig = sig;
  historyItems = items;

  const live = new Set();
  for (const h of items) {
    const key = itemKey(h);
    live.add(key);
    if (!searchIndex.has(key)) {
      // Sensitive previews are masked — never index their text.
      searchIndex.set(key, h.sensitive ? itemKind(h) : `${itemKind(h)} ${(h.preview || '').toLowerCase()}`);
    }
  }
  for (const [key, entry] of rowCache) {
    if (!live.has(key)) {
      entry.el.remove();
      if (thumbObserver) thumbObserver.unobserve(entry.kind);
      rowCache.delete(key);
    }
  }
  for (const key of [...searchIndex.keys()]) if (!live.has(key)) searchIndex.delete(key);
  setText(el.recentCount, String(items.length));
  renderFilters();
  renderHistory();
}

function originLabel(h) {
  if (h.source !== 'remote') return 'This ' + HOST_WORD;
  return peerNames.get(h.source_peer_id || '') || peerNames.get('') || 'peer';
}

function matchesFilter(h) {
  if (kindFilter === 'pinned' && !h.favorite) return false;
  if (kindFilter !== 'all' && kindFilter !== 'pinned' && itemKind(h) !== kindFilter) return false;
  const q = searchQuery.trim().toLowerCase();
  return !q || (searchIndex.get(itemKey(h)) || '').includes(q);
}
function visibleItems() {
  return historyItems.filter(matchesFilter);
}

function renderHistory() {
  const sig = `${historySig}\u0000${searchQuery}\u0000${kindFilter}`;
  if (sig === renderedSig) return;
  renderedSig = sig;

  const visible = visibleItems();
  const total = historyItems.length;
  el.clearBtn.hidden = total === 0;

  const list = el.recent;
  let empty = list.querySelector('.list-empty');
  if (!visible.length) {
    for (const entry of rowCache.values()) entry.el.remove();
    if (!empty) {
      empty = document.createElement('div');
      empty.className = 'list-empty';
      list.append(empty);
    }
    const t = document.createElement('div');
    t.className = 't';
    const s = document.createElement('div');
    s.className = 's';
    if (total > 0) {
      t.textContent = 'No match';
      s.textContent = 'Try another word or filter.';
    } else {
      t.textContent = 'Nothing has crossed yet';
      s.textContent = 'Copy something on either device — it lands here, on both.';
    }
    empty.replaceChildren(t, s);
    return;
  }
  if (empty) empty.remove();

  // Keyed reconcile: reuse rows, patch only what changed, move nodes only
  // when the order actually differs.
  let cursor = list.firstElementChild;
  const shown = new Set();
  visible.forEach((h, i) => {
    const key = itemKey(h);
    shown.add(key);
    let entry = rowCache.get(key);
    if (!entry) {
      entry = createRow(key);
      rowCache.set(key, entry);
    }
    patchRow(entry, h, i);
    if (entry.el === cursor) cursor = cursor.nextElementSibling;
    else list.insertBefore(entry.el, cursor);
  });
  for (const [key, entry] of rowCache) {
    if (!shown.has(key) && entry.el.parentNode) entry.el.remove();
  }
}

function make(tag, cls) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  return n;
}

function createRow(key) {
  const row = make('div', 'row');
  row.setAttribute('role', 'listitem');
  row.dataset.key = key;
  const main = make('button', 'row-main');
  main.type = 'button';
  const idx = make('span', 'idx');
  idx.setAttribute('aria-hidden', 'true');
  const kind = make('span', 'kind');
  kind.setAttribute('aria-hidden', 'true');
  const text = make('span', 'row-text');
  const preview = make('span', 'preview');
  const origin = make('span', 'origin');
  text.append(preview, origin);
  const side = make('span', 'row-side');
  const pinned = make('span', 'pinned');
  pinned.innerHTML = ICON.pinMini;
  const time = make('span', 'time');
  const copied = make('span', 'copied');
  copied.textContent = 'Copied';
  side.append(pinned, time, copied);
  main.append(idx, kind, text, side);

  const acts = make('div', 'row-acts');
  const open = make('button', 'act open');
  open.type = 'button';
  open.innerHTML = ICON.open;
  open.title = 'Open link';
  open.setAttribute('aria-label', 'Open link in browser');
  open.hidden = true;
  const pin = make('button', 'act pin');
  pin.type = 'button';
  pin.innerHTML = ICON.star;
  acts.append(open, pin);

  row.append(main, acts);
  return { el: row, main, idx, kind, preview, origin, time, open, pin, h: null, sig: '', kindName: '' };
}

function displayText(h) {
  if (h.sensitive) return '••••••••••••';
  return (h.preview || '').slice(0, PREVIEW_DOM_CHARS).replace(/\s+/g, ' ').trim() || '(empty)';
}

function isWebUrl(h) {
  return itemKind(h) === 'url' && !h.sensitive && /^https?:\/\/\S+$/i.test((h.preview || '').trim());
}

function patchRow(entry, h, index) {
  entry.h = h;
  const kind = itemKind(h);
  const from = originLabel(h);
  const remote = h.source === 'remote';
  const sig = [kind, h.favorite, h.sensitive, h.time, from, remote].join('|');
  if (entry.sig !== sig) {
    entry.sig = sig;
    if (entry.kindName !== kind) {
      entry.kindName = kind;
      entry.kind.innerHTML = ICON[kind];
      // DIR-P3-02(b): lazy thumbnail — only rows actually scrolled into
      // view ever fetch bytes. Sensitive images never get one.
      if (kind === 'image' && h.hash && !h.sensitive) {
        entry.kind.dataset.hash = h.hash;
        getThumbObserver().observe(entry.kind);
      }
    }
    entry.preview.textContent = displayText(h);
    entry.preview.className = 'preview' + (h.sensitive ? ' masked' : kind === 'code' ? ' code' : '');

    // Direction first: what came in from which device, what went out.
    const dir = make('span', 'dir' + (remote ? ' in' : ''));
    dir.innerHTML = remote ? ICON.inArrow : ICON.outArrow;
    dir.append(document.createTextNode(from));
    const parts = [dir];
    if (h.sensitive) {
      const sens = make('span', 'sens');
      sens.innerHTML = ICON.lock;
      sens.append(document.createTextNode('Sensitive'));
      parts.push(sens);
    }
    entry.origin.replaceChildren(...parts);
    entry.time.textContent = h.time || '—';

    // Text rows carry their full payload in `preview`, so clicking copies
    // it straight back. Image rows fetch bytes on demand (DIR-P3-02(c)).
    const copyable = kind === 'image' ? !!h.hash : !!h.preview;
    entry.main.disabled = !copyable;
    entry.main.title = copyable ? 'Copy to clipboard' : '';
    const what = h.sensitive ? 'Sensitive item' : (kind === 'image' ? (h.preview || 'Image') : displayText(h).slice(0, 80));
    entry.main.setAttribute('aria-label',
      `${copyable ? 'Copy: ' : ''}${what}. ${remote ? 'Received from' : 'Copied on'} ${from}, ${h.time || ''}`);

    entry.open.hidden = !isWebUrl(h);
    entry.el.classList.toggle('pinned', !!h.favorite);
    // FluxVault: pinned items survive the vault TTL + cap.
    entry.pin.setAttribute('aria-pressed', String(!!h.favorite));
    const pinLabel = h.favorite ? 'Unpin' : 'Pin — keep it past the history limit';
    entry.pin.title = pinLabel;
    entry.pin.setAttribute('aria-label', pinLabel);
  }
  // The index doubles as the ⌘1–9 shortcut.
  setText(entry.idx, String(index + 1).padStart(2, '0'));
}

function renderFilters() {
  const counts = { all: historyItems.length, pinned: 0, text: 0, url: 0, code: 0, image: 0 };
  for (const h of historyItems) {
    counts[itemKind(h)]++;
    if (h.favorite) counts.pinned++;
  }
  // A filter whose bucket just emptied falls back to "All".
  if (kindFilter !== 'all' && !counts[kindFilter]) kindFilter = 'all';
  if (!el.filters.childElementCount) {
    for (const [id, label] of FILTERS) {
      const b = make('button', 'filter');
      b.type = 'button';
      b.dataset.filter = id;
      b.dataset.label = label;
      b.setAttribute('role', 'radio');
      b.textContent = label;
      el.filters.append(b);
    }
  }
  let buckets = 0;
  for (const b of el.filters.children) {
    const id = b.dataset.filter;
    const n = counts[id] || 0;
    if (id !== 'all' && n > 0) buckets++;
    b.hidden = id !== 'all' && n === 0;
    setAttr(b, 'aria-checked', String(id === kindFilter));
    setAttr(b, 'aria-label', `${b.dataset.label}, ${n} item${n === 1 ? '' : 's'}`);
    b.tabIndex = id === kindFilter ? 0 : -1;
  }
  // One bucket only (e.g. all text, nothing pinned) → filters add nothing.
  el.filters.hidden = buckets < 2 && kindFilter === 'all';
}

function selectFilter(id) {
  kindFilter = id;
  renderFilters();
  renderHistory();
}
el.filters.addEventListener('click', (e) => {
  const b = e.target.closest('.filter');
  if (b) selectFilter(b.dataset.filter);
});
el.filters.addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
  const btns = [...el.filters.children].filter((c) => !c.hidden);
  const idx = btns.findIndex((c) => c.dataset.filter === kindFilter);
  const next = btns[(idx + (e.key === 'ArrowRight' ? 1 : -1) + btns.length) % btns.length];
  if (!next) return;
  e.preventDefault();
  selectFilter(next.dataset.filter);
  next.focus();
});

// ── Copy ─────────────────────────────────────────────────────────
// The async Clipboard API first; WKWebView sometimes rejects it, so fall
// back to the legacy execCommand path (works on a user gesture).
async function copyText(text) {
  if (!text) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch {}
    ta.remove();
    return ok;
  }
}

function b64ToBlob(b64, type) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type });
}

// Decodes locally instead of `fetch(dataUri)`: the app CSP has no
// `connect-src data:`, so the old fetch-based path always failed and image
// rows reported "Image unavailable to copy".
async function copyImage(hash) {
  try {
    const b64 = await invoke('fluxsync_fetch_item', { hash });
    await navigator.clipboard.write([new ClipboardItem({ 'image/png': b64ToBlob(b64, 'image/png') })]);
    return true;
  } catch (_) {
    showToast('That image is no longer available to copy', 'err');
    return false;
  }
}

const copiedTimers = new WeakMap();
async function copyEntry(entry) {
  const h = entry && entry.h;
  if (!h || entry.main.disabled) return;
  const ok = itemKind(h) === 'image' ? await copyImage(h.hash) : await copyText(h.preview);
  if (!ok) {
    if (itemKind(h) !== 'image') showToast('Copy failed', 'err');
    return;
  }
  entry.el.classList.add('copied');
  clearTimeout(copiedTimers.get(entry.el));
  copiedTimers.set(entry.el, setTimeout(() => entry.el.classList.remove('copied'), 1400));
  showToast('Copied — on your other devices too', 'ok');
}

// ── Thumbnails (DIR-P3-02(b)) ────────────────────────────────────
// The daemon keeps only a handful of recent image payloads, and a payload
// can be several MB of PNG. Decode once, downscale to a 52 px square and
// keep only that tiny thumbnail (LRU-capped), never the full bytes.
const THUMB_CACHE_MAX = 24;
const thumbCache = new Map(); // hash -> small data: URI
let thumbObserver = null;
function getThumbObserver() {
  if (thumbObserver) return thumbObserver;
  thumbObserver = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      thumbObserver.unobserve(entry.target);
      loadThumbnail(entry.target);
    }
  }, { root: $('view-clipboard'), rootMargin: '80px 0px', threshold: 0.01 });
  return thumbObserver;
}

function makeThumb(dataUri) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      const size = 52;
      const c = document.createElement('canvas');
      c.width = size;
      c.height = size;
      const scale = Math.max(size / img.naturalWidth, size / img.naturalHeight);
      const w = img.naturalWidth * scale;
      const hh = img.naturalHeight * scale;
      c.getContext('2d').drawImage(img, (size - w) / 2, (size - hh) / 2, w, hh);
      resolve(c.toDataURL('image/png'));
    };
    img.onerror = reject;
    img.src = dataUri;
  });
}

async function loadThumbnail(kindEl) {
  const hash = kindEl.dataset.hash;
  if (!hash) return;
  try {
    let uri = thumbCache.get(hash);
    if (uri) {
      thumbCache.delete(hash); // refresh LRU position
    } else {
      const b64 = await invoke('fluxsync_fetch_item', { hash });
      uri = await makeThumb(`data:image/png;base64,${b64}`);
    }
    thumbCache.set(hash, uri);
    while (thumbCache.size > THUMB_CACHE_MAX) thumbCache.delete(thumbCache.keys().next().value);
    if (kindEl.dataset.hash !== hash) return;
    const img = document.createElement('img');
    img.className = 'thumb-img';
    img.alt = '';
    img.src = uri;
    kindEl.replaceChildren(img);
  } catch (_) {
    // No bytes cached for this hash (evicted / never received here).
  }
}

// ── FluxVault favorites ──────────────────────────────────────────
async function toggleFavorite(entry) {
  const h = entry && entry.h;
  if (!h || !h.hash) return;
  const favorite = !h.favorite;
  entry.pin.setAttribute('aria-pressed', String(favorite)); // optimistic
  try {
    await invoke('fluxsync_set_favorite', { hash: h.hash, favorite });
    showToast(favorite ? 'Pinned — kept past the history limit' : 'Unpinned', 'ok');
  } catch (err) {
    showToast(`${favorite ? 'Pin' : 'Unpin'} failed: ${err}`, 'err');
  }
  refreshState();
}

el.recent.addEventListener('click', (e) => {
  const row = e.target.closest('.row');
  if (!row) return;
  const entry = rowCache.get(row.dataset.key);
  if (!entry) return;
  if (e.target.closest('.pin')) toggleFavorite(entry);
  else if (e.target.closest('.open')) invoke('fluxsync_open_url', { url: (entry.h.preview || '').trim() });
  else if (e.target.closest('.row-main')) copyEntry(entry);
});

// ↑/↓ walk the list, `p` pins, `o` opens a link; ↑ on the first row goes
// back to the search box.
el.recent.addEventListener('keydown', (e) => {
  const row = e.target.closest('.row');
  if (!row) return;
  const entry = rowCache.get(row.dataset.key);
  const mains = [...el.recent.querySelectorAll('.row-main')];
  const idx = mains.indexOf(row.querySelector('.row-main'));
  let next = null;
  if (e.key === 'ArrowDown') next = mains[Math.min(idx + 1, mains.length - 1)];
  else if (e.key === 'ArrowUp') next = idx <= 0 ? el.search : mains[idx - 1];
  else if (e.key === 'Home') next = mains[0];
  else if (e.key === 'End') next = mains[mains.length - 1];
  else if (!e.metaKey && !e.ctrlKey && (e.key === 'p' || e.key === 'P')) {
    e.preventDefault();
    toggleFavorite(entry);
    return;
  } else if (!e.metaKey && !e.ctrlKey && (e.key === 'o' || e.key === 'O') && entry && isWebUrl(entry.h)) {
    e.preventDefault();
    invoke('fluxsync_open_url', { url: entry.h.preview.trim() });
    return;
  }
  if (next) {
    e.preventDefault();
    next.focus();
    next.scrollIntoView({ block: 'nearest' });
  }
});

// ── Search (DIR-P3-02(a): local, instant, no daemon round-trip) ──
el.search.addEventListener('input', () => {
  searchQuery = el.search.value;
  renderHistory();
});
el.search.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    e.stopPropagation();
    if (el.search.value) {
      el.search.value = '';
      searchQuery = '';
      renderHistory();
    } else {
      el.search.blur();
    }
  } else if (e.key === 'ArrowDown') {
    const first = el.recent.querySelector('.row-main');
    if (first) { e.preventDefault(); first.focus(); }
  } else if (e.key === 'Enter') {
    // Enter copies the best (first) match.
    const first = visibleItems()[0];
    if (first) { e.preventDefault(); copyEntry(rowCache.get(itemKey(first))); }
  }
});

// ── Pending firewall decisions ───────────────────────────────────
let pendingSig = '';
let pendingCount = 0;
function renderPending(s) {
  const pending = Array.isArray(s.pending) ? s.pending : [];
  const sig = pending.map((p) => `${p.hash}|${p.direction}|${p.kind}|${p.sensitive}`).join('\n');
  if (sig === pendingSig) return;
  pendingSig = sig;
  pendingCount = pending.length;
  el.pending.hidden = pending.length === 0;
  el.pending.replaceChildren(...pending.map(buildPendingCard));
  el.pendingBadge.hidden = pending.length === 0;
  setText(el.pendingBadge, String(pending.length));
  paintPendingStrip();
}
// Time-sensitive: announced on every tab, one click from the decision.
function paintPendingStrip() {
  const show = pendingCount > 0 && activeTab !== 'firewall';
  el.pendingStrip.hidden = !show;
  if (show) {
    setText(el.pendingStripText, pendingCount === 1
      ? '1 item is waiting for your decision'
      : `${pendingCount} items are waiting for your decision`);
  }
}
el.pendingStrip.addEventListener('click', () => selectTab('firewall'));

const KIND_NOUN = { text: 'text', url: 'link', code: 'code', image: 'image' };
function buildPendingCard(p) {
  const card = make('div', 'pend');
  const head = make('div', 'pend-head');
  const title = make('span', 'pend-title');
  const incoming = p.direction !== 'outbound';
  const noun = KIND_NOUN[(p.kind || 'text').toLowerCase()] || 'item';
  title.textContent = incoming ? `Incoming ${noun} — let it in?` : `Outgoing ${noun} — send it?`;
  head.append(title);
  if (p.sensitive) {
    const sec = make('span', 'pend-secret');
    sec.textContent = 'SECRET';
    head.append(sec);
  }
  const prev = make('div', 'pend-preview' + (p.sensitive ? ' masked' : ''));
  prev.textContent = p.sensitive ? '••••••••••••' : ((p.preview || '').slice(0, 400) || '(no preview)');
  const acts = make('div', 'pend-acts');
  const reject = make('button', 'btn danger');
  reject.textContent = 'Block';
  const approve = make('button', 'btn flux');
  approve.textContent = incoming ? 'Let it in' : 'Send it';
  const resolve = async (allow) => {
    reject.disabled = true;
    approve.disabled = true;
    try {
      await invoke('fluxsync_resolve_pending', { hash: p.hash, allow });
    } catch (err) {
      showToast(`${allow ? 'Approve' : 'Block'} failed: ${err}`, 'err');
      reject.disabled = false;
      approve.disabled = false;
    }
    refreshState();
  };
  reject.addEventListener('click', () => resolve(false));
  approve.addEventListener('click', () => resolve(true));
  acts.append(reject, approve);
  card.append(head, prev, acts);
  return card;
}

// ── FluxFirewall: rules matrix ───────────────────────────────────
// Rows = content kinds, columns = Allow / Ask / Block. Built once and
// updated in place, so a state push never steals keyboard focus.
const FW_RULES = [['allow', 'Allow'], ['ask', 'Ask'], ['deny', 'Block']];
const FW_KINDS = [
  ['text', 'Text', 'Plain text'],
  ['url', 'Links', 'URLs'],
  ['code', 'Code', 'Code-shaped content'],
  ['image', 'Images', 'PNG images'],
  ['sensitive', 'Secrets', 'Detected keys & tokens'],
];
function defaultFirewall() {
  return { enabled: false, text: 'allow', url: 'allow', code: 'allow', image: 'allow', sensitive: 'ask' };
}
let fw = defaultFirewall();
let fwSig = '';

(function buildMatrix() {
  for (const [field, label, hint] of FW_KINDS) {
    const row = make('div', 'mx-row');
    row.setAttribute('role', 'radiogroup');
    row.setAttribute('aria-label', `${label} rule`);
    const lab = make('span', 'mx-label');
    const b = document.createElement('b');
    b.textContent = label;
    const h = document.createElement('span');
    h.textContent = hint;
    lab.append(b, h);
    row.append(lab);
    for (const [rule, ruleLabel] of FW_RULES) {
      const c = make('button', 'cell');
      c.type = 'button';
      c.dataset.field = field;
      c.dataset.rule = rule;
      c.setAttribute('role', 'radio');
      c.setAttribute('aria-label', `${label}: ${ruleLabel}`);
      c.title = ruleLabel;
      c.append(document.createElement('i'));
      row.append(c);
    }
    el.fwRules.append(row);
  }
})();

function paintFirewall() {
  el.fwToggle.classList.toggle('on', !!fw.enabled);
  setAttr(el.fwToggle, 'aria-checked', String(!!fw.enabled));
  if (fw.enabled) {
    const asks = FW_KINDS.filter(([f]) => fw[f] === 'ask').length;
    const blocks = FW_KINDS.filter(([f]) => fw[f] === 'deny').length;
    const bits = [];
    if (blocks) bits.push(`${blocks} blocked`);
    if (asks) bits.push(`${asks} ask first`);
    setText(el.fwSub, bits.length ? `On — ${bits.join(' · ')}` : 'On — everything allowed');
  } else {
    setText(el.fwSub, 'Off — everything passes');
  }
  el.fwRules.classList.toggle('off', !fw.enabled);
  for (const c of el.fwRules.querySelectorAll('.cell')) {
    const on = (fw[c.dataset.field] || 'allow') === c.dataset.rule;
    setAttr(c, 'aria-checked', String(on));
    c.tabIndex = on ? 0 : -1;
    c.disabled = !fw.enabled;
  }
}

function renderFirewall(s) {
  const next = Object.assign(defaultFirewall(), s.firewall || {});
  const sig = JSON.stringify(next);
  if (sig === fwSig) return;
  fwSig = sig;
  fw = next;
  paintFirewall();
}

async function pushFirewall(policy) {
  const prev = fw;
  fw = policy;
  fwSig = JSON.stringify(policy);
  paintFirewall(); // optimistic
  try {
    await invoke('fluxsync_set_firewall', { policy });
  } catch (err) {
    fw = prev;
    fwSig = JSON.stringify(prev);
    paintFirewall();
    showToast(`Firewall update failed: ${err}`, 'err');
  }
  refreshState();
}

el.fwToggle.addEventListener('click', () => pushFirewall(Object.assign({}, fw, { enabled: !fw.enabled })));
el.fwRules.addEventListener('click', (e) => {
  const c = e.target.closest('.cell');
  if (!c || !fw.enabled) return;
  const { field, rule } = c.dataset;
  if ((fw[field] || 'allow') !== rule) pushFirewall(Object.assign({}, fw, { [field]: rule }));
});
el.fwRules.addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
  const c = e.target.closest('.cell');
  if (!c || !fw.enabled) return;
  const order = FW_RULES.map(([r]) => r);
  const i = order.indexOf(c.dataset.rule);
  const rule = order[(i + (e.key === 'ArrowRight' ? 1 : -1) + order.length) % order.length];
  e.preventDefault();
  pushFirewall(Object.assign({}, fw, { [c.dataset.field]: rule }));
  requestAnimationFrame(() => el.fwRules.querySelector(`.cell[data-field="${c.dataset.field}"][data-rule="${rule}"]`)?.focus());
});

// ── Devices (FluxMesh) ───────────────────────────────────────────
// Every linked device, with a per-device unpair. Built with textContent
// only — peer names are attacker-controlled (Hello data). Rebuilt only
// when something visible changed.
let devicesSig = null;
function renderDevices(s) {
  const peers = Array.isArray(s.peers) && s.peers.length ? s.peers : [{
    peer_id: s.peer_id, name: s.peer_name, platform: s.peer_platform,
    battery: s.peer_battery, charging: s.peer_charging, primary: true,
  }];
  const sig = peers.map((p) => [peerIdHex(p.peer_id), p.name, p.platform, p.battery, p.charging, p.primary].join('|')).join('\n');
  if (sig === devicesSig) return;
  devicesSig = sig;
  setText(el.devicesCount, String(peers.length));
  el.devices.replaceChildren(...peers.map((p) => {
    const row = make('div', 'dev');
    const key = (p.platform || '').toLowerCase();
    const node = make('span', 'node');
    node.setAttribute('aria-hidden', 'true');
    node.innerHTML = (key === 'android' || key === 'ios') ? ICON.phone : ICON.computer;
    const text = make('div', 'dev-text');
    const name = make('span', 'dev-name');
    const display = isRealPeerName(p.name) ? p.name.trim() : 'Unnamed device';
    name.textContent = display;
    name.title = display;
    const meta = make('span', 'dev-meta');
    const live = make('span', 'live');
    live.textContent = p.primary && peers.length > 1 ? 'PRIMARY' : 'LINKED';
    const bits = [PLATFORM_LABELS[key] || p.platform || ''];
    if (batteryKnown(p.battery)) bits.push(`${p.battery}%${p.charging ? ' · charging' : ''}`);
    meta.append(live, document.createTextNode(bits.filter(Boolean).join(' · ')));
    text.append(name, meta);
    const btn = make('button', 'btn danger sm');
    btn.textContent = 'Unpair';
    // The daemon `revoke` op drops just this peer; with no id (older
    // daemon) fall back to `unpair`, which resets the primary link.
    const hex = peerIdHex(p.peer_id);
    btn.addEventListener('click', () => unpairPeer(hex, display));
    row.append(node, text, btn);
    return row;
  }));
}

async function unpairPeer(peerHex, name) {
  const ok = await confirmDialog({
    title: `Unpair ${name || 'this device'}?`,
    message: 'It’s disconnected and forgotten. You’ll have to pair it again to share a clipboard with it.',
    confirmLabel: 'Unpair',
    danger: true,
  });
  if (!ok) return;
  try {
    if (peerHex) await invoke('fluxsync_revoke_peer', { peerId: peerHex });
    else await invoke('fluxsync_unpair');
    showToast(`${name || 'Device'} unpaired`, 'ok');
    refreshState();
  } catch (err) {
    showToast(`Unpair failed: ${err}`, 'err');
  }
}

$('pair-another').addEventListener('click', () => invoke('fluxsync_open_pair'));
$('reset-all').addEventListener('click', async () => {
  const ok = await confirmDialog({
    title: 'Reset all pairings?',
    message: 'Every paired device is unpaired and forgotten. Use this if pairing gets stuck — you can pair again right after.',
    confirmLabel: 'Reset everything',
    danger: true,
  });
  if (!ok) return;
  try {
    await invoke('fluxsync_unpair');
    showToast('All pairings reset', 'ok');
    refreshState();
  } catch (err) {
    showToast(`Reset failed: ${err}`, 'err');
  }
});

// ── Controls ─────────────────────────────────────────────────────
el.toggle.addEventListener('click', async () => {
  if (isToggling || !daemonReachable) return;
  const willBeOn = !syncOn;
  isToggling = true;
  syncOn = willBeOn;
  el.toggle.classList.toggle('on', willBeOn);
  el.toggle.setAttribute('aria-checked', String(willBeOn));
  try {
    await invoke('fluxsync_toggle', { on: willBeOn });
  } catch (err) {
    // Backend rejected — revert visual state and tell the user why.
    syncOn = !willBeOn;
    el.toggle.classList.toggle('on', !willBeOn);
    el.toggle.setAttribute('aria-checked', String(!willBeOn));
    showToast(daemonReachable ? `Toggle failed: ${err}` : 'Service unreachable — toggle reverted', 'err');
  } finally {
    isToggling = false;
  }
  refreshState();
});

$('retry-btn').addEventListener('click', async () => {
  setText(el.daemonLabel, 'fluxsyncd · retrying…');
  await refreshState();
  if (!daemonReachable) showToast('Still unreachable — the service may be restarting', 'err');
});

$('onboarding-skip').addEventListener('click', dismissOnboarding);
$('header-settings').addEventListener('click', () => invoke('fluxsync_open_settings'));
el.pairCta.addEventListener('click', () => { invoke('fluxsync_open_pair'); });

el.clearBtn.addEventListener('click', async () => {
  const ok = await confirmDialog({
    title: 'Clear clipboard history?',
    message: 'Pinned items are kept. Only this device is cleared — your other devices keep their own history.',
    confirmLabel: 'Clear',
    danger: true,
  });
  if (!ok) return;
  try {
    await invoke('fluxsync_clear_history');
    showToast('History cleared', 'ok');
    refreshState();
  } catch (err) {
    showToast(`Clear failed: ${err}`, 'err');
  }
});

// ── Keyboard ─────────────────────────────────────────────────────
//   ⌘/Ctrl ,     Settings            /  or ⌘/Ctrl F   Search
//   ⌘/Ctrl 1–9   Copy item 01–09     Esc              Clear search / hide
document.addEventListener('keydown', (e) => {
  if (document.querySelector('.fs-scrim')) return; // a dialog owns the keyboard
  const mod = IS_MAC ? e.metaKey : e.ctrlKey;
  const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
  if (mod && e.key === ',') {
    e.preventDefault();
    invoke('fluxsync_open_settings');
    return;
  }
  if (currentView === 'paired' && ((mod && e.key.toLowerCase() === 'f') || (!typing && !mod && e.key === '/'))) {
    e.preventDefault();
    selectTab('clipboard');
    el.search.focus();
    el.search.select();
    return;
  }
  if (currentView === 'paired' && mod && /^[1-9]$/.test(e.key)) {
    const h = visibleItems()[Number(e.key) - 1];
    if (h) {
      e.preventDefault();
      copyEntry(rowCache.get(itemKey(h)));
    }
    return;
  }
  if (e.key === 'Escape' && !typing) {
    getCurrentWindow().close(); // the Rust CloseRequested handler hides it
  }
});

// ── Window drag (long-press on any non-interactive area) ─────────
let dragTimer = null;
let dragActive = false;
document.addEventListener('mousedown', (e) => {
  if (e.button !== 0) return;
  if (e.target.closest('button, input, a, .row, .fs-scrim')) return;
  dragActive = false;
  dragTimer = setTimeout(async () => {
    dragActive = true;
    try { await getCurrentWindow().startDragging(); } catch (_) {}
  }, 150);
});
document.addEventListener('mouseup', () => {
  if (dragTimer) { clearTimeout(dragTimer); dragTimer = null; }
});
document.addEventListener('contextmenu', (e) => {
  if (dragActive) { e.preventDefault(); dragActive = false; }
});

// ── Lifecycle ────────────────────────────────────────────────────
let pollHandle = null;
let unlistenState = null;
async function onShow() {
  await refreshState();
  // Live updates via the `state-update` Tauri event (see `subscribe_state`
  // in src-tauri/src/lib.rs). The poll is only a safety net and skips
  // itself while the event stream is healthy.
  if (!unlistenState) {
    unlistenState = await listen('state-update', (event) => applyState(event.payload));
  }
  if (!pollHandle) {
    pollHandle = setInterval(() => {
      if (Date.now() - lastStateAt > 4500) refreshState();
    }, 5000);
  }
}

selectTab(activeTab);
getCurrentWindow().onFocusChanged(({ payload }) => {
  // Refresh on focus. Do NOT auto-hide on blur: closing hides the window
  // (see lib.rs), and a blur-hide also blanked the WebView on next show.
  if (payload) onShow();
});
// First load (the menu window is created visible).
onShow();
