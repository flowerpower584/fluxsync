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
  void label;
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
  document.getElementById('pairing-entry').style.display = isPaired ? 'none' : 'flex';

  if (isPaired) {
    renderHero(s);
    renderPeer(s);
    renderRecent(s.history || []);
  } else {
    setHero('off', 'NO DEVICE PAIRED');
    renderRecent([]);
  }
  renderMetrics(s);
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
    renderMetrics(null);
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

function renderRecent(history) {
  const list = document.getElementById('recent');
  document.getElementById('recent-count').textContent = `${history.length} ITEMS`;
  list.innerHTML = '';
  history.slice(0, 5).forEach(h => {
    const item = document.createElement('button');
    item.className = 'history-item';
    
    const k = document.createElement('span'); 
    k.className = 'kind mono'; 
    k.textContent = (h.kind || 'TEXT').toUpperCase();
    
    const p = document.createElement('span'); 
    p.className = 'preview'; 
    p.textContent = h.preview || '';
    
    const t = document.createElement('span'); 
    t.className = 'time mono'; 
    t.textContent = h.time || '—';
    
    item.append(k, p, t);
    list.append(item);
  });
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
