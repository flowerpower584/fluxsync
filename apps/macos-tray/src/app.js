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
  document.getElementById('tray-container').style.display = isPaired ? 'flex' : 'none';
  document.getElementById('pairing-entry').style.display = isPaired ? 'none' : 'block';

  if (isPaired) {
    renderHero(s);
    renderPeer(s);
    renderRecent(s.history || []);
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

document.getElementById('open-settings').addEventListener('click', () => {
  invoke('fluxsync_open_settings');
});

document.getElementById('entry-show-qr').addEventListener('click', () => openPair());
document.getElementById('entry-scan-peer').addEventListener('click', () => openPair());

document.getElementById('unpair-btn').addEventListener('click', async () => {
  if (!confirm('This will disconnect and unpair your device. Continue?')) return;
  try {
    await invoke('fluxsync_unpair');
    showToast('Device unpaired.');
    refreshState();
    // [FIX] Immediately show QR window after unpairing for better UX.
    openPair();
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
  // payload === true → focused (just shown); false → blurred (hidden).
  if (payload) onShow(); else win.hide();
});
// First load when the window is created visible (during `tauri dev`).
onShow();
