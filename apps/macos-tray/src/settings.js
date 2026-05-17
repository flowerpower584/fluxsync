// FluxSync Settings Window Logic
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let currentTab = 'general';
let unlistenState = null;
let lastState = null;

// Toast singleton — same pattern as the tray popup, kept inline so the
// two windows don't have to share a module.
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

async function refreshState() {
  try {
    const resp = await invoke('fluxsync_status');
    const s = resp && resp.data ? resp.data : null;
    if (s) {
      lastState = s;
      updateUI(s);
    }
  } catch (e) {
    console.error('Failed to refresh settings state', e);
  }
}

function fmtUptime(secs) {
  if (typeof secs !== 'number' || secs <= 0) return '—';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  if (h > 0) return `${h}H ${m.toString().padStart(2, '0')}M`;
  if (m > 0) return `${m}M ${s.toString().padStart(2, '0')}S`;
  return `${s}S`;
}

function updateUI(s) {
  // General tab — battery threshold + slider stay in sync with the daemon.
  document.getElementById('threshold-display').textContent = s.battery_threshold || 20;
  document.getElementById('threshold-slider').value = s.battery_threshold || 20;

  // Daemon-backed toggle: charge_override now lives on State.
  document.getElementById('opt-resume-on-charge').classList.toggle('on', !!s.charge_override);

  // Frontend-local prefs (the daemon doesn't track these). localStorage
  // hydrates them so the visual state survives reload.
  const launch = localStorage.getItem('fs.launchAtLogin') === '1';
  const dock = localStorage.getItem('fs.showInDock') === '1';
  document.getElementById('opt-launch-at-login').classList.toggle('on', launch);
  document.getElementById('opt-show-in-dock').classList.toggle('on', dock);

  // Telemetry pane — pulls everything from `s.metrics` if present.
  const m = s.metrics || null;
  document.getElementById('metric-rtt').textContent = m && m.last_rtt_ms ? `${m.last_rtt_ms} MS` : '—';
  document.getElementById('metric-rtt-p99').textContent = m && m.rtt_p99_ms ? `${m.rtt_p99_ms} MS` : '—';
  document.getElementById('metric-reconnects').textContent = m ? `${m.reconnects ?? 0}` : '—';
  document.getElementById('metric-uptime').textContent = m ? fmtUptime(m.uptime_session_secs) : '—';

  // Update device list if on devices tab
  if (currentTab === 'devices') {
    renderDevices(s);
  }
}

function renderDevices(s) {
  const list = document.getElementById('device-list');
  list.innerHTML = '';
  
  // Filter out 'pending' placeholder to avoid confusion.
  const hasRealPeer = s.peer_name && s.peer_name !== "pending";

  if (hasRealPeer) {
    const item = document.createElement('div');
    item.className = 'device-item';
    item.innerHTML = `
      <div>
        <div class="name-row">
          <div class="dot"></div>
          <span class="name">${s.peer_name}</span>
        </div>
        <div class="meta">ANDROID · ${s.peer_battery}%</div>
        <div class="last-seen">LAST SEEN · NOW</div>
      </div>
      <button class="unpair-btn" id="unpair-active">UNPAIR</button>
    `;
    list.appendChild(item);
  } else {
    list.innerHTML = '<div style="text-align:center;color:var(--fs-muted);padding:20px;">No devices paired yet.</div>';
  }
}

// ── Tab Navigation ──────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tabId = btn.getAttribute('data-tab');
    switchTab(tabId);
  });
});

function switchTab(tabId) {
  currentTab = tabId;
  
  // Update buttons
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-tab') === tabId);
  });
  
  // Update panes
  document.querySelectorAll('.pane').forEach(p => {
    p.style.display = p.id === `pane-${tabId}` ? 'block' : 'none';
  });
  
  refreshState();
}

// ── Controls ────────────────────────────────────────────────────
document.getElementById('threshold-slider').addEventListener('input', (e) => {
  document.getElementById('threshold-display').textContent = e.target.value;
});

document.getElementById('threshold-slider').addEventListener('change', async (e) => {
  const val = parseInt(e.target.value);
  const prev = lastState ? (lastState.battery_threshold || 20) : 20;
  try {
    await invoke('fluxsync_set_threshold', { value: val });
  } catch (err) {
    e.target.value = prev;
    document.getElementById('threshold-display').textContent = prev;
    showToast(`Couldn't update threshold: ${err}`);
  }
});

document.getElementById('opt-resume-on-charge').addEventListener('click', async () => {
  const btn = document.getElementById('opt-resume-on-charge');
  const isNowOn = !btn.classList.contains('on');
  btn.classList.toggle('on', isNowOn); 
  try {
    await invoke('fluxsync_set_charge_override', { value: isNowOn });
  } catch (err) {
    btn.classList.toggle('on', !isNowOn);
    showToast(`Couldn't update preference: ${err}`);
  }
});

document.getElementById('opt-launch-at-login').addEventListener('click', async () => {
  const btn = document.getElementById('opt-launch-at-login');
  const isNowOn = !btn.classList.contains('on');
  btn.classList.toggle('on', isNowOn);
  localStorage.setItem('fs.launchAtLogin', isNowOn ? '1' : '0');
  try {
    await invoke('fluxsync_set_launch_at_login', { value: isNowOn });
  } catch (err) {
    btn.classList.toggle('on', !isNowOn);
    localStorage.setItem('fs.launchAtLogin', !isNowOn ? '1' : '0');
    showToast(`Couldn't update preference: ${err}`);
  }
});

document.getElementById('opt-show-in-dock').addEventListener('click', async () => {
  const btn = document.getElementById('opt-show-in-dock');
  const isNowOn = !btn.classList.contains('on');
  btn.classList.toggle('on', isNowOn);
  localStorage.setItem('fs.showInDock', isNowOn ? '1' : '0');
  try {
    await invoke('fluxsync_set_show_in_dock', { value: isNowOn });
  } catch (err) {
    btn.classList.toggle('on', !isNowOn);
    localStorage.setItem('fs.showInDock', !isNowOn ? '1' : '0');
    showToast(`Couldn't update preference: ${err}`);
  }
});

document.getElementById('opt-prefer-lan').addEventListener('click', async () => {
  const btn = document.getElementById('opt-prefer-lan');
  const isNowOn = !btn.classList.contains('on');
  btn.classList.toggle('on', isNowOn);
  try {
    await invoke('fluxsync_set_prefer_lan', { value: isNowOn });
  } catch (err) {
    btn.classList.toggle('on', !isNowOn);
    showToast(`Couldn't update preference: ${err}`);
  }
});

document.getElementById('btn-add-device').addEventListener('click', () => {
  invoke('fluxsync_open_pair');
});

document.getElementById('btn-reset-session').addEventListener('click', async () => {
  if (confirm("This will disconnect your current device and reset the session. Continue?")) {
    try {
      await invoke('fluxsync_unpair');
      await new Promise(r => setTimeout(r, 100));
      await invoke('fluxsync_open_pair');
      showToast("Session reset successfully.");
    } catch (err) {
      showToast(`Reset failed: ${err}`);
    }
  }
});

// Event delegation for the dynamic Unpair button
document.getElementById('device-list').addEventListener('click', async (e) => {
  if (e.target.classList.contains('unpair-btn')) {
    try {
      await invoke('fluxsync_unpair');
      showToast("Device unpaired.");
    } catch (err) {
      showToast(`Unpair failed: ${err}`);
    }
  }
});

document.getElementById('link-license').addEventListener('click', () => {
  invoke('fluxsync_open_url', { url: 'https://github.com/flowerpower584/fluxsync/blob/main/LICENSE-MIT' });
});

document.getElementById('link-author').addEventListener('click', () => {
  invoke('fluxsync_open_url', { url: 'https://github.com/flowerpower584' });
});

document.getElementById('btn-check-updates').addEventListener('click', () => {
  showToast("You are on the latest hardened build (v0.5.0).");
});

// ── Initialization ─────────────────────────────────────────────
(async () => {
  await refreshState();
  unlistenState = await listen('state-update', (event) => {
    lastState = event.payload;
    updateUI(event.payload);
  });
})();
setInterval(refreshState, 5000);
