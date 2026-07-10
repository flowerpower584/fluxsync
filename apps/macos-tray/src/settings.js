// FluxSync Settings Window Logic
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

(function tagHostOS() {
  const ua = navigator.userAgent;
  const os = /Windows/i.test(ua) ? 'windows'
    : /Macintosh|Mac OS/i.test(ua) ? 'macos'
    : /Linux/i.test(ua) ? 'linux'
    : 'unknown';
  document.body.dataset.os = os;
  const deviceLabel = { windows: 'PC', macos: 'Mac', linux: 'Linux' }[os] || 'device';
  const sub = document.getElementById('general-subtitle');
  if (sub) sub.textContent = `How FluxSync behaves on this ${deviceLabel}.`;
})();

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
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
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
    setOfflineBanner(false);
  } catch (e) {
    console.error('Failed to refresh settings state', e);
    setOfflineBanner(true);
  }
}

// DIR-P3-03: surface daemon-unreachable instead of swallowing it — same
// show/clear behavior as the tray popup's "DAEMON OFFLINE" hero state.
function setOfflineBanner(show) {
  const el = document.getElementById('offline-banner');
  if (el) el.style.display = show ? 'flex' : 'none';
}

// DIR-P3-06: keep `aria-checked` in lockstep with the visual `.on` class on
// every `role="switch"` toggle button — the class alone is invisible to
// assistive tech.
function setToggleState(btn, on) {
  if (!btn) return;
  btn.classList.toggle('on', on);
  btn.setAttribute('aria-checked', String(on));
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
  // Device name: skip the refresh while the field is focused so a
  // 5s poll (or a live state-update push) doesn't stomp what the user is
  // mid-typing — same hazard `threshold-slider` doesn't have (a drag is
  // transient; a text field holds partial input across ticks).
  const nameInput = document.getElementById('device-name-input');
  if (document.activeElement !== nameInput) {
    nameInput.value = s.device_name || '';
  }

  // General tab — battery threshold + slider stay in sync with the daemon.
  document.getElementById('threshold-display').textContent = s.battery_threshold || 20;
  document.getElementById('threshold-slider').value = s.battery_threshold || 20;

  // Daemon-backed toggle: charge_override now lives on State.
  setToggleState(document.getElementById('opt-resume-on-charge'), !!s.charge_override);

  // Telemetry pane — pulls everything from `s.metrics` if present.
  const m = s.metrics || null;
  document.getElementById('metric-rtt').textContent = m && m.last_rtt_ms ? `${m.last_rtt_ms} MS` : '—';
  document.getElementById('metric-rtt-p99').textContent = m && m.rtt_p99_ms ? `${m.rtt_p99_ms} MS` : '—';
  document.getElementById('metric-items').textContent = m ? `${m.items_sent ?? 0} ↑ ${m.items_received ?? 0} ↓` : '—';
  document.getElementById('metric-dups').textContent = m ? `${m.dedup_drops ?? 0}` : '—';
  document.getElementById('metric-reconnects').textContent = m ? `${m.reconnects ?? 0}` : '—';
  document.getElementById('metric-hs-failed').textContent = m ? `${m.handshakes_failed ?? 0}` : '—';
  document.getElementById('metric-uptime').textContent = m ? fmtUptime(m.uptime_session_secs) : '—';

  // Update device list if on devices tab
  if (currentTab === 'devices') {
    renderDevices(s);
  }
}

// TOFU placeholder the daemon projects into a peer's name between handshake
// completion and the `Msg::Hello` that carries its real device name (see
// `fluxsyncd::handshake::TOFU_PLACEHOLDER_NAME`). Same treatment as the
// "pending" sentinel — never a real identity, never shown raw.
const TOFU_PLACEHOLDER = 'New Peer';
const PLATFORM_LABELS = { macos: 'macOS', windows: 'Windows', linux: 'Linux', android: 'Android', ios: 'iOS' };
// Friendlier stand-in for a peer whose Hello hasn't landed yet — mirrors
// pair.js's `friendlyPeerName` (pair.js:61-66) so this pane never surfaces
// the raw "New Peer"/"pending" bookkeeping values.
const PLATFORM_FRIENDLY = {
  macos: 'a Mac', windows: 'a PC', linux: 'a Linux device',
  android: 'an Android phone', ios: 'an iPhone',
};

function isRealPeerName(name) {
  const n = (name || '').trim();
  return !!n && n !== 'pending' && n !== TOFU_PLACEHOLDER;
}

function friendlyDeviceName(name, platform) {
  if (isRealPeerName(name)) return name.trim();
  const label = PLATFORM_FRIENDLY[(platform || '').toLowerCase()];
  return label ? `Pairing with ${label}…` : 'Pairing…';
}

// peer_id rides the State DTO as a 32-byte array (serde `[u8;32]`); the
// daemon `revoke` op wants the full hex string. Returns '' if malformed.
function peerIdHex(id) {
  if (!Array.isArray(id) || id.length !== 32) return '';
  return id.map((b) => (b & 0xff).toString(16).padStart(2, '0')).join('');
}

// H-TRAY-01: `name`/`platform` are attacker-controlled (the peer's
// self-reported Hello data). NEVER interpolate them into innerHTML — build
// every row with the DOM API + textContent so a name like `<img onerror=…>`
// can't run privileged Tauri invokes.
function buildDeviceRow({ name, platform, battery, charging, connected, onUnpair }) {
  const item = document.createElement('div');
  item.className = 'device-item';

  const info = document.createElement('div');

  const nameRow = document.createElement('div');
  nameRow.className = 'name-row';
  const dot = document.createElement('div');
  dot.className = 'dot';
  const nameEl = document.createElement('span');
  nameEl.className = 'name';
  nameEl.textContent = name;
  nameRow.appendChild(dot);
  nameRow.appendChild(nameEl);

  const meta = document.createElement('div');
  meta.className = 'meta';
  // 255 / missing / >100 = no real battery reading yet → '—', never a fake
  // percentage (this is the "255%" bug: the old code printed `peer_battery`
  // straight through with no sentinel guard).
  const battText = typeof battery === 'number' && battery <= 100
    ? `${battery}%${charging ? ' ⚡' : ''}`
    : '—';
  meta.textContent = platform ? `${battText} · ${platform}` : battText;

  const lastSeen = document.createElement('div');
  lastSeen.className = 'last-seen';
  lastSeen.textContent = connected ? 'CONNECTED' : 'OFFLINE';

  info.appendChild(nameRow);
  info.appendChild(meta);
  info.appendChild(lastSeen);

  const btn = document.createElement('button');
  btn.className = 'unpair-btn';
  btn.textContent = 'UNPAIR';
  btn.addEventListener('click', onUnpair);

  item.appendChild(info);
  item.appendChild(btn);
  return item;
}

// FluxMesh: render every linked peer from `s.peers`, not just the legacy
// single-peer projection — the old version only ever showed one row (and,
// via `peer_battery` with no sentinel guard, sometimes "255%"). Falls back
// to the legacy `peer_name`/`peer_battery` row only when `peers` is empty
// but a real (non-placeholder) legacy peer is projected — keeps this pane
// working against an older daemon build that predates `State.peers`.
function renderDevices(s) {
  const list = document.getElementById('device-list');
  list.innerHTML = '';

  const peers = Array.isArray(s.peers) ? s.peers : [];

  if (peers.length > 0) {
    peers.forEach((p) => {
      const hex = peerIdHex(p.peer_id);
      const displayName = friendlyDeviceName(p.name, p.platform);
      const row = buildDeviceRow({
        name: displayName,
        platform: PLATFORM_LABELS[(p.platform || '').toLowerCase()] || '',
        battery: p.battery,
        charging: !!p.charging,
        // `s.peers` is rebuilt from the live session set at every
        // `EmitState` (see `driver::build_peers`) — a dead session never
        // lingers in it, so every entry here is, by construction, connected.
        connected: true,
        onUnpair: async () => {
          if (!hex) return;
          if (!confirm(`Unpair ${displayName}? You'll have to pair again to reconnect.`)) return;
          try {
            await invoke('fluxsync_revoke_peer', { peerId: hex });
            showToast('Device unpaired.');
          } catch (err) {
            showToast(`Unpair failed: ${err}`);
          }
        },
      });
      list.appendChild(row);
    });
    return;
  }

  if (!isRealPeerName(s.peer_name)) {
    const empty = document.createElement('div');
    empty.style.cssText = 'text-align:center;color:var(--fs-muted);padding:20px;';
    empty.textContent = 'No devices paired yet.';
    list.appendChild(empty);
    return;
  }

  const linked = s.status === 'syncing' || s.status === 'paused';
  const row = buildDeviceRow({
    name: s.peer_name.trim(),
    platform: PLATFORM_LABELS[(s.peer_platform || '').toLowerCase()] || '',
    battery: s.peer_battery,
    charging: !!s.peer_charging,
    connected: linked,
    onUnpair: async () => {
      if (!confirm("Unpair this device? You'll have to pair again to reconnect.")) return;
      try {
        await invoke('fluxsync_unpair');
        showToast('Device unpaired.');
      } catch (err) {
        showToast(`Unpair failed: ${err}`);
      }
    },
  });
  list.appendChild(row);
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
    const active = b.getAttribute('data-tab') === tabId;
    b.classList.toggle('active', active);
    b.setAttribute('aria-selected', active ? 'true' : 'false');
    // DIR-P3-06: roving tabindex — only the active tab sits in the Tab
    // order; arrow keys (below) move focus between the rest.
    b.tabIndex = active ? 0 : -1;
  });

  // Update panes
  document.querySelectorAll('.pane').forEach(p => {
    p.style.display = p.id === `pane-${tabId}` ? 'block' : 'none';
  });

  refreshState();
}

// DIR-P3-06: standard WAI-ARIA tabs keyboard pattern — arrow keys move
// focus and activate (this sidebar is visually a column, so Up/Down are
// primary; Left/Right also work since screen-reader users may expect the
// horizontal convention regardless of layout). Home/End jump to the ends.
const TAB_ORDER = ['general', 'devices', 'network', 'about'];
document.querySelector('.sidebar').addEventListener('keydown', (e) => {
  const idx = TAB_ORDER.indexOf(currentTab);
  let next = null;
  if (e.key === 'ArrowDown' || e.key === 'ArrowRight') next = TAB_ORDER[(idx + 1) % TAB_ORDER.length];
  else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') next = TAB_ORDER[(idx - 1 + TAB_ORDER.length) % TAB_ORDER.length];
  else if (e.key === 'Home') next = TAB_ORDER[0];
  else if (e.key === 'End') next = TAB_ORDER[TAB_ORDER.length - 1];
  if (!next) return;
  e.preventDefault();
  switchTab(next);
  document.querySelector(`.tab-btn[data-tab="${next}"]`)?.focus();
});

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

// DIR-P3-01: save on blur (native `change` semantics for a text input),
// and Enter triggers the same blur instead of needing a separate Save
// button — mirrors the slider's "commit on release" feel.
document.getElementById('device-name-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') e.target.blur();
});

document.getElementById('device-name-input').addEventListener('change', async (e) => {
  const val = e.target.value.trim();
  const prev = lastState ? (lastState.device_name || '') : '';
  if (!val) {
    e.target.value = prev;
    showToast("Device name can't be empty.");
    return;
  }
  try {
    await invoke('fluxsync_set_device_name', { name: val });
    showToast('Device name updated.');
  } catch (err) {
    e.target.value = prev;
    showToast(`Couldn't rename device: ${err}`);
  }
});

document.getElementById('opt-resume-on-charge').addEventListener('click', async () => {
  const btn = document.getElementById('opt-resume-on-charge');
  const isNowOn = !btn.classList.contains('on');
  setToggleState(btn, isNowOn);
  try {
    await invoke('fluxsync_set_charge_override', { value: isNowOn });
  } catch (err) {
    setToggleState(btn, !isNowOn);
    showToast(`Couldn't update preference: ${err}`);
  }
});

document.getElementById('opt-launch-at-login').addEventListener('click', async () => {
  const btn = document.getElementById('opt-launch-at-login');
  const isNowOn = !btn.classList.contains('on');
  setToggleState(btn, isNowOn);
  try {
    await invoke('fluxsync_set_launch_at_login', { value: isNowOn });
  } catch (err) {
    setToggleState(btn, !isNowOn);
    showToast(`Couldn't update preference: ${err}`);
  }
});

document.getElementById('btn-add-device').addEventListener('click', () => {
  invoke('fluxsync_open_pair');
});

document.getElementById('btn-reset-session').addEventListener('click', async () => {
  // `fluxsync_unpair` (unlike per-row `fluxsync_revoke_peer` in
  // `renderDevices`) wipes trust for EVERY paired device, not just one —
  // the confirm copy must say so plainly before the user commits to it.
  if (confirm('This will unpair ALL your devices and reset the session. Continue?')) {
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

document.getElementById('link-license').addEventListener('click', () => {
  invoke('fluxsync_open_url', { url: 'https://github.com/flowerpower584/fluxsync/blob/main/LICENSE-MIT' });
});

document.getElementById('link-author').addEventListener('click', () => {
  invoke('fluxsync_open_url', { url: 'https://github.com/flowerpower584' });
});

document.getElementById('btn-check-updates').addEventListener('click', () => {
  // QA #6/#7: don't claim a hardcoded (wrong) version or fake an update
  // check. Report the daemon's own version when known; FluxSync ships no
  // auto-updater by design — releases live on GitHub.
  const v = lastState && lastState.version ? ` (v${lastState.version})` : '';
  showToast(`FluxSync${v} has no auto-update — get releases from GitHub.`);
});

// ── Initialization ─────────────────────────────────────────────
(async () => {
  await refreshState();
  // Launch at login reflects real OS autostart state, not a cached pref.
  try {
    const enabled = await invoke('fluxsync_get_launch_at_login');
    setToggleState(document.getElementById('opt-launch-at-login'), !!enabled);
  } catch (e) {
    console.error('Failed to read launch-at-login state', e);
  }
  unlistenState = await listen('state-update', (event) => {
    lastState = event.payload;
    updateUI(event.payload);
  });
})();
setInterval(refreshState, 5000);
