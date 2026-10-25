// FluxSync Settings window logic.
import {
  tagHostOS, OS_DEVICE_WORD, PLATFORM_LABELS, isRealPeerName, peerIdHex,
  batteryKnown, setText, setAttr, showToast, confirmDialog,
} from './ui.js';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const $ = (id) => document.getElementById(id);

const HOST_OS = tagHostOS();
setText($('general-subtitle'), `On this ${OS_DEVICE_WORD[HOST_OS] || 'device'}.`);

let currentTab = 'general';
let lastState = null;

async function refreshState() {
  try {
    const resp = await invoke('fluxsync_status');
    const s = resp && resp.data ? resp.data : null;
    if (s) {
      lastState = s;
      updateUI(s);
    }
    setOnline(true);
  } catch (e) {
    setOnline(false);
  }
}

// DIR-P3-03: surface daemon-unreachable instead of swallowing it — same
// show/clear behavior as the tray popup's "Daemon offline" state.
function setOnline(up) {
  $('offline-banner').hidden = up;
  const st = $('side-status');
  st.classList.toggle('up', up);
  st.classList.toggle('down', !up);
  setText($('side-status-text'), up ? 'Service running' : 'Service offline');
}

// DIR-P3-06: keep `aria-checked` in lockstep with the visual `.on` class on
// every `role="switch"` toggle — the class alone is invisible to AT.
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
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
  if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`;
  return `${s}s`;
}

const slider = $('threshold-slider');
let sliderDragging = false;
function paintSlider(value) {
  const min = Number(slider.min);
  const max = Number(slider.max);
  slider.style.setProperty('--fill', `${((value - min) / (max - min)) * 100}%`);
  setText($('threshold-display'), `${value}%`);
}

function updateUI(s) {
  // Device name: skip while the field is focused so a state push doesn't
  // stomp what the user is mid-typing.
  const nameInput = $('device-name-input');
  if (document.activeElement !== nameInput && nameInput.value !== (s.device_name || '')) {
    nameInput.value = s.device_name || '';
  }

  // Threshold: never yank the thumb out from under a drag.
  const threshold = s.battery_threshold || 20;
  if (!sliderDragging && Number(slider.value) !== threshold) {
    slider.value = threshold;
    paintSlider(threshold);
  }

  setToggleState($('opt-resume-on-charge'), !!s.charge_override);

  if (s.version) {
    setText($('side-version'), `v${s.version}`);
    const build = s.build_id && s.build_id !== 'unknown' ? ` · build ${s.build_id}` : '';
    setText($('about-version'), `Version ${s.version}${build}`);
  }

  // Network pane — everything from `s.metrics` when present.
  const m = s.metrics || null;
  setText($('metric-rtt'), m && m.last_rtt_ms ? `${m.last_rtt_ms} ms` : '—');
  setText($('metric-rtt-p99'), m && m.rtt_p99_ms ? `${m.rtt_p99_ms} ms` : '—');
  setText($('metric-items'), m ? `${m.items_sent ?? 0} / ${m.items_received ?? 0}` : '—');
  setText($('metric-dups'), m ? `${m.dedup_drops ?? 0}` : '—');
  setText($('metric-reconnects'), m ? `${m.reconnects ?? 0}` : '—');
  setText($('metric-hs-failed'), m ? `${m.handshakes_failed ?? 0}` : '—');
  setText($('metric-uptime'), m ? fmtUptime(m.uptime_session_secs) : '—');
  const mdns = s.mdns_enabled !== false;
  const pill = $('mdns-pill');
  setText(pill, mdns ? 'ON' : 'OFF');
  pill.className = 'pill ' + (mdns ? 'ok' : 'warn');

  renderDevices(s);
}

// Friendlier stand-in for a peer whose Hello hasn't landed yet, so this
// pane never surfaces the raw "New Peer"/"pending" bookkeeping values.
const PLATFORM_FRIENDLY = {
  macos: 'a Mac', windows: 'a PC', linux: 'a Linux device',
  android: 'an Android phone', ios: 'an iPhone',
};
function friendlyDeviceName(name, platform) {
  if (isRealPeerName(name)) return name.trim();
  const label = PLATFORM_FRIENDLY[(platform || '').toLowerCase()];
  return label ? `Pairing with ${label}…` : 'Pairing…';
}

const ICON_PHONE = '<svg width="13" height="18" viewBox="0 0 11 16" fill="none" stroke="currentColor" stroke-width="1.15"><rect x="0.5" y="0.5" width="10" height="15" rx="2"/><circle cx="5.5" cy="13" r="0.7" fill="currentColor" stroke="none"/></svg>';
const ICON_COMPUTER = '<svg width="19" height="16" viewBox="0 0 16 14" fill="none" stroke="currentColor" stroke-width="1.15"><rect x="0.5" y="0.5" width="15" height="10" rx="1.5"/><path d="M5 13h6M8 10.5V13" stroke-linecap="round"/></svg>';

// H-TRAY-01: `name`/`platform` are attacker-controlled (the peer's
// self-reported Hello data). NEVER interpolate them into innerHTML — build
// every row with the DOM API + textContent.
function buildDeviceRow({ name, platform, platformKey, battery, charging, connected, primary, onUnpair }) {
  const item = document.createElement('div');
  item.className = 'device-item';

  const icon = document.createElement('div');
  icon.className = 'd-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.innerHTML = (platformKey === 'android' || platformKey === 'ios') ? ICON_PHONE : ICON_COMPUTER;

  const info = document.createElement('div');
  info.className = 'd-info';
  const nameRow = document.createElement('div');
  nameRow.className = 'name-row';
  const nameEl = document.createElement('span');
  nameEl.className = 'name';
  nameEl.textContent = name;
  nameEl.title = name;
  const status = document.createElement('span');
  status.className = 'status' + (connected ? ' on' : '');
  status.textContent = connected ? 'CONNECTED' : 'OFFLINE';
  nameRow.append(nameEl, status);

  const meta = document.createElement('div');
  meta.className = 'meta';
  // 255 / missing / >100 = no real battery reading yet → never a fake %.
  const bits = [];
  if (platform) bits.push(platform);
  if (batteryKnown(battery)) bits.push(`${battery}%${charging ? ' ⚡ charging' : ''}`);
  if (primary) bits.push('primary link');
  meta.textContent = bits.join(' · ') || '—';
  info.append(nameRow, meta);

  const btn = document.createElement('button');
  btn.className = 'btn danger sm';
  btn.textContent = 'Unpair';
  btn.addEventListener('click', onUnpair);

  item.append(icon, info, btn);
  return item;
}

async function confirmUnpair(displayName) {
  return confirmDialog({
    title: `Unpair ${displayName}?`,
    message: "It's disconnected and forgotten. You'll have to pair again to sync with it.",
    confirmLabel: 'Unpair',
    danger: true,
  });
}

// FluxMesh: render every linked peer from `s.peers`. Falls back to the
// legacy `peer_name`/`peer_battery` projection only when `peers` is empty
// but a real (non-placeholder) legacy peer is projected — keeps this pane
// working against an older daemon build. Rebuilt only when something
// visible changed, so state pushes never steal focus from a button.
let devicesSig = null;
function renderDevices(s) {
  const peers = Array.isArray(s.peers) ? s.peers : [];
  const legacy = peers.length === 0 && isRealPeerName(s.peer_name);
  const sig = peers.length
    ? peers.map((p) => [peerIdHex(p.peer_id), p.name, p.platform, p.battery, p.charging, p.primary].join('|')).join('\n')
    : (legacy ? ['legacy', s.peer_name, s.peer_platform, s.peer_battery, s.peer_charging, s.status].join('|') : 'none');
  if (sig === devicesSig) return;
  devicesSig = sig;

  const count = peers.length || (legacy ? 1 : 0);
  const countEl = $('tab-devices-count');
  countEl.hidden = count === 0;
  setText(countEl, String(count));

  const list = $('device-list');
  if (peers.length > 0) {
    list.replaceChildren(...peers.map((p) => {
      const hex = peerIdHex(p.peer_id);
      const key = (p.platform || '').toLowerCase();
      const displayName = friendlyDeviceName(p.name, p.platform);
      return buildDeviceRow({
        name: displayName,
        platform: PLATFORM_LABELS[key] || '',
        platformKey: key,
        battery: p.battery,
        charging: !!p.charging,
        // `s.peers` is rebuilt from the live session set at every
        // `EmitState` (see `driver::build_peers`) — every entry is connected.
        connected: true,
        primary: peers.length > 1 && !!p.primary,
        onUnpair: async () => {
          if (!hex || !(await confirmUnpair(displayName))) return;
          try {
            await invoke('fluxsync_revoke_peer', { peerId: hex });
            showToast('Device unpaired', 'ok');
            refreshState();
          } catch (err) {
            showToast(`Unpair failed: ${err}`, 'err');
          }
        },
      });
    }));
    return;
  }

  if (!legacy) {
    const empty = document.createElement('div');
    empty.className = 'device-empty';
    empty.textContent = 'No devices paired yet.';
    list.replaceChildren(empty);
    return;
  }

  const key = (s.peer_platform || '').toLowerCase();
  list.replaceChildren(buildDeviceRow({
    name: s.peer_name.trim(),
    platform: PLATFORM_LABELS[key] || '',
    platformKey: key,
    battery: s.peer_battery,
    charging: !!s.peer_charging,
    connected: s.status === 'syncing' || s.status === 'paused',
    primary: false,
    onUnpair: async () => {
      if (!(await confirmUnpair(s.peer_name.trim()))) return;
      try {
        await invoke('fluxsync_unpair');
        showToast('Device unpaired', 'ok');
        refreshState();
      } catch (err) {
        showToast(`Unpair failed: ${err}`, 'err');
      }
    },
  }));
}

// ── Tabs ────────────────────────────────────────────────────────
const TAB_ORDER = ['general', 'devices', 'network', 'about'];
function switchTab(tabId, focus) {
  if (!TAB_ORDER.includes(tabId)) return;
  currentTab = tabId;
  document.querySelectorAll('.tab-btn').forEach((b) => {
    const active = b.dataset.tab === tabId;
    b.classList.toggle('active', active);
    b.setAttribute('aria-selected', active ? 'true' : 'false');
    // DIR-P3-06: roving tabindex — only the active tab sits in Tab order.
    b.tabIndex = active ? 0 : -1;
    if (active && focus) b.focus();
  });
  document.querySelectorAll('.pane').forEach((p) => {
    p.hidden = p.id !== `pane-${tabId}`;
  });
  $('pane-content').scrollTop = 0;
}

document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

// DIR-P3-06: WAI-ARIA tabs keyboard pattern — arrows move focus and
// activate; Home/End jump to the ends.
document.querySelector('.tabs').addEventListener('keydown', (e) => {
  const idx = TAB_ORDER.indexOf(currentTab);
  let next = null;
  if (e.key === 'ArrowDown' || e.key === 'ArrowRight') next = TAB_ORDER[(idx + 1) % TAB_ORDER.length];
  else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') next = TAB_ORDER[(idx - 1 + TAB_ORDER.length) % TAB_ORDER.length];
  else if (e.key === 'Home') next = TAB_ORDER[0];
  else if (e.key === 'End') next = TAB_ORDER[TAB_ORDER.length - 1];
  if (!next) return;
  e.preventDefault();
  switchTab(next, true);
});

// Deep link from the tray popup ("Devices ›"): it writes the wanted tab to
// localStorage just before showing this (already loaded, hidden) window.
const TAB_LINK_KEY = 'fs.settingsTab';
function consumeTabLink(raw) {
  try {
    const v = JSON.parse(raw || 'null');
    if (v && v.tab && Date.now() - (v.at || 0) < 10_000) switchTab(v.tab);
  } catch (_) {}
}
window.addEventListener('storage', (e) => {
  if (e.key === TAB_LINK_KEY && e.newValue) consumeTabLink(e.newValue);
});
try { consumeTabLink(localStorage.getItem(TAB_LINK_KEY)); } catch (_) {}

// ── Controls ────────────────────────────────────────────────────
slider.addEventListener('pointerdown', () => { sliderDragging = true; });
window.addEventListener('pointerup', () => { sliderDragging = false; });
slider.addEventListener('input', () => paintSlider(Number(slider.value)));
slider.addEventListener('change', async () => {
  sliderDragging = false;
  const val = parseInt(slider.value, 10);
  const prev = lastState ? (lastState.battery_threshold || 20) : 20;
  try {
    await invoke('fluxsync_set_threshold', { value: val });
  } catch (err) {
    slider.value = prev;
    paintSlider(prev);
    showToast(`Couldn't update threshold: ${err}`, 'err');
  }
});

// DIR-P3-01: save on blur (native `change` semantics), Enter commits too.
const nameInput = $('device-name-input');
nameInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') nameInput.blur();
  if (e.key === 'Escape') {
    nameInput.value = lastState ? (lastState.device_name || '') : '';
    nameInput.blur();
  }
});
nameInput.addEventListener('input', () => nameInput.classList.remove('error'));
nameInput.addEventListener('change', async () => {
  const val = nameInput.value.trim();
  const prev = lastState ? (lastState.device_name || '') : '';
  if (val === prev) return;
  if (!val) {
    nameInput.value = prev;
    showToast("Device name can't be empty", 'err');
    return;
  }
  try {
    await invoke('fluxsync_set_device_name', { name: val });
    showToast('Device name updated — peers see it on their next connection', 'ok');
  } catch (err) {
    nameInput.value = prev;
    nameInput.classList.add('error');
    showToast(`Couldn't rename device: ${err}`, 'err');
  }
});

async function flipSwitch(btn, command) {
  const isNowOn = !btn.classList.contains('on');
  setToggleState(btn, isNowOn);
  try {
    await invoke(command, { value: isNowOn });
  } catch (err) {
    setToggleState(btn, !isNowOn);
    showToast(`Couldn't update preference: ${err}`, 'err');
  }
}
$('opt-resume-on-charge').addEventListener('click', (e) => flipSwitch(e.currentTarget, 'fluxsync_set_charge_override'));
$('opt-launch-at-login').addEventListener('click', (e) => flipSwitch(e.currentTarget, 'fluxsync_set_launch_at_login'));

// Appearance — stored by theme.js, shared live with every window.
const themeSeg = $('theme-seg');
function paintTheme() {
  const pref = window.fsTheme ? window.fsTheme.get() : 'dark';
  for (const b of themeSeg.querySelectorAll('button')) {
    const on = b.dataset.themeChoice === pref;
    setAttr(b, 'aria-checked', String(on));
    b.tabIndex = on ? 0 : -1;
  }
}
themeSeg.addEventListener('click', (e) => {
  const b = e.target.closest('button[data-theme-choice]');
  if (!b || !window.fsTheme) return;
  window.fsTheme.set(b.dataset.themeChoice);
  paintTheme();
});
themeSeg.addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
  const btns = [...themeSeg.querySelectorAll('button')];
  const idx = btns.findIndex((b) => b.getAttribute('aria-checked') === 'true');
  const next = btns[(idx + (e.key === 'ArrowRight' ? 1 : -1) + btns.length) % btns.length];
  e.preventDefault();
  next.click();
  next.focus();
});
window.addEventListener('storage', (e) => { if (e.key === 'fs.theme') paintTheme(); });
paintTheme();

$('btn-add-device').addEventListener('click', () => invoke('fluxsync_open_pair'));

$('btn-reset-session').addEventListener('click', async () => {
  // `fluxsync_unpair` (unlike per-row `fluxsync_revoke_peer`) wipes trust
  // for EVERY paired device — the copy must say so plainly.
  const ok = await confirmDialog({
    title: 'Reset all pairings?',
    message: 'Every paired device is unpaired and the session is reset. A fresh QR code opens so you can pair again.',
    confirmLabel: 'Reset everything',
    danger: true,
  });
  if (!ok) return;
  try {
    await invoke('fluxsync_unpair');
    await new Promise((r) => setTimeout(r, 100));
    await invoke('fluxsync_open_pair');
    showToast('Session reset', 'ok');
    refreshState();
  } catch (err) {
    showToast(`Reset failed: ${err}`, 'err');
  }
});

const REPO = 'https://github.com/flowerpower584/fluxsync';
$('link-license').addEventListener('click', () => invoke('fluxsync_open_url', { url: `${REPO}/blob/main/LICENSE-MIT` }));
$('link-author').addEventListener('click', () => invoke('fluxsync_open_url', { url: 'https://github.com/flowerpower584' }));
// QA #6/#7: no fake update check. FluxSync ships no auto-updater by design —
// open the releases page so the user can compare with the version above.
$('btn-check-updates').addEventListener('click', () => invoke('fluxsync_open_url', { url: `${REPO}/releases/latest` }));

// Settings has no menu bar, so wire the usual close shortcut.
document.addEventListener('keydown', (e) => {
  if (document.querySelector('.fs-scrim')) return;
  const mod = e.metaKey || e.ctrlKey;
  if (mod && e.key.toLowerCase() === 'w') {
    e.preventDefault();
    window.__TAURI__.window.getCurrentWindow().close();
  }
});

// ── Initialization ─────────────────────────────────────────────
paintSlider(Number(slider.value));
(async () => {
  await refreshState();
  // Launch at login reflects real OS autostart state, not a cached pref.
  try {
    setToggleState($('opt-launch-at-login'), !!(await invoke('fluxsync_get_launch_at_login')));
  } catch (_) { /* leave it off */ }
  await listen('state-update', (event) => {
    lastState = event.payload;
    setOnline(true);
    updateUI(event.payload);
  });
})();
// Safety poll: the network counters keep moving even when no event fires.
setInterval(() => { if (!document.hidden) refreshState(); }, 5000);
