// Shared UI helpers for the three desktop windows. Each window used to
// carry its own copy of the toast, host-OS sniffing and peer-id helpers;
// they live here once now.

export const IS_MAC = /Macintosh|Mac OS/i.test(navigator.userAgent);

// Tag <body> with the host OS so CSS can paint per-platform details and
// return it for copy ("This Mac" vs "This PC").
export function tagHostOS() {
  const ua = navigator.userAgent;
  const os = /Windows/i.test(ua) ? 'windows'
    : /Macintosh|Mac OS/i.test(ua) ? 'macos'
    : /Linux/i.test(ua) ? 'linux'
    : 'unknown';
  document.body.dataset.os = os;
  return os;
}

export const OS_NAMES = { windows: 'Windows', macos: 'macOS', linux: 'Linux' };
export const OS_DEVICE_WORD = { windows: 'PC', macos: 'Mac', linux: 'Linux' };
export const PLATFORM_LABELS = {
  macos: 'macOS', windows: 'Windows', linux: 'Linux', android: 'Android', ios: 'iOS',
};

// TOFU placeholder the daemon projects into `peer_name` between handshake
// completion and the `Msg::Hello` that carries the peer's real device name
// (see `fluxsyncd::handshake::TOFU_PLACEHOLDER_NAME`). Never a real identity.
export const TOFU_PLACEHOLDER = 'New Peer';

export function isRealPeerName(name) {
  const n = (name || '').trim();
  return !!n && n !== 'pending' && n !== TOFU_PLACEHOLDER;
}

// peer_id rides the State DTO as a 32-byte array (serde `[u8;32]`); the
// daemon `revoke` op wants the full hex string. Returns '' if malformed.
export function peerIdHex(id) {
  if (!Array.isArray(id) || id.length !== 32) return '';
  return id.map((b) => (b & 0xff).toString(16).padStart(2, '0')).join('');
}

// 255 / null / >100 = the daemon has no real reading yet (or the host has
// no battery at all — most desktops). Never render those as a percentage.
export function batteryKnown(level) {
  return typeof level === 'number' && level >= 0 && level <= 100;
}

// Write only when the value actually changes: state pushes arrive every
// few seconds and most fields are unchanged, so skipping no-op writes
// avoids needless style invalidation.
export function setText(el, text) {
  if (el && el.textContent !== text) el.textContent = text;
}
export function setAttr(el, name, value) {
  if (el && el.getAttribute(name) !== value) el.setAttribute(name, value);
}

// Toast singleton — slide-in bottom, auto-dismiss. Re-uses one DOM node
// so rapid messages collapse into one. `tone` = 'ok' | 'err' | undefined.
let toastTimer = null;
export function showToast(message, tone) {
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
  el.classList.remove('ok', 'err');
  if (tone) el.classList.add(tone);
  // Force a reflow so a toast re-shown while visible restarts its slide.
  void el.offsetWidth;
  el.classList.add('visible');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('visible'), tone === 'err' ? 4200 : 2600);
}

// In-app confirmation sheet, styled like the rest of the app (the native
// `confirm()` reads "tauri.localhost says…" on Windows and can't be
// themed). Resolves true on confirm, false on cancel / Esc / backdrop.
// Built with textContent only — callers pass peer names through here.
export function confirmDialog({ title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false }) {
  return new Promise((resolve) => {
    const previouslyFocused = document.activeElement;
    const scrim = document.createElement('div');
    scrim.className = 'fs-scrim';
    const dialog = document.createElement('div');
    dialog.className = 'fs-dialog';
    dialog.setAttribute('role', 'alertdialog');
    dialog.setAttribute('aria-modal', 'true');
    const h = document.createElement('h2');
    h.id = 'fs-dialog-title';
    h.textContent = title;
    dialog.setAttribute('aria-labelledby', h.id);
    const p = document.createElement('p');
    p.id = 'fs-dialog-msg';
    p.textContent = message;
    dialog.setAttribute('aria-describedby', p.id);
    const actions = document.createElement('div');
    actions.className = 'actions';
    const cancel = document.createElement('button');
    cancel.className = 'btn ghost';
    cancel.textContent = cancelLabel;
    const ok = document.createElement('button');
    ok.className = danger ? 'btn danger solid' : 'btn flux';
    ok.textContent = confirmLabel;
    actions.append(cancel, ok);
    dialog.append(h, p, actions);
    scrim.append(dialog);
    document.body.append(scrim);
    requestAnimationFrame(() => scrim.classList.add('visible'));
    // Destructive actions default-focus Cancel so a stray Enter is safe.
    (danger ? cancel : ok).focus();

    let done = false;
    function close(result) {
      if (done) return;
      done = true;
      document.removeEventListener('keydown', onKey, true);
      scrim.classList.remove('visible');
      setTimeout(() => scrim.remove(), 180);
      if (previouslyFocused && previouslyFocused.focus) previouslyFocused.focus();
      resolve(result);
    }
    function onKey(e) {
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(false); }
      else if (e.key === 'Tab') {
        // Two-button focus trap.
        e.preventDefault();
        (document.activeElement === ok ? cancel : ok).focus();
      }
    }
    document.addEventListener('keydown', onKey, true);
    cancel.addEventListener('click', () => close(false));
    ok.addEventListener('click', () => close(true));
    scrim.addEventListener('mousedown', (e) => { if (e.target === scrim) close(false); });
  });
}
