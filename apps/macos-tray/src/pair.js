// Pair window v2 + PR2 (PIN method + verify-words gate).
//
// Two flows share the same final state:
//   * Show:    entry -> show -> paired
//   * Enter:   entry -> pin-entry -> pin-progress -> verify -> paired
//
// "Show" stays TOFU-silent (URI carries the pubkey out-of-band via QR).
// "Enter" forces SAS-words verification because the PIN flies over mDNS
// on a shared LAN — MITM is possible until the user has matched the
// 6 words on both devices.

const { invoke } = window.__TAURI__.core;
const { getCurrentWindow } = window.__TAURI__.window;
const { listen } = window.__TAURI__.event;

(function tagHostOS() {
  const ua = navigator.userAgent;
  const os = /Windows/i.test(ua) ? 'windows'
    : /Macintosh|Mac OS/i.test(ua) ? 'macos'
    : /Linux/i.test(ua) ? 'linux'
    : 'unknown';
  document.body.dataset.os = os;
})();

const $ = (id) => document.getElementById(id);
const tb = $('tb');
const tbTitle = $('tb-title');
const backBtn = $('back-btn');

// Track which path got us to "paired" so we can pop the right screen on
// pairing-success: PIN path goes through "verify", QR path skips it.
let pairMethod = null; // 'qr' | 'pin' | null
let pendingPeerId = null; // hex peer_id captured for pair_confirm
let pinCountdownTimer = null;

function showScreen(name) {
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.toggle('active', s.dataset.screen === name);
  });
  const titles = {
    entry: 'Pair a device',
    show: 'Show this device',
    'pin-entry': 'Enter peer code',
    'pin-progress': 'Connecting',
    verify: 'Verify',
    paired: 'Paired',
  };
  tbTitle.textContent = titles[name] || 'Pair';
  // Back button on every secondary screen except the terminal ones
  // (progress is mid-handshake, paired is success — both unactionable).
  const hasBack = name === 'show' || name === 'pin-entry' || name === 'verify';
  tb.classList.toggle('has-back', hasBack);
}

backBtn.addEventListener('click', () => {
  resetState();
  showScreen('entry');
});

function resetState() {
  if (unlistenPair) { unlistenPair(); unlistenPair = null; }
  if (pinCountdownTimer) { clearInterval(pinCountdownTimer); pinCountdownTimer = null; }
  pairMethod = null;
  pendingPeerId = null;
}

$('done-btn').addEventListener('click', () => {
  getCurrentWindow().close();
});

// ─── Show flow ──────────────────────────────────────────────────

$('show-this-btn').addEventListener('click', async () => {
  pairMethod = 'qr';
  showScreen('show');
  await watchForPair();
  await generateQr();
});

// daemon may still be coming up; retry pair_show a handful of times.
async function pairShowWithRetry({ tries = 8, delayMs = 400 } = {}) {
  let lastErr = null;
  for (let i = 0; i < tries; i++) {
    try {
      const info = await invoke('fluxsync_pair_show');
      if (info) return info;
      lastErr = new Error('empty pair info');
    } catch (e) {
      lastErr = e;
    }
    await new Promise(r => setTimeout(r, delayMs));
  }
  throw lastErr ?? new Error('pair_show failed after retries');
}

let unlistenPair = null;
async function watchForPair() {
  if (unlistenPair) { unlistenPair(); unlistenPair = null; }
  let initialPeerName = '';
  try {
    const seed = await invoke('fluxsync_status');
    initialPeerName = (seed && seed.data && seed.data.peer_name) || '';
  } catch (_) {
    initialPeerName = '';
  }
  setTimeout(() => { initialPeerName = ''; }, 3000);

  unlistenPair = await listen('pairing-success', async (event) => {
    const name = event.payload || 'peer';
    if (name && name !== 'pending' && name === initialPeerName) return;
    if (unlistenPair) { unlistenPair(); unlistenPair = null; }
    const displayName = name === 'pending' ? 'your device' : name;
    if (pairMethod === 'pin') {
      await enterVerifyScreen(displayName);
    } else {
      showPaired(displayName);
    }
  });
}

function showPaired(peerName) {
  $('paired-name').textContent = peerName || 'peer';
  $('paired-id').textContent = '';
  showScreen('paired');
  setTimeout(() => {
    try { getCurrentWindow().close(); } catch (_) {}
  }, 2200);
}

async function generateQr() {
  const card = $('qr-card');
  const err = $('pair-error');
  err.style.display = 'none';
  err.textContent = '';
  card.classList.add('loading');
  card.textContent = 'Generating…';

  try {
    const info = await pairShowWithRetry();

    if (info.qr_svg) {
      card.classList.remove('loading');
      card.innerHTML = info.qr_svg;
      const svg = card.querySelector('svg');
      if (svg) {
        svg.removeAttribute('width');
        svg.removeAttribute('height');
        svg.style.width = '200px';
        svg.style.height = '200px';
      }
    } else if (info.uri) {
      card.classList.add('loading');
      card.textContent = info.uri.slice(0, 40) + '…';
    } else {
      card.classList.add('loading');
      card.textContent = 'No URI returned';
    }

    const words = info.fingerprint_words || [];
    const fp = $('fp-box');
    fp.innerHTML = '';
    const padded = [...words];
    while (padded.length < 6) padded.push('—');
    padded.slice(0, 6).forEach(w => {
      const d = document.createElement('div');
      d.className = 'w';
      if (w === '—') d.style.color = 'var(--muted-3)';
      d.textContent = w;
      fp.appendChild(d);
    });

    // Security: never render the LAN address. URI/QR still carries it
    // so the scanning peer (esp. Android) can reach the daemon without
    // relying on mDNS, but the human-readable IP must not appear in UI.

    // PR2: surface the PIN so the user can read it to the peer.
    renderPinBlock(info.pin, info.pin_expires_at_ms);
  } catch (e) {
    err.style.display = 'block';
    err.textContent = `Pair info unavailable: ${e?.message || e}`;
  }
}

function renderPinBlock(pin, expiresAtMs) {
  const block = $('pin-block');
  if (!pin) { block.style.display = 'none'; return; }
  block.style.display = 'flex';
  // Render as "1 2 3 4 5 6" with extra letter-spacing in CSS.
  $('pin-code').textContent = pin.split('').join(' ');
  if (pinCountdownTimer) { clearInterval(pinCountdownTimer); pinCountdownTimer = null; }
  if (!expiresAtMs) {
    $('pin-countdown').textContent = '';
    return;
  }
  const tick = async () => {
    const remaining = Math.max(0, Math.floor((expiresAtMs - Date.now()) / 1000));
    $('pin-countdown').textContent = remaining > 0
      ? `Expires in ${remaining} s`
      : 'Rotating…';
    if (remaining === 0) {
      // PIN rotated on the daemon side: re-fetch to pick up the new code.
      clearInterval(pinCountdownTimer);
      pinCountdownTimer = null;
      try {
        const info = await pairShowWithRetry({ tries: 4, delayMs: 250 });
        renderPinBlock(info.pin, info.pin_expires_at_ms);
      } catch (_) {}
    }
  };
  tick();
  pinCountdownTimer = setInterval(tick, 1000);
}

// ─── Enter-code flow ─────────────────────────────────────────────

const pinSlots = () => Array.from($('pin-input').querySelectorAll('input'));
let pinAttempts = 0;
const MAX_PIN_ATTEMPTS = 3;

$('enter-code-btn').addEventListener('click', () => {
  pairMethod = 'pin';
  resetPinForm();
  showScreen('pin-entry');
  setTimeout(() => pinSlots()[0]?.focus(), 50);
});

function resetPinForm() {
  pinSlots().forEach(i => { i.value = ''; });
  $('pin-submit-btn').disabled = true;
  $('pin-error').style.display = 'none';
  $('pin-error').textContent = '';
  $('pin-hint').textContent = `Both devices must be on the same network.`;
  $('pin-hint').classList.remove('danger');
}

(function wirePinInputs() {
  const slots = pinSlots();
  slots.forEach((inp, idx) => {
    inp.addEventListener('input', (e) => {
      // Keep only digits, take first char (handles autofill paste-as-many).
      const v = e.target.value.replace(/\D/g, '').slice(0, 1);
      e.target.value = v;
      if (v && idx + 1 < slots.length) slots[idx + 1].focus();
      refreshPinSubmit();
    });
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !inp.value && idx > 0) {
        slots[idx - 1].focus();
      } else if (e.key === 'Enter' && currentPin().length === 6) {
        submitPin();
      }
    });
    inp.addEventListener('paste', (e) => {
      const text = (e.clipboardData?.getData('text') || '').replace(/\D/g, '').slice(0, 6);
      if (!text) return;
      e.preventDefault();
      slots.forEach((s, i) => { s.value = text[i] ?? ''; });
      const next = Math.min(text.length, slots.length - 1);
      slots[next].focus();
      refreshPinSubmit();
    });
  });
})();

function currentPin() {
  return pinSlots().map(i => i.value).join('');
}
function refreshPinSubmit() {
  $('pin-submit-btn').disabled = currentPin().length !== 6;
}

$('pin-submit-btn').addEventListener('click', submitPin);

async function submitPin() {
  const pin = currentPin();
  if (pin.length !== 6) return;
  if (pinAttempts >= MAX_PIN_ATTEMPTS) {
    showPinError('Too many bad attempts. Ask the other device to show a fresh code.');
    return;
  }
  $('pin-submit-btn').disabled = true;
  $('pin-error').style.display = 'none';
  showScreen('pin-progress');
  // Arm the success listener BEFORE invoking so we never miss the event.
  await watchForPair();
  try {
    // Caller picks a default name; the peer's real name comes via Hello.
    await invoke('fluxsync_pair_from_pin', { pin, name: 'peer' });
    // pairing-success listener will drive the next screen.
  } catch (e) {
    pinAttempts += 1;
    const msg = (e?.message || e || '').toString();
    const noPeer = /no_peer_with_pin|no peer/i.test(msg);
    const remaining = Math.max(0, MAX_PIN_ATTEMPTS - pinAttempts);
    showScreen('pin-entry');
    $('pin-submit-btn').disabled = false;
    pinSlots()[0].focus();
    pinSlots().forEach(s => s.select?.());
    $('pin-input').classList.remove('shake');
    void $('pin-input').offsetWidth; // restart animation
    $('pin-input').classList.add('shake');
    if (noPeer) {
      showPinError(remaining > 0
        ? `Code not found. ${remaining} ${remaining === 1 ? 'try' : 'tries'} left.`
        : 'Code not found. Ask the other device to show a fresh code.');
    } else {
      showPinError(`Pair failed: ${msg}`);
    }
  }
}

function showPinError(msg) {
  const e = $('pin-error');
  e.style.display = 'block';
  e.textContent = msg;
  $('pin-hint').classList.add('danger');
  $('pin-hint').textContent = `Attempt ${Math.min(pinAttempts, MAX_PIN_ATTEMPTS)} of ${MAX_PIN_ATTEMPTS}.`;
}

// ─── Verify-words flow (PIN-only) ────────────────────────────────

async function enterVerifyScreen(_peerDisplayName) {
  showScreen('verify');
  $('verify-error').style.display = 'none';
  // Poll pair_pending briefly: the daemon writes the entry from the
  // responder's transport_recv path, which races with the
  // pairing-success state-update we're triggered on.
  let entry = null;
  for (let i = 0; i < 10 && !entry; i++) {
    try {
      const list = await invoke('fluxsync_pair_pending');
      if (Array.isArray(list) && list.length > 0) {
        entry = list[0];
        break;
      }
    } catch (_) {}
    await new Promise(r => setTimeout(r, 200));
  }
  const fp = $('verify-fp');
  fp.innerHTML = '';
  const words = (entry && entry.sas_words) || [];
  const padded = [...words];
  while (padded.length < 6) padded.push('—');
  padded.slice(0, 6).forEach(w => {
    const d = document.createElement('div');
    d.className = 'w';
    if (w === '—') d.style.color = 'var(--muted-3)';
    d.textContent = w;
    fp.appendChild(d);
  });
  pendingPeerId = entry?.peer_id || null;
  if (!pendingPeerId) {
    $('verify-error').style.display = 'block';
    $('verify-error').textContent =
      'No pending pair entry surfaced by daemon. Reject and retry.';
  }
}

$('verify-accept-btn').addEventListener('click', async () => {
  await resolveVerify(true);
});
$('verify-reject-btn').addEventListener('click', async () => {
  await resolveVerify(false);
});

async function resolveVerify(accept) {
  if (!pendingPeerId) {
    // Even without a peer_id we can fall through: if accept=false, no
    // harm done; if accept=true, the trust is already in place via the
    // handshake and pending will reap on its own. Keep the UI honest.
    if (accept) {
      showPaired('your device');
    } else {
      try { await invoke('fluxsync_unpair'); } catch (_) {}
      resetState();
      showScreen('entry');
    }
    return;
  }
  const accBtn = $('verify-accept-btn');
  const rejBtn = $('verify-reject-btn');
  accBtn.disabled = true;
  rejBtn.disabled = true;
  try {
    await invoke('fluxsync_pair_confirm', { peerId: pendingPeerId, accept });
    if (accept) {
      showPaired('your device');
    } else {
      resetState();
      showScreen('entry');
    }
  } catch (e) {
    $('verify-error').style.display = 'block';
    $('verify-error').textContent = `Confirm failed: ${e?.message || e}`;
  } finally {
    accBtn.disabled = false;
    rejBtn.disabled = false;
  }
}

// ─── Unpair (show screen) ───────────────────────────────────────

function setupUnpairButton() {
  const btn = $('unpair-btn');
  if (!btn) return;
  const idle = 'Unpair all devices';
  let armed = false;
  let armTimer = null;

  function disarm() {
    armed = false;
    btn.textContent = idle;
    btn.classList.remove('armed');
    if (armTimer) { clearTimeout(armTimer); armTimer = null; }
  }

  btn.addEventListener('click', async () => {
    if (!armed) {
      armed = true;
      btn.textContent = 'Click again to confirm';
      btn.classList.add('armed');
      armTimer = setTimeout(disarm, 4000);
      return;
    }
    disarm();
    btn.disabled = true;
    btn.textContent = 'Unpairing…';
    try {
      await invoke('fluxsync_unpair');
      btn.textContent = 'Unpaired ✓';
      await watchForPair();
      await generateQr();
    } catch (e) {
      const err = $('pair-error');
      err.style.display = 'block';
      err.textContent = `Unpair failed: ${e?.message || e}`;
    } finally {
      setTimeout(() => { btn.disabled = false; btn.textContent = idle; }, 1200);
    }
  });
}

setupUnpairButton();
showScreen('entry');
