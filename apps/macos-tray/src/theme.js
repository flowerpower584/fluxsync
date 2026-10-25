// Appearance bootstrap — a classic (non-module) script loaded in <head> of
// every window so `data-theme` is set before first paint (no dark→light
// flash). The preference ('dark' | 'light' | 'system') lives in
// localStorage, which all three windows share (same origin); the `storage`
// event keeps already-open windows in step when Settings changes it, and
// the media query keeps 'system' live when the OS appearance flips.
(function () {
  var KEY = 'fs.theme';
  var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;

  function pref() {
    try {
      var v = localStorage.getItem(KEY);
      return v === 'light' || v === 'system' ? v : 'dark';
    } catch (_) {
      return 'dark';
    }
  }

  function apply() {
    var p = pref();
    var resolved = p === 'system' ? (mq && mq.matches ? 'light' : 'dark') : p;
    var root = document.documentElement;
    root.setAttribute('data-theme', resolved);
    root.setAttribute('data-theme-pref', p);
  }

  apply();
  if (mq) {
    if (mq.addEventListener) mq.addEventListener('change', apply);
    else if (mq.addListener) mq.addListener(apply);
  }
  window.addEventListener('storage', function (e) {
    if (e.key === KEY) apply();
  });

  window.fsTheme = {
    get: pref,
    set: function (p) {
      try { localStorage.setItem(KEY, p); } catch (_) {}
      apply();
    },
  };
})();
