/* login.js — the sign-in page (login.html). The ThreatSim server (server.py) checks the password. */
(function () {
  'use strict';

  const $ = sel => document.querySelector(sel);
  const form = $('#signInForm');
  const button = $('#signInButton');
  const error = $('#signInError');
  const status = $('#signInStatus');
  const showPassword = $('#showPassword');
  const fields = { username: form.username, password: form.password };
  const PAGES = ['index.html', 'simulator.html'];
  const PAUSE_KEY = 'threatsim.signin.pause';   // sessionStorage: a sign-in pause, across reloads
  const LOCK_MAX = 15 * 60;                     // the longest pause the server gives (seconds)
  const params = new URLSearchParams(location.search);
  const next = PAGES.includes(params.get('next')) ? params.get('next') : '';
  let lockTimer = null;
  let lock = null;   // { user, end }: the server paused sign-in for this username until end (performance.now())
  let submitting = false;   // a sign-in request is on its way: leave the button alone

  const NO_SERVER = "Sign-in needs the ThreatSim server, and this page isn't coming from it. In the ThreatSim "
    + 'folder, run python3 server.py, then open the address it prints.';
  const OFFLINE = "Can't reach the ThreatSim server just now. Check that it's running, then try again.";
  const ORIGIN = "The server turned the sign-in down because the request didn't come from its own address. "
    + 'Reload the page and try again. (Behind a reverse proxy, the proxy must pass on the Host header.)';
  const NO_COOKIE = "You signed in, but this browser didn't keep the sign-in cookie. Allow cookies for this site "
    + 'and try again. (Behind a reverse proxy, X-Forwarded-Proto must match how the site is opened.)';
  const ENDED = {
    expired: 'Your session ended after 12 hours without use. Sign in again to continue.',
    signedout: 'You have been signed out.',
    password: 'The password was changed, so you need to sign in again.',
    notchanged: 'Your session ended before the password could be changed, so it was not changed. '
      + 'Sign in with your current password.',
    ended: 'Your session has ended. Sign in again to continue.',
  };
  const own = (obj, key) => key !== null && Object.prototype.hasOwnProperty.call(obj, key);

  function showError(message, field) {
    error.textContent = message;
    error.hidden = false;
    for (const [name, input] of Object.entries(fields)) {
      if (name === field) {
        input.setAttribute('aria-invalid', 'true');
        input.setAttribute('aria-describedby', error.id);
      } else {
        input.removeAttribute('aria-invalid');
        input.removeAttribute('aria-describedby');
      }
    }
  }

  function clearError() {
    error.hidden = true;
    error.textContent = '';
    for (const input of Object.values(fields)) {
      input.removeAttribute('aria-invalid');
      input.removeAttribute('aria-describedby');
    }
  }

  /** Keep keyboard focus in the form when the button it was on gets disabled. */
  function keepFocus() {
    const active = document.activeElement;
    if (!active || active === document.body || active === button) fields.password.focus();
  }

  const store = (fn, fallback) => { try { return fn(); } catch (_) { return fallback; } };   // storage may be blocked

  const userKey = name => String(name || '').trim().toLowerCase();   // close to the server's NFKC + casefold

  /**
   * After too many failed attempts the server pauses sign-in for that username (from this address). The
   * button waits while the username field still holds it; another username can be tried at once. The
   * message is announced once; the countdown is on the button, so screen readers don't repeat it.
   */
  function showLock(seconds, user, save = true) {
    clearInterval(lockTimer);
    lock = { user: userKey(user), end: performance.now() + seconds * 1000 };   // monotonic: system clock changes don't matter
    if (save) store(() => sessionStorage.setItem(PAUSE_KEY, JSON.stringify({ user: lock.user, start: Date.now(), wait: seconds })));
    keepFocus();
    showError(`Too many failed attempts. Sign-in as ${user.trim()} is paused for ${seconds} second${seconds === 1 ? '' : 's'}.`);
    submitting = false;
    applyLock();
    lockTimer = setInterval(applyLock, 1000);
  }

  function applyLock() {
    if (!lock) return;
    const left = Math.ceil((lock.end - performance.now()) / 1000);
    if (left <= 0) {
      clearInterval(lockTimer);
      lock = null;
      store(() => sessionStorage.removeItem(PAUSE_KEY));
      button.disabled = false;
      button.textContent = 'Sign in';
      clearError();
      status.textContent = 'You can sign in again.';
      return;
    }
    if (submitting) return;
    const paused = userKey(fields.username.value) === lock.user;
    button.disabled = paused;
    button.textContent = paused ? `Try again in ${left} s` : 'Sign in';
  }

  const failed = r => 'Wrong username or password.'
    + (r.left <= 2 ? ` ${r.left} more ${r.left === 1 ? 'try' : 'tries'} before sign-in pauses.` : '');

  /**
   * What an answer says about the server: 'ok' (ThreatSim answered), 'away' (a proxy in front couldn't reach
   * it just now: any 5xx but 501) or 'none' (something else answered, such as a plain web server's 404 or 501).
   */
  const kind = (res, body) => (body ? 'ok' : res.status >= 500 && res.status !== 501 ? 'away' : 'none');
  const readJson = async res => { try { return await res.json(); } catch (_) { return null; } };

  // The browser can restore the box as ticked (Back, reload) without a change event.
  const syncShowPassword = () => { fields.password.type = showPassword.checked ? 'text' : 'password'; };
  showPassword.addEventListener('change', syncShowPassword);
  addEventListener('pageshow', syncShowPassword);
  syncShowPassword();
  form.next.value = next;

  // Why the visitor is here; then drop that from the address so a reload doesn't repeat it.
  const ended = params.get('ended');
  if (own(ENDED, ended)) status.textContent = ENDED[ended];
  if (params.get('error') === 'invalid') showError('Wrong username or password.', 'password');
  if (params.get('error') === 'locked') showError('Too many failed attempts. Sign-in is paused for a while; try again later.');
  if (params.get('problem') === 'server') showError(NO_SERVER);
  const dropParams = (...names) => {
    if (!names.some(n => params.has(n))) return;
    names.forEach(n => params.delete(n));
    const qs = params.toString();
    try { history.replaceState(history.state, '', location.pathname + (qs ? '?' + qs : '') + location.hash); } catch (_) { /* keep it */ }
  };
  dropParams('ended', 'error');

  // The button starts disabled in the HTML, so the form can't be sent before this script runs.
  button.disabled = false;
  fields.username.addEventListener('input', applyLock);
  const saved = store(() => JSON.parse(sessionStorage.getItem(PAUSE_KEY)), null);
  if (saved && typeof saved.user === 'string' && saved.wait > 0 && saved.wait <= LOCK_MAX) {
    const left = Math.ceil((saved.start + saved.wait * 1000 - Date.now()) / 1000);
    // a start in the future means the clock went back: drop it rather than trust it
    if (saved.start <= Date.now() && left > 0) showLock(left, saved.user, false);
    else store(() => sessionStorage.removeItem(PAUSE_KEY));
  }

  if (location.protocol === 'file:') {
    showError(NO_SERVER);
    button.disabled = true;
  } else {
    // Is the server there, and is this visitor already signed in (a page restored by Back)?
    fetch('api/session', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } })
      .then(async res => {
        const body = await readJson(res);
        const k = kind(res, body);
        if (k === 'none') {
          showError(NO_SERVER);
          button.disabled = true;
        } else if (k === 'ok') {
          if (params.get('problem') === 'server') { clearError(); dropParams('problem'); }
          if (body.ok) location.replace(next || PAGES[0]);
        }
      })
      .catch(() => { /* unreachable for now: say so if sign-in fails */ });
  }

  form.addEventListener('keydown', e => { if (e.key === 'Enter' && e.repeat) e.preventDefault(); });   // a held Enter: send once
  form.addEventListener('submit', async e => {
    e.preventDefault();
    if (button.disabled) return;
    status.textContent = '';
    const username = fields.username.value;
    const password = fields.password.value;
    if (!username.trim()) { showError('Enter your username.', 'username'); fields.username.focus(); return; }
    if (!password) { showError('Enter your password.', 'password'); fields.password.focus(); return; }

    clearError();
    keepFocus();
    button.disabled = true;
    button.textContent = 'Signing in…';
    submitting = true;
    let stay = false;   // true when the button must stay disabled: signed in (leaving) or paused
    try {
      let res;
      try {
        res = await fetch('login', {
          method: 'POST', credentials: 'same-origin', cache: 'no-store',
          headers: { Accept: 'application/json' },
          body: new URLSearchParams({ username, password, next }),
        });
      } catch (_) {
        showError(OFFLINE);
        return;
      }
      const r = await readJson(res);
      const k = kind(res, r);
      if (k !== 'ok') {
        showError(k === 'away' ? OFFLINE : NO_SERVER);
      } else if (r.ok) {
        // make sure the browser kept the session cookie before leaving, or the next page bounces straight back
        const check = await fetch('api/session', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } })
          .then(readJson).catch(() => null);
        if (check && check.ok === false) {
          showError(NO_COOKIE);
        } else {
          stay = true;
          store(() => sessionStorage.removeItem(PAUSE_KEY));
          location.replace(PAGES.includes(r.next) ? r.next : PAGES[0]);
        }
      } else if (r.reason === 'locked') {
        stay = true;
        showLock(r.wait || 30, username);
      } else if (r.reason === 'origin') {
        showError(ORIGIN);
      } else {
        showError(failed(r), 'password');
        fields.password.select();
      }
    } finally {
      submitting = false;
      if (!stay) {
        button.disabled = false;
        button.textContent = 'Sign in';
        applyLock();   // another username's pause may still be counting down
      }
    }
  });

  fields.username.focus();
})();
