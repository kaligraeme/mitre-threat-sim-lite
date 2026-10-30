/* login.js — the sign-in page (index.html). */
(function () {
  'use strict';

  const $ = sel => document.querySelector(sel);
  const form = $('#signInForm');
  const button = $('#signInButton');
  const error = $('#signInError');
  const fields = { username: form.username, password: form.password };
  let lockTimer = null;

  function showError(message, field) {
    error.textContent = message;
    error.hidden = false;
    for (const [name, input] of Object.entries(fields)) {
      if (name === field) input.setAttribute('aria-invalid', 'true');
      else input.removeAttribute('aria-invalid');
    }
  }

  function clearError() {
    error.hidden = true;
    for (const input of Object.values(fields)) input.removeAttribute('aria-invalid');
  }

  /** After too many failed attempts: count down, then let the user try again. */
  function showLock(seconds) {
    clearInterval(lockTimer);
    button.disabled = true;
    button.textContent = 'Sign in';
    let left = seconds;
    const tick = () => {
      if (left <= 0) {
        clearInterval(lockTimer);
        button.disabled = false;
        error.hidden = true;
        return;
      }
      showError(`Too many failed attempts. Try again in ${left} second${left === 1 ? '' : 's'}.`);
      left--;
    };
    tick();
    lockTimer = setInterval(tick, 1000);
  }

  $('#defaultHint').hidden = !Auth.usingDefaultPassword();
  $('#showPassword').addEventListener('change', e => { fields.password.type = e.target.checked ? 'text' : 'password'; });

  if (!Auth.storageAvailable()) {
    showError('This browser is blocking site storage, which ThreatSim needs for sign-in and for its database. '
      + 'Allow storage for this site, then reload the page.');
    button.disabled = true;
  } else if (Auth.lockout()) {
    showLock(Auth.lockout());
  }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    if (button.disabled) return;
    const username = fields.username.value;
    const password = fields.password.value;
    if (!username.trim()) { showError('Enter your username.', 'username'); fields.username.focus(); return; }
    if (!password) { showError('Enter your password.', 'password'); fields.password.focus(); return; }

    clearError();
    button.disabled = true;
    button.textContent = 'Signing in…';
    let locked = false;
    try {
      const r = await Auth.signIn(username, password);
      if (r.ok) {
        location.replace(Auth.nextPage());
        return;
      }
      if (r.reason === 'locked') {
        locked = true;
        showLock(r.wait);
      } else if (r.reason === 'storage') {
        showError('This browser is blocking site storage, so ThreatSim cannot keep you signed in. Allow storage for this site and try again.');
      } else {
        showError('Wrong username or password.'
          + (r.left <= 2 ? ` ${r.left} more ${r.left === 1 ? 'try' : 'tries'} before a ${Auth.LOCK_SECONDS}-second pause.` : ''), 'password');
        fields.password.select();
      }
    } catch (err) {
      showError('Sign-in failed: ' + err.message);
    } finally {
      if (!locked) {
        button.disabled = false;
        button.textContent = 'Sign in';
      }
    }
  });

  fields.username.focus();
})();
