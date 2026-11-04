/*
 * auth.js — the signed-in side of ThreatSim's sign-in, for the protected pages (global `Auth`).
 *
 * The ThreatSim server (server.py) checks the session on every request and serves these pages,
 * and their scripts, only to a signed-in user. It adds who that is to the page as
 * <html data-user data-default-password>. This file adds Change password and Sign out to the
 * header and the default-password banner, renews the session while the page is in use, and takes
 * the page to sign-in when the session ends (12 hours without use, or Sign out in another tab).
 */
(function (global) {
  'use strict';

  const doc = global.document;
  const root = doc.documentElement;
  const SIGN_IN_PAGE = 'login.html';
  const PAGES = ['index.html', 'simulator.html', 'threatmodel.html'];   // pages sign-in may return to
  const SIGNAL_KEY = 'threatsim.auth.signal';       // tells this browser's other tabs to check the session
  const MIN_PASSWORD = 8;
  const CHECK_MS = 60 * 1000;
  const RENEW_MS = 5 * 60 * 1000;                   // an active page renews its session at most this often

  const account = { user: root.dataset.user || '', isDefault: root.dataset.defaultPassword === 'true' };

  function hide() {
    root.style.visibility = 'hidden';
    if (doc.body) doc.body.inert = true;
  }
  function show() {
    root.style.visibility = '';
    if (doc.body) doc.body.inert = false;
  }

  /** This page's file name for ?next=, also when the address is / or has no .html. */
  function thisPage() {
    let p = global.location.pathname.split('/').pop() || PAGES[0];
    try { p = decodeURIComponent(p); } catch (_) { /* keep the raw name */ }
    p = p.toLowerCase();
    return p.includes('.') ? p : p + '.html';
  }

  /** Hide the page and go to sign-in; if the browser stops the redirect, the page stays hidden. */
  function leave(reason, comeBack = true) {
    hide();
    const q = new URLSearchParams();
    const page = thisPage();
    if (comeBack && PAGES.includes(page) && page !== PAGES[0]) q.set('next', page);
    if (reason) q.set('ended', reason);
    const qs = q.toString();
    global.location.replace(SIGN_IN_PAGE + (qs ? '?' + qs : ''));
  }

  // Not served by server.py (a plain static server, or opened from disk): there is no sign-in to
  // check, so don't show the app; the sign-in page explains.
  if (!account.user) {
    hide();
    global.location.replace(SIGN_IN_PAGE + '?problem=server');
    return;
  }

  async function api(path, options) {
    const res = await global.fetch(path, Object.assign({ credentials: 'same-origin', cache: 'no-store' }, options,
      { headers: Object.assign({ Accept: 'application/json' }, options && options.headers) }));
    let body = null;
    try { body = await res.json(); } catch (_) { /* not JSON */ }
    return { status: res.status, body: body || {} };
  }

  const signal = () => { try { global.localStorage.setItem(SIGNAL_KEY, String(Date.now())); } catch (_) { /* storage blocked */ } };

  /**
   * Ask the server whether the session still stands; leave the page if it has ended. A server that
   * can't be reached doesn't end the page: the next check tries again. Resolves to true if the page stays.
   */
  async function check(renew = false) {
    let r;
    try { r = await api('api/session' + (renew ? '?renew=1' : '')); } catch (_) { return true; }
    if (r.status !== 200) return true;
    if (r.body.ok === false) {
      leave(r.body.reason && r.body.reason !== 'none' ? r.body.reason : 'ended');
      return false;
    }
    if (r.body.ok && (r.body.user !== account.user || r.body.defaultPassword !== account.isDefault)) {
      account.user = r.body.user;
      account.isDefault = !!r.body.defaultPassword;
      const who = doc.querySelector('.account .who');
      if (who) { who.textContent = account.user; who.title = 'Signed in as ' + account.user; }
      renderDefaultBanner();
    }
    return true;
  }

  let lastRenew = Date.now();   // the server renewed the session when it served this page
  /** Using the page counts as use of the session: renew it now and then while someone is active. */
  function renew() {
    const now = Date.now();
    if (Math.abs(now - lastRenew) < RENEW_MS) return;
    lastRenew = now;
    check(true);
  }

  function watchSession() {
    global.addEventListener('storage', e => { if (e.key === SIGNAL_KEY || e.key === null) check(); });
    doc.addEventListener('visibilitychange', () => { if (!doc.hidden) check(); });
    // A page kept in the back-forward cache comes back without being served again: hide it on the
    // way out, and show it again only once the server says the session still stands.
    global.addEventListener('pagehide', e => { if (e.persisted) hide(); });
    global.addEventListener('pageshow', e => { if (e.persisted) check().then(stays => { if (stays) show(); }); });
    global.setInterval(check, CHECK_MS);
    for (const type of ['pointerdown', 'keydown', 'wheel']) global.addEventListener(type, renew, { capture: true, passive: true });
  }

  async function signOut() {
    let r = null;
    try { r = await api('logout', { method: 'POST' }); } catch (_) { /* unreachable */ }
    if (!r || r.status !== 200) {
      say(!r || r.status >= 500 ? "Couldn't sign out: the server didn't answer. Try again."
        : r.body.reason === 'origin' ? "Couldn't sign out: the server refused a request that didn't come from its own address. Reload the page and try again."
          : "Couldn't sign out. Reload the page and try again.", 'err');
      return;
    }
    signal();
    leave('signedout', false);
  }

  // ---------- account controls ----------

  function h(tag, props, ...kids) {
    const n = doc.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null) continue;
      if (k === 'text') n.textContent = v;
      else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
      else n.setAttribute(k, v);
    }
    for (const kid of kids) if (kid != null) n.append(kid);
    return n;
  }

  let dialog = null;
  let resetDialog = null;
  let dialogBusy = () => false;
  let note = null;        // the header's status line ("Password changed")
  let noteTimer = 0;

  /** Show a short status line in the header; kind 'err' for a failure. */
  function say(text, kind) {
    if (!note) return;
    global.clearTimeout(noteTimer);
    note.textContent = text;
    note.classList.toggle('err', kind === 'err');
    noteTimer = global.setTimeout(() => { note.textContent = ''; }, 10000);
  }

  // A held Enter repeats: don't let the repeats reopen the dialog or send the form again.
  const ignoreHeldEnter = e => { if (e.key === 'Enter' && e.repeat) e.preventDefault(); };

  /** Add the account controls and banner as soon as the header is parsed, before the page first paints. */
  function mountWhenReady() {
    const ready = () => { const hd = doc.querySelector('header'); return !!hd && (!!hd.nextElementSibling || doc.readyState !== 'loading'); };
    if (ready()) { mountAccount(); return; }
    const mo = new MutationObserver(() => { if (ready()) { mo.disconnect(); mountAccount(); } });
    mo.observe(root, { childList: true, subtree: true });
    doc.addEventListener('DOMContentLoaded', () => { mo.disconnect(); mountAccount(); });
  }

  function mountAccount() {
    const header = doc.querySelector('header .wrap');
    if (!header || header.querySelector('.account')) return;
    note = h('span', { class: 'account-note', role: 'status' });   // present from the start, so screen readers announce changes
    header.append(h('div', { class: 'account' },
      h('span', { class: 'who', title: 'Signed in as ' + account.user }, account.user),
      note,
      h('button', { type: 'button', class: 'link', id: 'accountPassword', on: { click: openPasswordDialog, keydown: ignoreHeldEnter } }, 'Change password'),
      h('button', { type: 'button', class: 'link', on: { click: signOut } }, 'Sign out')));
    renderDefaultBanner();
  }

  function renderDefaultBanner() {
    const header = doc.querySelector('header');
    if (!header || !header.querySelector('.account')) return;
    const old = doc.getElementById('authBanner');
    const hadFocus = !!old && old.contains(doc.activeElement);
    if (old) old.remove();
    if (account.isDefault) {
      const width = header.querySelector('.wrap').className;   // same width as the page header (the Threat Profile page's is wider)
      header.after(h('div', { id: 'authBanner', class: 'auth-banner', role: 'status' },
        h('div', { class: width },
          h('span', {}, 'You are signed in with the default password (admin). Change it so that nobody else can sign in with it.'),
          h('button', { type: 'button', on: { click: openPasswordDialog, keydown: ignoreHeldEnter } }, 'Change password'))));
    } else if (hadFocus) {
      const opener = doc.getElementById('accountPassword');
      if (opener) opener.focus();   // the banner's button had focus and is gone: don't drop focus to the page
    }
  }

  function openPasswordDialog() {
    if (!dialog) dialog = buildDialog();
    if (dialog.open) return;
    if (!dialogBusy()) resetDialog();   // reopened while a change is still being saved: show that one
    dialog.showModal();
    dialog.querySelector('#pwCurrent').focus();
  }

  /** Quick checks before asking the server, which checks everything again. */
  function precheck(current, next, confirm) {
    if (!current) return { field: 'current', message: 'Enter your current password.' };
    if ([...next.normalize('NFKC')].length < MIN_PASSWORD) return { field: 'next', message: `Use at least ${MIN_PASSWORD} characters.` };
    if (next !== confirm) return { field: 'confirm', message: 'The two new passwords do not match.' };
    return null;
  }

  function buildDialog() {
    const field = (id, label, autocomplete) => [
      h('label', { for: id }, label),
      h('input', { id, name: id, type: 'password', autocomplete, required: '' }),
    ];
    const error = h('p', { id: 'pwError', class: 'form-error', role: 'alert', hidden: '' });
    const submit = h('button', { type: 'submit', class: 'primary' }, 'Change password');
    const cancel = h('button', { type: 'button' }, 'Cancel');
    const form = h('form', { class: 'auth-form', method: 'dialog', novalidate: '' },
      h('h2', { id: 'pwTitle' }, 'Change password'),
      // for password managers: which saved sign-in this change belongs to
      h('input', { type: 'text', name: 'username', autocomplete: 'username', value: account.user, readonly: '', hidden: '' }),
      ...field('pwCurrent', 'Current password', 'current-password'),
      ...field('pwNext', `New password (at least ${MIN_PASSWORD} characters)`, 'new-password'),
      ...field('pwConfirm', 'Confirm new password', 'new-password'),
      error,
      h('div', { class: 'dialog-actions' }, cancel, submit));
    const d = h('dialog', { class: 'auth-dialog', 'aria-labelledby': 'pwTitle' }, form);
    const inputs = { current: form.pwCurrent, next: form.pwNext, confirm: form.pwConfirm };
    const clearError = () => {
      error.hidden = true;
      error.textContent = '';
      for (const i of Object.values(inputs)) { i.removeAttribute('aria-invalid'); i.removeAttribute('aria-describedby'); }
    };
    const showError = (message, fieldName) => {
      error.textContent = message;
      error.hidden = false;
      const input = inputs[fieldName];
      if (input) {
        input.setAttribute('aria-invalid', 'true');
        input.setAttribute('aria-describedby', 'pwError');
        input.focus();
      }
    };
    let busy = false;
    dialogBusy = () => busy;
    resetDialog = () => { for (const i of Object.values(inputs)) i.value = ''; clearError(); };
    cancel.addEventListener('click', () => d.close());
    d.addEventListener('cancel', e => { if (busy) e.preventDefault(); });   // Escape while the change is being saved
    d.addEventListener('keydown', e => { if (e.key === 'Escape') e.stopPropagation(); });   // the dialog handles it, not the page behind
    form.addEventListener('keydown', ignoreHeldEnter);
    form.addEventListener('submit', async e => {
      e.preventDefault();
      if (busy) return;
      clearError();
      const values = { current: inputs.current.value, next: inputs.next.value, confirm: inputs.confirm.value };
      const problem = precheck(values.current, values.next, values.confirm);
      if (problem) { showError(problem.message, problem.field); return; }
      busy = true;
      if (doc.activeElement === submit) inputs.confirm.focus();   // a disabled button would drop focus to the page
      submit.disabled = cancel.disabled = true;
      submit.textContent = 'Changing…';
      try {
        let r;
        try {
          r = await api('api/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(values) });
        } catch (_) {
          r = { status: 0, body: { message: "The server didn't answer, so the password was not changed. Try again." } };
        }
        if (r.status === 200 && r.body.ok) {
          d.close();
          resetDialog();
          account.isDefault = false;
          renderDefaultBanner();
          const active = doc.activeElement;
          if (!active || active === doc.body || d.contains(active)) {
            const opener = doc.getElementById('accountPassword');
            if (opener) opener.focus();
          }
          say('Password changed');
          signal();
        } else if (r.status === 401) {
          d.close();
          leave(r.body.ended === 'password' ? 'password' : 'notchanged');   // reset elsewhere: the old password is gone too
        } else {
          const message = r.body.message || (r.body.reason === 'origin'
            ? 'The server refused the request because it did not come from this address. Reload the page and try again.'
            : 'The password was not changed. Try again.');
          if (d.open) showError(message, r.body.field);
          else say('Password not changed: ' + message, 'err');
        }
      } finally {
        busy = false;
        submit.disabled = cancel.disabled = false;
        submit.textContent = 'Change password';
        if (d.open && !d.contains(doc.activeElement)) inputs.current.focus();   // keep keyboard users in the dialog
      }
    });
    doc.body.append(d);
    return d;
  }

  watchSession();
  mountWhenReady();

  global.Auth = { user: () => account.user, check, signOut };
})(window);
