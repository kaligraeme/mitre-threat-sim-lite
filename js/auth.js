/*
 * auth.js — sign-in for ThreatSim (global `Auth`).
 *
 * ThreatSim is a static, browser-only app, so this gates this browser's copy of it; it is not
 * server-side security (anyone with the files or the browser's developer tools can get past it).
 * The password is never stored: only a PBKDF2-HMAC-SHA-256 hash with a random salt.
 *
 * localStorage
 *   threatsim.auth.users     { <username>: { salt, hash, iterations, isDefault, changed } }
 *   threatsim.auth.session   { user, started, expires }
 *   threatsim.auth.attempts  { count, until }   failed sign-ins, for a short lockout
 *
 * Pages: index.html is the sign-in page; protected pages call Auth.requireSignIn() in <head>.
 */
(function (global) {
  'use strict';

  const USERS_KEY = 'threatsim.auth.users';
  const SESSION_KEY = 'threatsim.auth.session';
  const ATTEMPTS_KEY = 'threatsim.auth.attempts';
  const DEFAULT_USER = 'admin';
  const DEFAULT_PASSWORD = 'admin';
  const ITERATIONS = 310000;          // PBKDF2 rounds for new hashes; each record keeps its own count
  const SESSION_HOURS = 12;
  const MAX_ATTEMPTS = 5;             // failed sign-ins before a pause
  const LOCK_SECONDS = 30;
  const MIN_PASSWORD = 8;
  const SIGN_IN_PAGE = 'index.html';
  const HOME_PAGE = 'data.html';
  const PAGES = ['data.html', 'simulator.html'];   // pages sign-in may return to

  // ---------- storage ----------

  function read(key) {
    try { return JSON.parse(global.localStorage.getItem(key)); } catch (_) { return null; }
  }
  function write(key, value) {
    global.localStorage.setItem(key, JSON.stringify(value));   // throws when the browser blocks storage
  }
  function remove(key) {
    try { global.localStorage.removeItem(key); } catch (_) { /* storage unavailable */ }
  }
  function storageAvailable() {
    try {
      const k = 'threatsim.auth.probe';
      global.localStorage.setItem(k, '1');
      global.localStorage.removeItem(k);
      return true;
    } catch (_) { return false; }
  }

  // ---------- hashing ----------

  const utf8 = s => new TextEncoder().encode(s);
  const toHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  const fromHex = s => Uint8Array.from((s.match(/../g) || []).map(h => parseInt(h, 16)));

  /** PBKDF2-HMAC-SHA-256, 32 bytes. WebCrypto where the browser offers it, else the same algorithm in JS. */
  async function pbkdf2(password, salt, iterations) {
    const subtle = global.crypto && global.crypto.subtle;
    if (subtle) {
      const key = await subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveBits']);
      return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
    }
    return pbkdf2Js(utf8(password), salt, iterations);
  }

  // SHA-256 (FIPS 180-4) for pages served over plain http from an address other than localhost,
  // where browsers withhold crypto.subtle. Gives the same PBKDF2 result as WebCrypto.
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const IV = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);

  /** One compression of the block in W[0..15] into state h. */
  function compress(h) {
    for (let i = 16; i < 64; i++) {
      const x = W[i - 15], y = W[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const t1 = (k + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      k = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + k) | 0;
  }
  const loadBlock = (bytes, off) => {
    for (let i = 0; i < 16; i++, off += 4) W[i] = (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
  };
  /** SHA-256 of msg continued from `state`, which has already absorbed `prefixLen` bytes (whole blocks). */
  function finish(state, msg, prefixLen) {
    const h = Uint32Array.from(state);
    const len = (msg.length + 9 + 63) & ~63;
    const buf = new Uint8Array(len);
    buf.set(msg);
    buf[msg.length] = 0x80;
    const bits = (prefixLen + msg.length) * 8;
    const hi = Math.floor(bits / 0x100000000), lo = bits >>> 0;
    buf[len - 8] = hi >>> 24; buf[len - 7] = hi >>> 16; buf[len - 6] = hi >>> 8; buf[len - 5] = hi;
    buf[len - 4] = lo >>> 24; buf[len - 3] = lo >>> 16; buf[len - 2] = lo >>> 8; buf[len - 1] = lo;
    for (let off = 0; off < len; off += 64) { loadBlock(buf, off); compress(h); }
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) { out[4 * i] = h[i] >>> 24; out[4 * i + 1] = h[i] >>> 16; out[4 * i + 2] = h[i] >>> 8; out[4 * i + 3] = h[i]; }
    return out;
  }
  const sha256 = bytes => finish(IV, bytes, 0);

  function pbkdf2Js(password, salt, iterations) {
    const key = new Uint8Array(64);
    key.set(password.length > 64 ? sha256(password) : password);
    const padState = pad => { const h = Uint32Array.from(IV); loadBlock(key.map(b => b ^ pad), 0); compress(h); return h; };
    const inner = padState(0x36), outer = padState(0x5c);   // HMAC key blocks, absorbed once
    const hmac = msg => finish(outer, finish(inner, msg, 64), 64);
    const first = new Uint8Array(salt.length + 4);
    first.set(salt);
    first[salt.length + 3] = 1;   // block index 1: 32 bytes need only one block
    let u = hmac(first);
    const t = u.slice();
    for (let i = 1; i < iterations; i++) {
      u = hmac(u);
      for (let j = 0; j < 32; j++) t[j] ^= u[j];
    }
    return t;
  }

  const sameBytes = (a, b) => {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  };

  async function makeRecord(password, isDefault) {
    const salt = global.crypto.getRandomValues(new Uint8Array(16));
    const hash = await pbkdf2(password, salt, ITERATIONS);
    return { salt: toHex(salt), hash: toHex(hash), iterations: ITERATIONS, isDefault, changed: isDefault ? null : new Date().toISOString() };
  }

  // ---------- accounts ----------

  const normalizeUser = u => String(u || '').trim().toLowerCase();
  const users = () => read(USERS_KEY);

  /** The account store, created with the default admin / admin account on first use. */
  async function ensureAccounts() {
    const existing = users();
    if (existing && typeof existing === 'object' && Object.keys(existing).length) return existing;
    const created = { [DEFAULT_USER]: await makeRecord(DEFAULT_PASSWORD, true) };
    write(USERS_KEY, created);
    return created;
  }

  /** True while the default account still has its default password (or no account exists yet). */
  function usingDefaultPassword() {
    const u = users();
    return !u || !Object.keys(u).length || !!(u[DEFAULT_USER] && u[DEFAULT_USER].isDefault);
  }

  async function verify(rec, password) {
    const hash = await pbkdf2(password, fromHex(rec.salt), rec.iterations || ITERATIONS);
    return sameBytes(hash, fromHex(rec.hash));
  }

  // ---------- sessions ----------

  /** The signed-in session, or null when there is none, it expired, or its account is gone. */
  function session() {
    const s = read(SESSION_KEY);
    const u = users();
    if (!s || !s.user || !(Date.now() < s.expires) || !u || !u[s.user]) return null;
    return s;
  }

  function lockout() {
    const a = read(ATTEMPTS_KEY) || { count: 0, until: 0 };
    return a.until > Date.now() ? Math.ceil((a.until - Date.now()) / 1000) : 0;
  }

  /**
   * Check a username and password and start a session.
   * Returns { ok, isDefault } or { ok: false, reason: 'locked' | 'invalid' | 'storage', wait?, left? }.
   */
  async function signIn(username, password) {
    if (!storageAvailable()) return { ok: false, reason: 'storage' };
    const wait = lockout();
    if (wait) return { ok: false, reason: 'locked', wait };
    const all = await ensureAccounts();
    const user = normalizeUser(username);
    const rec = Object.prototype.hasOwnProperty.call(all, user) ? all[user] : null;
    // hash even for an unknown user, so both failures take the same time
    const ok = rec ? await verify(rec, String(password)) : (await pbkdf2(String(password), new Uint8Array(16), ITERATIONS), false);
    if (!ok) {
      const a = read(ATTEMPTS_KEY) || { count: 0, until: 0 };
      a.count = (a.until > Date.now() ? 0 : a.count) + 1;
      if (a.count >= MAX_ATTEMPTS) { a.count = 0; a.until = Date.now() + LOCK_SECONDS * 1000; }
      write(ATTEMPTS_KEY, a);
      return a.until > Date.now() ? { ok: false, reason: 'locked', wait: LOCK_SECONDS } : { ok: false, reason: 'invalid', left: MAX_ATTEMPTS - a.count };
    }
    remove(ATTEMPTS_KEY);
    const now = Date.now();
    write(SESSION_KEY, { user, started: now, expires: now + SESSION_HOURS * 3600 * 1000 });
    return { ok: true, isDefault: !!rec.isDefault };
  }

  function signOut() {
    remove(SESSION_KEY);
    global.location.replace(SIGN_IN_PAGE);
  }

  /**
   * Change the signed-in user's password. Returns { ok } or { ok: false, field, message }.
   * Rules: the current password must match; the new one has at least MIN_PASSWORD characters,
   * differs from the current one and from the username, and is not the default password.
   */
  async function changePassword(current, next, confirm) {
    const s = session();
    if (!s) return { ok: false, field: 'current', message: 'Your session has ended. Sign in again.' };
    const all = users();
    const rec = all && all[s.user];
    if (!rec || !(await verify(rec, String(current)))) return { ok: false, field: 'current', message: 'The current password is not right.' };
    next = String(next);
    if (next.length < MIN_PASSWORD) return { ok: false, field: 'next', message: `Use at least ${MIN_PASSWORD} characters.` };
    if (next === String(current)) return { ok: false, field: 'next', message: 'Choose a password different from the current one.' };
    if (normalizeUser(next) === s.user || next === DEFAULT_PASSWORD) return { ok: false, field: 'next', message: 'Choose a password that is not the username or the default password.' };
    if (next !== String(confirm)) return { ok: false, field: 'confirm', message: 'The two new passwords do not match.' };
    all[s.user] = await makeRecord(next, false);
    write(USERS_KEY, all);
    return { ok: true };
  }

  // ---------- page guards ----------

  const thisPage = () => (global.location.pathname.split('/').pop() || SIGN_IN_PAGE);

  /** Where sign-in should go next: a known page from ?next=, else the Data page. Nothing else is accepted. */
  function nextPage(search = global.location.search) {
    const next = new URLSearchParams(search).get('next');
    return PAGES.includes(next) ? next : HOME_PAGE;
  }

  /** For protected pages, in <head>: send signed-out visitors to the sign-in page, then back here. */
  function requireSignIn() {
    if (session()) {
      watchSession();
      if (global.document.readyState === 'loading') global.document.addEventListener('DOMContentLoaded', mountAccount);
      else mountAccount();
      return true;
    }
    // hide the page while the browser leaves it (its own scripts skip their start-up without a session)
    global.document.documentElement.style.visibility = 'hidden';
    const page = thisPage();
    global.location.replace(SIGN_IN_PAGE + (PAGES.includes(page) ? '?next=' + encodeURIComponent(page) : ''));
    return false;
  }

  /** For the sign-in page, in <head>: skip it when already signed in. */
  function redirectIfSignedIn() {
    if (session()) { global.location.replace(nextPage()); return true; }
    return false;
  }

  /** Leave the page when the session ends in another tab, or expires while it is open. */
  function watchSession() {
    const check = () => { if (!session()) global.location.replace(SIGN_IN_PAGE + '?next=' + encodeURIComponent(thisPage())); };
    global.addEventListener('storage', e => { if (e.key === null || e.key === SESSION_KEY || e.key === USERS_KEY) check(); });
    global.document.addEventListener('visibilitychange', () => { if (!global.document.hidden) check(); });
    global.setInterval(check, 60 * 1000);
  }

  // ---------- account controls (protected pages) ----------

  function h(tag, props, ...kids) {
    const n = global.document.createElement(tag);
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

  function mountAccount() {
    const s = session();
    const header = global.document.querySelector('header .wrap');
    if (!s || !header || header.querySelector('.account')) return;
    header.append(h('div', { class: 'account' },
      h('span', { class: 'who', title: 'Signed in as ' + s.user }, s.user),
      h('button', { type: 'button', class: 'link', on: { click: openPasswordDialog } }, 'Change password'),
      h('button', { type: 'button', class: 'link', on: { click: signOut } }, 'Sign out')));
    renderDefaultBanner();
  }

  function renderDefaultBanner() {
    const old = global.document.getElementById('authBanner');
    if (old) old.remove();
    if (!usingDefaultPassword()) return;
    const header = global.document.querySelector('header');
    const width = header.querySelector('.wrap').className;   // same width as the page header (the Simulator's is wider)
    header.after(h('div', { id: 'authBanner', class: 'auth-banner', role: 'status' },
      h('div', { class: width },
        h('span', {}, 'You are signed in with the default password (admin). Change it so others with access to this browser cannot sign in as you.'),
        h('button', { type: 'button', on: { click: openPasswordDialog } }, 'Change password'))));
  }

  function openPasswordDialog() {
    if (!dialog) dialog = buildDialog();
    dialog.querySelector('form').reset();
    dialog.querySelector('.form-error').hidden = true;
    dialog.querySelectorAll('input').forEach(i => i.removeAttribute('aria-invalid'));
    dialog.showModal();
    dialog.querySelector('input').focus();
  }

  function buildDialog() {
    const field = (id, label, autocomplete) => [
      h('label', { for: id }, label),
      h('input', { id, name: id, type: 'password', autocomplete, required: '' }),
    ];
    const error = h('p', { class: 'form-error', role: 'alert', hidden: '' });
    const submit = h('button', { type: 'submit', class: 'primary' }, 'Change password');
    const form = h('form', { class: 'auth-form', novalidate: '' },
      h('h2', { id: 'pwTitle' }, 'Change password'),
      ...field('pwCurrent', 'Current password', 'current-password'),
      ...field('pwNext', `New password (at least ${MIN_PASSWORD} characters)`, 'new-password'),
      ...field('pwConfirm', 'Confirm new password', 'new-password'),
      error,
      h('div', { class: 'dialog-actions' },
        h('button', { type: 'button', on: { click: () => d.close() } }, 'Cancel'),
        submit));
    const d = h('dialog', { class: 'auth-dialog', 'aria-labelledby': 'pwTitle' }, form);
    form.addEventListener('submit', async e => {
      e.preventDefault();
      if (submit.disabled) return;
      submit.disabled = true;
      submit.textContent = 'Changing…';
      error.hidden = true;
      form.querySelectorAll('input').forEach(i => i.removeAttribute('aria-invalid'));
      try {
        const r = await changePassword(form.pwCurrent.value, form.pwNext.value, form.pwConfirm.value);
        if (r.ok) {
          d.close();
          renderDefaultBanner();
          const who = global.document.querySelector('.account .who');
          if (who) {
            const note = h('span', { class: 'account-note', role: 'status' }, 'Password changed');
            who.after(note);
            global.setTimeout(() => note.remove(), 4000);
          }
        } else {
          error.textContent = r.message;
          error.hidden = false;
          const input = { current: form.pwCurrent, next: form.pwNext, confirm: form.pwConfirm }[r.field];
          if (input) { input.setAttribute('aria-invalid', 'true'); input.focus(); }
        }
      } catch (err) {
        error.textContent = 'Could not change the password: ' + err.message;
        error.hidden = false;
      } finally {
        submit.disabled = false;
        submit.textContent = 'Change password';
      }
    });
    global.document.body.append(d);
    return d;
  }

  global.Auth = {
    DEFAULT_USER, MIN_PASSWORD, SESSION_HOURS, MAX_ATTEMPTS, LOCK_SECONDS, PAGES,
    signIn, signOut, changePassword, session, lockout, usingDefaultPassword, storageAvailable,
    requireSignIn, redirectIfSignedIn, nextPage,
    // exposed for tests: the hashing primitives
    _pbkdf2: pbkdf2, _pbkdf2Js: pbkdf2Js, _sha256: sha256,
  };
})(window);
