#!/usr/bin/env python3
"""ThreatSim server: serves the app and makes everyone sign in before they can use it.

    python3 server.py                         # http://127.0.0.1:8000
    python3 server.py --host 0.0.0.0 --port 8443 --cert cert.pem --key key.pem
    python3 server.py --set-password admin    # set or reset a password (creates the account if new)

Without a session, only the sign-in page (login.html) and the stylesheet and script it needs are
served. Every other page and script, including the Data page (index.html) and the Simulator, needs
a signed-in session; a page asked for without one redirects to login.html, anything else gets 401.

Accounts are kept in <data dir>/users.json as PBKDF2-HMAC-SHA-256 hashes (310,000 iterations,
random salt). On first start the file is created with the account admin / admin. Sessions are an
HttpOnly cookie holding a random token, kept in memory: restarting the server signs everyone out.
Only the Python standard library is used.
"""
import argparse
import getpass
import hashlib
import hmac
import html
import http.server
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import unicodedata
import urllib.parse
from datetime import datetime, timezone
from email.utils import formatdate, parsedate_to_datetime

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_USER = 'admin'
DEFAULT_PASSWORD = 'admin'
ITERATIONS = 310_000              # PBKDF2 rounds for new hashes; each record keeps its own count
SESSION_IDLE = 12 * 3600          # a session ends after this long without use (seconds)
MAX_ATTEMPTS = 5                  # failed sign-ins from one address before a pause
LOCK_BASE = 30                    # the first pause; each further pause within an hour doubles it
LOCK_MAX = 15 * 60
MIN_PASSWORD = 8                  # characters (Unicode code points)
MAX_FIELD = 1024                  # longest username or password accepted
MAX_BODY = 16 * 1024              # largest request body accepted
PAGES = ('index.html', 'simulator.html')               # signed-in pages sign-in may return to
PUBLIC = {'login.html', 'css/app.css', 'js/login.js'}  # served without a session
ROOT_FILES = {'index.html', 'simulator.html', 'login.html'}
SERVED_DIRS = ('css/', 'js/')
TYPES = {
    '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8', '.json': 'application/json',
    '.txt': 'text/plain; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
    '.ico': 'image/x-icon', '.woff2': 'font/woff2',
}
TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{32,128}')
DUMMY_SALT = bytes(16)
HASH_SLOTS = threading.BoundedSemaphore(max(1, min(4, os.cpu_count() or 1)))   # hashes running at once


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ---------- passwords ----------

def normalize_user(name):
    return unicodedata.normalize('NFKC', name).strip().casefold()


def normalize_password(password):
    return unicodedata.normalize('NFKC', password)


def pbkdf2(password, salt, iterations):
    with HASH_SLOTS:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8', 'surrogatepass'), salt, iterations)


def make_record(password, is_default=False):
    salt = secrets.token_bytes(16)
    return {
        'salt': salt.hex(), 'hash': pbkdf2(password, salt, ITERATIONS).hex(), 'iterations': ITERATIONS,
        'isDefault': is_default,
        'changed': None if is_default else datetime.now(timezone.utc).isoformat(timespec='seconds'),
    }


def verify(rec, password):
    """True if password matches the account record. A missing or malformed record never matches."""
    try:
        salt, want = bytes.fromhex(rec['salt']), bytes.fromhex(rec['hash'])
        iterations = int(rec.get('iterations') or ITERATIONS)
    except (KeyError, TypeError, ValueError, AttributeError):
        pbkdf2(password, DUMMY_SALT, ITERATIONS)   # same time as a real check
        return False
    return hmac.compare_digest(pbkdf2(password, salt, iterations), want)


def password_problem(user, current, new, confirm):
    """Why `new` can't be the password for `user` (field, message), or None. Inputs are normalized."""
    if len(new) < MIN_PASSWORD:
        return 'next', f'Use at least {MIN_PASSWORD} characters.'
    if len(new) > MAX_FIELD:
        return 'next', f'Use at most {MAX_FIELD} characters.'
    if current is not None and new == current:
        return 'next', 'Choose a password different from the current one.'
    if normalize_user(new) == user or new == DEFAULT_PASSWORD:
        return 'next', 'Choose a password that is not the username or the default password.'
    if new != confirm:
        return 'confirm', 'The two new passwords do not match.'
    return None


class Accounts:
    """users.json: {"users": {name: {salt, hash, iterations, isDefault, changed}}}, re-read when it changes
    on disk (for --set-password while the server runs) and written atomically with mode 0600."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.users, self.stamp = {}, None
        if not os.path.exists(path):
            self.users = {DEFAULT_USER: make_record(DEFAULT_PASSWORD, is_default=True)}
            self._save()
            log(f'Created {path} with the account {DEFAULT_USER} / {DEFAULT_PASSWORD}.')
        self._reload()

    def _reload(self):
        try:
            st = os.stat(self.path)
            if self.stamp == (st.st_mtime_ns, st.st_size):
                return
            with open(self.path, encoding='utf-8') as f:
                data = json.load(f)
            users = data.get('users') if isinstance(data, dict) else None
            if not isinstance(users, dict) or not all(isinstance(r, dict) for r in users.values()):
                raise ValueError('no "users" object')
            self.users, self.stamp = users, (st.st_mtime_ns, st.st_size)
        except (OSError, ValueError) as e:   # keep the accounts already loaded; never fall back to a default
            if self.stamp is None:
                raise SystemExit(f'Cannot read the accounts file {self.path}: {e}. Fix it, or delete it to start again with {DEFAULT_USER} / {DEFAULT_PASSWORD}.')
            log(f'Warning: cannot re-read {self.path} ({e}); still using the accounts loaded before.')

    def _save(self):
        tmp = f'{self.path}.{os.getpid()}.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump({'users': self.users}, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        st = os.stat(self.path)
        self.stamp = (st.st_mtime_ns, st.st_size)

    def get(self, user):
        with self.lock:
            self._reload()
            rec = self.users.get(user)
            return dict(rec) if isinstance(rec, dict) else None

    def set(self, user, rec):
        with self.lock:
            self._reload()
            self.users[user] = rec
            self._save()

    def default_in_use(self):
        rec = self.get(DEFAULT_USER)
        return bool(rec and rec.get('isDefault'))


# ---------- sessions and failed sign-ins ----------

class Sessions:
    """Signed-in sessions, in memory, keyed by a hash of the cookie token. A session ends after
    SESSION_IDLE seconds without use, at sign-out, or when its account's password changes (its stamp
    no longer matches the account's hash)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.live = {}    # key -> {'user', 'stamp', 'last'}   (last: time.monotonic())
        self.ended = {}   # key -> (reason, when): why a recent session ended, kept for a day

    @staticmethod
    def key(token):
        return hashlib.sha256(token.encode('ascii')).hexdigest()

    def create(self, user, stamp):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self._prune()
            self.live[self.key(token)] = {'user': user, 'stamp': stamp, 'last': time.monotonic()}
        return token

    def get(self, token, touch):
        """(session, None) or (None, reason): 'expired', 'signedout', 'password', or 'ended' for a token
        this server doesn't know (it was restarted, or the session ended over a day ago)."""
        k, now = self.key(token), time.monotonic()
        with self.lock:
            s = self.live.get(k)
            if s is None:
                return None, self.ended.get(k, ('ended', 0))[0]
            if now - s['last'] >= SESSION_IDLE:
                del self.live[k]
                self.ended[k] = ('expired', now)
                return None, 'expired'
            if touch:
                s['last'] = now
            return dict(s), None

    def restamp(self, token, stamp):
        with self.lock:
            s = self.live.get(self.key(token))
            if s:
                s['stamp'] = stamp

    def end(self, token, reason='signedout'):
        k = self.key(token)
        with self.lock:
            if self.live.pop(k, None) is not None:
                self.ended[k] = (reason, time.monotonic())

    def _prune(self):
        now = time.monotonic()
        for k in [k for k, s in self.live.items() if now - s['last'] >= SESSION_IDLE]:
            del self.live[k]
            self.ended[k] = ('expired', now)
        for k in [k for k, (_, t) in self.ended.items() if now - t > 86400]:
            del self.ended[k]


class Throttle:
    """Failed sign-ins per client address: after MAX_ATTEMPTS, a pause of LOCK_BASE seconds, doubling for
    each further pause (up to LOCK_MAX) until the address has been quiet for an hour."""

    def __init__(self):
        self.lock = threading.Lock()
        self.by_addr = {}

    def _entry(self, addr, now):
        e = self.by_addr.get(addr)
        return e if e and now - e['last'] < 3600 else None

    def wait(self, addr):
        now = time.monotonic()
        with self.lock:
            e = self._entry(addr, now)
            return max(0, math.ceil(e['until'] - now)) if e else 0

    def fail(self, addr):
        """Count a failure. Returns (seconds paused, attempts left before the next pause)."""
        now = time.monotonic()
        with self.lock:
            e = self._entry(addr, now) or {'count': 0, 'locks': 0, 'until': 0.0}
            e['count'] += 1
            e['last'] = now
            if e['count'] >= MAX_ATTEMPTS:
                e['count'] = 0
                e['locks'] += 1
                e['until'] = now + min(LOCK_BASE * 2 ** (e['locks'] - 1), LOCK_MAX)
            self.by_addr[addr] = e
            if len(self.by_addr) > 10000:
                for a in [a for a, x in self.by_addr.items() if now - x['last'] >= 3600]:
                    del self.by_addr[a]
            return max(0, math.ceil(e['until'] - now)), MAX_ATTEMPTS - e['count']

    def clear(self, addr):
        with self.lock:
            self.by_addr.pop(addr, None)


# ---------- HTTP ----------

def next_page(value):
    return value if value in PAGES else PAGES[0]


def servable(path):
    """Only the app's own pages, stylesheets and scripts are ever served: never server.py, the accounts
    file, the README or anything else in the folder."""
    if path in ROOT_FILES:
        return True
    if not path.startswith(SERVED_DIRS):
        return False
    if any(not part or part.startswith('.') for part in path.split('/')):
        return False
    return os.path.splitext(path)[1].lower() in TYPES


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'ThreatSim'
    protocol_version = 'HTTP/1.1'
    timeout = 30   # seconds a connection may sit idle

    def version_string(self):
        return self.server_version

    # ----- request helpers -----

    def peer_is_proxy(self):
        if not self.server.behind_proxy:
            return False
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False

    def client_addr(self):
        if self.peer_is_proxy():
            fwd = self.headers.get('X-Forwarded-For', '')
            last = fwd.split(',')[-1].strip()
            if last:
                return last
        return self.client_address[0]

    def address_string(self):   # for the access log
        return self.client_addr()

    def is_https(self):
        if self.server.tls:
            return True
        return self.peer_is_proxy() and self.headers.get('X-Forwarded-Proto', '').strip().lower() == 'https'

    def public_host(self):
        if self.peer_is_proxy() and self.headers.get('X-Forwarded-Host'):
            return self.headers['X-Forwarded-Host'].split(',')[0].strip()
        return self.headers.get('Host', '')

    def same_origin(self):
        """POSTs must come from a page at this server's own address (Origin, else Referer)."""
        source = self.headers.get('Origin') or self.headers.get('Referer')
        if not source or source == 'null':
            return False
        u = urllib.parse.urlsplit(source)
        host = self.public_host()
        return u.scheme in ('http', 'https') and bool(host) and u.netloc.lower() == host.lower()

    def split_target(self):
        """The request path as a relative path ('' for the root) and its query, or (None, {}) if malformed."""
        parts = urllib.parse.urlsplit(self.path)
        try:
            path = urllib.parse.unquote(parts.path, errors='strict')
        except UnicodeDecodeError:
            return None, {}
        if not path.startswith('/') or '\\' in path or '\x00' in path:
            return None, {}
        path = path[1:]
        if any(seg in ('.', '..') for seg in path.split('/')):
            return None, {}
        return path, urllib.parse.parse_qs(parts.query)

    def cookie_name(self):
        return '__Host-threatsim' if self.is_https() else 'threatsim'

    def cookie_token(self):
        name = self.cookie_name()
        for header in self.headers.get_all('Cookie') or []:
            for piece in header.split(';'):
                k, _, v = piece.strip().partition('=')
                if k == name and TOKEN_RE.fullmatch(v):
                    return v
        return None

    def current_session(self, touch):
        """(session, None), or (None, reason): reason is None when no session cookie was sent."""
        token = self.cookie_token()
        if not token:
            return None, None
        s, reason = SESSIONS.get(token, touch)
        if s:
            rec = ACCOUNTS.get(s['user'])
            if rec and hmac.compare_digest(str(rec.get('hash', '')), s['stamp']):
                s['token'] = token
                s['isDefault'] = bool(rec.get('isDefault'))
                return s, None
            reason = 'password' if rec else 'ended'   # its password was changed elsewhere, or the account removed
            SESSIONS.end(token, reason)
        return None, reason

    def read_body(self):
        """The request body as bytes, or None after replying with an error."""
        if self.headers.get('Transfer-Encoding'):
            self.close_connection = True
            self.reply(411, 'Send a Content-Length.')
            return None
        length = self.headers.get('Content-Length')
        if length is None:
            return b''   # no length and no chunking: no body
        if not length.isdigit():
            self.close_connection = True
            self.reply(400, 'Bad Content-Length.')
            return None
        n = int(length)
        if n > MAX_BODY:
            self.close_connection = True
            self.reply(413, 'Request too large.')
            return None
        return self.rfile.read(n)

    def form(self, body):
        """Fields from a form-encoded or JSON body: {name: str}."""
        ctype = self.headers.get('Content-Type', '').split(';')[0].strip().lower()
        try:
            if ctype == 'application/json':
                data = json.loads(body.decode('utf-8'))
                return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(data, dict) else {}
            if ctype == 'application/x-www-form-urlencoded':
                return {k: v[0] for k, v in urllib.parse.parse_qs(body.decode('utf-8'), keep_blank_values=True).items()}
        except (UnicodeDecodeError, ValueError):
            pass
        return {}

    def wants_json(self):
        return 'application/json' in self.headers.get('Accept', '')

    # ----- responses -----

    def security_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "frame-ancestors 'none'")
        self.send_header('Referrer-Policy', 'same-origin')
        if self.server.tls:
            self.send_header('Strict-Transport-Security', 'max-age=31536000')

    def reply(self, status, body=b'', ctype='text/plain; charset=utf-8', headers=(), head=False):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(status)
        self.security_headers()
        for k, v in headers:
            self.send_header(k, v)
        if not any(k.lower() == 'cache-control' for k, _ in headers):
            self.send_header('Cache-Control', 'no-store')
        if body or status not in (204, 304):
            self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body and not head and self.command != 'HEAD':
            self.wfile.write(body)

    def reply_json(self, status, data, headers=()):
        self.reply(status, json.dumps(data), 'application/json', headers)

    def redirect(self, location, status=302, headers=()):
        self.reply(status, b'', headers=[('Location', location), *headers])

    def session_cookie(self, token):
        attrs = 'Path=/; HttpOnly; SameSite=Lax' + ('; Secure' if self.is_https() else '')
        if token is None:
            return 'Set-Cookie', f'{self.cookie_name()}=; Max-Age=0; {attrs}'
        return 'Set-Cookie', f'{self.cookie_name()}={token}; {attrs}'

    def send_file(self, path, head, session=None, headers=()):
        full = os.path.realpath(os.path.join(APP_DIR, *path.split('/')))
        if not full.startswith(ROOT + os.sep) or not os.path.isfile(full):
            return self.reply(404, 'Not found.')
        ctype = TYPES[os.path.splitext(path)[1].lower()]
        if path.endswith('.html'):
            with open(full, 'rb') as f:
                body = f.read()
            if session:   # tell the page who is signed in (auth.js reads these)
                attrs = ' data-user="%s" data-default-password="%s"' % (
                    html.escape(session['user'], quote=True), 'true' if session['isDefault'] else 'false')
                text = body.decode('utf-8')
                i = text.find('<html')
                if i >= 0:
                    body = (text[:i + 5] + attrs + text[i + 5:]).encode('utf-8')
            return self.reply(200, body, ctype, headers=headers, head=head)
        st = os.stat(full)
        modified = formatdate(st.st_mtime, usegmt=True)
        cache = [('Cache-Control', 'no-cache' if path in PUBLIC else 'private, no-cache'), ('Last-Modified', modified)]
        since = self.headers.get('If-Modified-Since')
        if since:
            try:
                if int(st.st_mtime) <= parsedate_to_datetime(since).timestamp():
                    return self.reply(304, b'', headers=cache)
            except (TypeError, ValueError, OverflowError):
                pass
        with open(full, 'rb') as f:
            body = f.read()
        return self.reply(200, body, ctype, headers=cache, head=head)

    # ----- routes -----

    def do_HEAD(self):
        self.do_GET(head=True)

    def do_GET(self, head=False):
        path, query = self.split_target()
        if path is None:
            return self.reply(400, 'Bad request.')
        if path == 'api/session':
            if head:
                return self.reply(405, 'Use GET.', headers=[('Allow', 'GET')])
            return self.api_session(query)
        if path == '':
            path = 'index.html'
        if not servable(path):
            return self.reply(404, 'Not found.')
        if path == 'login.html':
            s, _ = self.current_session(touch=False)
            if s:   # already signed in
                return self.redirect(next_page((query.get('next') or [''])[0]))
            return self.send_file(path, head)
        if path in PUBLIC:
            return self.send_file(path, head)
        s, reason = self.current_session(touch=True)
        if not s:
            clear = [self.session_cookie(None)] if reason else []   # a stale cookie: drop it
            if not path.endswith('.html'):
                return self.reply(401, 'Sign in first.', headers=clear)
            q = {}
            if path != PAGES[0]:
                q['next'] = path
            if reason:
                q['ended'] = reason
            return self.redirect('login.html' + ('?' + urllib.parse.urlencode(q) if q else ''), headers=clear)
        return self.send_file(path, head, session=s if path.endswith('.html') else None)

    def do_POST(self):
        path, _ = self.split_target()
        routes = {'login': self.post_login, 'logout': self.post_logout, 'api/password': self.post_password}
        if path not in routes:
            self.close_connection = True   # its body is never read
            return self.reply(404, 'Not found.')
        if not self.same_origin():
            self.close_connection = True
            return self.reply_json(403, {'ok': False, 'reason': 'origin'})
        body = self.read_body()
        if body is None:
            return
        routes[path](self.form(body))

    def api_session(self, query):
        """GET api/session: who is signed in (?renew=1 also counts as use, for an active page). Not being
        signed in is an answer here, not an error: {"ok": false, "reason": ...} with status 200."""
        s, reason = self.current_session(touch='renew' in query)
        if not s:
            clear = [self.session_cookie(None)] if reason else []
            return self.reply_json(200, {'ok': False, 'reason': reason or 'none'}, headers=clear)
        self.reply_json(200, {'ok': True, 'user': s['user'], 'defaultPassword': s['isDefault']})

    def post_login(self, fields):
        addr = self.client_addr()
        nxt = next_page(fields.get('next', ''))
        wait = THROTTLE.wait(addr)
        if wait:
            return self.login_failed(429, {'ok': False, 'reason': 'locked', 'wait': wait}, nxt)
        username, password = fields.get('username', ''), fields.get('password', '')
        user, pw = normalize_user(username[:MAX_FIELD * 4]), normalize_password(password[:MAX_FIELD * 4])
        rec = ACCOUNTS.get(user) if user and len(username) <= MAX_FIELD else None
        if rec and len(pw) <= MAX_FIELD:
            ok = verify(rec, pw)
        else:   # an unknown user, or a password too long to be one: take as long as a real check
            pbkdf2(pw[:MAX_FIELD], DUMMY_SALT, ITERATIONS)
            ok = False
        if ok:
            THROTTLE.clear(addr)
            old = self.cookie_token()
            if old:
                SESSIONS.end(old)   # a fresh token for every sign-in
            token = SESSIONS.create(user, rec['hash'])
            cookie = self.session_cookie(token)
            if self.wants_json():
                return self.reply_json(200, {'ok': True, 'next': nxt}, headers=[cookie])
            return self.redirect(nxt, 303, headers=[cookie])
        wait, left = THROTTLE.fail(addr)
        if wait:
            return self.login_failed(429, {'ok': False, 'reason': 'locked', 'wait': wait}, nxt)
        return self.login_failed(401, {'ok': False, 'reason': 'invalid', 'left': left}, nxt)

    def login_failed(self, status, data, nxt):
        headers = [('Retry-After', str(data['wait']))] if data.get('wait') else []
        if self.wants_json():
            return self.reply_json(status, data, headers=headers)
        q = {'error': data['reason']}
        if nxt != PAGES[0]:
            q['next'] = nxt
        return self.redirect('login.html?' + urllib.parse.urlencode(q), 303)

    def post_logout(self, fields):
        token = self.cookie_token()
        if token:
            SESSIONS.end(token)
        cookie = self.session_cookie(None)
        if self.wants_json():
            return self.reply_json(200, {'ok': True}, headers=[cookie])
        return self.redirect('login.html?ended=signedout', 303, headers=[cookie])

    def post_password(self, fields):
        s, reason = self.current_session(touch=True)
        if not s:
            return self.reply_json(401, {'ok': False, 'reason': 'session', 'ended': reason or 'ended'})
        addr = self.client_addr()
        wait = THROTTLE.wait(addr)
        if wait:
            return self.reply_json(429, {'ok': False, 'reason': 'locked', 'wait': wait,
                                         'message': f'Too many wrong passwords. Try again in {wait} seconds.'},
                                   headers=[('Retry-After', str(wait))])
        current = normalize_password(fields.get('current', ''))
        new = normalize_password(fields.get('next', ''))
        confirm = normalize_password(fields.get('confirm', ''))
        if not current:
            return self.reply_json(400, {'ok': False, 'field': 'current', 'message': 'Enter your current password.'})
        problem = password_problem(s['user'], current, new, confirm)
        if problem:
            return self.reply_json(400, {'ok': False, 'field': problem[0], 'message': problem[1]})
        if len(current) > MAX_FIELD or not verify(ACCOUNTS.get(s['user']), current):
            wait, _ = THROTTLE.fail(addr)
            return self.reply_json(400, {'ok': False, 'field': 'current', 'message': 'The current password is not right.'})
        THROTTLE.clear(addr)
        rec = make_record(new)
        ACCOUNTS.set(s['user'], rec)
        SESSIONS.restamp(s['token'], rec['hash'])   # this session stays; the user's other sessions end
        self.reply_json(200, {'ok': True})


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, tls_context, behind_proxy):
        self.tls = tls_context is not None
        self.behind_proxy = behind_proxy
        if ':' in addr[0]:
            self.address_family = socket.AF_INET6
        super().__init__(addr, Handler)
        if tls_context:   # handshakes run in each connection's thread, not in the accept loop
            self.socket = tls_context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ssl.SSLError, OSError)):
            return   # a client that went away, timed out or didn't speak TLS: not worth a traceback
        super().handle_error(request, client_address)


def set_password(user):
    user = normalize_user(user)
    if not user or len(user) > MAX_FIELD:
        raise SystemExit('Give a username.')
    rec = ACCOUNTS.get(user)
    print(('Changing the password of ' if rec else 'Creating the account ') + user)
    for _ in range(3):
        new = normalize_password(getpass.getpass('New password: '))
        problem = password_problem(user, None, new, normalize_password(getpass.getpass('Repeat it: ')))
        if not problem:
            ACCOUNTS.set(user, make_record(new))
            print('Saved. A running server signs this account out of its sessions.')
            return
        print(problem[1])
    raise SystemExit('Password not changed.')


def main():
    global ACCOUNTS, SESSIONS, THROTTLE, ROOT
    ap = argparse.ArgumentParser(description='Serve ThreatSim and require sign-in.')
    ap.add_argument('--host', default='127.0.0.1', help='address to listen on (default 127.0.0.1; 0.0.0.0 for all)')
    ap.add_argument('--port', type=int, default=8000)
    ap.add_argument('--data-dir', default=os.path.join(APP_DIR, '.threatsim'), help='where users.json is kept')
    ap.add_argument('--cert', help='TLS certificate (PEM) to serve HTTPS')
    ap.add_argument('--key', help='private key for --cert (PEM)')
    ap.add_argument('--behind-proxy', action='store_true',
                    help='trust X-Forwarded-For/-Proto/-Host from a reverse proxy on this machine')
    ap.add_argument('--set-password', metavar='USER', help='set the password of USER (creates the account), then exit')
    args = ap.parse_args()

    ROOT = os.path.realpath(APP_DIR)
    os.makedirs(args.data_dir, mode=0o700, exist_ok=True)
    ACCOUNTS = Accounts(os.path.join(args.data_dir, 'users.json'))
    SESSIONS, THROTTLE = Sessions(), Throttle()
    if args.set_password:
        return set_password(args.set_password)

    ctx = None
    if args.cert or args.key:
        if not (args.cert and args.key):
            raise SystemExit('Give both --cert and --key.')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(args.cert, args.key)
    httpd = Server((args.host, args.port), ctx, args.behind_proxy)
    scheme = 'https' if ctx else 'http'
    shown = f'[{args.host}]' if ':' in args.host else args.host
    log(f'ThreatSim on {scheme}://{shown}:{args.port}/  (accounts: {ACCOUNTS.path})')
    if ACCOUNTS.default_in_use():
        log(f'Warning: {DEFAULT_USER} still has the default password "{DEFAULT_PASSWORD}". Sign in and change it.')
    try:
        local = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        local = args.host == 'localhost'
    if not ctx and not local and not args.behind_proxy:
        log('Warning: serving plain HTTP on a network address: passwords cross the network unencrypted. '
            'Use --cert/--key, or a reverse proxy that serves HTTPS.')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


ACCOUNTS = SESSIONS = THROTTLE = ROOT = None

if __name__ == '__main__':
    main()
