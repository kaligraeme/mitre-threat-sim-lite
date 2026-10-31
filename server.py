#!/usr/bin/env python3
"""ThreatSim server: serves the app and makes everyone sign in before they can use it.

    python3 server.py                         # http://localhost:8000
    python3 server.py --host 0.0.0.0 --port 8443 --cert cert.pem --key key.pem
    python3 server.py --set-password admin    # set or reset a password (creates the account if new)

Without a session, only the sign-in page (login.html) and the stylesheet and script it needs are
served. Every other page and script, including the Data page (index.html) and the Simulator, needs
a signed-in session; a page asked for without one redirects to login.html, anything else gets 401.

Accounts are kept in <data dir>/users.json as PBKDF2-HMAC-SHA-256 hashes (310,000 iterations,
random salt), outside the app folder. On first start the file is created with the account
admin / admin. Sessions are an HttpOnly cookie holding a random token, kept in memory: restarting
the server signs everyone out. Only the Python standard library is used. The Threat Modelling tab's
optional Claude features (tm_claude.py) also need the Anthropic SDK and ANTHROPIC_API_KEY; without
them, or with an SDK that fails to load or is too old, the tab works offline and nothing is sent anywhere.
"""
import argparse
import collections
import contextlib
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

try:
    import tm_claude   # the Threat Modelling tab's optional Claude features (tm_claude.py, next to this file)
    TM_CLAUDE_PROBLEM = ''
except Exception as e:   # optional: a missing or broken tm_claude.py must never keep the server from starting
    tm_claude = None
    TM_CLAUDE_PROBLEM = ('tm_claude.py is missing.' if isinstance(e, ImportError) and e.name == 'tm_claude' else
                         f'tm_claude.py could not be loaded ({type(e).__name__}: {" ".join(str(e).split())[:160]}).')

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_USER = 'admin'
DEFAULT_PASSWORD = 'admin'
ITERATIONS = 310_000              # PBKDF2 rounds for new hashes; each record keeps its own count
SESSION_IDLE = 12 * 3600          # a session ends after this long without use (seconds)
MAX_ATTEMPTS = 5                  # wrong passwords for one username from one address before a pause
MAX_ADDR_ATTEMPTS = 20            # wrong passwords for any usernames from one address before a pause
FAIL_WINDOW = 15 * 60             # ... within this many seconds
LOCK_BASE = 30                    # the first pause; each further one doubles it ...
LOCK_MAX = 15 * 60                # ... up to this,
QUIET_RESET = 3600                # ... until this long passes without a wrong password
MIN_PASSWORD = 8                  # characters (Unicode code points)
MAX_FIELD = 1024                  # longest username or password accepted
MAX_BODY = 16 * 1024              # largest request body accepted (sign-in, password change)
TM_IMAGE_BODY = 6 * 1024 * 1024   # a diagram picture sent for Claude to read (base64 in JSON; the page sends under 5 MB)
TM_TEXT_BODY = 2 * 1024 * 1024    # a draft threat register sent for Claude to write up
TM_BODY_GRACE = 15                # seconds either may take to get going; from then on ...
TM_BODY_RATE = 8 * 1024           # ... it must have kept up at least this many bytes a second, however long it takes
TM_BODY_TIME = 120                # seconds a refused body is read for, so the client sees the answer
TM_PARSE = threading.BoundedSemaphore(2)   # bodies read as JSON at once (a picture takes a few times its size meanwhile)
MAX_CONNECTIONS = 128             # open connections at once; more are dropped
PAGES = ('index.html', 'simulator.html', 'threatmodel.html')   # signed-in pages sign-in may return to
PUBLIC = {'login.html', 'css/app.css', 'js/login.js'}  # served without a session
ROOT_FILES = {'index.html', 'simulator.html', 'threatmodel.html', 'login.html'}
SERVED_DIRS = ('css/', 'js/', 'examples/')
TYPES = {
    '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8', '.json': 'application/json',
    '.txt': 'text/plain; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
    '.ico': 'image/x-icon', '.woff2': 'font/woff2',
    '.drawio': 'text/plain; charset=utf-8',   # the page reads it as text; an XML type would run scripts in the file
}
TM_POSTS = {'api/tm/decompose': TM_IMAGE_BODY, 'api/tm/enrich': TM_TEXT_BODY, 'api/tm/cancel': MAX_BODY}   # route -> largest body
TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{32,128}')
LENGTH_RE = re.compile(r'[0-9]{1,9}')
DUMMY_SALT = bytes(16)
HASH_SLOTS = threading.BoundedSemaphore(max(1, min(4, os.cpu_count() or 1)))   # hashes running at once
WRITE_CHUNK = 64 * 1024           # the 30 s socket timeout applies to each chunk, not to a whole file


LOG_LOCK = threading.Lock()


def log(msg):
    """One line on stderr, written whole: lines from different threads never run together."""
    with LOG_LOCK:
        sys.stderr.write(f'{msg}\n')
        sys.stderr.flush()


def default_data_dir():
    """Where users.json lives unless --data-dir says otherwise: outside the app folder, so that serving
    the folder with another web server by mistake can never publish the password hashes."""
    legacy = os.path.join(APP_DIR, '.threatsim')
    if os.path.exists(os.path.join(legacy, 'users.json')):
        return legacy   # where the first version kept it; main() warns
    base = os.environ.get('XDG_DATA_HOME') or (os.environ.get('LOCALAPPDATA') if os.name == 'nt' else None) \
        or os.path.join(os.path.expanduser('~'), '.local', 'share')
    return os.path.join(base, 'threatsim')


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
    on disk (for --set-password while the server runs) and written atomically with mode 0600. The copy in
    memory changes only once a write has succeeded."""

    def __init__(self, path, create_default=True):
        self.path = path
        self.lock = threading.Lock()
        self.users, self.stamp = {}, None
        if not os.path.exists(path):
            if not create_default:
                return   # --set-password on a new data dir: nothing is written until a password is accepted
            self._save({DEFAULT_USER: make_record(DEFAULT_PASSWORD, is_default=True)})
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
        except FileNotFoundError:
            if self.stamp is not None:
                log(f'Warning: {self.path} has gone; still using the accounts loaded before.')
        except PermissionError:   # keep the accounts already loaded; never fall back to a default
            if self.stamp is None:
                raise SystemExit(f'Cannot read the accounts file {self.path}: permission denied. Make it owned by '
                                 'the account that runs the server (run --set-password as that account).')
            log(f'Warning: cannot read {self.path} (permission denied); still using the accounts loaded before.')
        except (OSError, ValueError) as e:
            if self.stamp is None:
                raise SystemExit(f'Cannot read the accounts file {self.path}: {e}. Fix it, or move it away to '
                                 f'start again with {DEFAULT_USER} / {DEFAULT_PASSWORD}.')
            log(f'Warning: cannot re-read {self.path} ({e}); still using the accounts loaded before.')

    def _owner(self):
        """When root writes the file (sudo --set-password), keep it with the account that owns the data."""
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            return None
        for p in (self.path, os.path.dirname(self.path)):
            try:
                st = os.stat(p)
            except OSError:
                continue
            return (st.st_uid, st.st_gid) if st.st_uid != 0 else None
        return None

    def _save(self, users):
        tmp = f'{self.path}.{os.getpid()}.tmp'
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump({'users': users}, f, indent=1)
                f.flush()
                os.fsync(f.fileno())
            owner = self._owner()
            if owner:
                os.chown(tmp, *owner)
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        st = os.stat(self.path)
        self.users, self.stamp = users, (st.st_mtime_ns, st.st_size)

    def get(self, user):
        with self.lock:
            self._reload()
            rec = self.users.get(user)
            return dict(rec) if isinstance(rec, dict) else None

    def set(self, user, rec, expect=None):
        """Save rec as user's record. With expect (a hash), only if the stored record still has that
        hash: returns False if it changed meanwhile. Raises OSError if the file can't be written."""
        with self.lock:
            self._reload()
            if expect is not None and (self.users.get(user) or {}).get('hash') != expect:
                return False
            users = dict(self.users)
            users[user] = rec
            self._save(users)
            return True

    def default_in_use(self):
        rec = self.get(DEFAULT_USER)
        return bool(rec and rec.get('isDefault'))


# ---------- sessions and failed sign-ins ----------

class Sessions:
    """Signed-in sessions, in memory, keyed by a hash of the cookie token. A session ends after
    SESSION_IDLE seconds without use, at sign-out, or when its account's password changes (its stamp
    no longer matches the account's hash). on_end(key) is called for each session that ends."""

    def __init__(self, on_end=None):
        self.lock = threading.Lock()
        self.live = {}    # key -> {'user', 'stamp', 'last'}   (last: time.monotonic())
        self.ended = {}   # key -> (reason, when): why a recent session ended, kept for a day
        self.on_end = on_end

    def _ended(self, keys):
        """Tell on_end about sessions that have ended (outside the lock)."""
        for k in keys if self.on_end else ():
            try:
                self.on_end(k)
            except Exception as e:   # what follows a session's end never stops it ending
                log(f'Error: after a session ended: {type(e).__name__}')

    @staticmethod
    def key(token):
        return hashlib.sha256(token.encode('ascii')).hexdigest()

    def create(self, user, stamp):
        token = secrets.token_urlsafe(32)
        with self.lock:
            expired = self._prune()
            self.live[self.key(token)] = {'user': user, 'stamp': stamp, 'last': time.monotonic()}
        self._ended(expired)
        return token

    def get(self, token, touch):
        """(session, None) or (None, reason): 'expired', 'signedout', 'password', or 'ended' for a token
        this server doesn't know (it was restarted, or the session ended over a day ago)."""
        k, now = self.key(token), time.monotonic()
        with self.lock:
            s = self.live.get(k)
            if s is None:
                return None, self.ended.get(k, ('ended', 0))[0]
            if now - s['last'] < SESSION_IDLE:
                if touch:
                    s['last'] = now
                return dict(s), None
            del self.live[k]
            self.ended[k] = ('expired', now)
        self._ended([k])
        return None, 'expired'

    def end(self, token, reason='signedout'):
        k = self.key(token)
        with self.lock:
            ended = self.live.pop(k, None) is not None
            if ended:
                self.ended[k] = (reason, time.monotonic())
        self._ended([k] if ended else [])

    def end_user(self, user, keep, reason):
        """End every session of user but keep's (a token)."""
        spare, now = self.key(keep), time.monotonic()
        with self.lock:
            keys = [k for k, s in self.live.items() if s['user'] == user and k != spare]
            for k in keys:
                del self.live[k]
                self.ended[k] = (reason, now)
        self._ended(keys)

    def _prune(self):
        """Forget what is old; returns the keys of the sessions that expire now."""
        now = time.monotonic()
        expired = [k for k, s in self.live.items() if now - s['last'] >= SESSION_IDLE]
        for k in expired:
            del self.live[k]
            self.ended[k] = ('expired', now)
        for k in [k for k, (_, t) in self.ended.items() if now - t > 86400]:
            del self.ended[k]
        return expired


class Throttle:
    """Wrong passwords per key (an address and username, an address, an account). `limit` of them within
    FAIL_WINDOW start a pause of LOCK_BASE seconds; each further pause doubles it (up to LOCK_MAX) until an
    hour passes without a wrong password. Right passwords neither count nor keep old failures alive. A check
    must be reserved with begin() before it runs, and no more checks can run at once than there are
    attempts left, so attempts sent at the same moment can't overrun the limit."""

    def __init__(self, limit, forget_on_success):
        self.limit = limit
        self.forget_on_success = forget_on_success   # a right password clears the key's failures
        self.lock = threading.Lock()
        self.entries = {}

    def _entry(self, key, now):
        e = self.entries.get(key)
        if e and (e['busy'] or now - e['last'] < QUIET_RESET):
            while e['fails'] and now - e['fails'][0] >= FAIL_WINDOW:
                e['fails'].popleft()
            return e
        e = {'fails': collections.deque(), 'locks': 0, 'until': 0.0, 'busy': 0, 'last': now}   # last: last wrong password
        self.entries[key] = e
        if len(self.entries) > 10000:
            for k in [k for k, x in self.entries.items() if not x['busy'] and now - x['last'] >= QUIET_RESET]:
                del self.entries[k]
            self.entries[key] = e
        return e

    def wait(self, key):
        now = time.monotonic()
        with self.lock:
            e = self.entries.get(key)
            return max(0, math.ceil(e['until'] - now)) if e else 0

    def begin(self, key):
        """Reserve a check. Returns 0 if it may run, else the seconds to wait."""
        now = time.monotonic()
        with self.lock:
            e = self._entry(key, now)
            if e['until'] > now:
                return math.ceil(e['until'] - now)
            if len(e['fails']) + e['busy'] >= self.limit:
                return 1   # as many checks running as attempts left: try again in a moment
            e['busy'] += 1
            return 0

    def failed(self, key):
        """A reserved check failed. Returns (seconds paused, attempts left before the next pause)."""
        now = time.monotonic()
        with self.lock:
            e = self._entry(key, now)
            e['busy'] = max(0, e['busy'] - 1)
            e['fails'].append(now)
            e['last'] = now
            if len(e['fails']) >= self.limit:
                e['fails'].clear()
                e['locks'] += 1
                e['until'] = now + min(LOCK_BASE * 2 ** (e['locks'] - 1), LOCK_MAX)
            return max(0, math.ceil(e['until'] - now)), self.limit - len(e['fails'])

    def release(self, key):
        """Give back a reservation whose check didn't run."""
        with self.lock:
            e = self.entries.get(key)
            if e:
                e['busy'] = max(0, e['busy'] - 1)

    def passed(self, key):
        """A reserved check passed."""
        with self.lock:
            e = self.entries.get(key)
            if not e:
                return
            e['busy'] = max(0, e['busy'] - 1)
            if self.forget_on_success:
                e['fails'].clear()
                if not e['busy'] and e['until'] <= time.monotonic():
                    del self.entries[key]


def check_throttled(buckets, check):
    """Run check() unless one of the (throttle, key) buckets is paused, counting the result in each.
    Returns (ok, seconds paused, attempts left)."""
    taken = []
    for thr, key in buckets:
        wait = thr.begin(key)
        if wait:
            for t, k in taken:
                t.release(k)
            return False, wait, 0
        taken.append((thr, key))
    try:
        ok = bool(check())
    except BaseException:
        for t, k in taken:
            t.failed(k)
        raise
    if ok:
        for t, k in taken:
            t.passed(k)
        return True, 0, None
    results = [t.failed(k) for t, k in taken]
    return False, max(w for w, _ in results), min(left for _, left in results)


# ---------- HTTP ----------

def next_page(value):
    return value if value in PAGES else PAGES[0]


def servable(path):
    """Only the app's own pages, stylesheets and scripts are ever served: never server.py, the README or
    anything else in the folder."""
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
    timeout = 30   # seconds a connection may sit idle, or take to send or receive one chunk
    disable_nagle_algorithm = True   # send each answer at once, without waiting for the client's ACK

    def version_string(self):
        return self.server_version

    def parse_request(self):
        if not super().parse_request():
            return False
        if self.request_version == 'HTTP/0.9':   # no headers, so no cookie or origin to check
            self.close_connection = True
            return False
        return True

    # ----- request helpers -----

    def header(self, name, default=''):
        """A request header; safe before the headers are parsed (errors in the request line)."""
        headers = getattr(self, 'headers', None)
        value = headers.get(name) if hasattr(headers, 'get') else None
        return default if value is None else value

    def peer_is_proxy(self):
        if not self.server.behind_proxy:
            return False
        try:
            ip = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        ip = getattr(ip, 'ipv4_mapped', None) or ip   # ::ffff:127.0.0.1 on a dual-stack socket
        return ip.is_loopback

    def client_addr(self):
        if self.peer_is_proxy():
            last = self.header('X-Forwarded-For').split(',')[-1].strip()
            if last:
                return last
        return self.client_address[0]

    def address_string(self):   # for the access log
        return self.client_addr()

    def is_https(self):
        if self.server.tls:
            return True
        return self.peer_is_proxy() and self.header('X-Forwarded-Proto').strip().lower() == 'https'

    def public_host(self):
        if self.peer_is_proxy() and self.header('X-Forwarded-Host'):
            return self.header('X-Forwarded-Host').split(',')[0].strip()
        return self.header('Host')

    def same_origin(self):
        """POSTs must come from a page at this server's own address (Origin, else Referer)."""
        source = self.header('Origin') or self.header('Referer')
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
        # one name per instance (cookies ignore the port and the path), so two servers on one host name
        # don't sign each other out
        return f'__Host-threatsim-{self.server.instance}' if self.is_https() else f'threatsim-{self.server.instance}'

    def cookie_token(self):
        name = self.cookie_name()
        get_all = getattr(getattr(self, 'headers', None), 'get_all', None)
        for header in (get_all('Cookie') if get_all else None) or []:
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

    def body_length(self):
        """The declared body length: None for no body, -1 when it can't be trusted (chunked, several or bad
        Content-Length headers), else the number of bytes."""
        get_all = getattr(getattr(self, 'headers', None), 'get_all', None)
        values = (get_all('Content-Length') if get_all else None) or []
        if self.header('Transfer-Encoding') or len(values) > 1:
            return -1
        if not values:
            return None
        value = values[0].strip()
        return int(value) if LENGTH_RE.fullmatch(value) else -1

    def read_body(self, limit=MAX_BODY):
        """The request body as bytes, or None after replying with an error."""
        n = self.body_length()
        if n is None:
            return b''   # no length and no chunking: no body
        if n < 0:
            self.close_connection = True
            self.reply(400, 'Send the body with one plain Content-Length.')
            return None
        if n > limit:
            self.close_connection = True
            self.reply(413, 'Request too large.')
            return None
        return self.rfile.read(n)

    def form(self, body):
        """Fields from a form-encoded or JSON body: {name: str}."""
        ctype = self.header('Content-Type').split(';')[0].strip().lower()
        try:
            if ctype == 'application/json':
                data = json.loads(body.decode('utf-8'))
                return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(data, dict) else {}
            if ctype == 'application/x-www-form-urlencoded':
                return {k: v[0] for k, v in urllib.parse.parse_qs(body.decode('utf-8'), keep_blank_values=True).items()}
        except (UnicodeDecodeError, ValueError, RecursionError):
            pass
        return {}

    def wants_json(self):
        return 'application/json' in self.header('Accept')

    # ----- responses -----

    def security_headers(self, page=False):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        # the app's own pages run their scripts; anything else opened on its own (a diagram, an SVG) runs none
        self.send_header('Content-Security-Policy', "frame-ancestors 'none'" if page else "sandbox; frame-ancestors 'none'")
        self.send_header('Referrer-Policy', 'same-origin')
        if self.is_https():
            self.send_header('Strict-Transport-Security', 'max-age=31536000')

    def reply(self, status, body=b'', ctype='text/plain; charset=utf-8', headers=(), head=False, page=False):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(status)
        self.security_headers(page)
        for k, v in headers:
            self.send_header(k, v)
        if not any(k.lower() == 'cache-control' for k, _ in headers):
            self.send_header('Cache-Control', 'no-store')
        if body or status not in (204, 304):
            self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body and not head and self.command != 'HEAD':
            for i in range(0, len(body), WRITE_CHUNK):
                self.wfile.write(body[i:i + WRITE_CHUNK])

    def reply_json(self, status, data, headers=()):
        try:
            body = json.dumps(data, allow_nan=False)
        except (TypeError, ValueError):   # never send what a browser can't read as JSON (inf, nan, an object)
            log(f'Error: the answer to {self.command} {self.path.split("?")[0]} could not be written as JSON')
            status, body = 500, json.dumps({'ok': False, 'error': 'The server could not write its answer. Try again.'})
        self.reply(status, body, 'application/json', headers)

    def redirect(self, location, status=302, headers=()):
        self.reply(status, b'', headers=[('Location', location), *headers])

    def session_cookie(self, token):
        attrs = 'Path=/; HttpOnly; SameSite=Lax' + ('; Secure' if self.is_https() else '')
        if token is None:
            return 'Set-Cookie', f'{self.cookie_name()}=; Max-Age=0; {attrs}'
        return 'Set-Cookie', f'{self.cookie_name()}={token}; {attrs}'

    def send_file(self, path, head, session=None, headers=()):
        full = os.path.realpath(os.path.join(ROOT, *path.split('/')))
        # the file itself, not a link to some other file (a link could lead anywhere in or out of the folder)
        if os.path.relpath(full, ROOT).replace(os.sep, '/') != path or not os.path.isfile(full):
            return self.reply(404, 'Not found.')
        ctype = TYPES[os.path.splitext(path)[1].lower()]
        if path in ROOT_FILES:   # the app's own pages; any other HTML file is served like the rest, in a sandbox
            with open(full, 'rb') as f:
                body = f.read()
            if session:   # tell the page who is signed in (auth.js reads these)
                attrs = ' data-user="%s" data-default-password="%s"' % (
                    html.escape(session['user'], quote=True), 'true' if session['isDefault'] else 'false')
                text = body.decode('utf-8')
                i = text.find('<html')
                if i >= 0:
                    body = (text[:i + 5] + attrs + text[i + 5:]).encode('utf-8')
            return self.reply(200, body, ctype, headers=headers, head=head, page=True)
        st = os.stat(full)
        modified = formatdate(st.st_mtime, usegmt=True)
        cache = [('Cache-Control', 'no-cache' if path in PUBLIC else 'private, no-cache'), ('Last-Modified', modified)]
        since = self.header('If-Modified-Since')
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
        if self.body_length() not in (None, 0):
            self.close_connection = True   # a body nobody reads: don't let it be taken for the next request
        path, query = self.split_target()
        if path is None:
            return self.reply(400, 'Bad request.')
        if path == 'api/session':
            if head:
                return self.reply(405, 'Use GET.', headers=[('Allow', 'GET')])
            return self.api_session(query)
        if path in ('api/tm/status', 'api/tm/job'):
            if head:
                return self.reply(405, 'Use GET.', headers=[('Allow', 'GET')])
            return self.api_tm(path, query)
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
        return self.send_file(path, head, session=s if path in ROOT_FILES else None)

    def do_POST(self):
        path, _ = self.split_target()
        if path in TM_POSTS:
            return self.post_tm(path)
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

    # ----- Threat Modelling: Claude (optional, see tm_claude.py) -----

    def tm_session(self):
        """The signed-in session for an api/tm/ call, or None after replying 401."""
        s, reason = self.current_session(touch=False)
        if not s:
            clear = [self.session_cookie(None)] if reason else []
            self.reply_json(401, {'ok': False, 'error': 'Your session has ended. Sign in again.'}, headers=clear)
        return s

    def tm_state(self):
        return tm_claude.status() if tm_claude else {'available': False, 'model': '', 'reason': TM_CLAUDE_PROBLEM}

    def tm_limits(self):
        """The most one enrichment may hold (the page trims its request to these)."""
        return dict(tm_claude.LIMITS, bytes=TM_TEXT_BODY)

    def api_tm(self, path, query):
        """GET api/tm/status: can Claude be used here, and with what limits? GET api/tm/job?id=: a Claude job's kind,
        status (running, done, failed or cancelled), progress, and its result or error once it has ended."""
        s = self.tm_session()
        if not s:
            return
        state = self.tm_state()
        if path == 'api/tm/status':
            answer = {'ok': True, 'claude': state['available'], 'available': state['available'], 'model': state['model']}
            if state['available']:
                answer['limits'] = self.tm_limits()
            return self.reply_json(200, answer)
        job = tm_claude.JOBS.get(s['user'], (query.get('id') or [''])[0]) if tm_claude else None
        if not job:
            return self.reply_json(404, {'ok': False, 'error': 'That Claude request is not known here (it may have been '
                                         'released or have expired, or the server was restarted).'})
        self.reply_json(200, dict(job, ok=True))

    def read_tm_body(self, n, limit=None):
        """n bytes of body, or None after answering 408 (or when the client went away). However large it is, the body
        must keep coming: from TM_BODY_GRACE seconds after it starts, at least TM_BODY_RATE bytes a second on average.
        So a slow line has all the time a large picture needs, while a body that trickles in, or stalls, is let go
        within seconds. With limit (seconds), its bytes are dropped instead, and reading stops at that limit."""
        start, chunks, got, slow = time.monotonic(), [], 0, False
        try:
            while got < n:
                left = start + TM_BODY_GRACE + got / TM_BODY_RATE - time.monotonic()   # until it falls behind
                if limit is not None:
                    left = min(left, start + limit - time.monotonic())
                if left <= 0:
                    raise TimeoutError
                self.connection.settimeout(min(left, self.timeout))   # a read waits no longer than that
                chunk = self.rfile.read1(min(WRITE_CHUNK, n - got))
                if not chunk:
                    break   # the client went away
                if limit is None:
                    chunks.append(chunk)
                got += len(chunk)
        except TimeoutError:
            slow = True
        finally:
            self.connection.settimeout(self.timeout)
        if got >= n:
            return b''.join(chunks)
        self.close_connection = True
        if slow and limit is None:
            self.reply_json(408, {'ok': False, 'error': 'The request came in too slowly, or stopped coming. Try again.'})
        return None

    def discard_body(self, n):
        """Read and drop n bytes of body, so the client sees the answer instead of a reset connection; the connection
        is closed after the answer if they don't keep coming, or take over TM_BODY_TIME seconds."""
        self.read_tm_body(n, limit=TM_BODY_TIME)

    def post_tm(self, path):
        """POST api/tm/decompose or api/tm/enrich: start a Claude job and answer 202 with its id and kind; the page polls
        api/tm/job. A user with a job running gets 429 with that job's id and kind; a busy server 429 too, a body that
        comes in too slowly 408, and a job the host can't start a thread for 503. POST api/tm/cancel: see below."""
        s = self.tm_session()   # before reading a large body
        if not s:
            self.close_connection = True
            return
        if not self.same_origin():
            self.close_connection = True
            return self.reply_json(403, {'ok': False, 'reason': 'origin', 'error': "The request didn't come from this site."})
        if path == 'api/tm/cancel':
            return self.post_tm_cancel(s)
        if not self.tm_state()['available']:
            self.close_connection = True
            return self.reply_json(503, {'ok': False, 'error': 'Claude is not set up on this server.'})
        if self.header('Content-Type').split(';')[0].strip().lower() != 'application/json':
            self.close_connection = True
            return self.reply_json(415, {'ok': False, 'error': 'Send the request as JSON.'})
        n, limit = self.body_length(), TM_POSTS[path]
        if n is not None and n < 0:
            self.close_connection = True
            return self.reply_json(400, {'ok': False, 'error': 'Send the body with one plain Content-Length.'})
        n = n or 0
        if n > limit:
            self.close_connection = True
            what = 'picture' if path == 'api/tm/decompose' else 'draft threat register'
            return self.reply_json(413, {'ok': False, 'error': f'The {what} is too large to send to Claude (at most {limit // 2**20} MB).'})
        kind = path.rsplit('/', 1)[-1]
        # reserved before the body is read: one request per user at a time, and a few bodies arriving at once in all
        # (they don't hold a place among the jobs running)
        job, busy = tm_claude.JOBS.reserve(s['user'], kind, owner=Sessions.key(s['token']))
        if busy:
            self.discard_body(n)
            return self.reply_json(429, dict(busy, ok=False))
        handled = False
        try:
            body = self.read_tm_body(n)
            if body is None:
                return
            with TM_PARSE:
                if path == 'api/tm/decompose' and body.count(b'{') + body.count(b'[') > 64:   # a picture is one small object
                    return self.reply_json(400, {'ok': False, 'error': 'Send one picture with its media type, width and height.'})
                try:
                    data = json.loads(body.decode('utf-8'))
                except (UnicodeDecodeError, ValueError, RecursionError):
                    data = None
                if not isinstance(data, dict):
                    return self.reply_json(400, {'ok': False, 'error': 'Send a JSON object.'})
                if path == 'api/tm/decompose':
                    fn, checked = tm_claude.decompose, tm_claude.check_decompose(data)
                else:
                    fn, checked = tm_claude.enrich, tm_claude.check_enrichment(data)
            del body, data
            started = tm_claude.JOBS.start(job, fn, checked)   # False: stopped while it arrived (it stays, cancelled)
            handled = True
        except tm_claude.Refused as e:   # the wrong shape (400), over a limit (413), busy (429), no thread (503)
            answer = {'ok': False, 'error': str(e)}
            if e.status == 413:
                answer['limits'] = self.tm_limits()
            return self.reply_json(e.status, answer)
        except Exception as e:   # never a traceback for what a client sent
            log(f'{self.address_string()} {s["user"]}: Claude request not started ({type(e).__name__})')
            self.close_connection = True
            return self.reply_json(400, {'ok': False, 'error': "The request couldn't be read."})
        finally:
            if not handled:
                tm_claude.JOBS.release(job)
        log(f'{self.address_string()} {s["user"]}: Claude job {job.id[:6]} ' + (f'started ({kind})' if started else 'stopped before it started'))
        self.reply_json(202, {'ok': True, 'job': job.id, 'kind': kind})

    def post_tm_cancel(self, s):
        """POST api/tm/cancel {"job": id}: stop this user's running job (it sends no more requests to Claude and ends
        'cancelled' with whatever it has), or release a finished job's result. With "release": false a finished job is
        left as it is (a page that is closing stops its job this way, so a result that came after its last poll isn't
        lost). Answers {ok, status: 'cancelled', 'released' or 'ended'}, or 404 for a job this user doesn't have."""
        body = self.read_body()
        if body is None:
            return
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except (UnicodeDecodeError, ValueError, RecursionError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        query = self.split_target()[1]
        jid = data.get('job')
        if not isinstance(jid, str):
            jid = (query.get('id') or [''])[0]
        keep = data.get('release') is False or (query.get('release') or [''])[0] in ('0', 'false')
        outcome = tm_claude.JOBS.cancel(s['user'], jid, release=not keep) if tm_claude and jid else None
        if not outcome:
            return self.reply_json(404, {'ok': False, 'error': 'That Claude request is not known here (it may have been '
                                         'released or have expired, or the server was restarted).'})
        if outcome == 'cancelled':
            log(f'{self.address_string()} {s["user"]}: Claude job {jid[:6]} cancelled')
        self.reply_json(200, {'ok': True, 'status': outcome})

    def post_login(self, fields):
        addr = self.client_addr()
        nxt = next_page(fields.get('next', ''))
        username, password = fields.get('username', ''), fields.get('password', '')
        user, pw = normalize_user(username[:MAX_FIELD * 4]), normalize_password(password[:MAX_FIELD * 4])
        rec = ACCOUNTS.get(user) if user and len(username) <= MAX_FIELD else None

        def check():
            if rec and len(pw) <= MAX_FIELD:
                return verify(rec, pw)
            pbkdf2(pw[:MAX_FIELD], DUMMY_SALT, ITERATIONS)   # an unknown user, or a password too long to be one: same time
            return False

        # per username from this address (one person's typos don't pause colleagues behind the same
        # address), and per address (against trying many usernames)
        ok, wait, left = check_throttled([(USER_TRIES, (addr, user)), (ADDR_TRIES, addr)], check)
        if ok:
            old = self.cookie_token()
            token = SESSIONS.create(user, rec['hash'])
            if old:   # a fresh token for every sign-in; a Claude job this browser runs for this account goes on under it
                was, _ = SESSIONS.get(old, touch=False)
                if was and was['user'] == user and tm_claude:
                    tm_claude.JOBS.hand_over(Sessions.key(old), Sessions.key(token))
                SESSIONS.end(old)
            cookie = self.session_cookie(token)
            if self.wants_json():
                return self.reply_json(200, {'ok': True, 'next': nxt}, headers=[cookie])
            return self.redirect(nxt, 303, headers=[cookie])
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
            SESSIONS.end(token)   # which also stops the Claude job this session runs (claude_session_ended)
        cookie = self.session_cookie(None)
        if self.wants_json():
            return self.reply_json(200, {'ok': True}, headers=[cookie])
        return self.redirect('login.html?ended=signedout', 303, headers=[cookie])

    def post_password(self, fields):
        s, reason = self.current_session(touch=True)
        if not s:
            return self.reply_json(401, {'ok': False, 'reason': 'session', 'ended': reason or 'ended'})
        current = normalize_password(fields.get('current', ''))
        new = normalize_password(fields.get('next', ''))
        confirm = normalize_password(fields.get('confirm', ''))
        if not current:
            return self.reply_json(400, {'ok': False, 'field': 'current', 'message': 'Enter your current password.'})
        problem = password_problem(s['user'], current, new, confirm)
        if problem:
            return self.reply_json(400, {'ok': False, 'field': problem[0], 'message': problem[1]})
        verified = s['stamp']   # the hash this session was signed in with
        ok, wait, _ = check_throttled([(PASSWORD_TRIES, s['user'])],
                                      lambda: len(current) <= MAX_FIELD and verify(ACCOUNTS.get(s['user']), current))
        if wait:
            return self.reply_json(429, {'ok': False, 'reason': 'locked', 'wait': wait,
                                         'message': f'Too many wrong passwords. Try again in {wait} seconds.'},
                                   headers=[('Retry-After', str(wait))])
        if not ok:
            return self.reply_json(400, {'ok': False, 'field': 'current', 'message': 'The current password is not right.'})
        rec = make_record(new)
        try:
            saved = ACCOUNTS.set(s['user'], rec, expect=verified)
        except OSError as e:
            log(f'Error: cannot save {ACCOUNTS.path}: {e}')
            return self.reply_json(500, {'ok': False, 'message': 'The server could not save the new password, so it '
                                         'was not changed. Tell whoever runs the server.'})
        if not saved:
            return self.reply_json(409, {'ok': False, 'message': 'The password was changed somewhere else meanwhile, '
                                         'so this change was not made.'})
        # a new token for this browser: the old one, and any copy of it, ends with the old password, as do the account's
        # sessions in other browsers (and the Claude jobs they run); a Claude job this browser runs goes on under the new one
        token = SESSIONS.create(s['user'], rec['hash'])
        if tm_claude:
            tm_claude.JOBS.hand_over(Sessions.key(s['token']), Sessions.key(token))
        SESSIONS.end(s['token'], 'password')
        SESSIONS.end_user(s['user'], keep=token, reason='password')
        self.reply_json(200, {'ok': True}, headers=[self.session_cookie(token)])


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS   # connections waiting to be accepted (socketserver's default is 5)

    def __init__(self, addr, tls_context, behind_proxy, instance):
        self.tls = tls_context is not None
        self.behind_proxy = behind_proxy
        self.instance = instance   # names the session cookie
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        if ':' in addr[0]:
            self.address_family = socket.AF_INET6
        super().__init__(addr, Handler)
        if tls_context:   # handshakes run in each connection's thread, not in the accept loop
            self.socket = tls_context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)   # too many open connections: drop this one
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError, socket.timeout, ssl.SSLError)):
            return   # a client that went away, timed out or didn't speak TLS: not worth a traceback
        super().handle_error(request, client_address)


def claude_session_ended(key):
    """A session has ended: stop the Claude jobs started in it. Their results wait for their user to sign in again."""
    for jid, user in tm_claude.JOBS.session_ended(key) if tm_claude else ():
        log(f'{user}: Claude job {jid[:6]} stopped, as the session that started it has ended')


def instance_id(data_dir, port):
    """A random id kept in the data dir, naming this instance's session cookie. Falls back to the port."""
    path = os.path.join(data_dir, 'instance')
    try:
        with open(path, encoding='ascii') as f:
            value = f.read().strip()
        if re.fullmatch(r'[0-9a-f]{8}', value):
            return value
    except (OSError, ValueError):
        pass
    value = secrets.token_hex(4)
    try:
        with open(path, 'w', encoding='ascii') as f:
            f.write(value + '\n')
        return value
    except OSError:
        return str(port)


def port_number(text):
    n = int(text)
    if not 0 <= n <= 65535:
        raise argparse.ArgumentTypeError('a port is 0 to 65535')
    return n


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
            try:
                ACCOUNTS.set(user, make_record(new))
            except OSError as e:
                raise SystemExit(f'Cannot save {ACCOUNTS.path}: {e.strerror or e}. Password not changed.')
            print(f'Saved in {ACCOUNTS.path}. A running server signs this account out of its sessions.')
            return
        print(problem[1])
    raise SystemExit('Password not changed.')


def main():
    global ACCOUNTS, SESSIONS, USER_TRIES, ADDR_TRIES, PASSWORD_TRIES, ROOT
    ap = argparse.ArgumentParser(description='Serve ThreatSim and require sign-in.')
    ap.add_argument('--host', default='127.0.0.1', help='address to listen on (default 127.0.0.1; 0.0.0.0 for all)')
    ap.add_argument('--port', type=port_number, default=8000)
    ap.add_argument('--data-dir', help='where users.json is kept (default ~/.local/share/threatsim)')
    ap.add_argument('--cert', help='TLS certificate (PEM) to serve HTTPS')
    ap.add_argument('--key', help='private key for --cert (PEM)')
    ap.add_argument('--behind-proxy', action='store_true',
                    help='trust X-Forwarded-For/-Proto/-Host from a reverse proxy on this machine')
    ap.add_argument('--set-password', metavar='USER', help='set the password of USER (creates the account), then exit')
    args = ap.parse_args()

    ROOT = os.path.realpath(APP_DIR)
    data_dir = os.path.abspath(args.data_dir or default_data_dir())
    try:
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        ACCOUNTS = Accounts(os.path.join(data_dir, 'users.json'), create_default=not args.set_password)
    except OSError as e:
        raise SystemExit(f'Cannot use the data directory {data_dir}: {e.strerror or e}. Choose another with --data-dir.')
    SESSIONS = Sessions(on_end=claude_session_ended)
    USER_TRIES = Throttle(MAX_ATTEMPTS, forget_on_success=True)
    ADDR_TRIES = Throttle(MAX_ADDR_ATTEMPTS, forget_on_success=False)
    PASSWORD_TRIES = Throttle(MAX_ATTEMPTS, forget_on_success=True)
    if args.set_password:
        return set_password(args.set_password)
    if os.path.realpath(data_dir).startswith(ROOT + os.sep):
        log(f'Warning: the accounts file is inside the app folder ({data_dir}). Move it out and point --data-dir '
            'at it, so that serving the folder some other way can never publish it.')

    ctx = None
    if args.cert or args.key:
        if not (args.cert and args.key):
            raise SystemExit('Give both --cert and --key.')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(args.cert, args.key)
        except (OSError, ssl.SSLError) as e:
            raise SystemExit(f'Cannot load --cert {args.cert} and --key {args.key}: {getattr(e, "strerror", None) or e}')
    try:
        httpd = Server((args.host, args.port), ctx, args.behind_proxy, instance_id(data_dir, args.port))
    except OSError as e:   # address in use, no such address, no IPv6 ...
        raise SystemExit(f'Cannot listen on {args.host} port {args.port}: {e.strerror or e}')
    port = httpd.server_address[1]
    scheme = 'https' if ctx else 'http'
    try:
        ip = ipaddress.ip_address(args.host)
        local, wildcard = ip.is_loopback, ip.is_unspecified
    except ValueError:
        local, wildcard = args.host == 'localhost', False
    if args.host in ('127.0.0.1', '::1', 'localhost'):
        where = 'localhost'   # the name browsers and the README use for this machine
    else:
        where = "<this computer's address>" if wildcard else f'[{args.host}]' if ':' in args.host else args.host
    log(f'ThreatSim on {scheme}://{where}:{port}/  (accounts: {ACCOUNTS.path})')
    claude = tm_claude.status() if tm_claude else {'available': False, 'reason': TM_CLAUDE_PROBLEM}
    if claude['available']:
        daily = f' (each user at most {tm_claude.JOBS_PER_DAY} Claude jobs a day)' if tm_claude.JOBS_PER_DAY else ''
        fallback = ', with Anthropic\'s server-side fallback' if claude.get('fallback') else ', no server-side fallback'
        log(f'Threat Modelling: Claude is on ({claude["model"]}{fallback}); pictures and draft registers go to Anthropic\'s '
            f'API when a user asks{daily}.')
    else:
        log(f'Threat Modelling: Claude is off ({claude["reason"].rstrip(".")}). The tab works offline.')
    if ACCOUNTS.default_in_use():
        log(f'Warning: {DEFAULT_USER} still has the default password "{DEFAULT_PASSWORD}". Sign in and change it.')
    if not ctx and not local and not args.behind_proxy:
        log('Warning: serving plain HTTP on a network address: passwords cross the network unencrypted. '
            'Use --cert/--key, or a reverse proxy that serves HTTPS.')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if tm_claude:
            tm_claude.shutdown()   # no more Claude requests; its threads don't hold up the exit
        httpd.server_close()


ACCOUNTS = SESSIONS = USER_TRIES = ADDR_TRIES = PASSWORD_TRIES = ROOT = None

if __name__ == '__main__':
    main()
