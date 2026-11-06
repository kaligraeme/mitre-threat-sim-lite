/*
 * mappings-db.js — CTID Mappings Explorer data: NIST SP 800-53 Rev 5 controls mapped to ATT&CK techniques,
 * pulled from GitHub into a local IndexedDB database of its own (`threatsim-mappings`).
 *
 * Exposes a global `MappingsDB`. The mappings are kept apart from `mitre-attack-db` on purpose: the Data and
 * Threat Profile pages treat every row of that database's `meta` store as an ATT&CK or ATLAS knowledge base.
 *
 * Stores
 *   meta     one row per source: version, files, pulled-at, counts           keyPath 'source'
 *   rows     one row per CTID mapping object, key "<source>|<domain>|<n>"     index 'source'
 *   details  NIST control descriptions (optional), key "<source>|<id>"
 *   history  append-only log of pulls
 *
 * The meta, rows and history of a source not in SOURCES (another ThreatSim build may have used this browser)
 * are skipped by every read and left in place; only clearAll() removes them.
 *
 * Mappings Explorer © The MITRE Corporation (Center for Threat-Informed Defense), Apache License 2.0.
 */
(function (global) {
  'use strict';

  const DB_NAME = 'threatsim-mappings';
  const DB_VERSION = 1;

  const REPO = 'center-for-threat-informed-defense/mappings-explorer';
  const RAW_BASE = 'https://raw.githubusercontent.com/' + REPO + '/main/';
  // The repository publishes no index file: one call to the git trees API lists every path.
  const API_URL = 'https://api.github.com/repos/' + REPO + '/git/trees/main?recursive=1';
  const SITE = 'https://ctid.mitre.org/mappings/';
  const DESCRIPTIONS_PATH = 'src/mapex_convert/mappings/NIST_800-53/nist-rev5_descriptions.json';

  const sourceOf = id => SOURCES.find(s => s.id === id);

  const SOURCES = [
    { id: 'nist-800-53-r5', title: 'NIST SP 800-53 Rev 5', short: 'NIST 800-53', kind: 'controls',
      framework: 'nist_800_53', frameworkVersion: 'rev5', domains: ['enterprise-attack'], enabled: true,
      site: SITE + 'external/nist/',
      about: "CTID's mapping of NIST SP 800-53 Rev 5 security controls to the Enterprise ATT&CK techniques they mitigate.",
      matching: 'ThreatSim matches it to the stored Enterprise ATT&CK release by technique ID and follows the ' +
        'replacements of techniques revoked since.' },
  ];

  /**
   * The card note of a source: what it maps, the ATT&CK release the mapping targets (`which` says whose version
   * that is, e.g. 'stored' or 'latest'; leave attackVersion out when unknown) and how ThreatSim matches it.
   */
  function noteFor(id, attackVersion, which) {
    const s = sourceOf(id);
    if (!s) return '';
    const v = attackVersion ? 'The ' + (which || 'latest') + ' version targets ATT&CK ' + attackVersion + '. ' : '';
    return [s.about, v + s.matching].filter(Boolean).join(' ');
  }
  for (const s of SOURCES) s.note = noteFor(s.id);

  // Known files, used when GitHub's file listing can't be read (so a Pull always works).
  const PINNED_PATHS = [
    ...['16.1', '14.1', '12.1', '10.1', '9.0', '8.2'].map(a =>
      `mappings/nist_800_53/attack-${a}/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-${a}-enterprise.json`),
    DESCRIPTIONS_PATH,
  ];

  // NIST SP 800-53 Rev 5 family names, used for every control. CTID's Rev 5 files carry their own names in
  // metadata.capability_groups, but they still give CA its Rev 4 name, 'Security Assessment and Authorization'
  // (Rev 5 calls it 'Assessment, Authorization, and Monitoring'); every other family name there matches this table.
  const NIST_FAMILIES = {
    AC: 'Access Control', AT: 'Awareness and Training', AU: 'Audit and Accountability',
    CA: 'Assessment, Authorization, and Monitoring', CM: 'Configuration Management', CP: 'Contingency Planning',
    IA: 'Identification and Authentication', IR: 'Incident Response', MA: 'Maintenance', MP: 'Media Protection',
    PE: 'Physical and Environmental Protection', PL: 'Planning', PM: 'Program Management', PS: 'Personnel Security',
    PT: 'PII Processing and Transparency', RA: 'Risk Assessment', SA: 'System and Services Acquisition',
    SC: 'System and Communications Protection', SI: 'System and Information Integrity', SR: 'Supply Chain Risk Management',
  };

  const DOMAIN_OF = { enterprise: 'enterprise-attack', mobile: 'mobile-attack' };
  const DOMAIN_LABEL = { 'enterprise-attack': 'Enterprise', 'mobile-attack': 'Mobile' };

  // limits that keep a hostile or broken file from swamping the page
  const MAX_BYTES = 64 * 1048576;
  const MAX_OBJECTS = 200000;
  const MAX_TEXT = 4000;
  const MAX_NAME = 300;
  const MAX_REFS = 50;

  // ---------- database ----------

  let dbPromise = null;

  function open() {
    if (!dbPromise) {
      dbPromise = new Promise((resolve, reject) => {
        const q = indexedDB.open(DB_NAME, DB_VERSION);
        q.onupgradeneeded = () => {
          const db = q.result;
          if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta', { keyPath: 'source' });
          if (!db.objectStoreNames.contains('rows')) db.createObjectStore('rows', { keyPath: 'key' }).createIndex('source', 'source');
          if (!db.objectStoreNames.contains('details')) db.createObjectStore('details', { keyPath: 'key' });
          if (!db.objectStoreNames.contains('history')) db.createObjectStore('history', { keyPath: 'seq', autoIncrement: true });
        };
        q.onsuccess = () => {
          // another tab upgrading the database: let it, and reopen on the next call
          q.result.onversionchange = () => { q.result.close(); dbPromise = null; };
          resolve(q.result);
        };
        q.onerror = () => reject(openError(q.error));
        q.onblocked = () => reject(new Error("The mappings database can't be upgraded while another ThreatSim tab has it open: close the other tabs."));
      }).catch(e => { dbPromise = null; throw e; });
    }
    return dbPromise;
  }

  /** A failed open as a plain sentence (the browser's own text names versions the reader can't act on). */
  function openError(e) {
    const why = e && e.name === 'VersionError' ? ': it was created by a newer version of ThreatSim.'
      : ' (' + plain(e && e.message ? e.message : String(e), 200) + ').';
    return Object.assign(new Error("The mappings database in this browser can't be opened" + why), { name: (e && e.name) || 'Error', cause: e });
  }

  function req(r) {
    return new Promise((resolve, reject) => {
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  function txDone(tx) {
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('Transaction aborted'));
    });
  }

  const sourceRange = id => IDBKeyRange.bound(id + '|', id + '|\uffff');

  // ---------- text and IDs ----------

  const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', rsquo: '’', lsquo: '‘',
    rdquo: '”', ldquo: '“', ndash: '–', mdash: '—', hellip: '…', shy: '' };
  function decodeEntities(s) {
    return s.replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,8});/gi, (m, e) => {
      if (e[0] === '#') {
        const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : '';
      }
      const v = ENTITIES[e.toLowerCase()];
      return v === undefined ? m : v;
    });
  }

  const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
  const cap = (s, max) => (s.length > max ? s.slice(0, max - 1).trimEnd() + '…' : s);

  // bidirectional embeddings, overrides and isolates (U+202A-U+202E, U+2066-U+2069) and the invisible direction
  // marks (U+200E, U+200F, U+061C): they make stored text display differently from its characters, e.g. a
  // reversed name ('\u202Eexe.nigol' shows as 'login.exe'). CTID's text is English and needs none of them.
  const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

  /**
   * One-line plain text: tags removed, entities decoded, control and bidirectional formatting characters removed,
   * whitespace collapsed, capped. Non-strings give ''.
   */
  function plain(v, max = MAX_NAME) {
    if (typeof v !== 'string') return '';
    let s = v.replace(/<\/?[a-z][^<>]*>/gi, ' ');
    s = decodeEntities(s).replace(BIDI, '').replace(/[\u0000-\u001f\u007f\s]+/g, ' ').trim();
    return cap(s, max);
  }

  /** Plain text of an HTML description, keeping paragraph breaks as blank lines (other cleaning as plain()). */
  function htmlToText(v, max = MAX_TEXT) {
    if (typeof v !== 'string') return '';
    let s = v.replace(/<\s*(br|\/p|\/li|\/div|\/h\d)\b[^<>]*>/gi, '\n')
      .replace(/<\s*q\b[^<>]*>/gi, '“').replace(/<\s*\/q\s*>/gi, '”')
      .replace(/<\/?[a-z][^<>]*>/gi, '');
    s = decodeEntities(s).replace(BIDI, '').replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, ' ');
    s = s.split('\n').map(l => l.replace(/\s+/g, ' ').trim()).filter(Boolean).join('\n\n');
    return cap(s, max);
  }

  /** 'AC-02' -> 'AC-2', 'ac-2 (1)' -> 'AC-2(1)'; anything else null. */
  function nistId(v) {
    if (typeof v !== 'string') return null;
    const m = /^([A-Za-z]{2})-0*(\d{1,3})(?:\s*\(0*(\d{1,3})\))?$/.exec(v.trim());
    return m ? m[1].toUpperCase() + '-' + Number(m[2]) + (m[3] ? '(' + Number(m[3]) + ')' : '') : null;
  }

  function techniqueId(v) {
    if (typeof v !== 'string') return null;
    const s = v.trim().toUpperCase();
    return /^T\d{4}(\.\d{3})?$/.test(s) ? s : null;
  }

  function httpUrl(v) {
    if (typeof v !== 'string') return null;
    const s = v.trim();
    if (!/^https?:\/\//i.test(s) || s.length > 2000) return null;
    try {
      const u = new URL(s);
      return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
    } catch (_) { return null; }
  }

  /**
   * The http(s) links in one CTID reference string, in order. Some strings hold two links ('<url> <url>',
   * '<url>; <url>'), a link with words around it ('Ref: <url>', '<url> licensing') or a link inside a PDF viewer's
   * address ('chrome-extension://<id>/https://…'). A URL can't contain a raw space, so whitespace always separates;
   * ';' or ',' does just before another link, and at the end of one. A part that doesn't start with a link gives
   * the link inside it, if any; a part that does is kept whole (web.archive.org/web/<date>/https://… stays one link).
   * A host without a dot is no web site ('http://exa mple.com' gives 'http://exa', which is dropped).
   */
  function refUrls(v) {
    if (typeof v !== 'string' || v.length > 20000) return [];
    const out = [];
    for (const part of v.split(/\s+|[;,]+(?=https?:\/\/)/i)) {
      const at = part.search(/https?:\/\//i);
      const u = at < 0 ? null : httpUrl(part.slice(at).replace(/[;,]+$/, ''));
      if (u && new URL(u).hostname.includes('.') && !out.includes(u)) out.push(u);
    }
    return out;
  }

  /** 'rev5@16.1' -> 'Rev 5 · ATT&CK 16.1'. */
  function versionLabel(source, version) {
    const m = /^(.+)@(\d+(?:\.\d+)*)$/.exec(String(version));
    if (!m) return String(version);
    if (source === 'nist-800-53-r5') return (m[1] === 'rev5' ? 'Rev 5' : m[1]) + ' \u00b7 ATT&CK ' + m[2];
    return String(version);
  }

  function compareNum(a, b) {
    const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] || 0) - (pb[i] || 0);
      if (d) return d;
    }
    return 0;
  }

  /** Newer first: by ATT&CK version, then by framework version. */
  function compareVersions(a, b) {
    return compareNum(b.attackVersion, a.attackVersion) || String(b.frameworkVersion).localeCompare(String(a.frameworkVersion));
  }

  // ---------- discovery ----------

  const NIST_RE = /^mappings\/nist_800_53\/attack-(\d+(?:\.\d+)*)\/nist_800_53-rev5\/enterprise\/nist_800_53-rev5_attack-\1-enterprise\.json$/;

  /** Paths (with optional blob sizes) -> {<sourceId>: [Version]}, newest first. */
  function versionsFromPaths(entries) {
    const nist = new Map();
    const hasDescriptions = entries.some(e => e.path === DESCRIPTIONS_PATH);
    for (const { path, size } of entries) {
      const file = (domain) => ({ domain, url: RAW_BASE + path, size: Number.isFinite(size) && size > 0 ? size : null });
      let m;
      if ((m = NIST_RE.exec(path))) {
        const a = m[1];
        nist.set(a, { version: 'rev5@' + a, label: versionLabel('nist-800-53-r5', 'rev5@' + a), attackVersion: a, frameworkVersion: 'rev5',
          files: [file('enterprise-attack')], ...(hasDescriptions ? { descriptionsUrl: RAW_BASE + DESCRIPTIONS_PATH } : {}) });
      }
    }
    return { 'nist-800-53-r5': [...nist.values()].sort(compareVersions) };
  }

  // the reasons are short and bracket-free: the Data page puts them in brackets of its own
  async function fetchTree() {
    let res, tree;
    try {
      // default cache mode: the browser may reuse GitHub's answer for the minute its max-age allows
      res = await fetch(API_URL, { headers: { Accept: 'application/vnd.github+json' } });
    } catch (_) {
      throw new Error('GitHub API: network error');
    }
    if (!res.ok) throw new Error('GitHub API: HTTP ' + res.status);
    try { tree = await res.json(); } catch (_) { tree = null; }
    if (!tree || !Array.isArray(tree.tree)) throw new Error('GitHub API: unexpected reply');
    return tree.tree.filter(e => e && e.type === 'blob' && typeof e.path === 'string')
      .map(e => ({ path: e.path, size: Number(e.size) }));
  }

  // GitHub allows 60 unauthenticated API calls an hour per address, shared by everything behind it: the Data
  // page reuses a listing it read recently (only the paths that matter, in this browser's localStorage), and
  // falls back to the last listing it read, whatever its age, when GitHub can't be asked. The key is this
  // edition's own: a ThreatSim build with more sources keeps its longer copy under 'threatsim.ctidListing', and
  // would take this one for GitHub's whole listing
  const LISTING_KEY = 'threatsim.ctidListing.lite';
  const relevant = p => p === DESCRIPTIONS_PATH || NIST_RE.test(p);
  const validEntry = e => isObj(e) && typeof e.path === 'string' && relevant(e.path);

  /** This browser's copy of GitHub's listing, { at, entries }, or null when there is none (or it is broken). */
  function readListing() {
    try {
      const v = JSON.parse(localStorage.getItem(LISTING_KEY));
      const at = isObj(v) ? Number(v.at) : NaN;
      if (v.url === API_URL && Array.isArray(v.entries) && at > 0 && at <= Date.now()) {
        return { at, entries: v.entries.filter(validEntry).map(e => ({ path: e.path, size: Number(e.size) })) };
      }
    } catch (_) { /* nothing cached, or storage unavailable */ }
    return null;
  }

  function saveListing(at, entries) {
    try {
      localStorage.setItem(LISTING_KEY, JSON.stringify({ url: API_URL, at, entries: entries.filter(validEntry) }));
    } catch (_) { /* storage full or unavailable: the next load asks GitHub again */ }
  }

  /** Versions of a and those of b that a lacks, newest first. */
  const mergeVersions = (a, b) => [...a, ...b.filter(v => !a.some(x => x.version === v.version))].sort(compareVersions);

  /**
   * Latest mapping files of every source:
   * { sources: { <id>: { latest, versions, discovery } }, errors: { <id>?: msg }, discovery, discoveryError?,
   *   readError?: why GitHub's listing couldn't be read (a short reason without brackets),
   *   listedAt?: ISO time of the GitHub listing used, cached?: true when it came from this browser's copy,
   *   stale?: true when that copy is used because GitHub couldn't be read (for the sources whose discovery is
   *   'github-api'; listedAt and cached are then that copy's) }.
   * Reads GitHub's file listing (or, with maxAge in ms, this browser's copy of it when read less than that long
   * ago). When GitHub can't be read, the last copy this browser read is used, whatever its age, with the pinned
   * files it lacks added; without a copy (or with one that has no file of any source), or for a source the
   * listing has no files of, the pinned list of known files is used. Never throws.
   */
  async function fetchUpstreamIndex({ maxAge = 0 } = {}) {
    let listed = null, readError = null, listedAt = null, cached = false, stale = false;
    const copy = readListing();
    if (copy && maxAge > 0 && Date.now() - copy.at < maxAge) {
      listed = versionsFromPaths(copy.entries);
      listedAt = copy.at;
      cached = true;
    } else {
      try {
        const entries = await fetchTree();
        listedAt = Date.now();
        saveListing(listedAt, entries);
        listed = versionsFromPaths(entries);
      } catch (e) {
        readError = e.message;
        // what this browser read earlier says more than the built-in list: a newer file CTID has published since.
        // A copy without a file of any source says nothing: the built-in list is used, as without a copy
        const old = copy && versionsFromPaths(copy.entries);
        if (old && SOURCES.some(s => old[s.id].length)) {
          listed = old;
          listedAt = copy.at;
          cached = stale = true;
        }
      }
    }
    const pinned = versionsFromPaths(PINNED_PATHS.map(path => ({ path })));
    const out = { sources: {}, errors: {}, discovery: 'pinned' };
    for (const s of SOURCES) {
      let fromApi = listed && listed[s.id] && listed[s.id].length ? listed[s.id] : null;
      // an old copy may predate files this version of ThreatSim knows of
      if (fromApi && stale) fromApi = mergeVersions(fromApi, pinned[s.id]);
      const versions = fromApi || pinned[s.id];
      if (!versions.length) { out.errors[s.id] = 'no mapping files found'; continue; }
      out.sources[s.id] = { latest: versions[0], versions, discovery: fromApi ? 'github-api' : 'pinned' };
      if (fromApi) out.discovery = 'github-api';
    }
    const fellBack = SOURCES.filter(s => out.sources[s.id] && out.sources[s.id].discovery === 'pinned');
    let discoveryError = readError;
    if (!readError && listed && fellBack.length) discoveryError = "GitHub's file listing has no " + fellBack.map(s => s.short).join(' or ') + ' files';
    if (discoveryError) out.discoveryError = discoveryError;
    if (readError) out.readError = readError;
    if (listedAt) {
      out.listedAt = new Date(listedAt).toISOString();
      out.cached = cached;
      if (stale) out.stale = true;
    }
    return out;
  }

  /**
   * The stored version of a source as a Version the page can offer and pull again (from the files it was pulled
   * from), for when the file list no longer has it; null when the meta row doesn't describe one.
   */
  function versionFromMeta(meta) {
    const src = isObj(meta) && sourceOf(meta.source);
    if (!src || typeof meta.version !== 'string' || !Array.isArray(meta.files) || !meta.files.length) return null;
    const files = meta.files.filter(f => isObj(f) && src.domains.includes(f.domain) && httpUrl(f.url))
      .map(f => ({ domain: f.domain, url: f.url, size: Number.isFinite(f.bytes) && f.bytes > 0 ? f.bytes : null }));
    if (files.length !== meta.files.length || meta.attackVersion == null || meta.frameworkVersion == null) return null;
    const v = { version: meta.version, label: versionLabel(src.id, meta.version), attackVersion: String(meta.attackVersion),
      frameworkVersion: String(meta.frameworkVersion), files, stored: true };
    if (src.kind === 'controls') v.descriptionsUrl = httpUrl(meta.descriptionsUrl) || RAW_BASE + DESCRIPTIONS_PATH;
    return v;
  }

  // ---------- pull ----------

  const fmtMB = n => (n / 1048576).toFixed(1) + ' MB';

  /** An error whose `brief` is a short plain reason, for messages that add their own context. */
  const failure = (message, brief) => Object.assign(new Error(message), { brief });

  /** Streams one file: { text, bytes }. onProgress(bytes so far, expected total or 0). */
  async function download(url, onProgress, expected) {
    let res;
    try {
      res = await fetch(url, { cache: 'no-store' });
    } catch (_) {
      throw failure('could not be downloaded (network error)', 'network error');
    }
    if (!res.ok) throw failure('could not be downloaded (HTTP ' + res.status + ')', 'HTTP ' + res.status);
    // raw.githubusercontent.com sends the length of the compressed body, which says nothing about the bytes
    // read here: progress uses the size GitHub's file listing gives, and is indeterminate without one
    const total = expected || 0;
    const tooLarge = () => failure('is too large (over ' + fmtMB(MAX_BYTES) + ')', 'the file is too large');
    if (!res.body || !res.body.getReader) {
      const text = await res.text();
      if (text.length > MAX_BYTES) throw tooLarge();
      return { text, bytes: text.length };
    }
    const reader = res.body.getReader();
    const chunks = [];
    let received = 0;
    for (;;) {
      let step;
      try {
        step = await reader.read();
      } catch (_) {
        throw failure('could not be downloaded (the connection was cut off)', 'the connection was cut off');
      }
      const { done, value } = step;
      if (done) break;
      received += value.length;
      if (received > MAX_BYTES) { reader.cancel().catch(() => {}); throw tooLarge(); }
      chunks.push(value);
      onProgress(received, total && received <= total ? total : 0);
    }
    const buf = new Uint8Array(received);
    let off = 0;
    for (const c of chunks) { buf.set(c, off); off += c.length; }
    return { text: new TextDecoder('utf-8').decode(buf), bytes: received };
  }

  /** A metadata value as it may appear in a message ('' when missing or not a string or number). */
  const shown = v => (typeof v === 'string' || typeof v === 'number' ? plain(String(v), 40) : '');

  /** Refuse a file whose metadata doesn't match the source, version and domain its location says. */
  function checkMetadata(src, version, domain, doc, what) {
    if (!isObj(doc) || !isObj(doc.metadata) || !Array.isArray(doc.mapping_objects)) {
      throw new Error(what + ' is not a CTID mapping file (no metadata or mapping objects).');
    }
    const m = doc.metadata;
    const fw = shown(m.mapping_framework);
    if (!fw) throw new Error(what + ' names no mapping framework.');
    if (fw !== src.framework) throw new Error(what + ' maps "' + fw + '", not ' + src.title + '.');
    const domText = shown(m.technology_domain);
    if (!domText) throw new Error(what + ' names no ATT&CK domain.');
    const dom = DOMAIN_OF[domText.toLowerCase()];
    if (dom !== domain) {
      throw new Error(what + ' is for ' + (DOMAIN_LABEL[dom] || '"' + domText + '"') + ' ATT&CK, not ' + DOMAIN_LABEL[domain] + '.');
    }
    const av = shown(m.attack_version);
    if (!av) throw new Error(what + ' has no ATT&CK version.');
    if (av !== version.attackVersion) throw new Error(what + ' maps ATT&CK ' + av + ', not ' + version.attackVersion + ' as its location says.');
    const fvText = shown(m.mapping_framework_version);
    if (!fvText) throw new Error(what + ' has no framework version.');
    if (fvText !== version.frameworkVersion) throw new Error(what + ' is for ' + src.title.replace(/ Rev 5$/, '') + ' "' + fvText + '", not ' + version.frameworkVersion + '.');
    if (doc.mapping_objects.length > MAX_OBJECTS) throw new Error(what + ' has too many mapping objects (' + doc.mapping_objects.length.toLocaleString('en') + ').');
  }

  /** CTID mapping objects -> rows (see the header); objects that don't validate are counted and skipped. */
  function normalizeFile(src, domain, doc) {
    const rows = [];
    let skipped = 0;
    for (const o of doc.mapping_objects) {
      if (!isObj(o)) { skipped++; continue; }
      const tech = techniqueId(o.attack_object_id);
      if (!tech) { skipped++; continue; }
      const raw = o.capability_id;
      const capId = raw == null || raw === '' ? null : nistId(raw);
      if (raw != null && raw !== '' && !capId) { skipped++; continue; }
      if (capId && !NIST_FAMILIES[capId.slice(0, 2)]) { skipped++; continue; }   // not a Rev 5 family

      const group = capId ? capId.slice(0, 2) : null;   // the family is the ID's prefix
      const groupName = group ? NIST_FAMILIES[group] : null;   // the Rev 5 name, never the file's (see NIST_FAMILIES)
      // CTID called the NIST relation 'protects' up to ATT&CK 14.1 and 'mitigates' since
      const mappingType = capId ? 'mitigates' : null;
      const statusRaw = typeof o.status === 'string' ? o.status.trim().toLowerCase() : '';
      const status = !capId ? 'non_mappable' : /^[a-z_]{1,32}$/.test(statusRaw) && statusRaw !== 'non_mappable' ? statusRaw : 'complete';

      const refs = [];
      if (Array.isArray(o.references)) {
        for (const r of o.references) {
          for (const u of refUrls(r)) if (refs.length < MAX_REFS && !refs.includes(u)) refs.push(u);
          if (refs.length >= MAX_REFS) break;
        }
      }
      rows.push({
        key: src.id + '|' + domain + '|' + rows.length,
        source: src.id,
        domain,
        capabilityId: capId,
        capabilityIdRaw: capId ? plain(raw, 40) : null,
        capabilityName: capId ? plain(o.capability_description) : null,
        group,
        groupName,
        mappingType,
        techniqueId: tech,
        techniqueName: plain(o.attack_object_name),
        comments: plain(o.comments, MAX_TEXT) || null,
        references: refs,
        status,
      });
    }
    return { rows, skipped };
  }

  function normalizeDetails(src, doc) {
    if (!Array.isArray(doc)) return [];
    const out = new Map();
    for (const d of doc.slice(0, 5000)) {
      if (!isObj(d)) continue;
      const id = nistId(d.id);
      const text = htmlToText(d.description);
      if (id && text && !out.has(id)) out.set(id, { key: src.id + '|' + id, source: src.id, id, text });
    }
    return [...out.values()];
  }

  /**
   * Download, check and store one version of a source. onProgress(stage text, fraction 0..1 | null) reports the
   * steps. Everything is written in one transaction that replaces the source's previous rows, so a pull that fails
   * at any point leaves the stored data as it was. Returns the new meta row.
   */
  async function pullSource(id, version, onProgress = () => {}) {
    const src = sourceOf(id);
    if (!src) throw new Error('Unknown mapping source "' + id + '".');
    if (!isObj(version) || typeof version.version !== 'string' || !Array.isArray(version.files) || !version.files.length) {
      throw new Error('No ' + src.short + ' files to pull.');
    }
    const files = version.files.filter(f => isObj(f) && src.domains.includes(f.domain) && httpUrl(f.url));
    if (files.length !== version.files.length) throw new Error('The ' + src.short + ' file list is not valid.');
    const prev = await getMeta(id).catch(() => null);

    const rows = [], fileMeta = [];
    let skipped = 0;
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const what = 'The ' + src.short + ' ' + DOMAIN_LABEL[f.domain] + ' file';
      const step = 'Downloading ' + DOMAIN_LABEL[f.domain] + ' mappings' + (files.length > 1 ? ' (' + (i + 1) + ' of ' + files.length + ')' : '');
      onProgress(step + '…', i / files.length);
      let got;
      try {
        got = await download(f.url, (n, total) => {
          if (total) onProgress(step + ' — ' + fmtMB(n) + ' of ' + fmtMB(total), (i + n / total) / files.length);
          else onProgress(step + ' — ' + fmtMB(n), null);
        }, f.size);
      } catch (e) {
        throw new Error(what + ' ' + e.message + '.', { cause: e });
      }
      onProgress('Checking the ' + DOMAIN_LABEL[f.domain] + ' file…', null);
      await nextTick();
      let doc;
      try {
        doc = JSON.parse(got.text);
      } catch (e) {
        throw new Error(what + ' is not valid JSON.', { cause: e });
      }
      checkMetadata(src, version, f.domain, doc, what);
      const n = normalizeFile(src, f.domain, doc);
      if (!n.rows.length) throw new Error(what + ' has no usable mappings.');
      rows.push(...n.rows);
      skipped += n.skipped;
      fileMeta.push({ domain: f.domain, url: f.url, bytes: got.bytes });
    }

    // control descriptions are a nice-to-have: never fail a pull over them
    let details = [], detailsError = null;
    if (src.kind === 'controls' && version.descriptionsUrl && httpUrl(version.descriptionsUrl)) {
      onProgress('Downloading control descriptions…', null);
      let text = null;
      try {
        text = (await download(version.descriptionsUrl, () => {}, null)).text;
      } catch (e) {
        detailsError = e.brief || 'the file could not be downloaded';
      }
      if (text != null) {
        let doc;
        try { doc = JSON.parse(text); } catch (_) { detailsError = 'the file is not valid JSON'; }
        if (!detailsError) {
          details = normalizeDetails(src, doc);
          if (!details.length) detailsError = 'the file lists none';
        }
      }
    }

    onProgress('Writing to local database…', null);
    await nextTick();
    // rows: every stored object; mapped: those with a control, of which pairs are distinct (CTID's NIST file
    // repeats some); techniques: those with a control; nonMappable: techniques CTID judged no control maps to
    const byDomain = {};
    const caps = new Set(), techs = new Set(), pairs = new Set(), unmappable = new Set();
    let mapped = 0;
    for (const r of rows) {
      byDomain[r.domain] = (byDomain[r.domain] || 0) + 1;
      const t = r.domain + '|' + r.techniqueId;
      if (r.capabilityId) {
        mapped++;
        caps.add(r.capabilityId);
        techs.add(t);
        pairs.add(t + '|' + r.capabilityId + '|' + r.mappingType);
      } else {
        unmappable.add(t);
      }
    }
    const meta = {
      source: id,
      title: src.title,
      version: version.version,
      label: typeof version.label === 'string' ? plain(version.label, 120) : version.version,
      attackVersion: String(version.attackVersion),
      frameworkVersion: String(version.frameworkVersion),
      files: fileMeta,
      pulledAt: new Date().toISOString(),
      previousVersion: prev ? prev.version : null,
      counts: { rows: rows.length, mapped, pairs: pairs.size, capabilities: caps.size, techniques: techs.size,
        nonMappable: unmappable.size, byDomain, skipped },
      details: details.length,
    };
    if (src.kind === 'controls' && httpUrl(version.descriptionsUrl)) meta.descriptionsUrl = httpUrl(version.descriptionsUrl);
    if (detailsError) meta.detailsError = plain(detailsError, 200);

    const db = await open();
    const tx = db.transaction(['rows', 'details', 'meta', 'history'], 'readwrite');
    const rs = tx.objectStore('rows'), ds = tx.objectStore('details');
    rs.delete(sourceRange(id));
    ds.delete(sourceRange(id));
    for (const r of rows) rs.put(r);
    for (const d of details) ds.put(d);
    tx.objectStore('meta').put(meta);
    tx.objectStore('history').add({
      source: id, version: meta.version, label: meta.label, previousVersion: meta.previousVersion,
      pulledAt: meta.pulledAt, counts: meta.counts, details: meta.details,
    });
    await txDone(tx);
    return meta;
  }

  const nextTick = () => new Promise(r => setTimeout(r, 0));

  // ---------- reads ----------

  // rows of a source not in SOURCES are skipped (see the header)
  const listed = x => isObj(x) && !!sourceOf(x.source);

  async function getMeta(id) {
    const db = await open();
    if (!sourceOf(id)) return null;
    return (await req(db.transaction('meta').objectStore('meta').get(id))) || null;
  }

  async function getAllMeta() {
    const db = await open();
    return (await req(db.transaction('meta').objectStore('meta').getAll())).filter(listed);
  }

  async function getHistory(limit = 50) {
    const db = await open();
    const all = await req(db.transaction('history').objectStore('history').getAll());
    return all.reverse().filter(listed).slice(0, limit);
  }

  /** Everything stored for one source: { meta (null when not pulled), rows: [row], details: [detail] }. */
  async function loadSource(id) {
    const db = await open();
    if (!sourceOf(id)) return { meta: null, rows: [], details: [] };
    const tx = db.transaction(['meta', 'rows', 'details']);
    const range = sourceRange(id);
    const [meta, rows, details] = await Promise.all([
      req(tx.objectStore('meta').get(id)),
      req(tx.objectStore('rows').getAll(range)),
      req(tx.objectStore('details').getAll(range)),
    ]);
    // keys sort as text ('…|10' before '…|2'): give the rows back in file order
    const n = k => Number(k.slice(k.lastIndexOf('|') + 1));
    rows.sort((a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : n(a.key) - n(b.key)));
    return { meta: meta || null, rows, details };
  }

  async function clearAll() {
    const db = await open();
    const stores = ['meta', 'rows', 'details', 'history'];
    const tx = db.transaction(stores, 'readwrite');
    for (const s of stores) tx.objectStore(s).clear();
    await txDone(tx);
  }

  global.MappingsDB = {
    DB_NAME, SOURCES, NIST_FAMILIES, RAW_BASE, API_URL, SITE, PINNED_PATHS, LISTING_KEY,
    open, fetchUpstreamIndex, pullSource, getMeta, getAllMeta, getHistory, loadSource, clearAll,
    compareVersions, versionLabel, versionFromMeta, noteFor,
    // exposed for tests and for pages that show the same IDs
    nistId, plain, htmlToText, refUrls, versionsFromPaths, normalizeFile,
  };
})(window);
