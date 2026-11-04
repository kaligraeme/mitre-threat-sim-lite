/*
 * threatmodel.js — the Threat Modelling tab: upload a diagram, check its decomposition (CSA §3.2), run
 * STRIDE-LM through the threat profile built on the Threat Profile tab (§3.3), and download the register and the DFD.
 *
 * Reads the Threat Profile tab's saved profile (localStorage threatsim.sim.v1) and the MITRE data in AttackDB.
 * Claude is used only when the server says it has an API key (api/tm/status) and the user asks for it: to
 * read a picture of a diagram, and to write the threat events in more detail. Everything else runs in this
 * browser. The decomposition being worked on is kept in this browser for the user who made it.
 */
(function () {
  'use strict';

  const SIM_KEY = 'threatsim.sim.v1';
  const TM_KEY_OLD = 'threatsim.tm.v1';           // before decompositions were kept per user
  const CLAUDE_KEY_OLD = 'threatsim.tm.claude';   // before the answer to "Have Claude write…" was kept per user
  const JOB_KEY = 'threatsim.tm.job';             // sessionStorage: the Claude job this tab is waiting for
  const RUN_DB = 'threatsim-tm';                  // IndexedDB: each user's last run, kept in this browser
  const EXAMPLE = 'examples/sovereign-ai-architecture.drawio';
  const VENDOR = { excel: 'js/vendor/exceljs.min.js', pptx: 'js/vendor/pptxgen.bundle.js' };
  // What Claude takes in one picture: 2576 px on the long edge and 3.75 megapixels. Larger pictures are made
  // smaller here, so the positions Claude reads are in the size the page tells it.
  const MAX_IMAGE_EDGE = 2576;
  const MAX_IMAGE_PIXELS = 3750000;
  const MAX_IMAGE_BYTES = 3.5 * 1024 * 1024;
  const JOB_WAIT = 20 * 60 * 1000;                // the longest the page waits for a Claude job
  const STOP_WAIT = 15 * 1000;                    // after Cancel, how long to wait for what the job has done
  // The most one enrichment request may hold (the server refuses more). The server's own figures, which
  // api/tm/status gives, take precedence; these are its defaults.
  const ENRICH_LIMITS = { events: 400, sequences: 50, lenses: 30, software: 100, campaigns: 50, techniques: 30, steps: 12,
    path: 30, flows: 40, context: 12, text: 2000, bytes: 2 * 1024 * 1024 };
  const KINDS = { groups: 'Group', software: 'Software', campaigns: 'Campaign', caseStudies: 'Case study', entities: 'Entity', atlasSoftware: 'Software' };
  const FLAG = [['', 'Work it out'], ['yes', 'Yes'], ['no', 'No']];
  const STALE = 'The decomposition has changed since the last run. Run the model again to update the results and downloads.';
  const CLAUDE_NOTE = 'Claude is available on this server when you ask for it: reading a picture of a diagram sends the picture '
    + 'to Anthropic\'s API, and having it write the threat events in more detail sends element names, their context and the '
    + 'draft register to Anthropic\'s API.';

  const $ = sel => document.querySelector(sel);
  const USER = (window.Auth && window.Auth.user()) || '';
  const TM_KEY = USER ? `${TM_KEY_OLD}:${USER}` : '';   // the decomposition being worked on (not the picture)
  // this user's answer to "Have Claude write…" in this browser, 'on' or 'off': another user of the browser has their own
  const CLAUDE_KEY = USER ? `${CLAUDE_KEY_OLD}:${USER}` : '';
  const state = {
    models: {}, metas: [], loaded: false, dataError: '',
    selection: null, opts: { viaSoftware: true, viaCampaigns: true },
    claude: { available: false, model: '', limits: null },
    model: null,
    gen: '',            // which decomposition this is: new when one is loaded or started, the same through its edits
    saved: { gen: '', rev: 0 },   // the copy kept in this browser that this tab last saved or took up
    image: null,        // a picture just uploaded, waiting to be read by Claude or by hand
    modelImage: null,   // the picture the decomposition was made from, shown beside the editor
    result: null, stale: false, busy: false, running: false, tab: 'events',
    marks: { events: new Map(), sequences: new Map() },   // what Claude wrote in the results: 'all' of it, or 'part'
    rev: 0,             // counts the changes the results depend on: the decomposition, its name, the profile
    undo: [],           // the decomposition before each of the last changes that can be undone, the latest last
    open: {},           // editor section -> open (remembered across re-renders)
  };
  // Where the source diagram put each zone and element: id -> { geometry, parent } or { geometry, zone }.
  let home = new Map();

  // ---------------------------------------------------------------- small helpers

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k === 'on') for (const [ev, fn] of Object.entries(v)) node.addEventListener(ev, fn);
      else if (k === 'value' || (k in node && typeof v !== 'string')) node[k] = v;   // a textarea's value is a property
      else node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
    return node;
  }

  /** A status line: text (and any controls after it), with a spinner while busy, or as an error, warning or success. */
  function say(node, text, kind, ...extra) {
    node.classList.add('busy-line');
    for (const k of ['err', 'warn', 'ok']) node.classList.toggle(k, kind === k);
    node.replaceChildren(...(kind === 'busy' ? [el('span', { class: 'spinner', 'aria-hidden': 'true' })] : []),
      ...(text && text.length ? [el('span', {}, text)] : []), ...extra);
  }

  let noteTimer = 0;
  /**
   * Say what an edit did in the editor's status bar, kept in view while editing; a plain success clears itself.
   * While a change can still be undone, the bar goes on offering Undo, and says what it would put back.
   */
  function editNote(text, kind, ...extra) {
    clearTimeout(noteTimer);
    const line = $('#editStatus');
    if (!extra.length && state.undo.length) {
      say(line, text, kind === 'ok' ? '' : kind, ...undoControls(`Undo puts back ${state.undo[state.undo.length - 1].what}.`));
      return;
    }
    say(line, text, kind, ...extra);
    if (kind === 'ok') noteTimer = setTimeout(() => { if (line.classList.contains('ok')) say(line, ''); }, 12000);
  }

  const loading = {};
  function loadScript(key) {
    const src = VENDOR[key];
    const ready = () => (key === 'excel' ? window.ExcelJS : window.PptxGenJS && window.JSZip);
    if (ready()) return Promise.resolve();
    if (!loading[key]) {
      loading[key] = new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = src;
        s.onload = () => (ready() ? resolve() : reject(new Error(src + ' loaded but did not register')));
        s.onerror = () => { s.remove(); reject(new Error('Could not load ' + src)); };
        document.head.append(s);
      }).catch(e => { loading[key] = null; throw e; });
    }
    return loading[key];
  }

  function save(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const clone = v => JSON.parse(JSON.stringify(v));
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + 's'}`;
  const paint = () => new Promise(r => setTimeout(r, 30));   // let a status line show before heavy work

  function storage(name) {
    return {
      get(key) { try { return JSON.parse(window[name].getItem(key)); } catch (_) { return null; } },
      set(key, value) { try { window[name].setItem(key, JSON.stringify(value)); return true; } catch (_) { return false; } },
      remove(key) { try { window[name].removeItem(key); } catch (_) { /* storage blocked */ } },
    };
  }
  const store = storage('localStorage');
  const session = storage('sessionStorage');

  /** An id for a new decomposition, so tabs (and a kept run) can tell it from another one. */
  function newGen() {
    try { return Array.from(crypto.getRandomValues(new Uint8Array(9)), b => b.toString(16).padStart(2, '0')).join(''); } catch (_) {
      return Date.now().toString(36) + Math.random().toString(36).slice(2);
    }
  }

  // How the page was opened: what it says about a Claude job that leaving the page stopped, and it picks up.
  const RELOADED = (() => { try { return performance.getEntriesByType('navigation')[0].type === 'reload'; } catch (_) { return false; } })();
  const WHEN_LEFT = RELOADED ? 'the page was reloaded' : 'you left the page';

  /*
   * The last run, kept for the user who ran it in this browser's IndexedDB (a register is too large for
   * localStorage), with what it was made from: leaving the page, reloading it or signing out doesn't lose it,
   * and Claude's part of it isn't paid for twice. It is shown again on the next visit, marked out of date if the
   * decomposition, the profile or the MITRE data has changed since, and dropped when the decomposition is
   * replaced or cleared. Without IndexedDB nothing is kept, as before.
   */
  let runDb = null;
  function runStore(mode, fn) {
    if (!runDb) {
      runDb = new Promise((resolve, reject) => {
        const q = indexedDB.open(RUN_DB, 1);
        q.onupgradeneeded = () => q.result.createObjectStore('runs');
        q.onsuccess = () => {
          q.result.onversionchange = () => { q.result.close(); runDb = null; };
          resolve(q.result);
        };
        q.onerror = () => reject(q.error);
        q.onblocked = () => reject(new Error('blocked'));
      }).catch(e => { runDb = null; throw e; });
    }
    return runDb.then(db => new Promise((resolve, reject) => {
      const tx = db.transaction('runs', mode);
      const q = fn(tx.objectStore('runs'));
      tx.oncomplete = () => resolve(q.result);
      tx.onerror = tx.onabort = () => reject(tx.error);
    }));
  }
  const keepRun = rec => (USER ? runStore('readwrite', s => s.put(rec, USER)).catch(() => {}) : Promise.resolve());
  const lastRun = () => (USER ? runStore('readonly', s => s.get(USER)).catch(() => null) : Promise.resolve(null));
  const dropRun = () => (USER ? runStore('readwrite', s => s.delete(USER)).catch(() => {}) : Promise.resolve());

  /**
   * Call the server's threat-modelling API. A failure rejects with an Error carrying the HTTP status (0 when
   * the server couldn't be reached) and the answer; a 401 means the session ended, which auth.js handles.
   */
  async function api(path, body) {
    let res;
    try {
      res = await fetch(path, {
        method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
        headers: Object.assign({ Accept: 'application/json' }, body ? { 'Content-Type': 'application/json' } : {}),
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (_) {
      throw Object.assign(new Error('The server couldn’t be reached.'), { status: 0 });
    }
    let data = null;
    try { data = await res.json(); } catch (_) { /* not JSON, or cut short */ }
    if (res.status === 401 && window.Auth) window.Auth.check();
    if (!res.ok || !data || data.ok === false) {
      throw Object.assign(new Error(data && data.error ? data.error : `The server answered ${res.status}.`), { status: res.status, data });
    }
    return data;
  }
  // A poll that may well work next time: no answer, a gateway or server error, or an answer cut short.
  const transient = e => e.status === 0 || e.status >= 500 || e.status === 408 || (e.status >= 200 && e.status < 300 && !e.data);

  /**
   * Whether keyboard focus has nowhere useful to be: on the page itself, or on a control just disabled or hidden,
   * or still in a dialog that has just closed (the browser moves it to the page a moment later).
   */
  function focusLost() {
    const a = document.activeElement;
    return !a || a === document.body || !a.isConnected || a.disabled === true || !!a.closest('[hidden], dialog:not([open])');
  }
  function focusTo(target) {
    const n = typeof target === 'string' ? $(target) : target;
    if (n && !n.disabled && !n.closest('[hidden]')) n.focus();
  }

  // ---------------------------------------------------------------- MITRE data and the profile

  async function loadData() {
    state.metas = await AttackDB.getAllMeta();
    for (const m of state.metas) state.models[m.domain] = await SimEngine.loadModel(m.domain);
    state.loaded = true;
  }

  function readProfile() {
    const s = store.get(SIM_KEY);
    const selection = {};
    for (const k of Object.keys(KINDS)) selection[k] = new Set((s && s.selection && s.selection[k]) || []);
    state.selection = selection;
    state.opts = s && s.opts
      ? { viaSoftware: s.opts.viaSoftware !== false, viaCampaigns: s.opts.viaCampaigns !== false }
      : { viaSoftware: true, viaCampaigns: true };
  }
  // what the threat model depends on in the Threat Profile tab's saved state (it also keeps its own view settings there)
  const profileKey = () => JSON.stringify([Object.keys(KINDS).map(k => [...state.selection[k]].sort()), state.opts]);

  /**
   * The Threat Profile tab's scope settings that the threat model doesn't follow, as [platforms, domains switched off]:
   * its platform filter, and the knowledge bases switched off there (as the Threat Profile tab reads its saved state).
   */
  function simScope() {
    const s = store.get(SIM_KEY);
    const platforms = s && s.opts && Array.isArray(s.opts.platforms) ? s.opts.platforms.filter(p => typeof p === 'string').sort() : [];
    const on = s && Array.isArray(s.domains) ? s.domains : null;
    const known = s && Array.isArray(s.known) ? s.known : ['enterprise-attack', 'ics-attack', 'mobile-attack'];
    const off = on ? state.metas.map(m => m.domain).filter(d => known.includes(d) && !on.includes(d)).sort() : [];
    return JSON.stringify([platforms, off]);
  }
  const listOf = a => (a.length > 1 ? `${a.slice(0, -1).join(', ')} and ${a[a.length - 1]}` : a.join(''));
  const domainTitle = d => (AttackDB.DOMAINS.find(x => x.id === d) || {}).title || d;

  let shownScope = '';   // the Threat Profile scope the card last spoke of
  /** Why the counts here can differ from the Threat Profile tab's: the scope settings there that don't apply here, said plainly. */
  function scopeNote() {
    const [platforms, off] = JSON.parse(shownScope || simScope());
    if (!platforms.length && !off.length) return null;
    const there = [platforms.length ? `the profile is narrowed by its platform filter (${listOf(platforms)})` : '',
      off.length ? `${listOf(off.map(domainTitle))} ${off.length === 1 ? 'is' : 'are'} switched off` : ''].filter(Boolean);
    const how = platforms.length
      ? `it matches each element to the techniques of the platforms it runs on, worked out from its context${off.length ? ', and uses every knowledge base pulled in this browser' : ''}`
      : 'it uses every knowledge base pulled in this browser, for the elements each applies to';
    return el('p', { class: 'note', id: 'scopeNote', style: 'margin:6px 0 0' },
      `On the Threat Profile tab, ${there.join(', and ')}. The threat model doesn’t use ${there.length > 1 ? 'either' : platforms.length ? 'that filter' : 'that setting'}: `
      + `${how}, so the counts here can differ from the Threat Profile tab’s.`);
  }

  function profileSummary() {
    const roots = new Map();
    const techniques = { attack: new Set(), atlas: new Set() };
    for (const [domain, m] of Object.entries(state.models)) {
      if (!m) continue;
      const r = SimEngine.analyzeDomain(m, state.selection, Object.assign({}, state.opts, { platforms: new Set() }));
      for (const root of r.roots) roots.set(root.id, root);
      for (const t of r.techniques.values()) (domain === 'atlas' ? techniques.atlas : techniques.attack).add(t.tech.attackId);
    }
    return { roots: [...roots.values()], techniques };
  }

  function renderProfile() {
    const body = $('#profileBody');
    shownScope = simScope();
    if (!state.metas.length) {
      body.replaceChildren(el('p', {},
        'There is no MITRE data in this browser yet. ', el('a', { href: 'index.html', text: 'Pull it on the Data page' }),
        ', then come back here.'));
      return;
    }
    const { roots, techniques } = profileSummary();
    const versions = state.metas.map(m => `${(AttackDB.DOMAINS.find(d => d.id === m.domain) || {}).title || m.domain} ${m.version || ''}`.trim());
    const parts = [];
    if (roots.length) {
      parts.push(el('p', { class: 'lead' }, 'The threat model is driven by the profile you built on the ',
        el('a', { href: 'simulator.html', text: 'Threat Profile tab' }), ':'));
      parts.push(el('div', { class: 'chips' }, roots.map(r => el('span', { class: 'chip', title: KINDS_LABEL(r) }, `${r.name} (${r.attackId})`))));
      parts.push(el('p', { class: 'note', style: 'margin:8px 0 0' },
        `${techniques.attack.size} ATT&CK technique${techniques.attack.size === 1 ? '' : 's'}`
        + (techniques.atlas.size ? ` and ${techniques.atlas.size} ATLAS technique${techniques.atlas.size === 1 ? '' : 's'}` : '')
        + ` · MITRE data: ${versions.join(', ')}`));
      parts.push(scopeNote());
    } else {
      parts.push(el('p', {}, 'No threat profile yet. ', el('a', { href: 'simulator.html', text: 'Build one on the Threat Profile tab' }),
        ' — pick the groups, software, campaigns or ATLAS case studies the sector faces. Without one, the model assumes a generic external attacker.'));
      parts.push(el('p', { class: 'note' }, `MITRE data: ${versions.join(', ')}`));
    }
    if (!state.models['enterprise-attack']) {
      parts.push(el('p', { class: 'note' }, 'ATT&CK Enterprise isn’t pulled yet; the model needs it. ',
        el('a', { href: 'index.html', text: 'Pull it on the Data page' }), '.'));
    }
    body.replaceChildren(...parts.filter(Boolean));
  }
  const KINDS_LABEL = o => ({ group: 'ATT&CK group', software: 'Software', campaign: 'ATT&CK campaign', 'case-study': 'ATLAS case study', entity: 'ATLAS entity' })[o.kind] || o.kind;

  // ---------------------------------------------------------------- the diagram

  const canRun = () => !!(state.model && state.model.elements.length && state.models['enterprise-attack']);

  function setBusy(on) {
    state.busy = on;
    for (const b of ['#exampleBtn', '#scratchBtn', '#claudeReadBtn', '#handBtn', '#keepBtn']) $(b).disabled = on;
    $('#fileInput').disabled = on;
    $('#drop').classList.toggle('busy', on);
    for (const b of document.querySelectorAll('#editor [data-idle]')) b.disabled = on;   // Load context, Clear
    updateRun();
  }

  /** The Run button, and next to it why it can't be pressed yet. */
  function updateRun() {
    $('#runBtn').disabled = state.busy || !canRun();
    const m = state.model;
    const link = text => el('a', { href: 'index.html', text });
    let why = null;
    if (!m || !m.elements.length) why = 'Add at least one element to the decomposition to run the model.';
    else if (state.dataError) why = ['The MITRE data couldn’t be loaded in this browser, so the model can’t run. Reload the page, or pull the data again on the ', link('Data page'), '.'];
    else if (!state.loaded) why = 'Loading the MITRE data in this browser…';
    else if (!state.models['enterprise-attack']) why = ['The model needs MITRE ATT&CK Enterprise in this browser: ', link('pull it on the Data page'), ', then come back here.'];
    const hint = $('#runHint');
    hint.replaceChildren(...[].concat(why || []));
    hint.hidden = !why;
  }

  /**
   * After a load, keyboard focus goes where the user can go on from, not to the page (going busy disabled the
   * control they were on): to the picture's actions for a picture, else back to the control they used.
   */
  function refocus(focused, opener, picture) {
    if (!focused || !focusLost()) return;
    if (picture && state.image) focusTo(state.claude.available ? '#claudeReadBtn' : '#handBtn');
    else if (opener && opener.isConnected && opener !== document.body) focusTo(opener);
    if (focusLost()) focusTo('#fileInput');
  }

  /** A picture uploaded earlier still waits to be read: say so after something else was tried, so its buttons are clear. */
  function stillWaiting() {
    const img = state.image;
    if (!img) return '';
    const ways = [state.claude.available ? 'read it with Claude' : '', 'decompose it by hand', state.model ? 'keep the decomposition you were working on' : ''].filter(Boolean);
    return ` ${img.name} is still waiting: ${ways.length > 2 ? `${ways.slice(0, -1).join(', ')} or ${ways[ways.length - 1]}` : ways.join(' or ')}.`;
  }

  async function openFile(file) {
    if (!file || state.busy) return;
    const focused = !focusLost(), opener = document.activeElement;
    let picture = false;
    setBusy(true);
    const status = $('#diagramStatus');
    say(status, `Reading ${file.name}…`, 'busy');
    try {
      if (/\.(pptx|potx)$/i.test(file.name)) await loadScript('pptx');
      const r = await TMParse.parseFile(file);
      if (r.image) {
        const size = await pictureSize(r.image.blob);
        if (!size) {
          say(status, `${file.name} can’t be opened as a picture: the file may be damaged, or not be the kind of picture its name says.${stillWaiting()}`, 'err');
          return;
        }
        setImage(Object.assign({}, r.image, size));
        picture = true;
      } else if (await confirmReplace('file', file.name)) {
        clearImage();
        setModel(r.model);
        say(status, readSummary(r.model), 'ok');
      } else {
        say(status, `${file.name} wasn’t loaded: the decomposition you were working on is unchanged.${stillWaiting()}`);
      }
    } catch (e) {
      say(status, `${e.message}${stillWaiting()}`, 'err');
    } finally {
      setBusy(false);
      refocus(focused, opener, picture);
    }
  }

  const readSummary = m => `Read ${m.source.file || 'the diagram'}: ${plural(m.elements.length, 'element')}, `
    + `${plural(m.flows.length, 'data flow')}, ${plural(m.zones.length, 'trust zone')}.`;

  /** The picture's size in pixels, or null when the browser can't open it. */
  async function pictureSize(blob) {
    try {
      const b = await createImageBitmap(blob);
      const size = { width: b.width, height: b.height };
      b.close();
      return size.width && size.height ? size : null;
    } catch (_) {
      return null;
    }
  }

  /** A picture was uploaded: it has nothing to read, so the decomposition on the page (another diagram's) is put out of the way. */
  function setImage(image) {
    clearImage();
    state.image = Object.assign({}, image, { url: URL.createObjectURL(image.blob) });
    $('#stepDecomp').hidden = true;
    $('#stepRun').hidden = true;
    $('#imageActions').hidden = false;
    $('#claudeReadBtn').hidden = !state.claude.available;
    $('#keepBtn').hidden = !state.model;
    say($('#diagramStatus'), (state.claude.available
      ? `${image.name} is a picture. Claude can read the elements, flows and trust zones from it (the picture is sent to Anthropic's API), or you can decompose it by hand.`
      : `${image.name} is a picture, so there are no shapes to read. Decompose it by hand, or export the diagram from draw.io as XML.`)
      + (state.model ? ' The decomposition you were working on is put aside meanwhile.' : ''));
  }

  /** Put the uploaded picture away (it stays on show if the decomposition was made from it). */
  function clearImage() {
    const img = state.image;
    if (img && !(state.modelImage && state.modelImage.url === img.url)) URL.revokeObjectURL(img.url);
    state.image = null;
    $('#imageActions').hidden = true;
  }

  /** The picture the decomposition was made from, shown beside the editor. */
  function setModelImage(image) {
    const old = state.modelImage;
    if (old && (!image || old.url !== image.url) && !(state.image && state.image.url === old.url)) URL.revokeObjectURL(old.url);
    state.modelImage = image || null;
    if (image) $('#pictureImg').src = image.url;
    else $('#pictureImg').removeAttribute('src');
    $('#pictureFrame').classList.remove('full');
    $('#pictureZoom').setAttribute('aria-pressed', 'false');
  }

  function keepCurrent() {
    if (state.busy) return;
    clearImage();
    $('#stepDecomp').hidden = !state.model;
    $('#stepRun').hidden = !state.model;
    say($('#diagramStatus'), 'Kept the decomposition you were working on, and put the picture aside.');
    focusTo('#systemName');
  }

  async function exampleDiagram() {
    if (state.busy) return;
    const status = $('#diagramStatus');
    // asked before going busy, so that closing the question gives focus back to the button
    if (!(await confirmReplace('example'))) {
      say(status, `The example wasn’t loaded: the decomposition you were working on is unchanged.${stillWaiting()}`);
      return;
    }
    const focused = !focusLost(), opener = document.activeElement;
    setBusy(true);
    say(status, 'Loading the example…', 'busy');
    try {
      const res = await fetch(EXAMPLE, { credentials: 'same-origin' });
      if (!res.ok) throw new Error(`The example could not be loaded (${res.status}).`);
      const model = await TMParse.parseDrawio(await res.text(), 'sovereign-ai-architecture.drawio');
      clearImage();
      setModel(model);
      say(status, readSummary(model) + ' This is the Sovereign AI reference architecture re-modelled as a draw.io DFD, with the component context filled in.', 'ok');
    } catch (e) {
      say(status, `${e.message}${stillWaiting()}`, 'err');
    } finally {
      setBusy(false);
      refocus(focused, opener);
    }
  }

  const blankModel = file => TMParse.finish({
    name: '', source: { kind: file ? 'image' : 'manual', file: file || '', method: 'manual' },
    zones: [], elements: [], flows: [], notes: [],
  });

  async function startBlank() {
    if (state.busy || !(await confirmReplace('blank'))) return;
    clearImage();
    setModel(blankModel(''));
    say($('#diagramStatus'), 'Blank decomposition: add the zones, elements and data flows below.');
  }

  async function byHand() {
    const image = state.image;
    if (!image || state.busy || !(await confirmReplace('hand', image.name))) return;
    setModel(blankModel(image.name), { image });
    clearImage();
    say($('#diagramStatus'), 'Add the zones, elements and data flows you see in the picture.');
    focusTo('#systemName');
  }

  /**
   * The picture as Claude takes it: within its size limits, and always drawn afresh onto white, so the bytes
   * are the type they are sent as (whatever the file's name says) and carry none of the file's metadata.
   */
  async function imageForClaude(image) {
    let bitmap;
    try { bitmap = await createImageBitmap(image.blob); } catch (_) { throw new Error('the browser can’t open it as a picture.'); }
    if (!bitmap.width || !bitmap.height) throw new Error('the browser can’t open it as a picture.');
    const scale = Math.min(1, MAX_IMAGE_EDGE / Math.max(bitmap.width, bitmap.height), Math.sqrt(MAX_IMAGE_PIXELS / (bitmap.width * bitmap.height)));
    const width = Math.max(1, Math.floor(bitmap.width * scale));
    const height = Math.max(1, Math.floor(bitmap.height * scale));
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);
    ctx.imageSmoothingQuality = 'high';   // small labels stay readable when a large diagram is made smaller
    ctx.drawImage(bitmap, 0, 0, width, height);
    bitmap.close();
    const encode = (type, quality) => new Promise(r => canvas.toBlob(r, type, quality));
    let type = 'image/png';
    let blob = await encode(type);
    for (const quality of [0.88, 0.75, 0.6]) {
      if (blob && blob.size <= MAX_IMAGE_BYTES) break;
      type = 'image/jpeg';
      blob = await encode(type, quality);
    }
    if (!blob) throw new Error('the browser couldn’t encode it.');
    if (blob.size > MAX_IMAGE_BYTES) throw new Error('it is still too large to send after being made smaller.');
    const bytes = new Uint8Array(await blob.arrayBuffer());
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return { data: btoa(bin), mediaType: type, width, height };
  }

  /** Have Claude read the uploaded picture into a decomposition (or, given the record kept over a reload, pick that read up again). */
  async function claudeRead(rec) {
    const resume = rec && rec.kind === 'decompose' ? rec : null;
    if (state.busy || (!resume && !state.image)) return;
    const image = resume ? null : state.image;
    const name = resume ? String(rec.name || 'the picture') : image.name;
    if (!resume && !(await confirmReplace('claude', name))) return;
    const focused = !focusLost();
    setBusy(true);
    const status = $('#diagramStatus');
    let read = false;
    try {
      let size, body = null;
      if (resume) {
        size = { width: rec.width, height: rec.height };
        // the picture isn't kept over a reload; what the page shows now gives way to Claude's reading
        $('#stepDecomp').hidden = true;
        $('#stepRun').hidden = true;
      } else {
        say(status, 'Preparing the picture for Claude…', 'busy');
        let img;
        try {
          img = await imageForClaude(image);
        } catch (e) {
          say(status, `The picture couldn’t be prepared for Claude: ${e.message}`, 'err');
          return;
        }
        size = { width: img.width, height: img.height };
        body = { image: img.data, mediaType: img.mediaType, width: img.width, height: img.height, name: sendable(name, 120) };
      }
      const j = newJob('decompose', status, {
        busy: resume ? `Picking up Claude’s reading of ${name}, which was under way when ${WHEN_LEFT}…`
          : 'Claude is reading the diagram… this can take a minute.',
        progress: p => `Claude is reading the diagram… ${p}.`,
      });
      if (resume) Object.assign(j, { id: rec.id, started: rec.started || Date.now() });
      if (focused && focusLost()) j.cancel.focus();
      let out;
      try {
        out = await runJob(j, { path: 'api/tm/decompose', body, meta: { name, width: size.width, height: size.height } });
      } catch (e) {
        say(status, `Claude couldn’t read the diagram: ${e.message}`, 'err');
        return;
      }
      if (out.result && (out.status === 'done' || out.status === 'cancelled')) {
        const reply = out.result;
        const model = TMParse.finish(Object.assign({}, reply, {
          notes: (Array.isArray(reply.notes) ? reply.notes : []).map(n => `Claude’s note: ${n}`),
          source: { kind: 'image', file: name, method: 'claude' },
          page: { w: size.width, h: size.height },
        }));
        setModel(model, { image });   // before clearImage(), which would otherwise let the picture go
        if (!resume) clearImage();
        persist(true);
        release(j, out);
        read = true;
        say(status, readSummary(model) + ' Claude read these from the picture: check every element, flow and zone below before you run the model.'
          + (resume ? ' (The picture isn’t kept when you leave the page.)' : ''), 'ok');
      } else {
        release(j, out);
        // a read picked up after leaving the page has no picture here any more (it isn't kept): say how to go on
        if (out.status === 'cancelled') say(status, `Claude was stopped before it finished, so nothing was read.${resume ? ' Choose the picture again to have it read.' : ''}`);
        else say(status, `Claude couldn’t read the diagram: ${out.error || 'the request failed.'}`, 'err');
      }
    } catch (e) {
      console.error(e);
      say(status, `Claude couldn’t read the diagram: ${e.message}`, 'err');
      forgetJob('decompose');
    } finally {
      setBusy(false);
      if (!read && !state.image && state.model) {
        // nothing replaced what was on the page, and there is no picture waiting: show it again
        $('#stepDecomp').hidden = false;
        $('#stepRun').hidden = false;
      }
      if (focused && focusLost()) focusTo(read ? '#systemName' : state.image ? '#claudeReadBtn' : '#fileInput');
    }
  }

  // ---------------------------------------------------------------- replacing or clearing a decomposition

  /** Ask before a decomposition with anything in it is replaced or cleared. Resolves to true to go ahead. */
  function confirmReplace(what, file) {
    const m = state.model;
    if (!m || !(m.elements.length || m.zones.length || m.flows.length || String(m.name || '').trim())) return Promise.resolve(true);
    const d = $('#replaceDialog');
    if (d.open) return Promise.resolve(false);
    const clear = what === 'clear';
    const typed = m.elements.some(e => !missingContext(e)) ? ', with the context filled in' : '';
    const has = `${plural(m.elements.length, 'element')}, ${plural(m.flows.length, 'data flow')} and ${plural(m.zones.length, 'trust zone')}${typed}`;
    const by = {
      file: `with the one read from ${file}`, example: 'with the example', blank: 'with a blank one',
      hand: `with a blank one, to fill in from the picture ${file}`, claude: `with Claude’s reading of the picture ${file}`,
    }[what];
    $('#replaceTitle').textContent = clear ? 'Clear the decomposition?' : 'Replace the current decomposition?';
    $('#replaceText').textContent = (clear
      ? `This removes the decomposition you are working on (${has}) from this page and from this browser.`
      : `This replaces the decomposition you are working on (${has}) ${by}.`)
      + ' It is kept only in this browser, so it can’t be brought back: save a copy first if you may need it.';
    $('#replaceOk').textContent = clear ? 'Clear it' : 'Replace it';
    say($('#replaceSaved'), '');
    return new Promise(resolve => {
      d.returnValue = '';
      d.addEventListener('close', () => resolve(d.returnValue === 'ok'), { once: true });
      d.showModal();
      $('#replaceCancel').focus();
    });
  }

  async function clearDecomposition() {
    if (state.busy || !(await confirmReplace('clear'))) return;
    if (TM_KEY) store.remove(TM_KEY);
    dropRun();
    clearImage();
    forgetModel();
    say($('#diagramStatus'), 'Cleared. Choose a diagram to start again.');
    $('#fileInput').focus();
  }

  /** The page without a decomposition, here or because another tab cleared it (a picture waiting to be read stays). */
  function forgetModel() {
    clearTimeout(saveTimer);
    saveTimer = 0;
    state.model = null;
    state.gen = '';
    state.saved = { gen: '', rev: 0 };
    state.result = null;
    state.marks = { events: new Map(), sequences: new Map() };
    state.stale = false;
    state.undo = [];
    state.rev++;
    home = new Map();
    setModelImage(null);
    $('#keepBtn').hidden = true;
    $('#stepDecomp').hidden = true;
    if (!state.running) $('#stepRun').hidden = true;
    clearResults();
    say($('#editStatus'), '');
    updateRun();
  }

  /** Hide the results and their status lines; a run under way (another tab replaced the decomposition) keeps its own. */
  function clearResults() {
    if (state.running) return;
    $('#results').hidden = true;
    say($('#runStatus'), '');
    say($('#dlStatus'), '');
  }

  // ---------------------------------------------------------------- the decomposition

  /**
   * Show a decomposition. A new one gets an id of its own (and the run kept for the one it replaces goes); one
   * taken up again, restored or saved by another tab, keeps its id (gen). write false: it is kept as it is already.
   * show false: steps 3 and 4 stay as they are (a picture waiting to be read keeps them out of the way).
   */
  function setModel(model, { image = null, savedHome = null, gen = '', write = true, show = true } = {}) {
    state.model = model;
    if (!gen) dropRun();
    state.gen = gen || newGen();
    state.result = null;
    state.marks = { events: new Map(), sequences: new Map() };
    state.stale = false;
    state.undo = [];
    state.rev++;
    setHome(model, savedHome);
    setModelImage(image);
    clearResults();
    say($('#editStatus'), '');
    if (write) persist();
    if (show) {
      $('#stepDecomp').hidden = false;
      $('#stepRun').hidden = false;
    }
    if (state.image) $('#keepBtn').hidden = false;
    renderDecomposition();
  }

  let saveTimer = 0;
  /** Keep the decomposition in this browser for this user: soon, or now. */
  function persist(now) {
    clearTimeout(saveTimer);
    saveTimer = 0;
    if (now) writeModel(); else saveTimer = setTimeout(writeModel, 300);
  }
  function writeModel() {
    saveTimer = 0;
    // signed in as someone else since this page opened (in another tab): don't file this decomposition under them
    if (!state.model || !TM_KEY || (window.Auth && window.Auth.user() !== USER)) return;
    // each save of a decomposition has the next number after the last one kept, whichever tab saved that
    const kept = store.get(TM_KEY);
    const last = n => (Number.isInteger(n) && n > 0 ? n : 0);
    const rev = Math.max(state.saved.gen === state.gen ? last(state.saved.rev) : 0,
      kept && kept.user === USER && kept.gen === state.gen ? last(kept.rev) : 0) + 1;
    if (!store.set(TM_KEY, { user: USER, gen: state.gen, rev, model: state.model, home: [...home] })) {
      editNote('This browser won’t keep the decomposition between visits (storage is full or blocked). Save it as a file.', 'err');
      return;
    }
    state.saved = { gen: state.gen, rev };
  }

  // ---- other tabs of this page

  /** The id of the decomposition kept in this browser for this user (whichever tab saved it). */
  function keptGen() {
    const kept = TM_KEY ? store.get(TM_KEY) : null;
    return kept && kept.user === USER && typeof kept.gen === 'string' ? kept.gen : '';
  }

  let followLater = false;
  /**
   * Another tab of this page (the same user, the same browser) saved or cleared the decomposition: take that
   * up here, so this tab never saves an older copy over it. A tab out of sight does it when it is next shown.
   * An edit made in this tab that is about to be saved goes first (the other tabs then take it up), but a
   * decomposition replaced in another tab replaces this one, as was asked for there.
   */
  function follow() {
    if (!TM_KEY) return;
    if (document.hidden) { followLater = true; return; }
    followLater = false;
    const rec = store.get(TM_KEY);
    if (!rec) {
      if (state.model && state.saved.gen && state.saved.gen === state.gen) clearedElsewhere();
      return;
    }
    if (rec.user !== USER || !rec.model || !Array.isArray(rec.model.elements)) return;
    const gen = typeof rec.gen === 'string' ? rec.gen : '';
    const rev = Number.isInteger(rec.rev) ? rec.rev : 0;
    if (gen && gen === state.saved.gen && rev === state.saved.rev) return;   // the copy this tab has
    // a copy saved by an earlier version of this page has no id: take it as an edit of this decomposition
    const replaced = !!gen && gen !== state.gen;
    if (!replaced && saveTimer) return;
    let model;
    try { model = TMParse.finish(rec.model); } catch (_) { return; }
    clearTimeout(saveTimer);
    saveTimer = 0;
    if (replaced) {
      setModel(model, { savedHome: rec.home, gen, write: false, show: !state.image && !state.busy });
      state.saved = { gen, rev };
      if (!diagramBusy()) {
        say($('#diagramStatus'), state.image ? `The decomposition was replaced in another tab of this page.${stillWaiting()}`
          : 'The decomposition was replaced in another tab of this page, so this tab shows the new one too.');
      }
      return;
    }
    state.saved = { gen: gen || state.gen, rev };
    state.model = model;
    setHome(model, rec.home);
    dropUndo();
    state.rev++;
    renderDecomposition();
    markStale();
    editNote('Updated with the changes made in another tab of this page.');
  }

  // a diagram is being read here (its status line, with a Cancel, is in use)
  const diagramBusy = () => state.busy && !state.running;

  function clearedElsewhere() {
    forgetModel();
    if (!diagramBusy()) {
      say($('#diagramStatus'), state.image ? `The decomposition was cleared in another tab of this page.${stillWaiting()}`
        : 'The decomposition was cleared in another tab of this page. Choose a diagram to start again.');
    }
  }

  /** The decomposition changed: keep it, check it again, and mark the results out of date until the next run. */
  function changed({ soon = false, keepUndo = false } = {}) {
    state.rev++;
    if (!keepUndo) dropUndo();
    persist();
    if (soon) scheduleWarnings(); else renderWarnings();
    markStale();
  }

  function markStale(text) {
    if (!state.result) return;
    const first = !state.stale;
    state.stale = true;
    if (!state.busy && (first || text)) say($('#runStatus'), text || STALE, 'warn');
  }

  // ---- the source layout

  const box = g => (g && [g.x, g.y, g.w, g.h].every(Number.isFinite) && g.w > 0 && g.h > 0 ? { x: g.x, y: g.y, w: g.w, h: g.h } : null);

  /** Note where the diagram put every zone and element, or take the note kept with a saved decomposition. */
  function setHome(model, saved) {
    home = new Map();
    if (Array.isArray(saved)) {
      const ids = new Set([...model.zones, ...model.elements].map(x => x.id));
      for (const [id, h] of saved.filter(Array.isArray)) {
        if (ids.has(id) && h && typeof h === 'object') home.set(id, { geometry: box(h.geometry), parent: h.parent || null, zone: h.zone || null });
      }
      return;
    }
    for (const z of model.zones) home.set(z.id, { geometry: box(z.geometry), parent: z.parent || null });
    for (const e of model.elements) home.set(e.id, { geometry: box(e.geometry), zone: e.zone || null });
  }

  /**
   * The DFD keeps the diagram's own layout while every element is where the diagram drew it. An element moved
   * to another zone, or in a zone moved into another, loses its position (so the DFD is laid out
   * automatically) until it is back; the rest of the layout is kept meanwhile.
   */
  function applyLayout() {
    const m = state.model;
    const zoneById = new Map(m.zones.map(z => [z.id, z]));
    const placed = new Map();
    const zoneInPlace = id => {
      if (!id) return true;
      if (placed.has(id)) return placed.get(id);
      placed.set(id, false);   // guards a parent cycle
      const z = zoneById.get(id), h = home.get(id);
      const ok = !!z && !!h && (z.parent || null) === (h.parent || null) && zoneInPlace(z.parent);
      placed.set(id, ok);
      return ok;
    };
    for (const z of m.zones) {
      const h = home.get(z.id);
      if (h) z.geometry = zoneInPlace(z.id) ? box(h.geometry) : null;
    }
    for (const e of m.elements) {
      const h = home.get(e.id);
      if (h) e.geometry = (e.zone || null) === (h.zone || null) && zoneInPlace(e.zone) ? box(h.geometry) : null;
    }
  }

  function renderSource() {
    const m = state.model;
    if (!m) return;
    const how = {
      parsed: `Read from ${m.source.file || 'the diagram'}`,
      claude: `Read by Claude from the picture ${m.source.file || ''} — check it against the picture`,
      manual: m.source.kind === 'image' ? `Decomposed by hand from the picture ${m.source.file || ''}` : 'Built by hand',
    }[m.source.method] || 'Decomposition';
    const loose = m.elements.filter(e => !e.geometry);
    const drawn = m.elements.some(e => e.geometry || (home.get(e.id) || {}).geometry);
    let layout = '';
    if (m.elements.length && !loose.length) layout = ' In the DFD, the diagram keeps the source layout.';
    else if (m.elements.length && !drawn) layout = ' In the DFD, the diagram is laid out automatically.';
    else if (m.elements.length) {
      layout = ` In the DFD, the diagram is laid out automatically, because ${namesOf(loose)} ${loose.length === 1 ? 'has' : 'have'} no place in the`
        + ` source layout (added, or moved to another zone). Remove what you added and put back what you moved to keep the source layout.`;
    }
    $('#sourceLine').textContent = `${how.trim()}.${layout}`;
    $('#pictureBox').hidden = !(state.modelImage && m.source.kind === 'image');
  }

  const nameOf = e => String(e.label || '').trim() || 'Unnamed element';
  const zoneLabel = z => (z ? String(z.label || '').trim() || 'Unnamed trust zone' : '');
  function namesOf(list) {
    const names = list.slice(0, 3).map(e => `"${nameOf(e)}"`);
    if (list.length > 3) return `${names.join(', ')} and ${list.length - 3} more`;
    return names.length > 1 ? `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}` : names[0];
  }

  /** Zones in nesting order, with their depth. A zone no walk from the top reaches (a parent cycle) still comes, last. */
  function zoneTree() {
    const zones = state.model.zones;
    const ids = new Set(zones.map(z => z.id));
    const kids = new Map();
    for (const z of zones) {
      const p = ids.has(z.parent) && z.parent !== z.id ? z.parent : null;
      if (!kids.has(p)) kids.set(p, []);
      kids.get(p).push(z);
    }
    const out = [], seen = new Set();
    const walk = (parent, depth) => {
      for (const z of kids.get(parent) || []) {
        if (seen.has(z.id)) continue;
        seen.add(z.id);
        out.push({ zone: z, depth });
        walk(z.id, depth + 1);
      }
    };
    walk(null, 0);
    for (const z of zones) {
      if (seen.has(z.id)) continue;
      seen.add(z.id);
      out.push({ zone: z, depth: 0 });
      walk(z.id, 1);
    }
    return out;
  }
  const zoneText = t => `${'\u00a0\u00a0'.repeat(t.depth)}${t.depth ? '└ ' : ''}${zoneLabel(t.zone)}`;

  /** A zone and every zone inside it. */
  function subtreeOf(id) {
    const out = new Set([id]);
    for (let grew = true; grew;) {
      grew = false;
      for (const z of state.model.zones) if (!out.has(z.id) && out.has(z.parent)) { out.add(z.id); grew = true; }
    }
    return out;
  }

  /** A zone list's options, nested zones indented under their parents; for a zone's own "Inside" list (own), without it and the zones inside it. */
  function zoneOptions(selected, own, tree = zoneTree()) {
    const skip = own ? subtreeOf(own) : null;
    return [el('option', { value: '', text: '— none —', selected: !selected }),
      ...tree.filter(t => !skip || !skip.has(t.zone.id))
        .map(t => el('option', { value: t.zone.id, text: zoneText(t), selected: t.zone.id === selected }))];
  }

  /**
   * Draw the whole editor. Keyboard focus stays on the control with the same data-key (or moves to focusKey),
   * with its caret, and each table keeps its horizontal scroll, so a redraw doesn't move the user.
   */
  function renderDecomposition(focusKey) {
    const m = state.model;
    const editor = $('#editor');
    const active = document.activeElement;
    const key = focusKey || (active && editor.contains(active) && active.dataset.key) || '';
    let caret = null;
    if (!focusKey && key) {
      try { if (typeof active.selectionStart === 'number') caret = [active.selectionStart, active.selectionEnd]; } catch (_) { /* no caret */ }
    }
    const scroll = {};
    for (const s of editor.querySelectorAll('[data-scroll]')) scroll[s.dataset.scroll] = s.scrollLeft;

    const tree = zoneTree();
    const nameInput = el('input', { type: 'text', value: m.name || '', placeholder: 'e.g. Customer Portal', id: 'systemName', 'data-key': 'name',
      on: { input: e => { m.name = e.target.value; changed({ soon: true }); } } });
    const head = el('div', { class: 'editor-head' },
      el('label', { class: 'field', for: 'systemName' }, 'Name of the system (used in the deliverables)', nameInput));
    editor.replaceChildren(head, zonesSection(tree), elementsSection(tree), flowsSection(), toolsRow());

    for (const s of editor.querySelectorAll('[data-scroll]')) if (scroll[s.dataset.scroll]) s.scrollLeft = scroll[s.dataset.scroll];
    const target = key && editor.querySelector(`[data-key="${CSS.escape(key)}"]`);
    if (target) {
      target.focus({ preventScroll: true });
      if (caret) { try { target.setSelectionRange(caret[0], caret[1]); } catch (_) { /* not a text field */ } }
      reveal(target);
    }
    renderSource();
    renderWarnings();
  }

  /** Scroll a control into view when it is off-screen, or behind the status bar at the foot of the window. */
  function reveal(n) {
    const r = n.getBoundingClientRect();
    const bar = $('#editStatus').getBoundingClientRect();
    const bottom = bar.height && bar.top < window.innerHeight ? bar.top : window.innerHeight;
    if (r.top < 0 || r.bottom > bottom) n.scrollIntoView({ block: 'center' });
  }

  /** An editor section: a <details> whose summary carries the count, open by default when short. */
  function section(key, title, count, ...body) {
    const open = key in state.open ? state.open[key] : key === 'elements' || count <= 12;
    const d = el('details', { class: 'ed-section', open },
      el('summary', {}, el('h3', {}, title, el('span', { class: 'count', text: String(count) }))), ...body);
    d.addEventListener('toggle', () => { state.open[key] = d.open; });
    return d;
  }

  /** A button's handlers that act once: not again on the second click of a double-click, or while Enter is held. */
  const once = fn => ({
    click: ev => { if (ev.detail > 1) return; fn(); },
    keydown: ev => { if (ev.repeat && (ev.key === 'Enter' || ev.key === ' ')) ev.preventDefault(); },
  });

  /** A Remove button (acting once, so it doesn't remove the row that moves up under it). */
  function removeButton(key, aria, name, fn) {
    return el('button', { type: 'button', text: 'Remove', 'data-key': key, 'data-aria': aria, 'aria-label': aria.replace('{name}', name), on: once(fn) });
  }

  function zonesSection(tree) {
    const m = state.model;
    return section('zones', 'Trust zones', m.zones.length,
      el('p', {}, 'Each zone is a trust boundary (CSA §3.2 Task C). Flows between zones are where the threats that matter most are.'),
      m.zones.length ? el('div', { class: 'table-scroll', 'data-scroll': 'zones' }, el('table', { class: 'edit', id: 'zonesTable' },
        el('thead', {}, el('tr', {}, el('th', { text: 'Zone' }), el('th', { text: 'Inside' }), el('th', { class: 'num', text: 'Elements' }), el('th', {}))),
        el('tbody', {}, m.zones.map(z => zoneRow(z, tree))))) : el('p', { class: 'empty', text: 'No trust zones yet.' }),
      el('div', { class: 'ed-add' }, el('button', { type: 'button', text: 'Add a zone', 'data-key': 'add:zone', on: { click: addZone } })));
  }

  function zoneRow(z, tree) {
    const key = f => `z:${z.id}:${f}`;
    return el('tr', { 'data-zone': z.id },
      el('td', {}, el('input', { type: 'text', class: 'w-label', value: z.label, 'aria-label': 'Zone name', 'data-key': key('label'),
        on: { input: e => { z.label = e.target.value; renamedZone(z); changed({ soon: true }); } } })),
      el('td', {}, el('select', { class: 'w-zone', 'data-zones': 'parent', 'data-key': key('parent'),
        'data-aria': 'Zone that {name} sits in', 'aria-label': `Zone that ${zoneLabel(z)} sits in`,
        on: { change: e => { z.parent = e.target.value || null; movedZone(); } } }, zoneOptions(z.parent, z.id, tree))),
      el('td', { class: 'num', 'data-count': '' }, String(state.model.elements.filter(e => e.zone === z.id).length)),
      el('td', { class: 'del' }, removeButton(key('remove'), 'Remove zone {name}', zoneLabel(z), () => removeZone(z))));
  }

  function flagSelect(value, key, aria, name, onChange) {
    const v = value === true ? 'yes' : value === false ? 'no' : '';
    return el('select', { class: 'w-flag', 'data-key': key, 'data-aria': aria, 'aria-label': aria.replace('{name}', name),
      on: { change: e => onChange(e.target.value === 'yes' ? true : e.target.value === 'no' ? false : null) } },
    FLAG.map(([val, text]) => el('option', { value: val, text, selected: val === v })));
  }

  function elementsSection(tree) {
    const m = state.model;
    return section('elements', 'Elements', m.elements.length,
      el('p', {}, 'External entities, processes, clusters of processes and data stores (CSA Figure 3). "Crown jewel" and "AI element" are worked out from the context unless you set them. A crown jewel is marked with a star on the DFD; AI elements also get the MAESTRO / ATLAS pass.'),
      m.elements.length ? el('div', { class: 'table-scroll', 'data-scroll': 'elements' }, el('table', { class: 'edit', id: 'elementsTable' },
        el('thead', {}, el('tr', {}, ['Element', 'Type', 'Trust zone', 'What it does', 'Data it holds', 'Authentication', 'Trust', 'Crown jewel', 'AI element', '']
          .map(h => el('th', { text: h })))),
        el('tbody', {}, m.elements.map(e => elementRow(e, tree))))) : el('p', { class: 'empty', text: 'No elements yet.' }),
      el('div', { class: 'ed-add' }, el('button', { type: 'button', text: 'Add an element', 'data-key': 'add:element', on: { click: addElement } })));
  }

  function elementRow(e, tree) {
    const key = f => `e:${e.id}:${f}`;
    const name = nameOf(e);
    const ctx = (f, label, placeholder) => el('td', {}, el('textarea', { class: 'w-ctx', rows: 1, 'data-key': key(f),
      'data-aria': `${label} — {name}`, 'aria-label': `${label} — ${name}`, placeholder,
      value: e.context[f] || '', on: { input: ev => { e.context[f] = ev.target.value; markMissing(e); changed({ soon: true }); } } }));
    return el('tr', { 'data-el': e.id, class: missingContext(e) ? 'missing' : null },
      el('td', {}, el('input', { type: 'text', class: 'w-label', value: e.label, 'aria-label': 'Element name', 'data-key': key('label'),
        on: { input: ev => { e.label = ev.target.value; renamedElement(e); changed({ soon: true }); } } })),
      el('td', {}, el('select', { class: 'w-type', 'data-key': key('type'), 'data-aria': 'Type of {name}', 'aria-label': `Type of ${name}`,
        on: { change: ev => { e.type = ev.target.value; changed(); } } },
      TMParse.TYPES.map(t => el('option', { value: t, text: TMParse.TYPE_LABELS[t], selected: t === e.type })))),
      el('td', {}, el('select', { class: 'w-zone', 'data-zones': 'element', 'data-key': key('zone'),
        'data-aria': 'Trust zone of {name}', 'aria-label': `Trust zone of ${name}`,
        on: { change: ev => { e.zone = ev.target.value || null; movedElement(); } } }, zoneOptions(e.zone, null, tree))),
      ctx('purpose', 'What it does', 'What it does'),
      ctx('sensitivity', 'Data it holds', 'e.g. Restricted — PII'),
      ctx('auth', 'How it authenticates', 'e.g. SSO with MFA'),
      ctx('trust', 'How far it is trusted', 'e.g. Untrusted external'),
      el('td', {}, flagSelect(e.crownJewel, key('crown'), 'Crown jewel — {name}', name, v => { e.crownJewel = v; changed(); })),
      el('td', {}, flagSelect(e.ai, key('ai'), 'AI element — {name}', name, v => { e.ai = v; changed(); })),
      el('td', { class: 'del' }, removeButton(key('remove'), 'Remove {name}', name, () => removeElement(e))));
  }

  const missingContext = e => !['purpose', 'sensitivity', 'auth', 'trust'].some(k => String(e.context[k] || '').trim());
  const rowOf = (kind, id) => document.querySelector(`#editor tr[data-${kind}="${CSS.escape(id)}"]`);
  function markMissing(e) {
    const tr = rowOf('el', e.id);
    if (tr) tr.classList.toggle('missing', missingContext(e));
  }

  function flowsSection() {
    const m = state.model;
    return section('flows', 'Data flows', m.flows.length,
      el('p', {}, 'Directed connections between elements (CSA §3.2 Task B), labelled with the protocol or data they carry.'),
      m.flows.length ? el('div', { class: 'table-scroll', 'data-scroll': 'flows' }, el('table', { class: 'edit', id: 'flowsTable' },
        el('thead', {}, el('tr', {}, ['From', 'To', 'Label', 'Direction', '', ''].map(h => el('th', { text: h })))),
        el('tbody', {}, m.flows.map(flowRow)))) : el('p', { class: 'empty', text: m.elements.length < 2 ? 'Add at least two elements to draw a data flow.' : 'No data flows yet.' }),
      el('div', { class: 'ed-add' }, el('button', { type: 'button', text: 'Add a data flow', 'data-key': 'add:flow', disabled: m.elements.length < 2, on: { click: addFlow } })));
  }

  const OTHER_END = { source: 'target', target: 'source' };

  /**
   * A flow's From or To list: every element but the one at the flow's other end, so a flow always joins two
   * elements (one drawn from an element to itself would be left out of the model, and noted, on every reload).
   */
  function endOptions(f, side) {
    const other = f[OTHER_END[side]];
    return state.model.elements.filter(e => e.id !== other || e.id === f[side])
      .map(e => el('option', { value: e.id, text: nameOf(e), selected: e.id === f[side] }));
  }

  function flowRow(f) {
    const key = k => `f:${f.id}:${k}`;
    // a change to one end changes what the other end's list offers (not the list in use)
    const end = side => el('select', { class: 'w-flow', 'data-end': side, 'data-key': key(side),
      on: { change: ev => { f[side] = ev.target.value; refreshEnds(f, [OTHER_END[side]]); refreshFlowNote(f); nameFlow(f); changed(); } } }, endOptions(f, side));
    const tr = el('tr', { 'data-flow': f.id },
      el('td', {}, end('source')),
      el('td', {}, end('target')),
      el('td', {}, el('input', { type: 'text', class: 'w-label', value: f.label, placeholder: 'e.g. HTTPS / API', 'data-key': key('label'),
        on: { input: ev => { f.label = ev.target.value; nameFlow(f); changed({ soon: true }); } } })),
      el('td', {}, el('div', { class: 'dir' },
        el('label', { class: 'chk' }, el('input', { type: 'checkbox', checked: !!f.bidirectional, 'data-key': key('both'),
          on: { change: ev => { f.bidirectional = ev.target.checked; changed(); } } }), 'both ways'),
        el('button', { type: 'button', text: 'Reverse', 'data-key': key('reverse'), title: 'Swap From and To',
          on: once(() => reverseFlow(f)) }))),
      el('td', { class: 'note', 'data-note': '' }, flowNote(f)),
      el('td', { class: 'del' }, el('button', { type: 'button', text: 'Remove', 'data-key': key('remove'), on: once(() => removeFlow(f)) })));
    nameFlow(f, tr);
    return tr;
  }

  /** What tells one data flow from another in words: its ends, and its label when it has one. */
  function flowWords(f) {
    const end = id => `"${nameOf(state.model.elements.find(e => e.id === id) || { label: '' })}"`;
    const chars = Array.from(String(f.label || '').trim());
    const label = chars.length > 60 ? chars.slice(0, 59).join('') + '…' : chars.join('');
    return { from: end(f.source), to: end(f.target), ends: `from ${end(f.source)} to ${end(f.target)}`, label: label ? ` "${label}"` : '' };
  }

  /** The names a flow's controls give screen readers say which flow they belong to; kept current as the flow changes. */
  function nameFlow(f, tr = rowOf('flow', f.id)) {
    if (!tr) return;
    const w = flowWords(f);
    const names = {
      source: `From — the data flow${w.label} ${w.ends}`,
      target: `To — the data flow${w.label} ${w.ends}`,
      label: `Label of the data flow ${w.ends}`,
      both: `both ways — the data flow${w.label} ${w.ends}`,
      reverse: `Reverse the data flow${w.label} ${w.ends}`,
      remove: `Remove the data flow${w.label} ${w.ends}`,
    };
    for (const [k, name] of Object.entries(names)) {
      const n = tr.querySelector(`[data-key="${CSS.escape(`f:${f.id}:${k}`)}"]`);
      if (n) n.setAttribute('aria-label', name);
    }
  }

  /** Rebuild a flow's From or To lists (sides) in place, after the other end changed. */
  function refreshEnds(f, sides) {
    const tr = rowOf('flow', f.id);
    for (const side of sides) {
      const s = tr && tr.querySelector(`select[data-end="${side}"]`);
      if (!s) continue;
      s.replaceChildren(...endOptions(f, side));
      s.value = f[side];
    }
  }

  function reverseFlow(f) {
    [f.source, f.target] = [f.target, f.source];
    refreshEnds(f, ['source', 'target']);
    nameFlow(f);
    changed();
    editNote(`Reversed the data flow: it now runs ${flowWords(f).ends}.`, 'ok');
  }

  const crosses = f => {
    const a = state.model.elements.find(e => e.id === f.source), b = state.model.elements.find(e => e.id === f.target);
    return !!(a && b && (a.zone || null) !== (b.zone || null));
  };
  const flowNote = f => (crosses(f) ? 'crosses a trust boundary' : '');
  function refreshFlowNote(f) {
    const tr = rowOf('flow', f.id);
    const cell = tr && tr.querySelector('[data-note]');
    if (cell) cell.textContent = flowNote(f);
  }

  function toolsRow() {
    const contextInput = el('input', { type: 'file', accept: '.json,application/json', hidden: true, on: { change: e => loadContext(e.target.files[0], e.target) } });
    return el('div', { class: 'ed-tools' },
      el('button', { type: 'button', 'data-key': 'tool:save', text: 'Save the decomposition (.json)', on: { click: () => saveDecomposition() } }),
      el('button', { type: 'button', 'data-key': 'tool:context', 'data-idle': '', disabled: state.busy, text: 'Load component context (.json)',
        title: 'A JSON object keyed by element name or id: { "Database": { "purpose": …, "sensitivity": …, "auth": …, "trust": … } }',
        on: { click: () => contextInput.click() } }), contextInput,
      el('span', { class: 'spacer' }),
      el('button', { type: 'button', class: 'link', 'data-key': 'tool:clear', 'data-idle': '', disabled: state.busy, text: 'Clear the decomposition',
        on: { click: clearDecomposition } }));
  }

  // ---- edits that change what other controls show: updated in place, so nothing the user is on is redrawn

  /** An element was renamed: the flow lists that name it, and the labels its own row gives screen readers. */
  function renamedElement(e) {
    for (const o of document.querySelectorAll(`#editor select[data-end] option[value="${CSS.escape(e.id)}"]`)) o.textContent = nameOf(e);
    relabel(rowOf('el', e.id), nameOf(e));
    for (const f of state.model.flows) if (f.source === e.id || f.target === e.id) nameFlow(f);
  }
  function renamedZone(z) {
    const t = zoneTree().find(x => x.zone === z);
    for (const o of document.querySelectorAll(`#editor select[data-zones] option[value="${CSS.escape(z.id)}"]`)) o.textContent = t ? zoneText(t) : zoneLabel(z);
    relabel(rowOf('zone', z.id), zoneLabel(z));
  }
  function relabel(tr, name) {
    if (tr) for (const n of tr.querySelectorAll('[data-aria]')) n.setAttribute('aria-label', n.dataset.aria.replace('{name}', name));
  }

  /** An element moved to another zone: the zone counts, the flows' boundary notes, and the layout. */
  function movedElement() {
    applyLayout();
    for (const tr of document.querySelectorAll('#editor tr[data-zone]')) {
      const cell = tr.querySelector('[data-count]');
      if (cell) cell.textContent = String(state.model.elements.filter(e => e.zone === tr.dataset.zone).length);
    }
    for (const f of state.model.flows) refreshFlowNote(f);
    renderSource();
    changed();
  }

  /** A zone moved into another: the zone lists, and the layout. */
  function movedZone() {
    applyLayout();
    refreshZoneSelects();
    renderSource();
    changed();
  }

  /** Rebuild the zone lists whose zones changed, leaving the others (and the one in use) alone. */
  function refreshZoneSelects() {
    const m = state.model;
    const tree = zoneTree();
    for (const s of document.querySelectorAll('#editor select[data-zones]')) {
      const tr = s.closest('tr');
      const zone = s.dataset.zones === 'parent' ? m.zones.find(z => z.id === tr.dataset.zone) : null;
      const item = zone || m.elements.find(e => e.id === tr.dataset.el);
      if (!item) continue;
      const value = (zone ? zone.parent : item.zone) || '';
      const opts = zoneOptions(value, zone ? zone.id : null, tree);
      const same = s.options.length === opts.length && opts.every((o, i) => s.options[i].value === o.value && s.options[i].textContent === o.textContent);
      if (!same) s.replaceChildren(...opts);
      if (s.value !== value) s.value = value;
    }
  }

  // ---- warnings

  // finish()'s checks for a model with no elements, no flows or no zones speak of the diagram; the editor's say what to add.
  let editorWords = null;
  function editorWording() {
    if (editorWords) return editorWords;
    editorWords = new Map();
    try {
      const [none] = TMParse.finish({}).warnings;
      if (none) editorWords.set(none, 'Add the elements of the system: external entities, processes and data stores.');
      for (const w of TMParse.finish({ elements: [{ id: 'e', label: 'e' }] }).warnings) {
        if (/zone|boundar/i.test(w)) editorWords.set(w, 'No trust zones: without trust boundaries, the threats that cross zones — the ones that matter most — can’t be told apart.');
        else if (/flow/i.test(w)) editorWords.set(w, 'No data flows yet: CSA §3.2 needs the connections between elements.');
      }
    } catch (_) { /* keep finish()'s own words */ }
    return editorWords;
  }

  let warnTimer = 0;
  const scheduleWarnings = () => { clearTimeout(warnTimer); warnTimer = setTimeout(renderWarnings, 150); };

  /** The decomposition's warnings: what the run will say about it (finish()'s notes and CSA §3.2 checks), and the editor's own. */
  function renderWarnings() {
    clearTimeout(warnTimer);
    const m = state.model;
    if (!m) return;
    const words = editorWording();
    let list = [];
    try { list = TMParse.finish(clone(m)).warnings.map(w => words.get(w) || w); } catch (_) { /* checked again when the model runs */ }
    const bare = m.elements.filter(missingContext).length;
    if (bare) list.push(`${bare} element${bare === 1 ? ' has' : 's have'} no context (marked on the left): their threats will be generic and their severity understated.`);
    const names = m.elements.map(e => e.label.trim().toLowerCase());
    const dupe = names.findIndex((l, i) => l && names.indexOf(l) !== i);
    if (dupe >= 0) list.push(`Two elements share the name "${m.elements[dupe].label.trim()}": give each a distinct name so the register is unambiguous.`);
    const ul = $('#decompWarnings');
    ul.replaceChildren(...list.map(t => el('li', { text: t })));
    ul.hidden = !list.length;
    updateRun();
  }

  // ---- adding and removing

  function selectKey(key) {
    const n = $(`#editor [data-key="${CSS.escape(key)}"]`);
    if (n && n.select) n.select();
  }

  /** "Element 32", "Zone 4": numbered after the rows there are, skipping a name a row already has. */
  function freshName(word, items) {
    const taken = new Set(items.map(x => String(x.label || '').trim().toLowerCase()));
    let n = items.length + 1;
    while (taken.has(`${word} ${n}`.toLowerCase())) n++;
    return `${word} ${n}`;
  }

  function addZone() {
    const z = { id: TMParse.newId('z'), label: freshName('Zone', state.model.zones), parent: null, geometry: null };
    state.model.zones.push(z);
    changed();
    renderDecomposition(`z:${z.id}:label`);
    selectKey(`z:${z.id}:label`);
  }

  function addElement() {
    const e = { id: TMParse.newId('e'), label: freshName('Element', state.model.elements), type: 'process', zone: null, geometry: null,
      context: { purpose: '', sensitivity: '', auth: '', trust: '' }, crownJewel: null, ai: null };
    state.model.elements.push(e);
    changed();
    renderDecomposition(`e:${e.id}:label`);
    selectKey(`e:${e.id}:label`);
  }

  function addFlow() {
    const m = state.model;
    if (m.elements.length < 2) return;
    const f = { id: TMParse.newId('f'), source: m.elements[0].id, target: m.elements[1].id, label: '', bidirectional: false };
    m.flows.push(f);
    changed();
    renderDecomposition(`f:${f.id}:source`);
  }

  const UNDO_MAX = 10;
  const UNDO_KEY = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '') ? '⌘Z' : 'Ctrl+Z';

  /**
   * Make a change that can be undone (a removal, a context file loaded): the decomposition as it was is kept,
   * up to the last UNDO_MAX such changes, until an edit of another kind. Undo (or Ctrl+Z / ⌘Z) puts back the
   * latest first. mutate() makes the change and says what it did; focus: where keyboard focus goes next (for a
   * removal, the next row's Remove, so keyboard users stay where they were); back: where it goes after Undo.
   */
  function undoable({ what, mutate, focus, back, kind = '' }) {
    const before = { model: clone(state.model), home: clone([...home]), what, focus: back };
    const text = mutate();
    changed({ keepUndo: true });
    state.undo = state.undo.concat([before]).slice(-UNDO_MAX);
    renderDecomposition(typeof focus === 'function' ? focus() : focus);
    offerUndo(text, kind);
  }

  /** The status bar after a change that can be undone: what it did, then Undo and its shortcut (hint: what Undo does now). */
  function offerUndo(text, kind = '', hint = '') {
    if (!state.undo.length) { editNote(text, kind || 'ok'); return; }
    editNote(text, kind, ...undoControls(hint));
  }
  /** What the bar offers while a change can be undone; all of it goes (dropUndo) once nothing can. */
  function undoControls(hint = '') {
    const n = state.undo.length;
    return [hint ? el('span', { 'data-undo': '', text: hint }) : null,
      el('button', { type: 'button', id: 'undoBtn', text: 'Undo', 'data-undo': '', 'aria-keyshortcuts': 'Control+Z Meta+Z', on: { click: undoLast } }),
      el('span', { class: 'note', 'data-undo': '', text: `or press ${UNDO_KEY}${n > 1 ? ` · ${n} changes to undo, the latest first` : ''}` })].filter(Boolean);
  }

  function undoLast() {
    const u = state.undo.pop();
    if (!u) return;
    state.model = u.model;
    home = new Map(u.home);
    changed({ keepUndo: true });
    renderDecomposition(u.focus);
    const next = state.undo[state.undo.length - 1];
    offerUndo(`Put back ${u.what}.`, '', next ? `Undo again to put back ${next.what} too.` : '');
  }

  function dropUndo() {
    if (!state.undo.length) return;
    state.undo = [];
    for (const n of document.querySelectorAll('#editStatus [data-undo]')) n.remove();
  }

  // The Z key: by the letter the layout gives it when that is a Latin one (QWERTZ puts Z where QWERTY has Y), and
  // otherwise by its place, as with a Russian or Greek layout, where it types 'я' or 'ζ'.
  const isZ = e => (/^[a-z]$/i.test(e.key || '') ? e.key.toLowerCase() === 'z' : e.code === 'KeyZ' || e.keyCode === 90);

  // Ctrl+Z (⌘Z) while there is a change to undo, except in a text field, where it undoes the typing.
  function undoKey(e) {
    if (!state.undo.length || e.defaultPrevented || e.altKey || e.shiftKey || !(e.ctrlKey || e.metaKey) || !isZ(e)) return;
    const t = e.target;
    const typing = t && (t.isContentEditable || t.tagName === 'TEXTAREA'
      || (t.tagName === 'INPUT' && !/^(button|checkbox|radio|file|submit|reset|image|range|color)$/i.test(t.type)));
    if (typing || document.querySelector('dialog[open]') || $('#stepDecomp').hidden) return;
    e.preventDefault();
    undoLast();
  }

  function removeZone(z) {
    const m = state.model;
    const i = m.zones.indexOf(z);
    if (i < 0) return;
    undoable({
      what: `the trust zone "${zoneLabel(z)}"`,
      mutate: () => {
        const inside = m.elements.filter(e => e.zone === z.id).length;
        const parent = m.zones.find(p => p.id === z.parent);
        const where = parent ? `now in "${zoneLabel(parent)}"` : 'now outside every zone';
        // what was in the zone moves up to its parent, which on the diagram is where it was drawn
        const h = home.get(z.id);
        const up = h ? h.parent || null : z.parent || null;
        for (const e of m.elements) if (e.zone === z.id) e.zone = z.parent || null;
        for (const c of m.zones) if (c.parent === z.id) c.parent = z.parent || null;
        for (const x of home.values()) {
          if (x.zone === z.id) x.zone = up;
          if (x.parent === z.id) x.parent = up;
        }
        home.delete(z.id);
        m.zones = m.zones.filter(x => x !== z);
        applyLayout();
        return `Removed the trust zone "${zoneLabel(z)}"${inside ? `; its ${plural(inside, 'element is', 'elements are')} ${where}` : ''}.`;
      },
      focus: () => { const next = m.zones[i] || m.zones[i - 1]; return next ? `z:${next.id}:remove` : 'add:zone'; },
      back: `z:${z.id}:remove`,
    });
  }

  function removeElement(e) {
    const m = state.model;
    const i = m.elements.indexOf(e);
    if (i < 0) return;
    undoable({
      what: `the element "${nameOf(e)}"`,
      mutate: () => {
        const flows = m.flows.filter(f => f.source === e.id || f.target === e.id).length;
        m.elements = m.elements.filter(x => x !== e);
        m.flows = m.flows.filter(f => f.source !== e.id && f.target !== e.id);
        home.delete(e.id);
        return `Removed the element "${nameOf(e)}"${flows ? ` and its ${plural(flows, 'data flow')}` : ''}.`;
      },
      focus: () => { const next = m.elements[i] || m.elements[i - 1]; return next ? `e:${next.id}:remove` : 'add:element'; },
      back: `e:${e.id}:remove`,
    });
  }

  function removeFlow(f) {
    const m = state.model;
    const i = m.flows.indexOf(f);
    if (i < 0) return;
    const what = `the data flow ${flowWords(f).ends}`;
    undoable({
      what,
      mutate: () => { m.flows = m.flows.filter(x => x !== f); return `Removed ${what}.`; },
      focus: () => { const next = m.flows[i] || m.flows[i - 1]; return next ? `f:${next.id}:remove` : 'add:flow'; },
      back: `f:${f.id}:remove`,
    });
  }

  function saveDecomposition(line) {
    if (!state.model) return;
    const slug = String(state.model.name || 'system').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'system';
    const name = `${slug}-decomposition.json`;
    save(new Blob([TMParse.toJson(state.model)], { type: 'application/json' }), name);
    if (line) say(line, `Saved a copy as ${name}.`, 'ok');
    else editNote(`Saved a copy as ${name}.`, 'ok');
  }

  const CONTEXT_FIELDS = ['purpose', 'sensitivity', 'auth', 'trust'];

  /**
   * A component-context file over the decomposition. Its values win over what the elements have (that is what
   * loading it asks for), so the status says what it filled in and what it replaced, and Undo puts back what was.
   */
  async function loadContext(file, input) {
    input.value = '';   // the same file can be chosen again
    if (!file || !state.model || state.busy) return;
    let json;
    try {
      json = JSON.parse(await file.text());
      if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error('it isn’t a JSON object keyed by element name or id.');
    } catch (e) {
      editNote(`The context file can't be read: ${e.message}`, 'err');
      return;
    }
    const m = state.model;
    // what the file changes, worked out on a copy first
    const trial = clone(m);
    const missed = TMParse.applyContext(trial, json);
    let filled = 0, replaced = 0;
    const touched = [], overwritten = [];
    for (const e of m.elements) {
      const t = trial.elements.find(x => x.id === e.id);
      if (!t) continue;
      let filledHere = 0, replacedHere = 0;
      for (const f of CONTEXT_FIELDS) {
        const was = String(e.context[f] || '').trim();
        if (was === String(t.context[f] || '').trim()) continue;
        if (was) replacedHere++; else filledHere++;
      }
      for (const f of ['type', 'crownJewel', 'ai']) {
        if (e[f] === t[f]) continue;
        // a type, or a flag that was set, is replaced; a flag left to be worked out is filled in
        if (f === 'type' || typeof e[f] === 'boolean') replacedHere++; else filledHere++;
      }
      filled += filledHere;
      replaced += replacedHere;
      if (filledHere || replacedHere) touched.push(e);
      if (replacedHere) overwritten.push(e);
    }
    const list = missed.slice(0, 10).join(', ') + (missed.length > 10 ? ` and ${missed.length - 10} more` : '');
    const unmatched = missed.length ? ` No element matched: ${list}.` : '';
    if (!touched.length) {
      const matched = Object.values(json).filter(v => v && typeof v === 'object').length - missed.length;
      editNote(matched > 0 ? `${file.name} changes nothing: the ${plural(matched, 'element')} it names already ${matched === 1 ? 'has' : 'have'} that context.${unmatched}`
        : missed.length ? `No element in the decomposition matches ${file.name}: ${list}.` : `${file.name} names no element.`, matched > 0 && !missed.length ? 'ok' : 'warn');
      return;
    }
    const parts = [filled ? `${plural(filled, 'value')} filled in` : '',
      replaced ? `${plural(replaced, 'value')} replaced, in ${namesOf(overwritten)}` : ''].filter(Boolean);
    undoable({
      what: `the context as it was before ${file.name}`,
      mutate: () => {
        TMParse.applyContext(m, json);
        return `Context loaded from ${file.name} for ${plural(touched.length, 'element')}: ${parts.join('; ')}.${unmatched}`;
      },
      focus: 'tool:context',
      back: 'tool:context',
      kind: replaced || missed.length ? 'warn' : '',
    });
  }

  // ---------------------------------------------------------------- run

  const wantClaude = () => state.claude.available && $('#enrichChk').checked;

  // the MITRE data a run used, to tell later whether a kept run is still current
  const dataKey = () => state.metas.map(m => `${m.domain} ${m.version || ''}`).sort().join('|');

  /** Walk the decomposition through STRIDE-LM (and, if asked, have Claude write it up); rec picks up a run cut short by leaving the page. */
  async function run(rec) {
    const resume = rec && rec.kind === 'enrich' ? rec : null;
    if (state.busy || (!resume && !canRun())) return;
    const focused = !focusLost();
    setBusy(true);
    const status = $('#runStatus');
    const rev = state.rev;
    const gen = resume && typeof rec.gen === 'string' && rec.gen ? rec.gen : state.gen;
    const profile = profileKey(), data = dataKey();
    const snapshot = resume ? rec.model : clone(state.model);
    if (saveTimer) persist(true);   // the decomposition run is the one kept in this browser
    state.running = true;
    try {
      say(status, resume ? `Building the threat model again, to pick up the detail Claude was writing when ${WHEN_LEFT}…`
        : 'Walking every element through STRIDE-LM…', 'busy');
      await paint();
      const result = TMEngine.run(TMParse.finish(clone(snapshot)), {
        models: state.models, selection: state.selection, opts: state.opts, system: (snapshot.name || '').trim() || 'the system',
      });
      const marks = { events: new Map(), sequences: new Map() };
      let claude = null;
      if (resume || (wantClaude() && result.events.length)) claude = await enrich(result, snapshot, status, resume, focused, marks);
      state.result = result;
      state.marks = marks;
      state.stale = state.rev !== rev || (!!resume && !sameModel(snapshot, state.model));
      renderResults();
      $('#stepRun').hidden = false;
      const s = result.stats;
      let text = `${s.events + s.aiEvents} threat events at ${s.locations + s.aiLocations} threat-event locations.`;
      let kind = 'ok';
      if (claude) {
        text += ' ' + claude.text;
        if (claude.kind !== 'ok') kind = claude.kind;
      }
      // kept for the next visit, with what it was made from (unless another tab has replaced the decomposition meanwhile)
      if (gen && gen === state.gen && keptGen() === gen) {
        keepRun({ user: USER, gen, at: Date.now(), snapshot, profile, data, result, text, kind,
          marks: { events: [...marks.events], sequences: [...marks.sequences] } });
      }
      if (state.stale) {
        text += ' The decomposition or the threat profile has changed since this run started: run the model again to include the changes.';
        kind = 'warn';
      }
      say(status, text, kind);
      say($('#dlStatus'), '');
    } catch (e) {
      console.error(e);
      if (resume) forgetJob('enrich');
      say(status, `The threat model couldn't be built: ${e.message}`, 'err');
    } finally {
      state.running = false;
      setBusy(false);
      renderWarnings();
      if (focused && focusLost()) focusTo('#runBtn');
    }
  }

  /**
   * Text as the server can pass it on: a lone surrogate (a file can hold one, and the server can't encode it)
   * becomes U+FFFD, and text over n UTF-16 units is cut between two characters, never inside a pair.
   */
  function sendable(text, n = Infinity) {
    let s = String(text).replace(/[\ud800-\udbff][\udc00-\udfff]|[\ud800-\udfff]/g, c => (c.length === 2 ? c : '\ufffd'));
    if (s.length > n) {
      s = s.slice(0, n);
      if (/[\ud800-\udbff]$/.test(s)) s = s.slice(0, -1);
    }
    return s;
  }
  /** Every text in a request (keys too) made sendable. */
  const sendableAll = v => (typeof v === 'string' ? sendable(v) : Array.isArray(v) ? v.map(sendableAll)
    : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [sendable(k), sendableAll(x)])) : v);

  /**
   * The enrichment request (TMEngine.enrichmentRequest), cut to what the server takes in one job: every list and
   * text within its limits, and the first events in register order, as many as fit. left: the events not sent.
   */
  function enrichmentFor(result) {
    const L = Object.assign({}, ENRICH_LIMITS, state.claude.limits || {});
    const req = sendableAll(TMEngine.enrichmentRequest(result));
    const text = v => (typeof v === 'string' ? sendable(v, L.text) : v);
    const texts = o => (o && typeof o === 'object' && !Array.isArray(o) ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, text(v)])) : o);
    const list = (v, n, each = text) => (Array.isArray(v) ? v.slice(0, n).map(each) : v);
    const event = e => Object.assign(texts(e), {
      context: e.context && typeof e.context === 'object'
        ? Object.fromEntries(Object.entries(e.context).slice(0, L.context).map(([k, v]) => [sendable(k, 40), text(v)])) : e.context,
      techniques: list(e.techniques, L.techniques),
      sequence: list(e.sequence, L.steps),
    }, 'flows' in e ? { flows: list(e.flows, L.flows, texts) } : {});
    const out = Object.assign(texts(req), {
      lenses: list(req.lenses, L.lenses, texts),
      events: list(req.events || [], L.events, event),
      sequences: list(req.sequences || [], L.sequences, s => Object.assign(texts(s), { path: list(s.path, L.path) })),
    });
    for (const k of ['software', 'campaigns']) if (k in req) out[k] = list(req[k], L[k], texts);
    // and no larger than the body the server reads: the last events wait for another run
    const size = () => new Blob([JSON.stringify(out)]).size;
    while (out.events.length > 1 && size() > L.bytes * 0.95) out.events = out.events.slice(0, Math.floor(out.events.length * 0.9));
    return { request: out, left: (req.events || []).length - out.events.length };
  }

  /** A short fingerprint of a request, to tell after a reload whether a job was for the same draft. */
  function fingerprint(o) {
    const s = JSON.stringify(o);
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193);
    return `${(h >>> 0).toString(36)}.${s.length}`;
  }

  const MODEL_FIELDS = ['name', 'page', 'zones', 'elements', 'flows', 'id', 'label', 'parent', 'geometry', 'x', 'y', 'w', 'h', 'type', 'zone',
    'context', 'purpose', 'sensitivity', 'auth', 'trust', 'crownJewel', 'ai', 'source', 'target', 'bidirectional'];
  function sameModel(a, b) {
    if (!a || !b) return false;
    try {
      return JSON.stringify(TMParse.finish(clone(a)), MODEL_FIELDS) === JSON.stringify(TMParse.finish(clone(b)), MODEL_FIELDS);
    } catch (_) {
      return false;
    }
  }

  /** S/n as a reader scans them: "1–4, 6, 9–12" (at most 40 runs, then how many more). */
  function snRuns(list) {
    const sorted = [...new Set(list)].sort((a, b) => a - b);
    const runs = [];
    for (const n of sorted) {
      const last = runs[runs.length - 1];
      if (last && n === last[1] + 1) last[1] = n; else runs.push([n, n]);
    }
    const text = runs.slice(0, 40).map(([a, b]) => (a === b ? String(a) : `${a}–${b}`));
    if (runs.length > 40) return `${text.join(', ')} and ${runs.length - 40} more`;
    return text.length > 1 ? `${text.slice(0, -1).join(', ')} and ${text[text.length - 1]}` : text.join('');
  }

  const EVENT_FIELDS = ['title', 'sequence', 'event'], SEQUENCE_FIELDS = ['title', 'narrative'];
  const fieldsOf = (x, keys) => Object.fromEntries(keys.map(k => [k, x[k]]));

  /**
   * Mark what of Claude's answer the result holds, once TMEngine.applyEnrichment has merged it (was: each event's
   * and sequence's text before). A field Claude sent is used when the result took it, or when it is the engine's
   * own text, which leaves it as it was; it is refused only when the engine refuses it: asked about that field
   * alone, on a copy of the event (or sequence) as it was, the engine then says so in a warning. marks gets 'all'
   * where nothing Claude sent was refused, 'part' where some was used and some refused. Returns how many fields
   * were refused, of events and of sequences.
   */
  function markClaude(result, reply, was, marks) {
    const refuses = (events, sequences, answer) => {
      const probe = Object.assign({}, result, { events, sequences, locations: [], warnings: [] });
      try {
        TMEngine.applyEnrichment(probe, answer);
        return probe.warnings.length > 0;
      } catch (_) {
        return true;   // can't tell: not claimed as Claude's
      }
    };
    const refused = { events: 0, sequences: 0 };
    const mark = (kind, answers, items, key, keys, ask) => {
      const byKey = new Map(items.map(x => [x[key], x]));
      const seen = new Set();   // the engine takes an event's (or sequence's) first answer only
      for (const r of Array.isArray(answers) ? answers : []) {
        const x = r && byKey.get(key === 'sn' ? Number(r.sn) : String(r.id));
        if (!x || seen.has(x)) continue;
        seen.add(x);
        const before = was[kind].get(x[key]);
        let used = 0, out = 0;
        for (const k of keys) {
          if (r[k] === undefined) continue;
          if (JSON.stringify(x[k]) !== JSON.stringify(before[k]) || !ask(Object.assign({}, x, before), k, r[k])) used++;
          else out++;
        }
        refused[kind] += out;
        if (used) marks[kind].set(x[key], out ? 'part' : 'all');
      }
    };
    mark('events', reply.events, result.events, 'sn', EVENT_FIELDS,
      (ev, k, v) => refuses([ev], [], { events: [{ sn: ev.sn, [k]: v }] }));
    // a sequence's checks read its events as Claude left them, so the probe has them as they are now
    mark('sequences', reply.sequences, result.sequences, 'id', SEQUENCE_FIELDS,
      (s, k, v) => refuses(result.events, [s], { sequences: [{ id: s.id, [k]: v }] }));
    return refused;
  }

  /**
   * Have Claude write the threat events in more detail, and merge what comes back (TMEngine checks every
   * field). marks gets what Claude wrote (markClaude). Resolves to what the status line says about it: { text, kind }.
   */
  async function enrich(result, snapshot, status, resume, focused, marks) {
    const { request, left } = enrichmentFor(result);
    const fp = fingerprint(request);
    const total = result.events.length;
    const offline = 'Claude couldn’t write the detail, so the threat events are the offline engine’s.';
    const j = newJob('enrich', status, {
      busy: resume ? `Picking up the detail Claude was writing when ${WHEN_LEFT}…`
        : `Claude is writing the ${request.events.length} threat events in more detail… this can take a few minutes.`,
      progress: p => `Claude is writing the threat events in more detail… ${p}.`,
    });
    if (resume) {
      j.id = resume.id;
      j.started = resume.started || Date.now();
      if (resume.fp !== fp) {
        // the profile or the MITRE data changed meanwhile: the job's text is for another draft
        release(j);
        const text = `${RELOADED ? 'The page was reloaded' : 'You left the page'} while Claude was writing, and the draft register has changed since, so the threat events are the offline engine’s.`;
        result.warnings.push(text);
        return { text, kind: 'warn' };
      }
    }
    if (focused && focusLost()) j.cancel.focus();
    let out;
    try {
      out = await runJob(j, { path: 'api/tm/enrich', body: request, meta: { model: snapshot, fp, gen: state.gen } });
    } catch (e) {
      const text = `${offline} ${e.message}`;
      result.warnings.push(text);
      return { text, kind: 'warn' };
    }
    const reply = out.result;
    const was = {
      events: new Map(result.events.map(ev => [ev.sn, fieldsOf(ev, EVENT_FIELDS)])),
      sequences: new Map(result.sequences.map(s => [s.id, fieldsOf(s, SEQUENCE_FIELDS)])),
    };
    const fields = reply ? TMEngine.applyEnrichment(result, reply) : 0;
    const refused = reply ? markClaude(result, reply, was, marks) : { events: 0, sequences: 0 };
    release(j, out);
    if (fields) result.warnings.push(`Claude rewrote ${fields} text fields; review its wording before relying on it. Technique IDs, mitigations and detections are unchanged and come from the MITRE data.`);
    const full = [...marks.events.values()].filter(v => v === 'all').length;
    const part = marks.events.size - full;
    // which rows are Claude's, for the register's reader (its About sheet lists the run's warnings)
    if (marks.events.size && full < total) {
      const sns = kind => [...marks.events].filter(([, v]) => v === kind).map(([sn]) => sn);
      result.warnings.push((full ? `Claude’s text is in threat events ${snRuns(sns('all'))} (S/n)${part ? `, and part of it in ${snRuns(sns('part'))}` : ''}`
        : `Part of Claude’s text is in threat events ${snRuns(sns('part'))} (S/n)`) + '; the rest is the offline engine’s.');
    }
    const stopped = out.status === 'cancelled';
    const stopper = !resume ? 'You stopped Claude' : RELOADED ? 'Reloading the page stopped Claude' : 'Leaving the page stopped Claude';
    const why = [];
    if (left) why.push(`The server takes at most ${plural(request.events.length, 'threat event')} at a time, so the last ${left} weren’t sent.`);
    // the parts a cancelled job didn't get to are its own doing, not failures to report
    if (reply && reply.failed && !stopped) why.push(`${plural(reply.failed, 'part')} of the register couldn’t be written: ${(reply.errors || []).join(' ') || 'the request failed.'}`);
    if (stopped) why.push(`${stopper} before it finished.`);
    if (out.status === 'failed') why.push(out.error || 'The request failed.');
    const anyRefused = refused.events + refused.sequences > 0;
    if (total && full === total && !why.length && !anyRefused) return { text: 'Claude wrote the detail of every threat event.', kind: 'ok' };
    const written = marks.events.size;
    let lead, reasons = why;
    if (!written && stopped && !anyRefused) {
      lead = `${stopper} before it wrote any of the detail, so the threat events are the offline engine’s.`;
      reasons = left ? [why[0]] : [];
    } else if (!written) {
      lead = offline;
      if (!why.length && !anyRefused) reasons = ['Its answer couldn’t be used.'];
    } else if (full === total) lead = 'Claude wrote the detail of every threat event.';
    else {
      lead = (full ? `Claude wrote the detail of ${full} of ${plural(total, 'threat event')}${part ? `, and part of it for ${part} more` : ''}`
        : `Claude wrote part of the detail of ${part} of ${plural(total, 'threat event')}`)
        + `; ${part ? 'the rest is' : 'the others keep'} the offline engine’s text.`;
      // nothing of theirs refused and nothing went wrong: Claude didn't answer for them
      if (!why.length && !refused.events) reasons = ['Its answer left them out.'];
    }
    // what the engine refused (its own warning says how much, and why)
    const unused = !anyRefused ? '' : !refused.events ? 'Some of what it wrote for the attack sequences couldn’t be used'
      : written ? 'Some of what it wrote couldn’t be used' : 'What it wrote couldn’t be used';
    // the status line points at those notes; the register's About sheet, which lists the same warnings, has no figures
    const sentences = where => [lead, ...reasons, unused ? `${unused}${where}.` : ''].filter(Boolean).join(' ');
    result.warnings.push(sentences(''));
    return { text: sentences(', as the notes below the figures say'), kind: 'warn' };
  }

  // ---------------------------------------------------------------- Claude jobs

  /*
   * Claude's work runs as a job on the server (api/tm/decompose or api/tm/enrich), polled at api/tm/job, so
   * no proxy times out on a long request. The server runs one job at a time per user, and keeps a finished
   * job's result until the page releases it (api/tm/cancel) or 15 minutes pass. This tab keeps the job it is
   * waiting for in sessionStorage, so that after a reload it can pick up what the job did.
   */
  const jobs = { current: null, stopped: new Set() };
  const WHAT = { decompose: 'reading a picture of a diagram', enrich: 'writing threat events in more detail' };

  function jobRecord() {
    const r = session.get(JOB_KEY);
    return r && r.user === USER && typeof r.id === 'string' && r.id && (r.kind === 'decompose' || r.kind === 'enrich') ? r : null;
  }

  /**
   * Stop a running job, and release a finished one's result (release false: leave a finished job to be collected,
   * which the page does as it closes, for a reload to pick up). keepalive lets it go out as the page closes.
   */
  function cancelRequest(id, { keepalive = false, release = true } = {}) {
    try {
      return fetch('api/tm/cancel', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', keepalive,
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify(release ? { job: id } : { job: id, release: false }),
      }).catch(() => { /* the server forgets it in time anyway */ });
    } catch (_) {
      return Promise.resolve();
    }
  }

  /** A job's status line: a spinner, its text, room for another control, and Cancel. Parts change in place, so focus stays put. */
  function newJob(kind, line, { busy, progress }) {
    // started: when the server took the job (set once it has); the page's deadline runs from then
    const j = { id: '', kind, started: 0, stopping: 0, wake: null, busy, progress };
    const text = el('span', { text: busy });
    const extra = el('span', { class: 'row', hidden: true });
    j.cancel = el('button', { type: 'button', text: 'Cancel', on: { click: () => cancelJob(j) } });
    for (const k of ['err', 'warn', 'ok']) line.classList.remove(k);
    line.classList.add('busy-line');
    line.replaceChildren(el('span', { class: 'spinner', 'aria-hidden': 'true' }), text, extra, j.cancel);
    j.say = t => { if (text.textContent !== t) text.textContent = t; };
    j.extra = (...nodes) => {
      const had = extra.contains(document.activeElement);
      extra.replaceChildren(...nodes);
      extra.hidden = !nodes.length;
      if (had && !nodes.length) j.cancel.focus();
    };
    return j;
  }

  function cancelJob(j) {
    if (j.stopping) return;
    j.stopping = Date.now();
    if (j.id) {
      jobs.stopped.add(j.id);
      cancelRequest(j.id);
    }
    j.cancel.setAttribute('aria-disabled', 'true');   // not disabled: that would drop keyboard focus
    j.cancel.textContent = 'Stopping…';
    j.say('Stopping Claude…');
    if (j.wake) j.wake();
  }

  /** Wait ms, or until the job is woken (by Cancel). */
  const nap = (j, ms) => new Promise(resolve => {
    const done = () => { clearTimeout(timer); j.wake = null; resolve(); };
    const timer = setTimeout(done, ms);
    j.wake = done;
  });

  /**
   * Run a Claude job to its end: start it (unless it is one picked up after a reload), then poll it. Resolves
   * to { status: 'done' | 'cancelled' | 'failed', result, error }; rejects when the job can't be started. The
   * caller uses the result, then calls release().
   */
  async function runJob(j, { path, body, meta }) {
    jobs.current = j;
    try {
      if (!j.id) {
        const id = await startJob(j, path, body);
        if (!id) return { status: 'cancelled', result: null };
        j.id = id;
        // the 20 minutes run from now, not from the click: time spent waiting behind another job doesn't count, so
        // the server's own deadline for the job (15 minutes) always comes first
        j.started = Date.now();
        const rec = { user: USER, id, kind: j.kind, started: j.started };
        if (!session.set(JOB_KEY, Object.assign({}, rec, meta))) session.set(JOB_KEY, rec);   // too large to keep whole
        if (j.stopping) {   // Cancel was pressed while it was being started
          jobs.stopped.add(id);
          cancelRequest(id);
        }
      }
      return await pollJob(j);
    } finally {
      if (jobs.current === j) jobs.current = null;
    }
  }

  /** POST the job. When this user already has one running, wait for it to end (offering to cancel it), then try again. */
  async function startJob(j, path, body) {
    for (;;) {
      if (j.stopping) return '';
      try {
        const { job } = await api(path, body);
        if (typeof job !== 'string' || !job) throw new Error('The server didn’t start the request.');
        return job;
      } catch (e) {
        const other = e.status === 429 && e.data && typeof e.data.job === 'string' ? e.data.job : '';
        if (!other) throw e;
        if (!(await waitForOther(j, other, e.data.kind))) return '';
      }
    }
  }

  /** Wait while another of this user's Claude jobs runs. Resolves true once it has ended, false on Cancel. */
  async function waitForOther(j, other, kind) {
    const stopping = jobs.stopped.has(other);
    j.say(stopping ? 'Your last Claude request is still stopping. This one starts as soon as it has.'
      : `You already have a Claude request running (${WHAT[kind] || 'another task'}), in another tab or window. This one starts as soon as it ends.`);
    if (!stopping) {
      const btn = el('button', { type: 'button', text: 'Cancel that request', on: { click: () => {
        if (btn.getAttribute('aria-disabled')) return;
        jobs.stopped.add(other);
        // stops it if it is still running; if it has just ended, the tab that started it can still collect it
        cancelRequest(other, { release: false });
        btn.setAttribute('aria-disabled', 'true');
        btn.textContent = 'Stopping it…';
        if (j.wake) j.wake();
      } } });
      j.extra(btn);
    }
    const since = Date.now();   // the server ends any job within 15 minutes, so this wait has a bound of its own
    try {
      for (let wait = 1000; ; wait = Math.min(wait * 1.5, 5000)) {
        await nap(j, wait);
        if (j.stopping) return false;
        if (Date.now() > since + JOB_WAIT) throw new Error('Your other Claude request was still running after 20 minutes. Cancel it, or try again later.');
        try {
          const s = await api('api/tm/job?id=' + encodeURIComponent(other));
          if (s.status !== 'running') return true;
        } catch (e) {
          if (e.status === 404) return true;   // it ended and its result was collected
          if (e.status === 401) throw e;
        }
      }
    } finally {
      j.extra();
      if (!j.stopping) j.say(j.busy);
    }
  }

  /**
   * Poll a job until it ends. A poll that fails on the way (no answer, a 5xx, an answer cut short) is tried
   * again, waiting longer each time, until the page's deadline; a 401 or 404 ends the wait.
   */
  async function pollJob(j) {
    let wait = 1000, failures = 0;
    for (;;) {
      await nap(j, j.stopping ? 500 : wait);
      if (j.stopping && Date.now() - j.stopping > STOP_WAIT) {
        return { status: 'cancelled', result: null };   // still ending: the server stops it, and forgets it in time
      }
      if (!j.stopping && Date.now() > j.started + JOB_WAIT) {
        jobs.stopped.add(j.id);
        cancelRequest(j.id);
        return { status: 'failed', result: null, error: 'Claude took more than 20 minutes, so the page stopped waiting.' };
      }
      let s;
      try {
        s = await api('api/tm/job?id=' + encodeURIComponent(j.id));
      } catch (e) {
        if (e.status === 401) return { status: 'failed', result: null, error: 'Your session has ended. Sign in again, then try again.', signedOut: true };
        // after Cancel, a job that had just ended has been released by it
        if (e.status === 404 && j.stopping) return { status: 'cancelled', result: null, gone: true };
        if (e.status === 404) return { status: 'failed', result: null, error: 'The server no longer knows this request (it may have been restarted).', gone: true };
        if (!transient(e)) return { status: 'failed', result: null, error: e.message };
        failures++;
        wait = Math.min(30000, 2000 * 2 ** Math.min(failures - 1, 4));
        if (!j.stopping) j.say(`${j.busy} The server didn’t answer; trying again in ${Math.round(wait / 1000)} seconds.`);
        continue;
      }
      if (failures) {
        failures = 0;
        wait = 1000;
        if (!j.stopping) j.say(j.busy);
      }
      if (s.status === 'running') {
        if (!j.stopping) j.say(s.progress ? j.progress(s.progress) : j.busy);
        wait = Math.min(wait + 500, 3000);
        continue;
      }
      return { status: s.status === 'done' || s.status === 'cancelled' ? s.status : 'failed', result: s.result || null,
        error: s.error || (s.status === 'done' || s.status === 'cancelled' ? '' : 'The request failed.') };
    }
  }

  /** The page is done with a job: the server can forget its result, and this tab stops remembering it. */
  function release(j, out) {
    if (out && out.signedOut) return;   // picked up again after signing in
    if (j.id && !(out && out.gone)) cancelRequest(j.id);
    const rec = session.get(JOB_KEY);
    if (rec && rec.id === j.id) session.remove(JOB_KEY);
  }

  /** Let go of the job this tab remembers (of that kind), so a failure to use it isn't met again on every visit. */
  function forgetJob(kind) {
    const rec = jobRecord();
    if (!rec || rec.kind !== kind) return;
    cancelRequest(rec.id);
    session.remove(JOB_KEY);
  }

  /** After a reload: pick up the Claude job this tab was waiting for, and use what it did. */
  function resumeJob(rec) {
    if (rec.kind === 'decompose' && rec.width > 0 && rec.height > 0) return claudeRead(rec);
    if (rec.kind === 'enrich' && rec.model && Array.isArray(rec.model.elements) && state.models['enterprise-attack']) return run(rec);
    forgetJob(rec.kind);   // nothing on this page can use it
    return null;
  }

  // ---------------------------------------------------------------- results

  const TABS = [['events', 'Threat events'], ['profile', 'Threat profile'], ['sequences', 'Attack sequences'], ['coverage', 'STRIDE-LM coverage']];

  function renderResults() {
    const r = state.result;
    const s = r.stats;
    const kpi = (v, l) => el('div', { class: 'kpi' }, el('div', { class: 'v', text: String(v) }), el('div', { class: 'l', text: l }));
    $('#kpis').replaceChildren(
      kpi(s.elements, 'elements'), kpi(s.flows, 'data flows'), kpi(s.zones, 'trust zones'),
      kpi(s.events, `ATT&CK threat events (${s.high} High, ${s.medium} Medium, ${s.low} Low)`),
      kpi(s.aiEvents, `AI threat events (MAESTRO / ATLAS)`),
      kpi(r.sequences.length, 'attack sequences'));
    const warns = $('#runWarnings');
    warns.replaceChildren(...r.warnings.map(w => el('li', { text: w })));
    warns.hidden = !r.warnings.length;
    const counts = { events: r.events.length, profile: r.lenses.length, sequences: r.sequences.length };
    if (!TABS.some(t => t[0] === state.tab)) state.tab = 'events';
    $('#resultTabs').replaceChildren(...TABS.map(([key, label]) => el('button', {
      type: 'button', role: 'tab', id: `tab-${key}`, 'aria-controls': 'resultBody', 'aria-selected': String(key === state.tab),
      tabindex: key === state.tab ? '0' : '-1', 'data-tab': key, text: key in counts ? `${label} (${counts[key]})` : label,
      on: { click: () => selectTab(key), keydown: tabKey },
    })));
    renderTab();
    $('#results').hidden = false;
  }

  /** Show a tab's panel. The tabs themselves stay (only their state changes), so keyboard focus stays on them. */
  function selectTab(key, focus) {
    state.tab = key;
    for (const b of $('#resultTabs').querySelectorAll('[role="tab"]')) {
      const on = b.dataset.tab === key;
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
      if (on && focus) b.focus();
    }
    renderTab();
  }

  // The ARIA tabs keys: the arrow keys move to the previous or next tab and show it; Home and End, the first and last.
  function tabKey(ev) {
    const keys = TABS.map(t => t[0]);
    const i = keys.indexOf(ev.currentTarget.dataset.tab);
    const to = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: keys.length - 1 }[ev.key];
    if (to === undefined) return;
    ev.preventDefault();
    selectTab(keys[(to + keys.length) % keys.length], true);
  }

  function renderTab() {
    const body = $('#resultBody');
    body.setAttribute('aria-labelledby', `tab-${state.tab}`);
    body.replaceChildren({ events: eventsTable, profile: profileTable, sequences: sequencesList, coverage: coverageTable }[state.tab]());
    body.scrollTop = 0;
  }

  const elementLabel = id => (state.result.model.elements.find(e => e.id === id) || { label: id }).label;

  /** Marks what Claude wrote, so the analyst can find the text to review: all of it, or part (the rest is the engine's). */
  function byClaude(mark) {
    if (!mark) return null;
    return el('span', { class: 'by-claude', title: mark === 'all' ? 'Claude wrote this text' : 'Claude wrote part of this text; the rest is the offline engine’s' },
      mark === 'all' ? 'by Claude' : 'partly by Claude');
  }

  function eventsTable() {
    const r = state.result;
    return el('table', {},
      el('thead', {}, el('tr', {}, ['S/n', 'DFD #', 'Element', 'STRIDE-LM', 'Threat', 'Severity', 'Techniques'].map(h => el('th', { text: h })))),
      el('tbody', {}, r.events.map(ev => el('tr', {},
        el('td', { class: 'num', text: String(ev.sn) }),
        el('td', { class: 'num', text: String(ev.dfd) }),
        el('td', { text: elementLabel(ev.element) }),
        el('td', { text: ev.stride }),
        el('td', {}, el('strong', { text: ev.title }), byClaude(state.marks.events.get(ev.sn)), el('div', { class: 'note', text: ev.event })),
        el('td', {}, el('span', { class: `sev ${ev.severity}`, text: ev.severity })),
        el('td', { class: 'techs' }, ev.techniques.map(t => el('div', { title: t.name }, `${t.id}${t.attributed ? ' ◆' : ''}`)))))));
  }

  function profileTable() {
    const r = state.result;
    const rows = r.lenses.map(l => el('tr', {},
      el('td', { text: l.id }), el('td', {}, el('strong', { text: l.name }), el('div', { class: 'note', text: l.evidence })),
      el('td', { class: 'techs' }, l.techniques.map(t => el('div', { text: t }))), el('td', { text: l.status })));
    const ai = r.aiProfile.map(l => el('tr', {},
      el('td', { text: l.layer }), el('td', {}, el('strong', { text: `${l.layerName} — ${l.lens}` }), el('div', { class: 'note', text: l.summary })),
      el('td', { class: 'techs' }, l.techniques.map(t => el('div', { text: t }))), el('td', { class: 'note', text: l.caseStudies })));
    return el('div', {},
      el('table', {}, el('thead', {}, el('tr', {}, ['ID', 'Threat (lens) and evidence', 'Techniques', 'Status'].map(h => el('th', { text: h })))), el('tbody', {}, rows)),
      ai.length ? el('h3', { style: 'font-size:15px;margin:18px 0 6px', text: 'AI threat profile (MAESTRO layers, MITRE ATLAS)' }) : null,
      ai.length ? el('table', {}, el('thead', {}, el('tr', {}, ['Layer', 'Lens', 'ATLAS techniques', 'Case studies'].map(h => el('th', { text: h })))), el('tbody', {}, ai)) : null);
  }

  function sequencesList() {
    const r = state.result;
    if (!r.sequences.length) return el('p', { class: 'empty', text: 'No attack sequence could be traced from an entry point to a crown jewel. Mark the crown jewels and check the data flows.' });
    return el('div', {}, r.sequences.map(q => el('div', { class: 'seq' },
      el('h4', {}, `Attack sequence ${q.id}: ${q.title}`, byClaude(state.marks.sequences.get(q.id))),
      el('p', {}, el('strong', { text: 'Point of entry: ' }), q.entry),
      el('p', {}, el('strong', { text: 'Sequence (DFD threat events): ' }), q.steps.join(' → '),
        el('span', { class: 'mark' }, `   Threat actor: ${q.actor}${q.layers ? `   MAESTRO: ${q.layers}` : ''}`)),
      el('p', { text: q.narrative }))));
  }

  function coverageTable() {
    const r = state.result;
    const codes = ['S', 'T', 'R', 'I', 'D', 'E', 'LM'];
    return el('div', {},
      el('table', { class: 'cov' },
        el('thead', {}, el('tr', {}, ['#', 'Element', 'Type', ...codes, 'Raised'].map(h => el('th', { text: h })))),
        el('tbody', {}, r.coverage.map(c => {
          const e = r.model.elements.find(x => x.id === c.element);
          return el('tr', {},
            el('td', { class: 'num', text: c.dfd ? String(c.dfd) : '' }), el('td', { text: e.label }), el('td', { text: e.type }),
            ...codes.map(k => el('td', { class: c.cells[k] === 'n/a' ? 'na' : c.cells[k], text: c.cells[k] })),
            el('td', { class: 'num', text: String(c.raised) }));
        }))),
      el('p', { class: 'note', text: 'X = threat event raised · o = applicable, not raised in this pass (an omission for the analyst to review) · n/a = not applicable to this kind of element (STRIDE-per-element)' }));
  }

  async function download(kind) {
    if (!state.result) return;
    const status = $('#dlStatus');
    const button = kind === 'register' ? $('#dlRegister') : $('#dlDfd');
    const focused = document.activeElement === button;
    button.disabled = true;
    say(status, kind === 'register' ? 'Building the threat register…' : 'Drawing the data-flow diagram…', 'busy');
    try {
      await loadScript(kind === 'register' ? 'excel' : 'pptx');
      const writer = kind === 'register' ? TMRegister : TMDfd;
      const blob = await writer.build(state.result);
      save(blob, writer.FILE_NAME);
      say(status, state.stale ? 'Downloaded — from the last run, before your latest changes.' : 'Downloaded.', 'ok');
    } catch (e) {
      console.error(e);
      say(status, `The file couldn't be built: ${e.message}`, 'err');
    } finally {
      button.disabled = false;
      if (focused && focusLost()) button.focus();   // disabling it dropped keyboard focus
    }
  }

  // ---------------------------------------------------------------- start

  function claudeChosen() {
    if (!CLAUDE_KEY) return false;
    try { return localStorage.getItem(CLAUDE_KEY) === 'on'; } catch (_) { return false; }
  }

  async function claudeStatus() {
    try {
      const s = await api('api/tm/status');
      state.claude = { available: !!s.claude, model: s.model || '', limits: s.limits && typeof s.limits === 'object' ? s.limits : null };
    } catch (_) {
      state.claude = { available: false, model: '', limits: null };
    }
    const on = state.claude.available;
    $('#claudeNote').textContent = on ? CLAUDE_NOTE : '';
    $('#enrichLabel').hidden = !on;
    // off until this user has said otherwise in this browser: a run then sends nothing anywhere
    $('#enrichChk').checked = on && claudeChosen();
    $('#claudeReadBtn').hidden = !on;
  }

  /** The decomposition this user was working on in this browser, if any. */
  function restore() {
    const saved = TM_KEY ? store.get(TM_KEY) : null;
    if (!saved || saved.user !== USER || !saved.model || !Array.isArray(saved.model.elements)) return;
    try {
      // A flow from an element to itself (an earlier version of this page let one be drawn) is left out here, and
      // said once, rather than by finish(), whose note about it would stay with the decomposition for good.
      const flows = Array.isArray(saved.model.flows) ? saved.model.flows : [];
      const loop = f => !!f && typeof f === 'object' && f.source != null && String(f.source) === String(f.target);
      const loops = flows.filter(loop).length;
      // it keeps its id and its number; one kept by an earlier version of this page gets an id, kept with it from now on
      const gen = typeof saved.gen === 'string' && saved.gen ? saved.gen : '';
      setModel(TMParse.finish(Object.assign({}, saved.model, { flows: flows.filter(f => !loop(f)) })),
        { savedHome: saved.home, gen: gen || newGen(), write: !gen || loops > 0 });
      if (gen && !loops) state.saved = { gen, rev: Number.isInteger(saved.rev) ? saved.rev : 0 };
      say($('#diagramStatus'), 'Restored the decomposition you were working on.'
        + (loops ? ` ${plural(loops, 'data flow')} from an element to itself ${loops === 1 ? 'was' : 'were'} left out.` : '')
        + (saved.model.source && saved.model.source.kind === 'image' ? ' (The picture isn’t kept between visits.)' : ''));
    } catch (_) {
      store.remove(TM_KEY);
    }
  }

  /** The last run this user made in this browser, shown again if it was made from this decomposition (G1). */
  async function showLastRun() {
    const saved = await lastRun();
    if (!saved || saved.user !== USER || !state.model || state.result || state.busy) return;
    const r = saved.result;
    if (!r || !Array.isArray(r.events) || !r.stats || !r.model || !Array.isArray(r.model.elements)) {
      dropRun();
      return;
    }
    if (saved.gen !== state.gen) {
      // made from another decomposition: let it go, unless it is the one kept in this browser now (another tab's)
      if (keptGen() !== saved.gen) dropRun();
      return;
    }
    state.result = r;
    state.marks = { events: new Map(saved.marks && saved.marks.events), sequences: new Map(saved.marks && saved.marks.sequences) };
    state.stale = !sameModel(saved.snapshot, state.model) || saved.profile !== profileKey() || (state.metas.length > 0 && saved.data !== dataKey());
    try {
      renderResults();
    } catch (e) {
      console.error(e);
      state.result = null;
      $('#results').hidden = true;
      dropRun();
      return;
    }
    let when = '';
    try { when = new Date(saved.at).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }); } catch (_) { /* no date */ }
    say($('#runStatus'), `Your last run${when ? ` (${when})` : ''}, kept in this browser: ${saved.text || ''}`
      + (state.stale ? ' The decomposition, the threat profile or the MITRE data has changed since: run the model again to update the results and downloads.' : ''),
    state.stale ? 'warn' : saved.kind || 'ok');
  }

  function wire() {
    const input = $('#fileInput');
    input.addEventListener('change', () => { const f = input.files[0]; input.value = ''; openFile(f); });
    const drop = $('#drop');
    drop.addEventListener('dragover', e => { e.preventDefault(); if (!state.busy) drop.classList.add('over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('over'));
    drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); openFile(e.dataTransfer.files[0]); });
    $('#exampleBtn').addEventListener('click', exampleDiagram);
    $('#scratchBtn').addEventListener('click', startBlank);
    $('#claudeReadBtn').addEventListener('click', () => claudeRead());
    $('#handBtn').addEventListener('click', byHand);
    $('#keepBtn').addEventListener('click', keepCurrent);
    $('#pictureZoom').addEventListener('click', () => {
      $('#pictureZoom').setAttribute('aria-pressed', String($('#pictureFrame').classList.toggle('full')));
    });
    document.addEventListener('keydown', undoKey);
    $('#runBtn').addEventListener('click', () => run());
    $('#enrichChk').addEventListener('change', e => {
      if (!CLAUDE_KEY) return;
      try { localStorage.setItem(CLAUDE_KEY, e.target.checked ? 'on' : 'off'); } catch (_) { /* not remembered */ }
    });
    $('#dlRegister').addEventListener('click', () => download('register'));
    $('#dlDfd').addEventListener('click', () => download('dfd'));
    $('#replaceSave').addEventListener('click', () => saveDecomposition($('#replaceSaved')));
  }

  async function start() {
    // kept before decompositions and the Claude choice had an owner: whose they are can't be told, so they aren't used
    store.remove(TM_KEY_OLD);
    store.remove(CLAUDE_KEY_OLD);
    wire();
    readProfile();
    const claude = claudeStatus();
    restore();
    const rec = jobRecord();
    if (rec) setBusy(true);   // nothing else starts before that job is picked up again
    updateRun();
    try {
      await loadData();
      renderProfile();
    } catch (e) {
      state.dataError = e.message || String(e);
      $('#profileBody').replaceChildren(el('p', { class: 'busy-line err', text: `The MITRE data couldn't be loaded: ${state.dataError}` }));
    }
    if (state.model) renderWarnings();
    updateRun();
    if (rec) {
      await claude;
      setBusy(false);
      resumeJob(rec);
    } else if (state.model) {
      await showLastRun();
    }
  }

  window.addEventListener('storage', e => {
    // this user's Claude choice, made in another tab (null: the browser's storage for this site was cleared)
    if (e.key === null || (CLAUDE_KEY && e.key === CLAUDE_KEY)) $('#enrichChk').checked = state.claude.available && claudeChosen();
    // the decomposition, saved or cleared in another tab of this page
    if (TM_KEY && (e.key === TM_KEY || e.key === null)) follow();
    // The Threat Profile tab may change the profile in another browser tab, also while this page is still loading the MITRE data.
    if (e.key !== SIM_KEY && e.key !== null) return;
    const before = state.selection ? profileKey() : '';
    readProfile();
    if (profileKey() === before) {
      // only the Threat Profile tab's own settings changed; its platform filter and knowledge bases are said on the card
      if (state.loaded && simScope() !== shownScope) renderProfile();
      return;
    }
    if (state.loaded) renderProfile();
    state.rev++;
    markStale('The threat profile has changed on the Threat Profile tab since the last run. Run the model again to update the results and downloads.');
  });

  // An edit not saved yet is saved as soon as the user turns to another tab or window, so that one takes it up;
  // a tab shown again takes up what another saved meanwhile.
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { if (saveTimer) persist(true); } else follow();
  });
  window.addEventListener('blur', () => { if (saveTimer) persist(true); });
  window.addEventListener('pageshow', e => { if (e.persisted) follow(); });

  window.addEventListener('pagehide', e => {
    if (saveTimer) persist(true);
    const j = jobs.current;
    // Leaving for good (closing, going elsewhere, reloading): stop the job rather than leave it running unwatched.
    // Its record stays in this tab, so after a reload the page picks up what the job had done; release false
    // keeps a job that ended since the last poll collectable, so its result isn't lost in the gap.
    if (!e.persisted && j && j.id && !j.stopping) cancelRequest(j.id, { keepalive: true, release: false });
  });

  start();
})();
