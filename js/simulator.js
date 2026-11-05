/* simulator.js — threat profile builder + ATT&CK and ATLAS mapping dashboard. */
(function () {
  'use strict';

  // ---------- helpers ----------

  const $ = sel => document.querySelector(sel);

  /** el('div', {class, text, title, on:{click}, data:{k}, attrs:{}}, ...children) */
  function el(tag, props, ...kids) {
    const n = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v == null || v === false) continue;
        if (k === 'class') n.className = v;
        else if (k === 'text') n.textContent = v;
        else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
        else if (k === 'data') Object.assign(n.dataset, v);
        else if (k === 'checked' || k === 'disabled' || k === 'hidden' || k === 'value') n[k] = v;
        else n.setAttribute(k, v === true ? '' : v);
      }
    }
    append(n, kids);
    return n;
  }
  function append(n, kids) {
    for (const k of kids) {
      if (k == null || k === false) continue;
      if (Array.isArray(k)) append(n, k);
      else n.append(k instanceof Node ? k : String(k));
    }
  }

  const FOCUSABLE = 'button, input, select, textarea, a[href], summary';

  /**
   * Where a control sits, so the control that replaces it after a re-render can take focus: by its own
   * data-key (sort buttons, switches, matrix cells), else by its table row's data-row and its position among
   * the row's controls, else by its position in the tab's tools; nth tells same-key matches apart (a technique
   * in several matrix columns, one table per domain). null for anything else.
   */
  function placeOf(node) {
    if (!node || node === document.body || !node.closest || !node.isConnected) return null;
    const scope = node.closest('#drawer') ? '#drawer' : null;
    const nth = (sel, n) => [...document.querySelectorAll(sel)].filter(x => !!x.closest('#drawer') === !!scope).indexOf(n);
    if (node.dataset && node.dataset.key) { const sel = '[data-key="' + CSS.escape(node.dataset.key) + '"]'; return { sel, nth: nth(sel, node), at: -1, scope }; }
    const row = node.closest('[data-row]');
    if (row) { const sel = '[data-row="' + CSS.escape(row.dataset.row) + '"]'; return { sel, nth: nth(sel, row), at: [...row.querySelectorAll(FOCUSABLE)].indexOf(node), scope }; }
    const tools = node.closest('#tabTools');
    if (tools) return { sel: '#tabTools', nth: 0, at: [...tools.querySelectorAll(FOCUSABLE)].indexOf(node), scope };
    return null;
  }
  /** The control now at a place from placeOf (null when it is gone). */
  function findPlace(p) {
    if (!p) return null;
    const all = [...document.querySelectorAll(p.sel)].filter(x => !!x.closest('#drawer') === !!p.scope);
    const host = all[p.nth] || all[0];
    if (!host) return null;
    if (p.at < 0) return host;
    const ctl = host.querySelectorAll(FOCUSABLE);
    return ctl[p.at] || ctl[0] || null;
  }
  /**
   * Focus a control (scrolling only when it is out of view); one inside a disclosure the user had open (the
   * re-render closed it) opens it again. Returns whether the control took focus.
   */
  function focusQuiet(n) {
    if (!n) return false;
    for (let d = n.closest('details'); d; d = d.parentElement && d.parentElement.closest('details')) if (!d.open && !n.matches('summary')) d.open = true;
    const b = n.getBoundingClientRect();
    n.focus({ preventScroll: b.top >= 0 && b.bottom <= innerHeight });
    return document.activeElement === n;
  }

  const fmtN = n => (n ?? 0).toLocaleString();
  const plural = (n, one, many) => fmtN(n) + ' ' + (n === 1 ? one : many);
  /** 'A', 'A and B', 'A, B and C'. */
  const andList = xs => xs.length < 2 ? xs.join('') : xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1];
  const pct = (a, b) => b ? Math.round((a / b) * 100) + '%' : '0%';
  const domainInfo = id => AttackDB.DOMAINS.find(d => d.id === id) || { id, label: id, title: id, family: 'attack' };
  const domainLabel = id => domainInfo(id).label;          // Enterprise, ICS, ATLAS
  const domainTitle = id => domainInfo(id).title;          // Enterprise ATT&CK, ICS ATT&CK, ATLAS
  const familyOf = id => domainInfo(id).family;            // attack | atlas
  const familyName = id => AttackDB.FAMILIES[familyOf(id)].name;   // ATT&CK | ATLAS
  const byName = (a, b) => (a.name || '').localeCompare(b.name || '');
  // one shared collator: localeCompare with options builds a new one per call, which is slow in big sorts
  const idCmp = new Intl.Collator(undefined, { numeric: true }).compare;
  const byAttackId = (a, b) => idCmp(String(a.attackId), String(b.attackId));

  const ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ' };
  const decodeEntities = t => t.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1));
      return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : m;
    }
    const k = e.toLowerCase();
    return Object.prototype.hasOwnProperty.call(ENTITIES, k) ? ENTITIES[k] : m;
  });

  /**
   * ATT&CK and ATLAS markup reduced to what md() renders. Citation markers go (ATT&CK "(Citation: …)",
   * ATLAS "[[ref]]" and, in older releases, "[[7]](url)"); <br> becomes a line break; ATLAS's
   * presentational wrappers (<atlas-example>, <atlas-technique>, <div>, <span>, <sup>) are dropped and
   * their text kept; ATLAS site-relative links point at atlas.mitre.org. Code spans and fences are left
   * untouched, and any other angle-bracket text (placeholders such as <profile_name>) stays as written.
   */
  function normalizeMarkup(text) {
    const code = [];
    return String(text)
      .replace(/```[\s\S]*?```|`[^`\n]+`/g, m => '\u0001' + (code.push(m) - 1) + '\u0002')
      .replace(/\s*\(Citation:[^)]*\)/g, '')
      .replace(/\[\[[^\]]*\]\](\(\s*[^)\s]*\s*\))?/g, '')
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/?(?:atlas-[a-z-]+|div|span|sup)(?:\s[^>]*)?>/gi, '')
      .replace(/<code>([^<]*)<\/code>/gi, '`$1`')
      .replace(/\]\(\s*\/?((?:tactics|techniques|mitigations|studies|entities|software)\/[^)\s]*)\s*\)/g, '](https://atlas.mitre.org/$1)')
      .replace(/\u0001(\d+)\u0002/g, (_, i) => code[Number(i)]);
  }

  /** Safe rendering of description markdown: paragraphs, bullets, tables, quotes, code, links, bold. */
  function md(text) {
    const frag = document.createDocumentFragment();
    if (!text) return frag;
    const inline = (s, parent) => {
      // [text](url), [text]() (no target: just the text), `code`, **bold**
      const re = /\[([^\]]+)\]\(\s*(https?:\/\/[^)\s]+)?\s*\)|`([^`]+)`|\*\*([^*]+)\*\*/g;
      let last = 0, m;
      while ((m = re.exec(s))) {
        if (m.index > last) parent.append(decodeEntities(s.slice(last, m.index)));
        if (m[1] != null) parent.append(m[2] ? el('a', { href: m[2], target: '_blank', rel: 'noopener', text: decodeEntities(m[1]) }) : decodeEntities(m[1]));
        else if (m[3] != null) parent.append(el('code', { text: decodeEntities(m[3]) }));
        else parent.append(el('strong', { text: decodeEntities(m[4]) }));
        last = re.lastIndex;
      }
      if (last < s.length) parent.append(decodeEntities(s.slice(last)));
    };
    const isRow = l => /^\s*\|.*\|\s*$/.test(l);
    const isRule = l => /^\s*\|?(\s*:?-+:?\s*\|)+\s*:?-*:?\s*\|?\s*$/.test(l);
    const cells = l => l.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim());
    const renderLines = lines => {
      // runs of the same kind of line: bullets, table rows, quotes, or paragraph text
      const kind = l => (/^\s*[*-]\s+/.test(l) ? 'ul' : isRow(l) ? 'table' : /^\s*>/.test(l) ? 'quote' : 'p');
      for (let i = 0; i < lines.length;) {
        const k = kind(lines[i]);
        let j = i;
        while (j < lines.length && kind(lines[j]) === k) j++;
        const run = lines.slice(i, j);
        if (k === 'ul') {
          const ul = el('ul');
          for (const l of run) { const li = el('li'); inline(l.replace(/^\s*[*-]\s+/, ''), li); ul.append(li); }
          frag.append(ul);
        } else if (k === 'table' && run.length > 1) {
          const rows = run.filter(l => !isRule(l)).map(cells);
          const hasHead = run.length > 1 && isRule(run[1]);
          const tr = (r, tag) => el('tr', {}, ...r.map(c => { const td = el(tag); inline(c, td); return td; }));
          frag.append(el('div', { class: 'md-table' }, el('table', {},
            hasHead ? el('thead', {}, tr(rows[0], 'th')) : null,
            el('tbody', {}, ...rows.slice(hasHead ? 1 : 0).map(r => tr(r, 'td'))))));
        } else if (k === 'quote') {
          const q = el('blockquote');
          inline(run.map(l => l.replace(/^\s*>\s?/, '')).join(' '), q);
          frag.append(q);
        } else {
          const p = el('p');
          inline(run.map(l => l.replace(/^\s*#{1,6}\s+/, '')).join(' '), p);
          frag.append(p);
        }
        i = j;
      }
    };
    // fenced code blocks keep their lines; everything else splits into blocks at blank lines
    normalizeMarkup(text).trim().split(/```[^\n`]*\n?([\s\S]*?)```/).forEach((part, i) => {
      if (i % 2) { frag.append(el('pre', {}, el('code', { text: decodeEntities(part.replace(/\n$/, '')) }))); return; }
      for (const block of part.split(/\n\s*\n/)) renderLines(block.split('\n').filter(l => l.trim()));
    });
    return frag;
  }

  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = el('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ---------- state ----------

  const STORE_KEY = 'threatsim.sim.v1';
  const PICK_TABS = [
    { key: 'groups', family: 'attack', label: 'Groups', kind: 'group', one: 'Group' },
    { key: 'software', family: 'attack', label: 'Software', kind: 'software', one: 'Software' },
    { key: 'campaigns', family: 'attack', label: 'Campaigns', kind: 'campaign', one: 'Campaign' },
    // ATLAS threat intelligence, in ATLAS's own categories
    { key: 'caseStudies', family: 'atlas', label: 'Case studies', kind: 'case-study', one: 'Case study' },
    { key: 'entities', family: 'atlas', label: 'Entities', kind: 'entity', one: 'Entity' },
    { key: 'atlasSoftware', family: 'atlas', label: 'Software', kind: 'software', one: 'Software' },
  ];
  const STATUS = {
    covered:   { label: 'Mitigated + detected', icon: '✓' },
    mitigated: { label: 'Mitigated only',       icon: 'M' },
    detected:  { label: 'Detected only',        icon: 'D' },
    gap:       { label: 'No coverage',          icon: '✕' },
  };
  const EXAMPLES = [
    ['groups', 'G0016'], ['groups', 'G1017'], ['groups', 'G0034'],
    ['campaigns', 'C0028'], ['software', 'S0604'], ['groups', 'G1015'],
    ['caseStudies', 'AML.CS0069'], ['caseStudies', 'AML.CS0057'], ['atlasSoftware', 'AML.S0015'],
  ];
  // ATT&CK domains a saved profile could have known before ATLAS was added
  const PRE_ATLAS_DOMAINS = ['enterprise-attack', 'ics-attack', 'mobile-attack'];

  const state = {
    models: {},
    available: [],
    domains: new Set(),
    selection: { groups: new Set(), software: new Set(), campaigns: new Set(),
                 caseStudies: new Set(), entities: new Set(), atlasSoftware: new Set() },
    opts: { viaSoftware: true, viaCampaigns: true, platforms: new Set() },
    inPlace: { mitigations: new Set(), detections: new Set() },
    ui: {
      pickFamily: 'attack', pickTab: 'groups', lastTab: {}, search: '', matchDesc: false,
      swType: '', swPlatform: '', swCategory: '', csType: '', entType: '', purpose: '', campSince: '',
      tab: 'matrix', matrixDomain: null, colorMode: 'usage', showAll: false, filter: '', sort: {},
      spiderDomain: null, spiderTable: false, spiderHow: false,   // the coverage chart: domain picked, table shown, help open
    },
    results: [],
    catalogs: null,
    // CTID mappings (MappingsDB): per source id { meta, details: Map id -> text, indexes: { domain: Index } };
    // errors: per source id, why it could not be read
    mappings: { sources: {}, errors: {} },
  };

  // Workbook export progress, reflected on the static export toolbar by syncExportUi().
  const exportUi = { busy: false, msg: '', err: false };

  function persist() {
    const s = {
      domains: [...state.domains],
      known: [...state.available],   // domains pulled when this was saved; ones pulled later start switched on
      selection: Object.fromEntries(Object.entries(state.selection).map(([k, v]) => [k, [...v]])),
      opts: { viaSoftware: state.opts.viaSoftware, viaCampaigns: state.opts.viaCampaigns, platforms: [...state.opts.platforms] },
      inPlace: { mitigations: [...state.inPlace.mitigations], detections: [...state.inPlace.detections] },
      ui: { pickFamily: state.ui.pickFamily, pickTab: state.ui.pickTab, lastTab: state.ui.lastTab, tab: state.ui.tab,
            colorMode: state.ui.colorMode, showAll: state.ui.showAll, matrixDomain: state.ui.matrixDomain, matchDesc: state.ui.matchDesc,
            spiderDomain: state.ui.spiderDomain, spiderTable: state.ui.spiderTable, spiderHow: state.ui.spiderHow },
    };
    try { localStorage.setItem(STORE_KEY, JSON.stringify(s)); } catch (_) { /* storage unavailable */ }
  }

  function restore() {
    let s = null;
    try { s = JSON.parse(localStorage.getItem(STORE_KEY)); } catch (_) {}
    if (!s) return false;
    if (Array.isArray(s.domains)) {
      const known = Array.isArray(s.known) ? s.known : PRE_ATLAS_DOMAINS;
      const added = state.available.filter(d => !known.includes(d) && domainInfo(d).enabled !== false);
      state.domains = new Set([...s.domains.filter(d => state.available.includes(d)), ...added]);
    }
    for (const k of Object.keys(state.selection)) state.selection[k] = new Set((s.selection && s.selection[k]) || []);
    if (s.opts) {
      state.opts.viaSoftware = s.opts.viaSoftware !== false;
      state.opts.viaCampaigns = s.opts.viaCampaigns !== false;
      state.opts.platforms = new Set(s.opts.platforms || []);
    }
    if (s.inPlace) {
      state.inPlace.mitigations = new Set(s.inPlace.mitigations || []);
      state.inPlace.detections = new Set(s.inPlace.detections || []);
    }
    if (s.ui) Object.assign(state.ui, s.ui);
    if (!state.ui.lastTab || typeof state.ui.lastTab !== 'object') state.ui.lastTab = {};
    return true;
  }

  const activeModels = () => state.available.filter(d => state.domains.has(d)).map(d => state.models[d]);
  /** Knowledge bases with a domain switched on, ATT&CK first. */
  const activeFamilies = () => Object.keys(AttackDB.FAMILIES).filter(f => activeModels().some(m => familyOf(m.domain) === f));

  /** Platforms each knowledge base's techniques name (ATT&CK: Windows, Linux…; ATLAS: Generative AI…). */
  function familyPlatforms(family) {
    const out = new Set();
    for (const m of Object.values(state.models)) {
      if (familyOf(m.domain) !== family) continue;
      for (const t of m.byKind.technique || []) for (const p of t.platforms || []) if (p !== 'None') out.add(p);
    }
    return out;
  }
  /** The platform filter as it applies to one domain: only the selected platforms of its knowledge base,
   *  so picking Windows narrows ATT&CK without emptying ATLAS, and the reverse. */
  const platformsFor = domain => {
    const own = familyPlatforms(familyOf(domain));
    return new Set([...state.opts.platforms].filter(p => own.has(p)));
  };

  /** First active-domain record for a STIX id (falls back to any loaded domain). */
  function entity(id) {
    for (const m of activeModels()) { const o = m.byId.get(id); if (o) return o; }
    for (const m of Object.values(state.models)) { const o = m.byId.get(id); if (o) return o; }
    return null;
  }

  /** Union of selectable entities across active domains: kindKey -> [{obj, domains, techCount}] */
  function catalogs() {
    if (state.catalogs) return state.catalogs;
    const out = {};
    for (const tab of PICK_TABS) {
      const map = new Map();
      for (const m of activeModels().filter(x => familyOf(x.domain) === tab.family)) {
        for (const o of m.byKind[tab.kind] || []) {
          let e = map.get(o.id);
          if (!e) map.set(o.id, e = { obj: o, domains: [], techCount: 0 });
          e.domains.push(m.domain);
          e.techCount = Math.max(e.techCount, SimEngine.documentedTechniqueCount(m, o));
        }
      }
      out[tab.key] = [...map.values()];
    }
    return (state.catalogs = out);
  }

  // ---------- CTID mappings (NIST SP 800-53 Rev 5) ----------

  const MAP = SimEngine.MAPPING_SOURCES;   // { nist: {id, domains} }
  const NIST_PAGE = 'https://ctid.mitre.org/mappings/external/nist/';
  const mappingSource = key => state.mappings.sources[MAP[key].id] || null;
  /** The index for a source and domain: null when the source isn't pulled (an empty index when it has no rows there). */
  const mappingIndex = (key, domain) => { const s = mappingSource(key); return s ? s.indexes[domain] || null : null; };

  /** Read the pulled mapping sources once and index them against the loaded ATT&CK models. Never throws. */
  async function loadMappings() {
    const failAll = msg => { for (const key of Object.keys(MAP)) state.mappings.errors[MAP[key].id] = msg; };
    if (typeof MappingsDB === 'undefined') { failAll('the mappings module (js/mappings-db.js) did not load'); return; }
    let metas = [];
    try { metas = await MappingsDB.getAllMeta(); } catch (e) { console.error(e); failAll(e.message || String(e)); return; }
    for (const key of Object.keys(MAP)) {
      const id = MAP[key].id;
      if (!metas.some(m => m && m.source === id)) continue;
      try {
        const { meta, rows, details } = await MappingsDB.loadSource(id);
        if (!meta) continue;
        const byDomain = new Map();
        for (const row of Array.isArray(rows) ? rows : []) {
          if (!row || typeof row.domain !== 'string') continue;
          if (!byDomain.has(row.domain)) byDomain.set(row.domain, []);
          byDomain.get(row.domain).push(row);
        }
        const src = { meta, details: new Map(), indexes: {} };
        for (const d of Array.isArray(details) ? details : []) if (d && typeof d.id === 'string' && typeof d.text === 'string') src.details.set(d.id, d.text);
        for (const domain of MAP[key].domains) {
          if (!state.models[domain]) continue;
          src.indexes[domain] = SimEngine.indexMappings(state.models[domain], byDomain.get(domain) || []);
          src.indexes[domain].source = id;   // also when the source has no rows for this domain
        }
        state.mappings.sources[id] = src;
      } catch (e) {
        console.error(e);
        state.mappings.errors[id] = e.message || String(e);
      }
    }
  }

  // ---------- analysis ----------

  function analyze() {
    state.results = activeModels()
      .map(m => SimEngine.analyzeDomain(m, state.selection, Object.assign({ resolve: entity }, state.opts, { platforms: platformsFor(m.domain) })))
      .filter(r => r.roots.length);
    for (const r of state.results) {
      r.statusCounts = SimEngine.applyPosture(r, state.inPlace);
      r.mitPriority = SimEngine.prioritize(r.mitigations, state.inPlace.mitigations, r.domain, r.techniques);
      r.detPriority = SimEngine.prioritize(r.detections, state.inPlace.detections, r.domain, r.techniques);
      SimEngine.mapExternal(r, { nist: mappingIndex('nist', r.domain) });
    }
    if (!state.results.some(r => r.domain === state.ui.matrixDomain)) {
      state.ui.matrixDomain = state.results.length ? state.results[0].domain : null;
    }
  }

  function selectionSize() {
    return Object.values(state.selection).reduce((n, s) => n + s.size, 0);
  }

  function update({ picker = true } = {}) {
    persist();
    analyze();
    if (picker) renderPicker();
    renderResults();
  }

  // ---------- builder: domains, picker, scope ----------

  function renderDomains() {
    const host = $('#domainChips');
    host.replaceChildren(...state.available.map(d => {
      const cb = el('input', { type: 'checkbox', checked: state.domains.has(d) });
      cb.addEventListener('change', () => {
        if (!cb.checked && state.domains.size === 1) { cb.checked = true; return; }
        cb.checked ? state.domains.add(d) : state.domains.delete(d);
        state.catalogs = null;
        renderPlatforms();
        renderScopeLabels();
        renderPickerFilters();
        update();
      });
      return el('label', { class: 'chipbox' }, cb, domainTitle(d));
    }));
    $('#dataVersion').textContent = state.available
      .map(d => domainLabel(d) + ' v' + state.models[d].meta.version).join(' · ');
  }

  /** Keep the picker on a knowledge base that is switched on, and on one of its tabs. */
  function syncPickTab() {
    const fams = activeFamilies();
    if (fams.length && !fams.includes(state.ui.pickFamily)) state.ui.pickFamily = fams[0];
    const tabs = PICK_TABS.filter(t => t.family === state.ui.pickFamily);
    if (!tabs.some(t => t.key === state.ui.pickTab)) {
      const last = state.ui.lastTab[state.ui.pickFamily];
      state.ui.pickTab = tabs.some(t => t.key === last) ? last : tabs[0].key;
    }
    state.ui.lastTab[state.ui.pickFamily] = state.ui.pickTab;
  }

  /** Options for a picker select, from the values the current catalog actually has. */
  function fillSelect(sel, anyText, values, current, label = v => v) {
    sel.replaceChildren(el('option', { value: '', text: anyText }), ...values.map(v => el('option', { value: v, text: label(v) })));
    sel.value = values.includes(current) ? current : '';
    return sel.value;
  }

  function renderPickerFilters() {
    syncPickTab();
    const tab = state.ui.pickTab;
    const isSoftware = tab === 'software' || tab === 'atlasSoftware';
    $('#swType').hidden = !isSoftware;
    $('#swPlatform').hidden = tab !== 'software';
    $('#swCategory').hidden = tab !== 'atlasSoftware';
    $('#csType').hidden = tab !== 'caseStudies';
    $('#entType').hidden = tab !== 'entities';
    $('#purpose').hidden = tab !== 'caseStudies' && tab !== 'entities';
    $('#campSince').hidden = tab !== 'campaigns' && tab !== 'caseStudies';

    const cat = catalogs();
    const values = (rows, f) => [...new Set(rows.flatMap(e => [].concat(f(e.obj) || [])))].sort((a, b) => a.localeCompare(b));
    state.ui.swPlatform = fillSelect($('#swPlatform'), 'Any platform', values(cat.software, o => o.platforms), state.ui.swPlatform);
    state.ui.swCategory = fillSelect($('#swCategory'), 'Any category', values(cat.atlasSoftware, o => o.softwareCategories), state.ui.swCategory,
      v => v.replace(/-/g, ' ').replace(/\bai\b/g, 'AI'));
    state.ui.csType = fillSelect($('#csType'), 'Incidents & exercises', values(cat.caseStudies, o => o.caseType), state.ui.csType, v => v + 's');
    state.ui.entType = fillSelect($('#entType'), 'Any entity type', values(cat.entities, o => o.entityType), state.ui.entType);
    const purposeRows = tab === 'entities' ? cat.entities : cat.caseStudies;
    state.ui.purpose = fillSelect($('#purpose'), 'Any activity purpose', values(purposeRows, purposesOf), state.ui.purpose);

    const cs = $('#campSince');
    const now = new Date().getFullYear();
    const word = tab === 'caseStudies' ? 'Dated' : 'Active';
    cs.replaceChildren(el('option', { value: '', text: word + ' any time' }),
      ...[1, 2, 3, 5, 10].map(n => el('option', { value: String(now - n), text: word + ' since ' + (now - n) })));
    cs.value = state.ui.campSince;
  }

  /** Last date a campaign or case study was active; an ATLAS case study with no end date is ongoing. */
  const lastActive = obj => (obj.kind === 'case-study' && obj.firstSeen && !obj.lastSeen ? new Date().toISOString() : obj.lastSeen || obj.firstSeen);
  /** The year a date string names, read from the string so no time zone can shift it (ATLAS dates are plain days). */
  const yearOf = s => (s ? Number(String(s).slice(0, 4)) : null);
  /** ATLAS activity purposes of a case study or entity (Adversarial Operation, Security Evaluation…). */
  const purposesOf = obj => (familyOf(obj.domain) === 'atlas' && state.models[obj.domain] ? SimEngine.activityPurposes(state.models[obj.domain], obj) : []);

  function filteredCatalog() {
    const tab = state.ui.pickTab;
    const terms = state.ui.search.toLowerCase().split(/\s+/).filter(Boolean);
    let rows = catalogs()[tab].filter(({ obj }) => {
      if (terms.length) {
        const hay = [obj.name, obj.attackId, ...(obj.aliases || []), state.ui.matchDesc ? obj.description : '']
          .filter(Boolean).join(' ').toLowerCase();
        if (!terms.every(t => hay.includes(t))) return false;
      }
      if (tab === 'software' || tab === 'atlasSoftware') {
        if (state.ui.swType && obj.softwareType !== state.ui.swType) return false;
        if (tab === 'software' && state.ui.swPlatform && !(obj.platforms || []).includes(state.ui.swPlatform)) return false;
        if (tab === 'atlasSoftware' && state.ui.swCategory && !(obj.softwareCategories || []).includes(state.ui.swCategory)) return false;
      }
      if (tab === 'caseStudies' && state.ui.csType && obj.caseType !== state.ui.csType) return false;
      if (tab === 'entities' && state.ui.entType && obj.entityType !== state.ui.entType) return false;
      if ((tab === 'entities' || tab === 'caseStudies') && state.ui.purpose && !purposesOf(obj).includes(state.ui.purpose)) return false;
      if ((tab === 'campaigns' || tab === 'caseStudies') && state.ui.campSince) {
        const last = lastActive(obj);
        if (!last || yearOf(last) < Number(state.ui.campSince)) return false;
      }
      return true;
    });
    if (tab === 'campaigns' || tab === 'caseStudies') rows.sort((a, b) => String(lastActive(b.obj) || '').localeCompare(String(lastActive(a.obj) || '')) || byName(a.obj, b.obj));
    else rows.sort((a, b) => byName(a.obj, b.obj));
    return rows;
  }

  /** Selected threats of a tab that exist in the domains switched on (a pinned older ATLAS release may lack some). */
  function selectedPresent(key) {
    const present = new Set(catalogs()[key].map(e => e.obj.id));
    return [...state.selection[key]].filter(id => present.has(id)).length;
  }

  function renderPicker() {
    syncPickTab();
    // the switch and tabs are rebuilt below; keep keyboard focus on the button that was used
    const focused = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.pick : null;
    const fams = activeFamilies();
    const famHost = $('#pickFamily');
    famHost.hidden = fams.length < 2;
    famHost.replaceChildren(...fams.map(f => {
      const n = PICK_TABS.filter(t => t.family === f).reduce((sum, t) => sum + selectedPresent(t.key), 0);
      return el('button', {
        'aria-pressed': String(state.ui.pickFamily === f), data: { pick: 'family:' + f },
        on: { click: () => { state.ui.pickFamily = f; state.ui.pickTab = null; renderPickerFilters(); renderPicker(); persist(); } },
      }, AttackDB.FAMILIES[f].name + ' ', el('span', { class: 'count', text: n ? '(' + n + ')' : '' }));
    }));
    $('#pickTabs').setAttribute('aria-label', AttackDB.FAMILIES[state.ui.pickFamily].name + ' threat categories');
    $('#pickTabs').replaceChildren(...PICK_TABS.filter(t => t.family === state.ui.pickFamily).map(t => {
      const n = selectedPresent(t.key);
      return el('button', {
        role: 'tab', 'aria-selected': String(state.ui.pickTab === t.key), data: { pick: 'tab:' + t.key },
        on: { click: () => { state.ui.pickTab = t.key; renderPickerFilters(); renderPicker(); persist(); } },
      }, t.label + ' ', el('span', { class: 'count', text: n ? '(' + n + ')' : '' }));
    }));
    if (focused) { const b = document.querySelector(`[data-pick="${focused}"]`); if (b) b.focus(); }

    const rows = filteredCatalog();
    const sel = state.selection[state.ui.pickTab];
    // domain badges only when this knowledge base has more than one domain switched on (Enterprise + ICS)
    const familyDomains = activeModels().filter(m => familyOf(m.domain) === state.ui.pickFamily).length;
    $('#pickShown').textContent = fmtN(rows.length) + ' shown';
    const list = $('#pickList');
    if (!rows.length) {
      const tab = PICK_TABS.find(t => t.key === state.ui.pickTab);
      const atlas = activeModels().find(m => familyOf(m.domain) === 'atlas');
      list.replaceChildren(el('div', { class: 'empty', style: 'padding:12px', text: catalogs()[tab.key].length ? 'Nothing matches these filters.'
        : atlas && tab.family === 'atlas' ? `ATLAS v${atlas.meta.version} has no ${tab.label.toLowerCase()}: ATLAS added entities and software in release 2026.10. Pull a newer ATLAS release on the Data page.`
          : 'None in the domains switched on.' }));
      return;
    }
    list.replaceChildren(...rows.map(({ obj, domains, techCount }) => {
      const cb = el('input', { type: 'checkbox', checked: sel.has(obj.id), 'aria-label': obj.name });
      cb.addEventListener('change', () => {
        cb.checked ? sel.add(obj.id) : sel.delete(obj.id);
        update();
      });
      const aliases = (obj.aliases || []).filter(a => a !== obj.name);
      const metaText = [obj.attackId, ...pickMeta(obj), aliases.join(', ')].filter(Boolean).join(' · ');
      return el('label', { class: 'pick', role: 'option', 'aria-selected': String(sel.has(obj.id)) },
        cb,
        el('span', { class: 'nm' }, obj.name, familyDomains > 1 ? domains.map(d => el('span', { class: 'dbadge', text: domainLabel(d) })) : null),
        el('span', { class: 'tc', title: obj.kind === 'entity' ? 'Techniques it used, including in the case studies attributed to it' : 'Techniques used directly',
          text: techCount + ' TTPs' }),
        el('span', { class: 'meta', title: metaText, text: metaText }),
      );
    }));
  }

  /** Short facts for a picker row (after the ID, before aliases). */
  function pickMeta(obj) {
    const y = s => yearOf(s) || '?';
    const span = (a, b) => (y(a) === y(b) ? String(y(a)) : y(a) + '–' + y(b));
    switch (obj.kind) {
      case 'software': return [obj.softwareType, (obj.softwareCategories || []).join(', ')];
      case 'campaign': return [obj.firstSeen || obj.lastSeen ? y(obj.firstSeen) + '–' + y(obj.lastSeen) : null];
      case 'case-study': return [obj.caseType, obj.firstSeen ? (obj.lastSeen ? span(obj.firstSeen, obj.lastSeen) : y(obj.firstSeen) + '–ongoing') : null,
        purposesOf(obj).join(', ')];
      case 'entity': return [obj.entityType, purposesOf(obj).join(', ')];
      default: return [];
    }
  }

  function renderPlatforms() {
    // one group per knowledge base switched on; each group filters only its own domains (platformsFor)
    const groups = activeFamilies().map(f => {
      const counts = new Map();
      for (const m of activeModels().filter(x => familyOf(x.domain) === f)) {
        for (const t of m.byKind.technique || []) for (const p of t.platforms || []) {
          if (p !== 'None') counts.set(p, (counts.get(p) || 0) + 1);
        }
      }
      return { f, plats: [...counts.keys()].sort((a, b) => counts.get(b) - counts.get(a)) };
    });
    const all = new Set(groups.flatMap(g => g.plats));
    for (const p of [...state.opts.platforms]) if (!all.has(p)) state.opts.platforms.delete(p);
    $('#platGrid').replaceChildren(...groups.flatMap(g => [
      groups.length > 1 ? el('div', { class: 'plat-h', text: AttackDB.FAMILIES[g.f].name }) : null,
      ...g.plats.map(p => {
        const cb = el('input', { type: 'checkbox', checked: state.opts.platforms.has(p) });
        cb.addEventListener('change', () => {
          cb.checked ? state.opts.platforms.add(p) : state.opts.platforms.delete(p);
          renderPlatformSummary();
          update({ picker: false });
        });
        return el('label', {}, cb, p);
      }),
    ]));
    renderPlatformSummary();
  }

  /** Scope options name the threat types of the knowledge bases switched on. */
  function renderScopeLabels() {
    const f = activeFamilies();
    const attack = f.includes('attack'), atlas = f.includes('atlas');
    $('#optSoftwareHint').textContent = attack && atlas
      ? 'Add techniques from software linked to selected groups, campaigns, entities and case studies'
      : atlas ? 'Add techniques from software linked to selected entities and case studies'
        : 'Add techniques from malware and tools linked to selected groups and campaigns';
    $('#optCampaignsLabel').textContent = attack && atlas ? 'Include attributed campaigns and case studies'
      : atlas ? 'Include attributed case studies' : 'Include attributed campaigns';
    $('#optCampaignsHint').textContent = attack && atlas
      ? 'Add techniques from campaigns attributed to selected groups, and case studies attributed to selected entities'
      : atlas ? 'Add techniques from case studies attributed to selected entities'
        : 'Add techniques from campaigns attributed to selected groups';
  }

  function renderPlatformSummary() {
    const p = [...state.opts.platforms];
    $('#platSummary').textContent = p.length ? p.join(', ') : 'all';
  }

  // ---------- results ----------

  function renderResults() {
    renderProfileBar();
    const has = selectionSize() > 0;
    $('#emptyProfile').hidden = has && state.results.length > 0;
    $('#analysis').hidden = !(has && state.results.length);
    $('#exportBar').hidden = !(has && state.results.length);
    if (has && !state.results.length) {
      $('#emptyProfile').hidden = false;
      $('#emptyProfile').querySelector('p').textContent =
        'None of the selected threats appear in the domains you have switched on. Turn on another domain or pick different threats.';
    } else {
      const f = activeFamilies();
      const what = [f.includes('attack') ? 'ATT&CK groups, software or campaigns' : null, f.includes('atlas') ? 'ATLAS case studies, entities or software' : null]
        .filter(Boolean).join(', or ');
      $('#emptyProfile').querySelector('p').textContent =
        'Pick ' + what + ' on the left. You\'ll see the techniques they use, and the mitigations and detections that apply to them.';
    }
    if (!has || !state.results.length) { renderExamples(); return; }
    renderKpis();
    renderTabs();
    renderTab();
  }

  function renderExamples() {
    const host = $('#examples');
    host.replaceChildren();
    for (const [key, attackId] of EXAMPLES) {
      const tab = PICK_TABS.find(t => t.key === key);
      const found = state.available.filter(d => familyOf(d) === tab.family)
        .map(d => [d, (state.models[d].byKind[tab.kind] || []).find(x => x.attackId === attackId)])
        .filter(([, o]) => o);
      if (!found.length) continue;
      const o = found[0][1];
      host.append(el('button', {
        title: 'In ' + found.map(([d]) => domainTitle(d)).join(' and '),
        on: { click: () => {
          // switch on every domain the example appears in, so ICS-relevant examples show ICS too
          for (const [d] of found) state.domains.add(d);
          state.catalogs = null;
          state.selection[key].add(o.id);
          renderDomains(); renderPlatforms(); renderScopeLabels(); renderPickerFilters(); update();
        } },
      }, o.name, ...found.map(([d]) => el('span', { class: 'dbadge', text: domainLabel(d) }))));
    }
  }

  function renderProfileBar() {
    const bar = $('#profileBar');
    const chips = [];
    const activeIds = new Set(activeModels().flatMap(m => PICK_TABS.flatMap(t => (m.byKind[t.kind] || []).map(o => o.id))));
    for (const t of PICK_TABS) {
      for (const id of state.selection[t.key]) {
        const o = entity(id);
        if (!o) continue;
        const off = !activeIds.has(id);
        chips.push(el('span', { class: 'chip', title: off ? 'Not in the selected domains' : null, style: off ? 'opacity:.55' : null },
          el('span', { class: 'k', text: t.one }),
          el('span', { class: 'nm', text: o.name, on: { click: () => openDrawer(() => entityDrawer(id, t)) } }),
          el('button', { 'aria-label': 'Remove ' + o.name, text: '×', on: { click: () => { state.selection[t.key].delete(id); update(); } } }),
        ));
      }
    }
    if (!chips.length) { bar.replaceChildren(el('span', { class: 'label', text: 'Threat profile: nothing selected yet' })); return; }
    bar.replaceChildren(el('span', { class: 'label', text: 'Threat profile' }), ...chips,
      el('button', { class: 'link', text: 'Clear all', on: { click: () => { for (const s of Object.values(state.selection)) s.clear(); update(); } } }));
  }

  function totals() {
    const t = { tech: 0, subs: 0, tacticsHit: 0, tacticsAll: 0, mit: 0, mitIn: 0, det: 0, detIn: 0, dc: 0, dcShared: 0,
                covered: 0, mitigated: 0, detected: 0, gap: 0 };
    const dcDomains = new Map();   // data components are shared across domains: count each once
    for (const r of state.results) {
      t.tech += r.techniques.size;
      const hit = new Set();
      for (const x of r.techniques.values()) {
        if (x.tech.isSubtechnique) t.subs++;
        for (const ta of x.tech.tactics || []) hit.add(ta);
      }
      t.tacticsHit += r.model.tactics.filter(ta => hit.has(ta.shortname)).length;
      t.tacticsAll += r.model.tactics.length;
      t.mit += r.mitigations.size;
      t.det += r.detections.size;
      for (const e of r.dataComponents.values()) {
        const k = e.obj.attackId || e.obj.id;
        dcDomains.set(k, (dcDomains.get(k) || 0) + 1);
      }
      for (const id of r.mitigations.keys()) if (state.inPlace.mitigations.has(r.domain + '|' + id)) t.mitIn++;
      for (const id of r.detections.keys()) if (state.inPlace.detections.has(r.domain + '|' + id)) t.detIn++;
      for (const k of Object.keys(STATUS)) t[k] += r.statusCounts[k];
    }
    t.dc = dcDomains.size;
    t.dcShared = [...dcDomains.values()].filter(n => n > 1).length;
    return t;
  }

  function renderKpis() {
    hideTip();
    const t = totals();
    const tile = (lbl, val, sub) => el('div', { class: 'tile' },
      el('div', { class: 'lbl', text: lbl }), el('div', { class: 'val', text: val }), el('div', { class: 'sub', text: sub }));
    const noPosture = !t.mitIn && !t.detIn;
    const r = spiderResult();
    const cov = tacticCoverage(r);
    const plot = el('div', { class: 'sp-plot' });
    // the headline figure first (export.js reads the gap from the hero's first .val), then the chart, then its key:
    // on a phone the chart comes straight after the figure; wider, the key sits under the figure, beside the chart
    const hero = el('div', { class: 'tile hero' },
      el('div', { class: 'hero-head' },
        el('div', { class: 'lbl', text: 'Techniques with no mitigation or detection in place' }),
        el('div', { class: 'val' }, fmtN(t.gap), el('small', { text: pct(t.gap, t.tech) + ' of ' + fmtN(t.tech) })),
        noPosture ? el('div', { class: 'sub', style: 'margin-top:6px', text: 'Mark mitigations as in place and detections as deployed to simulate your coverage.' }) : null),
      spiderFigure(r, cov, plot),
      levelsKey(),
    );
    // ATLAS defines no detection strategies, so its techniques can only be mitigated
    const atlas = state.results.filter(x => familyOf(x.domain) === 'atlas').length;
    const atlasOnly = atlas === state.results.length;
    // a control of the coverage tile (domain switch, the chart, table toggle, How to read) had focus: give it to its replacement
    const active = document.activeElement;
    const place = active && $('#kpis').contains(active) ? placeOf(active) : null;
    $('#kpis').replaceChildren(
      tile('Techniques in scope', fmtN(t.tech), fmtN(t.subs) + ' sub-techniques · ' + t.tacticsHit + ' of ' + t.tacticsAll + ' tactics'),
      tile('Mitigations', fmtN(t.mit), fmtN(t.mitIn) + ' in place'),
      tile('Detection strategies', fmtN(t.det), atlasOnly ? 'ATLAS has none; its detection controls are listed as mitigations'
        : fmtN(t.detIn) + ' deployed' + (atlas ? ' · ATT&CK only' : '')),
      tile('Data components', fmtN(t.dc), atlasOnly ? 'none: ATLAS defines no detection strategies'
        : 'telemetry the detections rely on' + (t.dcShared ? ` · ${fmtN(t.dcShared)} used by more than one domain` : '')),
      hero,
    );
    placeSpiderTable();
    watchKpiWidth();
    if (cov.axes.length >= 3) mountSpider(plot, r, cov.axes); else stopSpider();
    watchTaps();
    if (place && (!document.activeElement || document.activeElement === document.body)) focusQuiet(findPlace(place));
  }

  /**
   * Where "Show as table" shows the table: under the chart while the coverage tile is one column (phones); wider, on
   * a row of its own under the KPI tiles, as wide as all of them, so every column fits and the tiles beside the chart
   * keep their height. Hidden, it stays in the same place for screen readers. Runs on each render, and when the KPI
   * area changes width (the tile's columns come from a container query).
   */
  function placeSpiderTable() {
    const wrap = $('#spiderTable'), kpis = $('#kpis');
    const hero = wrap && kpis.querySelector('.hero');
    if (!hero || !hero.getClientRects().length) return;   // not laid out: placed when it is
    const oneColumn = getComputedStyle(hero).gridTemplateColumns.trim().split(/\s+/).length < 2;
    const home = oneColumn ? hero.querySelector('figure.spider') : kpis;
    if (wrap.parentElement === home) return;
    const focused = wrap.contains(document.activeElement) ? document.activeElement : null;
    home.append(wrap);
    if (!focused) return;
    focused.focus({ preventScroll: true });
    // the sideways scroller is a Tab stop only while it scrolls (phones): once it no longer does, the table keeps the focus
    if (!wrap.contains(document.activeElement)) wrap.querySelector('table').focus({ preventScroll: true });
  }
  /**
   * The table's scroller lost the focus: when a wider window stopped it scrolling (with or before a move), the
   * browser took the focus away, to nothing. The table takes it then, on the next frame, if nothing else has.
   */
  function keepTableFocus(e) {
    const sc = e.currentTarget;
    if (e.target !== sc || e.relatedTarget || sc.scrollWidth > sc.clientWidth) return;
    requestAnimationFrame(() => {
      const table = sc.querySelector('table');
      if (table && table.isConnected && (!document.activeElement || document.activeElement === document.body)) table.focus({ preventScroll: true });
    });
  }
  let kpiWatch = null;
  function watchKpiWidth() {
    if (kpiWatch || typeof ResizeObserver !== 'function') return;
    // on the next frame, not inside the observer (moving the table changes the area's height)
    kpiWatch = new ResizeObserver(() => requestAnimationFrame(placeSpiderTable));
    kpiWatch.observe($('#kpis').parentElement);
  }

  // ---------- coverage by tactic: the spider chart in the hero tile ----------

  // The chart's rings. A technique scores 3 when it is mitigated and detected, 2 when only one of the two is in
  // place (partial), 1 when neither is; a tactic's point sits at the average score of its profile techniques.
  const LEVELS = [
    { n: 1, label: STATUS.gap.label, icons: ['gap'] },
    { n: 2, label: 'Partial', icons: ['mitigated', 'detected'] },
    { n: 3, label: STATUS.covered.label, icons: ['covered'] },
  ];
  const LEVEL_OF = { gap: 1, mitigated: 2, detected: 2, covered: 3 };

  /**
   * One result's coverage per tactic, in matrix order, for the tactics with at least one profile technique:
   * axes [{ tactic, n, covered, partial, gap, sum }] (sum adds up the scores, so the average is sum / n). A technique
   * under several tactics counts in each; unplaced counts techniques under no tactic of the matrix.
   */
  function tacticCoverage(r) {
    const rows = new Map(r.model.tactics.map(ta => [ta.shortname, { tactic: ta, n: 0, covered: 0, partial: 0, gap: 0, sum: 0 }]));
    let unplaced = 0;
    for (const t of r.techniques.values()) {
      let placed = false;
      for (const sn of new Set(t.tech.tactics || [])) {
        const a = rows.get(sn);
        if (!a) continue;
        placed = true;
        a.n++;
        a.sum += LEVEL_OF[t.status];
        if (t.status === 'covered') a.covered++; else if (t.status === 'gap') a.gap++; else a.partial++;
      }
      if (!placed) unplaced++;
    }
    return { axes: [...rows.values()].filter(a => a.n), unplaced };
  }
  // In whole numbers, so 3 (and 3.0) only when every technique of the tactic scores 3, and a dot's colour always
  // agrees with the figure shown beside it.
  /** The highest level a tactic's average reaches: 1, 2 or 3. */
  const levelReached = a => (a.sum >= 3 * a.n ? 3 : a.sum >= 2 * a.n ? 2 : 1);
  /** A tactic's average to one decimal, rounded down. */
  const avgText = a => (Math.floor((10 * a.sum) / a.n) / 10).toFixed(1);

  /**
   * The result the chart shows: the domain picked with its switch; else Enterprise when it has a tactic to chart;
   * else the first result that has one; else Enterprise, else the first.
   */
  function spiderResult() {
    const charted = r => tacticCoverage(r).axes.length > 0;
    const ent = state.results.find(r => r.domain === 'enterprise-attack');
    return state.results.find(r => r.domain === state.ui.spiderDomain)
      || (ent && charted(ent) ? ent : null) || state.results.find(charted) || ent || state.results[0];
  }

  /**
   * The levels, with the status icons the matrix and tables use: the key to the rings and the dots, and how to read
   * the chart (closed until asked for; it stays open across re-renders).
   */
  function levelsKey() {
    const how = el('details', { class: 'sp-how', open: !!state.ui.spiderHow },
      el('summary', { data: { key: 'spider|how' }, text: 'How to read this chart' }),
      el('p', { text: 'A tactic\'s point sits at the average level of its techniques (a technique under several tactics counts in each), '
        + 'and its dot takes the colour of the highest level that average reaches. Averages are shown rounded down to one decimal, '
        + 'so 3.0 means every technique is mitigated and detected.' }));
    how.addEventListener('toggle', () => { if (!!state.ui.spiderHow !== how.open) { state.ui.spiderHow = how.open; persist(); } });
    return el('div', { class: 'sp-key' },
      el('ul', { 'aria-label': 'Coverage levels' }, ...LEVELS.map(l => el('li', {},
        el('span', { class: 'stat-badge sp-icons', 'aria-hidden': 'true' }, ...l.icons.map(k => el('span', { class: 'ic ' + k, text: STATUS[k].icon }))),
        el('span', {}, el('b', { text: l.n + ' ' }), l.label + (l.n === 2 ? ': mitigated or detected only' : ''))))),
      how);
  }

  function spiderFigure(r, cov, plot) {
    const { axes, unplaced } = cov;
    const label = domainLabel(r.domain);
    const atlas = familyOf(r.domain) === 'atlas';
    const c = r.statusCounts;
    const many = state.results.length > 1;
    // the caption is shown above the table's sideways scroller (inside it, a phone would cut it off)
    const caption = 'Coverage by tactic, ' + domainTitle(r.domain) + ' (levels: 1 no coverage, 2 partial, 3 mitigated + detected; '
      + 'averages rounded down to one decimal' + (axes.length > 1 ? '; a technique under several tactics counts in each' : '') + ')';
    const tableWrap = el('div', { id: 'spiderTable', class: 'sp-table-wrap' + (state.ui.spiderTable ? '' : ' vh') },
      el('p', { class: 'sp-table-note', 'aria-hidden': 'true', text: caption }),
      el('div', { class: 'table-scroll', on: { focusout: keepTableFocus } }, spiderTable(axes, caption)));
    const toggle = el('button', {
      type: 'button', class: 'sp-btn', 'aria-pressed': String(!!state.ui.spiderTable), 'aria-controls': 'spiderTable',
      data: { key: 'spider|table' }, text: 'Show as table',
      on: { click: () => {
        state.ui.spiderTable = !state.ui.spiderTable;
        persist();
        toggle.setAttribute('aria-pressed', String(state.ui.spiderTable));
        tableWrap.classList.toggle('vh', !state.ui.spiderTable);
      } },
    });
    // the domain's techniques, each counted once (the table and the chart count a technique under each of its tactics)
    const counts = !r.techniques.size ? null : label + ' · ' + plural(r.techniques.size, 'technique', 'techniques') + ': ' + (atlas
      ? fmtN(c.mitigated) + ' mitigated, ' + fmtN(c.gap) + ' no coverage.'
      : fmtN(c.covered) + ' mitigated + detected, ' + fmtN(c.mitigated + c.detected) + ' partial (M ' + fmtN(c.mitigated) + ' · D '
        + fmtN(c.detected) + '), ' + fmtN(c.gap) + ' no coverage.');
    return el('figure', { class: 'spider', 'aria-labelledby': 'spiderTitle' },
      el('div', { class: 'sp-head' },
        el('span', { id: 'spiderTitle', class: 'sp-title', text: 'Average coverage by tactic' }),
        many
          ? el('div', { class: 'seg', role: 'group', 'aria-label': 'Domain shown in the chart' }, ...state.results.map(x => el('button', {
            type: 'button', 'aria-pressed': String(x === r), text: domainLabel(x.domain), data: { key: 'spider|' + x.domain },
            on: { click: () => { if (x === r) return; state.ui.spiderDomain = x.domain; persist(); renderKpis(); } },
          })))
          : el('span', { class: 'sp-domain', text: domainTitle(r.domain) })),
      axes.length >= 3 ? plot : axes.length ? spiderRows(r, axes) : null,
      // under the chart: what it covers, and the switch for the table that follows
      el('div', { class: 'sp-foot' }, el('div', { class: 'sp-notes' },
        counts ? el('p', { text: counts }) : null,
        axes.length && axes.length < 3 ? el('p', { text: 'The profile\'s ' + label + ' techniques fall under only ' + plural(axes.length, 'tactic', 'tactics')
          + '. A spider chart needs at least three, so ' + (axes.length === 1 ? 'its average is' : 'each tactic\'s average is') + ' shown on a line from 1 to 3.' }) : null,
        !axes.length ? el('p', { text: r.techniques.size ? 'None of these techniques is under a tactic of the ' + domainTitle(r.domain) + ' matrix, so there is nothing to chart.'
          : 'There are no ' + label + ' techniques to chart.' }) : null,
        unplaced && axes.length ? el('p', { text: plural(unplaced, 'technique is', 'techniques are') + ' under no tactic of the ' + domainTitle(r.domain)
          + ' matrix and ' + (unplaced === 1 ? 'is' : 'are') + ' left out of the chart.' }) : null,
        atlas && axes.length ? el('p', { text: 'ATLAS has no detection strategies, so its techniques are only ever mitigated (2) or not covered (1): '
          + 'ATLAS tactics top out at 2, inside the outer ring.' }) : null),
        axes.length ? toggle : null),
      axes.length ? tableWrap : null,
    );
  }

  /**
   * The chart's numbers as a table (visually hidden until "Show as table"; screen readers always have it). It can
   * take the focus, though it is no Tab stop, for when the table moves (placeSpiderTable).
   */
  function spiderTable(axes, caption) {
    // the average (what the chart draws) next to the tactic, so a phone shows both before the table scrolls sideways
    const head = ['Tactic', 'Average', 'Techniques', STATUS.covered.label.replace(' + ', ' +\u00a0'), 'Partial', STATUS.gap.label];
    return el('table', { class: 'data sp-table', tabindex: '-1' },
      el('caption', { class: 'vh', text: caption }),
      el('thead', {}, el('tr', {}, ...head.map((h, i) => el('th', { scope: 'col', class: i ? 'num' : null, text: h })))),
      el('tbody', {}, ...axes.map(a => el('tr', { data: { tactic: a.tactic.shortname } },
        el('th', { scope: 'row', text: a.tactic.name }),
        el('td', { class: 'num', text: avgText(a) }),
        ...[a.n, a.covered, a.partial, a.gap].map(v => el('td', { class: 'num', text: fmtN(v) }))))));
  }

  /**
   * What the chart shows, in a sentence (its accessible name): the lowest and the highest average as shown, with
   * every tactic at that figure (named up to three, then counted).
   */
  function spiderSummary(r, axes) {
    const shown = axes.map(avgText);
    const lo = shown.reduce((m, v) => (Number(v) < Number(m) ? v : m)), hi = shown.reduce((m, v) => (Number(v) > Number(m) ? v : m));
    const at = v => {
      const names = axes.filter((a, i) => shown[i] === v).map(a => a.tactic.name);
      return v + ', for ' + (names.length <= 3 ? andList(names) : names.slice(0, 2).join(', ') + ' and ' + (names.length - 2) + ' more');
    };
    const what = domainLabel(r.domain) + ' tactic';
    return 'Average coverage of ' + plural(axes.length, what, what + 's') + ', on a scale from 1 (no coverage) to 3 (mitigated and detected): '
      + (axes.length === 1 ? axes[0].tactic.name + ' at ' + lo : lo === hi ? 'all at ' + lo : 'lowest ' + at(lo) + '; highest ' + at(hi))
      + '. The table that follows lists every tactic.';
  }

  /** One tactic in words, for the screen reader as the arrow keys move along the chart. */
  const spiderAxisText = a => a.tactic.name + ': average ' + avgText(a) + ' of 3. ' + plural(a.n, 'technique', 'techniques') + ': '
    + fmtN(a.covered) + ' mitigated and detected, ' + fmtN(a.partial) + ' partial, ' + fmtN(a.gap) + ' no coverage.';

  /**
   * The tooltip for a tactic, at its dot (anchor). On the spider, plot is the box of the rings on screen: the tooltip
   * keeps off it. It goes beside the rings on the axis's own side (dir: the axis's direction), else above or below
   * them (the side the dot is on first), else beside them on the other side (a short window, such as a phone held
   * sideways), wherever the window has room; prefer names the place to try first (the one it had, while it follows a
   * scroll). A window too small for all of these gets the one of them, kept inside the window, that covers the least
   * of the rings. The dot rows (no plot) put it beside the dot on its side, else the other, else below or above it.
   * Returns the place used.
   */
  function spiderTip(anchor, a, dir = [1, 0], plot = null, prefer = null) {
    const tip = $('#tip');
    tip.replaceChildren(
      el('b', { text: a.tactic.name }),
      el('div', { class: 'row' }, el('strong', { class: 'tip-val', text: avgText(a) }), ' average level, rounded down'),
      el('div', { class: 'row', text: plural(a.n, 'profile technique', 'profile techniques') + ': ' + fmtN(a.covered) + ' mitigated + detected, '
        + fmtN(a.partial) + ' partial, ' + fmtN(a.gap) + ' no coverage' }),
    );
    tip.dataset.of = 'spider';   // Escape closes it wherever the focus is (closeSpiderTip)
    tip.style.left = tip.style.top = '0px';   // measured at its natural width, wherever it was before
    tip.hidden = false;
    const b = anchor.getBoundingClientRect();
    const w = tip.offsetWidth, h = tip.offsetHeight, gap = 10, pad = 8;
    const clampX = x => Math.min(Math.max(pad, x), innerWidth - w - pad), clampY = y => Math.min(Math.max(pad, y), innerHeight - h - pad);
    const fits = ([, x, y]) => x >= pad && x + w <= innerWidth - pad && y >= pad && y + h <= innerHeight - pad;
    const midX = b.left + b.width / 2 - w / 2, midY = b.top + b.height / 2 - h / 2;
    let spot = null;
    if (plot) {
      const above = ['above', clampX(midX), plot.top - gap - h], below = ['below', clampX(midX), plot.bottom + gap];
      const right = ['right', plot.right + gap, clampY(midY)], left = ['left', plot.left - gap - w, clampY(midY)];
      const ends = dir[1] < 0 ? [above, below] : [below, above], sides = dir[0] < 0 ? [left, right] : [right, left];
      // an axis that points up or down has no side of its own: above or below it is. The far side comes last (it
      // covers the other side's labels)
      const places = Math.abs(dir[0]) < 0.25 ? ends.concat(sides) : [sides[0], ...ends, sides[1]];
      const over = ([, x, y]) => {   // how much of the rings' box a place covers, once kept inside the window
        x = clampX(x); y = clampY(y);
        return Math.max(0, Math.min(x + w, plot.right) - Math.max(x, plot.left)) * Math.max(0, Math.min(y + h, plot.bottom) - Math.max(y, plot.top));
      };
      // where nothing fits outside the rings: the place that covers least of them, but never the dot it describes
      const clear = places.filter(([, x, y]) => { x = clampX(x); y = clampY(y); return !(b.left < x + w && b.right > x && b.top < y + h && b.bottom > y); });
      spot = places.find(p => p[0] === prefer && fits(p)) || places.find(fits)
        || (clear.length ? clear : places).reduce((m, p) => (over(p) < over(m) ? p : m));
    }
    if (!spot) {
      const right = b.right + gap + w <= innerWidth - pad, left = b.left - gap - w >= pad;
      spot = left && (dir[0] < 0 || !right) ? ['dot', b.left - gap - w, midY] : right ? ['dot', b.right + gap, midY]
        : ['dot', midX, b.bottom + gap + h <= innerHeight - pad ? b.bottom + gap : b.top - gap - h];
    }
    tip.style.left = clampX(spot[1]) + 'px';
    tip.style.top = clampY(spot[2]) + 'px';
    return spot[0];
  }

  /** Escape, wherever the focus is: close a tooltip the coverage chart (or its dot rows) opened, and its highlight. */
  function closeSpiderTip() {
    const tip = $('#tip');
    if (tip.hidden || tip.dataset.of !== 'spider') return;
    if (spider && spider.clear) spider.clear(); else hideTip();
  }

  /** Fewer than three tactics make no spider: each tactic's average as a dot on a 1-3 line instead. */
  function spiderRows(r, axes) {
    const rows = el('div', { class: 'sp-rows', role: 'img', 'aria-label': spiderSummary(r, axes) },
      el('span'), el('span', { class: 'sp-scale' }, ...LEVELS.map(l => el('span', { class: 'l' + l.n, text: String(l.n) }))), el('span'),
      ...axes.map((a, i) => el('div', { class: 'sp-row', data: { i: String(i), tactic: a.tactic.shortname } },
        el('span', { class: 'sp-row-name', text: a.tactic.name }),
        el('span', { class: 'sp-track' }, ...LEVELS.map(l => el('span', { class: 'sp-tick l' + l.n })),
          el('span', { class: 'sp-mark l' + levelReached(a), style: 'left:' + ((a.sum / a.n - 1) * 50).toFixed(2) + '%' })),
        el('span', { class: 'sp-row-val', text: avgText(a) }))));
    rows.addEventListener('pointerover', e => {
      const row = e.target.closest('.sp-row');
      if (row) spiderTip(row.querySelector('.sp-mark'), axes[Number(row.dataset.i)]); else hideTip();
    });
    rows.addEventListener('pointerleave', e => { if (e.pointerType !== 'touch') hideTip(); });
    return rows;
  }

  const SVG_NS = 'http://www.w3.org/2000/svg';
  /** svgEl('circle', { cx, cy, r, class }, ...children): an SVG element (null attributes are skipped). */
  function svgEl(tag, attrs, ...kids) {
    const n = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null && v !== false) n.setAttribute(k, v);
    append(n, kids);
    return n;
  }

  let measureCtx;
  /** Width of a text in a CSS font, from a canvas (the labels are laid out before they are drawn). */
  function textWidth(text, font, px) {
    if (measureCtx === undefined) measureCtx = document.createElement('canvas').getContext('2d');
    if (!measureCtx) return text.length * px * 0.6;
    measureCtx.font = font;
    return measureCtx.measureText(text).width;
  }

  /** A label's words in lines no wider than max (a longer word keeps a line of its own). */
  function wrapWords(text, max, width) {
    const lines = [];
    for (const word of String(text).split(/\s+/).filter(Boolean)) {
      const joined = lines.length ? lines[lines.length - 1] + ' ' + word : null;
      if (joined != null && width(joined) <= max) lines[lines.length - 1] = joined; else lines.push(word);
    }
    return lines;
  }

  const SPIDER_MAX_R = 128;   // radius of the outer ring at most, in px
  const SPIDER_MIN_R = 48;    // a smaller chart is too small to read: let it grow taller, or shorten the labels, first
  /**
   * Fit the chart to a width: the largest radius whose tactic labels, set just beyond the outer ring, stay inside the
   * width and a height cap. A label is anchored by the side it is on (centred only on a vertical axis) and its lines
   * grow away from the chart; one that would come within an em of a label already placed (two names on one line
   * would read as one) moves further out along its own axis. Labels wrap only when that buys a clearly larger chart.
   * When even wrapped labels leave too small a chart (very long names, many tactics), the chart may grow taller, and
   * then the labels are cut short with an ellipsis (the tooltip and the table keep the full names); when nothing fits
   * (dozens of tactics in a narrow box), fit is false. Boxes are relative to the centre; cx, cy place the centre.
   */
  function spiderLayout(axes, W, stacked) {
    const n = axes.length;
    const px = stacked || W < 340 ? 11 : 12, lh = Math.round(px * 1.25), gap = 10;   // phones: 11px labels
    const font = px + 'px ' + getComputedStyle(document.body).fontFamily;
    const width = s => textWidth(s, font, px);
    // beside the figure and the key, a height cap keeps the tile compact; stacked under them (phones), the chart may
    // be as tall as wide, as the width is what limits it there
    const maxH = stacked ? W : Math.round(Math.min(300, Math.max(260, W * 0.8)));
    const angle = i => -Math.PI / 2 + (2 * Math.PI * i) / n;
    const dirs = axes.map((a, i) => [Math.cos(angle(i)), Math.sin(angle(i))]);
    const box = (L, i, d) => {
      const [c, s] = dirs[i];
      const x = d * c, y = d * s;
      const anchor = Math.abs(c) < 0.05 ? 'middle' : c > 0 ? 'start' : 'end';
      const left = anchor === 'start' ? x : anchor === 'end' ? x - L.w : x - L.w / 2;
      const top = anchor === 'middle' ? (s < 0 ? y - L.h : y) : y - L.h / 2 + (s * L.h) / 2;
      return { anchor, x, top, left, right: left + L.w, bottom: top + L.h };
    };
    const overlap = (a, b) => a.left < b.right + px && b.left < a.right + px && a.top < b.bottom + 1 && b.top < a.bottom + 1;
    const extent = (labels, R) => {
      const boxes = [];
      let clash = 0;   // labels that still overlap another after moving out as far as they may
      labels.forEach((L, i) => {
        let d = R + gap, b = box(L, i, d);
        for (let k = 0; k < 40 && boxes.some(o => overlap(o, b)); k++) b = box(L, i, d += 2);
        if (boxes.some(o => overlap(o, b))) clash++;
        boxes.push(b);
      });
      let x0 = -R - 6, x1 = R + 6, y0 = -R - 6, y1 = R + 6;   // the outer ring's dots
      for (const b of boxes) { x0 = Math.min(x0, b.left); x1 = Math.max(x1, b.right); y0 = Math.min(y0, b.top); y1 = Math.max(y1, b.bottom); }
      return { boxes, clash, x0, x1, y0, y1 };
    };
    // how badly a layout misses: px beyond the width and the height allowed, and a line's worth per clashing label
    const miss = (e, maxH) => Math.max(0, e.x1 - e.x0 - (W - 2)) + Math.max(0, e.y1 - e.y0 - maxH) + e.clash * lh;
    // the largest radius that fits, stepping down 4px then back up 1px (moved labels make the fit uneven in R)
    const layout = (labels, maxH, short) => {
      const ok = R => !miss(extent(labels, R), maxH);
      let R = SPIDER_MAX_R;
      while (R > 24 && !ok(R)) R -= 4;
      while (R < SPIDER_MAX_R && ok(R + 1)) R += 1;
      return { labels, R, short, miss: miss(extent(labels, R), maxH) };
    };
    const labelsOf = linesOf => axes.map(a => {
      const lines = linesOf(a.tactic.name);
      return { lines, w: Math.max(...lines.map(width)), h: lines.length * lh };
    });
    // at most two lines of at most max px; a name that runs on, or a word too long for a line, ends in an ellipsis
    const shorten = (name, max) => {
      const lines = wrapWords(name, max, width);
      const cut = (s, more) => {
        if (!more && width(s) <= max) return s;
        const cs = [...s];
        while (cs.length > 1 && width(cs.join('') + '…') > max) cs.pop();
        return cs.join('').trimEnd() + '…';
      };
      return lines.length <= 2 ? lines.map(s => cut(s, false)) : [cut(lines[0], false), cut(lines[1], true)];
    };
    const wraps = [Infinity, 140, 110, 90, 70].map(max => labelsOf(name => wrapWords(name, max, width)));
    const options = wraps.map(labels => layout(labels, maxH, false));
    // the first (least wrapped, then least cut) within 10% of the largest chart that fits
    const nearBest = os => { const best = Math.max(0, ...os.filter(o => !o.miss).map(o => o.R)); return best ? os.find(o => !o.miss && o.R >= best * 0.9) : null; };
    let pick = nearBest(options);
    if (!pick || pick.R < SPIDER_MIN_R) {
      // full names leave too small a chart: let it grow taller, then cut the labels short, the least cut that reaches a
      // readable size; failing that, the largest chart that fits, else (fit: false) the layout that misses least
      const tall = Math.max(maxH, Math.min(W, 520));
      const more = wraps.map(labels => layout(labels, tall, false))
        .concat([90, 70, 56, 44].map(max => layout(labelsOf(name => shorten(name, max)), tall, true)));
      const all = options.concat(more);
      pick = more.find(o => !o.miss && o.R >= SPIDER_MIN_R) || nearBest(all)
        || all.reduce((m, o) => (o.miss < m.miss || (o.miss === m.miss && o.R > m.R) ? o : m));
    }
    const e = extent(pick.labels, pick.R);
    return { n, px, lh, angle, R: pick.R, labels: pick.labels, boxes: e.boxes, short: pick.short, fit: !pick.miss,
      W, H: Math.ceil(e.y1 - e.y0) + 2, cx: (W - (e.x1 - e.x0)) / 2 - e.x0, cy: 1 - e.y0 };
  }

  // the chart on screen: { host, r, axes, w (width drawn for), at (tactic shown), by (what showed it), svg, clear, follow }
  let spider = null;
  let spiderWatch = null;   // redraws it when its width changes
  let tapWatch = false;

  /** Once: a tap outside the chart closes a tooltip that a tap on the chart opened. */
  function watchTaps() {
    if (tapWatch) return;
    tapWatch = true;
    document.addEventListener('pointerdown', e => {
      if (e.pointerType !== 'touch' || (e.target.closest && e.target.closest('.sp-svg, .sp-rows'))) return;
      if (spider && spider.clear) spider.clear();
      else if (document.querySelector('#kpis .sp-rows')) hideTip();
    }, { passive: true });
  }

  function mountSpider(host, r, axes) {
    const at = spider && spider.r.domain === r.domain && spider.at < axes.length ? spider.at : 0;
    spider = { host, r, axes, w: 0, at, svg: null, clear: null };
    if (typeof ResizeObserver === 'function') {
      // redraw on the next frame, not inside the observer (the new drawing changes the host's height)
      if (!spiderWatch) spiderWatch = new ResizeObserver(() => requestAnimationFrame(() => {
        const w = spider && spider.host.isConnected ? Math.round(spider.host.clientWidth) : 0;
        if (w && w !== spider.w) drawSpider();   // 0: hidden, nothing to fit
      }));
      spiderWatch.disconnect();
      spiderWatch.observe(host);
    }
    drawSpider();
  }
  function stopSpider() {
    spider = null;
    if (spiderWatch) spiderWatch.disconnect();
  }

  function drawSpider() {
    const sp = spider;
    const { host, r, axes } = sp;
    const hadFocus = !!sp.svg && document.activeElement === sp.svg, wasBy = sp.by;
    sp.w = Math.round(host.clientWidth);
    hideTip();
    const hero = host.closest('.hero');
    const stacked = !hero || getComputedStyle(hero).gridTemplateColumns.trim().split(/\s+/).length < 2;
    const g = spiderLayout(axes, Math.max(260, sp.w || 560), stacked);
    if (!g.fit) {
      // dozens of tactics in a narrow box: no labelling fits around a spider, so a line per tactic, as for fewer than three
      host.replaceChildren(spiderRows(r, axes), el('p', { class: 'sp-crowd', text: 'There are too many tactics to label around a spider chart '
        + 'at this width, so each tactic\'s average is shown on a line from 1 to 3.' }));
      Object.assign(sp, { svg: null, by: null, clear: hideTip, follow: null });
      return;
    }
    const { n, R, cx, cy, angle } = g;
    const f = v => v.toFixed(1);
    const xy = (i, v) => [cx + (R * v / 3) * Math.cos(angle(i)), cy + (R * v / 3) * Math.sin(angle(i))];
    const points = vals => vals.map((v, i) => xy(i, v).map(f).join(',')).join(' ');
    const half = Math.PI / n;
    // a ring is a polygon: halfway between two axes, its side is this much closer to the centre than its corners
    const sideMid = Math.cos(half);
    // a slice of the circle around an axis, out to radius out
    const slice = (i, out) => {
      const at = a => f(cx + out * Math.cos(a)) + ',' + f(cy + out * Math.sin(a));
      return 'M' + f(cx) + ',' + f(cy) + ' L' + at(angle(i) - half) + ' A' + f(out) + ',' + f(out) + ' 0 0 1 ' + at(angle(i) + half) + ' Z';
    };
    // the shaded band of a hovered axis: its share of the outer ring, from the centre to the middles of the ring's
    // two sides beside the axis (a slice of the circle would bulge out of the ring on a chart of few tactics)
    const band = i => {
      const at = (a, d) => f(cx + d * Math.cos(a)) + ',' + f(cy + d * Math.sin(a));
      return 'M' + f(cx) + ',' + f(cy) + ' L' + at(angle(i) - half, R * sideMid) + ' L' + at(angle(i), R) + ' L' + at(angle(i) + half, R * sideMid) + ' Z';
    };
    // hover slices reach out to the farthest label corner
    const reach = Math.max(...g.boxes.flatMap(b => [[b.left, b.top], [b.right, b.top], [b.left, b.bottom], [b.right, b.bottom]].map(([x, y]) => Math.hypot(x, y)))) + 4;
    const ringAt = angle(0) + half;   // ring numbers go between the first two axes, each on its own ring's side
    const svg = svgEl('svg', {
      class: 'sp-svg', viewBox: '0 0 ' + g.W + ' ' + g.H, width: g.W, height: g.H, role: 'img', tabindex: '0',
      'aria-label': spiderSummary(r, axes), 'data-key': 'spider|chart', 'data-cx': cx.toFixed(2), 'data-cy': cy.toFixed(2), 'data-r': R.toFixed(2),
    },
      svgEl('g', {}, ...axes.map((a, i) => svgEl('path', { class: 'sp-band', d: band(i), 'data-i': i }))),
      svgEl('g', {}, ...axes.map((a, i) => { const [x, y] = xy(i, 3); return svgEl('line', { class: 'sp-spoke', x1: f(cx), y1: f(cy), x2: f(x), y2: f(y), 'data-i': i }); })),
      svgEl('g', {}, ...LEVELS.map(l => svgEl('polygon', { class: 'sp-ring l' + l.n, points: points(axes.map(() => l.n)) }))),
      svgEl('polygon', { class: 'sp-area', points: points(axes.map(a => a.sum / a.n)) }),
      svgEl('g', {}, ...axes.map((a, i) => {
        const [x, y] = xy(i, a.sum / a.n);
        return svgEl('circle', { class: 'sp-dot l' + levelReached(a), cx: f(x), cy: f(y), r: 4, 'data-i': i });
      })),
      // on top of the data, with a halo, so a polygon lying on a ring never hides its number
      svgEl('g', {}, ...LEVELS.map(l => svgEl('text', {
        class: 'sp-ringnum', x: f(cx + (R * l.n / 3) * sideMid * Math.cos(ringAt)), y: f(cy + (R * l.n / 3) * sideMid * Math.sin(ringAt)),
        'text-anchor': 'middle', 'dominant-baseline': 'central',
      }, String(l.n)))),
      svgEl('g', { style: 'font-size:' + g.px + 'px' }, ...axes.map((a, i) => {
        const L = g.labels[i], b = g.boxes[i];
        return svgEl('text', { class: 'sp-label', 'text-anchor': b.anchor, 'dominant-baseline': 'central', 'data-i': i, 'data-tactic': a.tactic.shortname },
          ...L.lines.map((line, k) => svgEl('tspan', { x: f(cx + b.x), y: f(cy + b.top + (k + 0.5) * g.lh) }, line)));
      })),
      // hover targets: the slice around each axis, then each label's own box (a label set to one side of its axis can
      // reach into the next slice)
      svgEl('g', {}, ...axes.map((a, i) => svgEl('path', { class: 'sp-hit', d: slice(i, reach), 'data-i': i })),
        ...g.boxes.map((b, i) => svgEl('rect', { class: 'sp-hit', x: f(cx + b.left - 2), y: f(cy + b.top - 2), width: f(b.right - b.left + 4), height: f(b.bottom - b.top + 4), 'data-i': i }))),
    );
    if (g.short) svg.dataset.short = '1';
    const live = el('span', { class: 'vh', 'aria-live': 'polite' });
    const dot = i => svg.querySelector('.sp-dot[data-i="' + i + '"]');
    const dir = i => [Math.cos(angle(i)), Math.sin(angle(i))];
    // the rings' box on screen, out to the edge of an enlarged dot on the outer ring: the tooltip keeps off it
    const plotBox = () => {
      const s = svg.getBoundingClientRect(), k = s.width / g.W, m = R + 8;
      return { left: s.left + (cx - m) * k, right: s.left + (cx + m) * k, top: s.top + (cy - m) * k, bottom: s.top + (cy + m) * k };
    };
    let place = null;   // where the tooltip went (spiderTip): kept while it follows a scroll, if it still fits there
    // sp.by: what opened the tactic shown, 'pointer' (a hover or a tap) or 'key' (focus, the arrow keys); null: none
    const clear = () => {   // runs on every scroll: touches only what is highlighted
      for (const m of svg.querySelectorAll('.on')) m.classList.remove('on');
      for (const d of svg.querySelectorAll('.sp-dot[r="6"]')) d.setAttribute('r', '4');
      sp.by = null;
      hideTip();
    };
    const show = (i, by, announce) => {
      clear();
      sp.at = i;
      sp.by = by;
      for (const m of svg.querySelectorAll('[data-i="' + i + '"]')) m.classList.add('on');
      dot(i).setAttribute('r', '6');
      place = spiderTip(dot(i), axes[i], dir(i), plotBox());
      if (announce) live.textContent = spiderAxisText(axes[i]);
    };
    // A scroll (including the one that brings the chart into view when Tab reaches it) moves the chart under the
    // fixed tooltip. One the keyboard opened stays with its dot while the chart has focus (hidden while the dot is out
    // of view); onScroll closes any other, with its highlight. Returns whether it kept the tooltip.
    let frame = 0;
    const follow = () => {
      if (sp.by !== 'key' || document.activeElement !== svg) return false;
      if (!frame) frame = requestAnimationFrame(() => {
        frame = 0;
        if (sp.by !== 'key' || document.activeElement !== svg) return;
        const b = dot(sp.at).getBoundingClientRect();
        if (b.bottom < 0 || b.top > innerHeight) hideTip(); else place = spiderTip(dot(sp.at), axes[sp.at], dir(sp.at), plotBox(), place);
      });
      return true;
    };
    svg.addEventListener('pointerover', e => { const h = e.target.closest('.sp-hit'); if (h) show(Number(h.dataset.i), 'pointer'); });
    // a finger leaves as soon as it lifts: on touch the tooltip stays until the next tap elsewhere (or a scroll)
    svg.addEventListener('pointerleave', e => { if (e.pointerType !== 'touch') clear(); });
    // a click or a tap focuses the chart too, after the pointer has shown its tactic: that focus changes nothing
    let downAt = -Infinity;
    svg.addEventListener('pointerdown', () => { downAt = performance.now(); });
    svg.addEventListener('pointercancel', () => { downAt = -Infinity; });
    // keyboard: the chart is one Tab stop; the arrow keys move from tactic to tactic
    svg.addEventListener('focus', () => { if (performance.now() - downAt > 1000) show(sp.at, 'key'); });
    svg.addEventListener('blur', () => { live.textContent = ''; clear(); });
    svg.addEventListener('keydown', e => {
      if (e.key === 'Escape') { clear(); return; }
      const j = { ArrowRight: sp.at + 1, ArrowDown: sp.at + 1, ArrowLeft: sp.at - 1, ArrowUp: sp.at - 1, Home: 0, End: n - 1 }[e.key];
      if (j == null) return;
      e.preventDefault();
      show((j + n) % n, 'key', true);
    });
    host.replaceChildren(svg, live);
    sp.svg = svg;
    sp.clear = clear;
    sp.follow = follow;
    if (hadFocus) {   // redrawn for a new width: the new drawing keeps the focus, and shows a tooltip only if one was open
      svg.focus({ preventScroll: true });
      if (wasBy !== 'key') clear();
    }
  }

  /**
   * The window scrolled: the tooltip (fixed in place) would point at the wrong thing. Close it, and the chart's
   * highlight with it, unless it is the one the keyboard opened on the focused chart: that one follows the chart.
   */
  function onScroll() {
    if (spider && spider.follow && spider.follow()) return;
    if (spider && spider.clear) spider.clear(); else hideTip();
  }

  /** Distinct controls over all results; null (no count shown) when no result has the mapping. */
  const mappingTotal = key => {
    const ok = state.results.filter(r => r[key]);
    return ok.length ? new Set(ok.flatMap(r => [...r[key].controls.keys()])).size : null;
  };
  // Labels must not contain Matrix, Techniques, Mitigations or Detections (tests click tabs by text), and the
  // row must stay one line at 1280px: the 800-53 tab uses a short label with the full name as its title
  // ("NIST" is read out but not shown). A label is text or a function returning nodes (rebuilt each render).
  const TABS = [
    { key: 'matrix', label: 'Matrix' },
    { key: 'techniques', label: 'Techniques', count: r => r.techniques.size },
    { key: 'mitigations', label: 'Mitigations', count: r => r.mitigations.size },
    { key: 'detections', label: 'Detections', count: r => r.detections.size },
    { key: 'nist', label: () => [el('span', { class: 'vh', text: 'NIST ' }), '800-53'], title: 'NIST SP 800-53 Rev 5 controls mapped to the profile techniques (CTID Mappings Explorer)', total: () => mappingTotal('nist') },
    { key: 'telemetry', label: 'Telemetry', count: r => r.dataComponents.size },
    { key: 'assets', label: 'ICS assets', count: r => r.assets.size },
  ];

  function renderTabs() {
    const tabs = TABS.filter(t => t.key !== 'assets' || state.results.some(r => r.assets.size));
    if (!tabs.some(t => t.key === state.ui.tab)) state.ui.tab = 'matrix';
    // the row is rebuilt below: keep keyboard focus on the tab that was used
    const active = document.activeElement;
    const focused = active && active.closest && active.closest('#tabs') ? active.dataset.tab : null;
    const select = key => { state.ui.tab = key; state.ui.filter = ''; persist(); renderTabs(); renderTab(); };
    const host = $('#tabs');
    host.replaceChildren(...tabs.map((t, i) => {
      const n = t.total ? t.total() : t.count ? state.results.reduce((s, r) => s + t.count(r), 0) : null;
      const on = state.ui.tab === t.key;
      return el('button', {
        role: 'tab', 'aria-selected': String(on), tabindex: on ? '0' : '-1', title: t.title || null, data: { tab: t.key },
        'aria-controls': 'tabBody', id: 'tab-' + t.key,
        on: {
          click: () => select(t.key),
          // arrow keys move between tabs (the selected tab is the only one in the Tab order)
          keydown: e => {
            const j = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
            if (j == null) return;
            e.preventDefault();
            select(tabs[(j + tabs.length) % tabs.length].key);
            const b = host.querySelector('[data-tab="' + state.ui.tab + '"]');
            if (b) b.focus();
          },
        },
      }, typeof t.label === 'function' ? t.label() : t.label, n != null ? el('span', { class: 'count', text: ' ' + fmtN(n) }) : null);
    }));
    if (focused) { const b = host.querySelector('[data-tab="' + focused + '"]'); if (b) b.focus(); }
    // a row too wide for its column scrolls sideways (wide screens only): keep the selected tab in view
    const sel = host.querySelector('[aria-selected="true"]');
    if (sel && host.scrollWidth > host.clientWidth + 1) {
      const hr = host.getBoundingClientRect(), br = sel.getBoundingClientRect();
      if (br.left < hr.left) host.scrollLeft += br.left - hr.left;
      else if (br.right > hr.right) host.scrollLeft += br.right - hr.right;
    }
    $('#tabBody').setAttribute('aria-labelledby', 'tab-' + state.ui.tab);
  }

  function renderTab() {
    hideTip();
    const tools = $('#tabTools');
    const body = $('#tabBody');
    // a sort button, an in-place switch or a tool rebuilds the tab: put focus back on the control that replaced it
    const active = document.activeElement;
    const place = active && (tools.contains(active) || body.contains(active)) ? placeOf(active) : null;
    tools.replaceChildren();
    body.replaceChildren();
    ({ matrix: renderMatrix, techniques: renderTechniques, mitigations: renderMitigations, detections: renderDetections,
       nist: renderNist, telemetry: renderTelemetry, assets: renderAssets })[state.ui.tab](tools, body);
    if (place && (!document.activeElement || document.activeElement === document.body)) focusQuiet(findPlace(place));
  }

  function filterBox(placeholder, rerender, delay = 0) {
    const i = el('input', { type: 'search', placeholder, value: state.ui.filter });
    const tab = state.ui.tab;
    let timer = null;
    i.addEventListener('input', () => {
      state.ui.filter = i.value;
      if (!delay) { rerender(); return; }
      clearTimeout(timer);
      timer = setTimeout(() => { if (state.ui.tab === tab && i.isConnected) rerender(); }, delay);
    });
    return i;
  }

  function domainSwitch() {
    if (state.results.length < 2) return null;
    return el('div', { class: 'seg' }, ...state.results.map(r => el('button', {
      'aria-pressed': String(state.ui.matrixDomain === r.domain), text: domainLabel(r.domain),
      on: { click: () => { state.ui.matrixDomain = r.domain; persist(); renderTab(); } },
    })));
  }

  // ---------- matrix ----------

  function usageStep(count, max) {
    if (max <= 1) return 4;
    return 1 + Math.round(((count - 1) / (max - 1)) * 5);
  }

  function renderMatrix(tools, body) {
    const r = state.results.find(x => x.domain === state.ui.matrixDomain) || state.results[0];
    const mode = state.ui.colorMode;
    const showAll = el('input', { type: 'checkbox', checked: state.ui.showAll });
    showAll.addEventListener('change', () => { state.ui.showAll = showAll.checked; persist(); renderTab(); });

    let max = 1;
    for (const t of r.techniques.values()) max = Math.max(max, t.roots.size);

    append(tools, [
      domainSwitch(),
      el('div', { class: 'seg' }, ...[['usage', 'Usage'], ['coverage', 'Coverage']].map(([k, label]) => el('button', {
        'aria-pressed': String(mode === k), text: label,
        on: { click: () => { state.ui.colorMode = k; persist(); renderTab(); } },
      }))),
      el('label', { class: 'toggle' }, showAll, 'Show all techniques'),
      mode === 'usage'
        ? (max > 1
          ? el('span', { class: 'scale' }, '1', el('span', { class: 'ramp' }, ...[1, 2, 3, 4, 5, 6].map(i => el('span', { style: `background:var(--seq-${i})` }))), max + ' ' + whoPlural(r.domain))
          : el('span', { class: 'hint', text: 'Shade shows how many selected ' + whoPlural(r.domain) + ' use a technique.' }))
        : el('span', { class: 'legend' }, ...Object.entries(STATUS).map(([k, s]) => el('span', { class: 'stat-badge' }, el('span', { class: 'ic ' + k, text: s.icon }), s.label))),
    ]);

    const cols = SimEngine.matrixColumns(r, { showAll: state.ui.showAll });
    const cell = (tech, used, isSub) => {
      const cls = ['cell'];
      if (isSub) cls.push('sub');
      if (used) {
        cls.push('used');
        cls.push(mode === 'usage' ? 'u' + usageStep(used.roots.size, max) : 's-' + used.status);
      }
      return el('button', { class: cls.join(' '), data: { tech: tech.id, key: 'cell|' + r.domain + '|' + tech.id } },
        used && mode === 'coverage' ? el('span', { class: 'st', 'aria-label': STATUS[used.status].label, text: STATUS[used.status].icon }) : null,
        tech.name,
        el('span', { class: 'id', text: tech.attackId }),
        used && mode === 'usage' && max > 1 ? el('span', { class: 'badge', text: used.roots.size }) : null,
      );
    };

    const grid = el('div', { class: 'matrix' }, ...cols.map(c => el('div', { class: 'mcol' },
      el('h3', {}, c.tactic.name, el('span', { class: 'n', text: c.usedCount + ' technique' + (c.usedCount === 1 ? '' : 's') })),
      ...c.rows.map(row => el('div', { class: 'mgroup' },
        cell(row.tech, row.used, false),
        ...row.subs.map(s => cell(s.tech, s.used, true)))),
    )));

    grid.addEventListener('click', e => {
      const b = e.target.closest('.cell');
      if (b) openDrawer(() => techniqueDrawer(r.domain, b.dataset.tech));
    });
    grid.addEventListener('mouseover', e => {
      const b = e.target.closest('.cell');
      if (b) showTip(b, r, b.dataset.tech); else hideTip();
    });
    grid.addEventListener('mouseleave', hideTip);
    grid.addEventListener('focusin', e => { const b = e.target.closest('.cell'); if (b) showTip(b, r, b.dataset.tech); });
    grid.addEventListener('focusout', hideTip);

    body.append(el('div', { class: 'matrix-scroll' }, grid));
  }

  function rootNames(t, limit = 4) {
    const names = [...t.roots].map(id => (entity(id) || {}).name).filter(Boolean).sort();
    return names.length > limit ? names.slice(0, limit).join(', ') + ' +' + (names.length - limit) : names.join(', ');
  }

  function showTip(anchor, r, techId) {
    const tech = r.model.byId.get(techId);
    const t = r.techniques.get(techId);
    const tip = $('#tip');
    const mitN = r.model.to(techId, 'mitigates').length;
    const detN = r.model.to(techId, 'detects').length;
    tip.replaceChildren(
      el('b', { text: tech.attackId + ' ' + tech.name }),
      t ? el('div', { class: 'row', text: 'Used by ' + t.roots.size + ': ' + rootNames(t) }) : el('div', { class: 'row', text: 'Not used by this profile' }),
      el('div', { class: 'row', text: mitN + ' mitigations · ' + detN + ' detection strategies' }),
      mappingTipRow(r, techId),
      t ? el('div', { class: 'row', text: 'Coverage: ' + STATUS[t.status].label }) : null,
    );
    delete tip.dataset.of;   // a matrix cell's, not the coverage chart's
    tip.hidden = false;
    const a = anchor.getBoundingClientRect();
    const w = tip.offsetWidth, h = tip.offsetHeight;
    let x = a.right + 8, y = a.top;
    if (x + w > innerWidth - 8) x = Math.max(8, a.left - w - 8);
    if (y + h > innerHeight - 8) y = innerHeight - h - 8;
    tip.style.left = x + 'px';
    tip.style.top = Math.max(8, y) + 'px';
  }
  function hideTip() { const tip = $('#tip'); tip.hidden = true; delete tip.dataset.of; }

  /** "NIST 800-53: 12 controls" for a matrix cell, from the index (used or not). */
  function mappingTipRow(r, techId) {
    const st = r.mappingStatus || {};
    const parts = [];
    if (st.nist === 'ok') parts.push('NIST 800-53: ' + plural(SimEngine.controlsFor(r.nist.index, r.model, techId).length, 'control', 'controls'));
    return parts.length ? el('div', { class: 'row', text: parts.join(' · ') }) : null;
  }

  // ---------- tables ----------

  /** A row's key for focus restoring: the table, the result's domain and the row's object (a control, technique …). */
  const defaultRowKey = row => (row.r ? row.r.domain : '') + '|' + (row.id != null ? row.id : row.t ? row.t.tech.id : '');

  /**
   * cols: [{key, label, title, num, sort:(row)=>v, render:(row)=>node|string}]
   * opts: {id, defaultSort:{key,dir}, onRow:(row)=>void, rowClass:(row)=>string, rowKey:(row)=>string,
   *        empty: text for a table with no rows (default: "Nothing matches." with a filter typed, else "None in this profile.")}
   * Sortable headers hold a button (keyboard: Tab to it, Enter or Space sorts); each row carries data-row so the
   * control that had focus can be found again after a re-render (see placeOf).
   */
  function table(rows, cols, opts) {
    const s = state.ui.sort[opts.id] || opts.defaultSort;
    const col = cols.find(c => c.key === s.key && c.sort) || cols.find(c => c.sort);
    if (col) {
      const dir = s.dir === 'asc' ? 1 : -1;
      rows = [...rows].sort((a, b) => {
        const x = col.sort(a), y = col.sort(b);
        if (x === y) return 0;
        if (x == null) return 1;
        if (y == null) return -1;
        return (typeof x === 'string' ? idCmp(x, y) : x - y) * dir;
      });
    }
    const head = el('tr', {}, ...cols.map(c => {
      const sorted = col && c.key === col.key;
      // the click handler sits on the cell (a click anywhere in it sorts); the button gives it a Tab stop and Enter/Space
      return el('th', {
        class: (c.num ? 'num ' : '') + (c.sort ? 'sortable' : ''), title: c.title || null,
        'aria-sort': sorted ? (s.dir === 'asc' ? 'ascending' : 'descending') : null,
        on: c.sort ? { click: () => {
          const cur = state.ui.sort[opts.id] || opts.defaultSort;
          state.ui.sort[opts.id] = { key: c.key, dir: cur.key === c.key && cur.dir === 'desc' ? 'asc' : (cur.key === c.key ? 'desc' : (c.num ? 'desc' : 'asc')) };
          renderTab();
        } } : null,
      }, c.sort ? el('button', { type: 'button', class: 'sortbtn', data: { key: 'sort|' + opts.id + '|' + c.key } }, c.label) : c.label);
    }));
    const rowKey = opts.rowKey || defaultRowKey;
    const body = el('tbody', {}, ...rows.map(row => el('tr', {
      class: ((opts.onRow ? 'click ' : '') + (opts.rowClass ? opts.rowClass(row) : '')).trim() || null,
      data: { row: opts.id + '|' + rowKey(row) },
      on: opts.onRow ? { click: e => { if (!e.target.closest('input,a,button,label')) opts.onRow(row); } } : null,
    }, ...cols.map(c => el('td', { class: c.num ? 'num' : null }, c.render(row))))));
    if (!rows.length) {
      const empty = opts.empty || (state.ui.filter.trim() ? 'Nothing matches.' : 'None in this profile.');
      body.append(el('tr', {}, el('td', { colspan: cols.length, class: 'empty', text: empty })));
    }
    return el('div', { class: 'card table-scroll', style: 'padding:4px 8px' }, el('table', { class: 'data' }, el('thead', {}, head), body));
  }

  const meter = (n, total) => el('div', { class: 'meter' },
    el('div', { class: 'track' }, el('div', { class: 'fill', style: `width:${total ? (n / total) * 100 : 0}%` })),
    el('span', { class: 'v', text: n + ' / ' + total }));

  const statusBadge = st => el('span', { class: 'stat-badge' }, el('span', { class: 'ic ' + st, text: STATUS[st].icon }), STATUS[st].label);

  const idLink = o => o.url ? el('a', { href: o.url, target: '_blank', rel: 'noopener', class: 'mono', text: o.attackId }) : el('span', { class: 'mono', text: o.attackId || '—' });

  const matches = (o, extra = '') => {
    const q = state.ui.filter.trim().toLowerCase();
    return !q || [o.attackId, o.name, extra].join(' ').toLowerCase().includes(q);
  };

  function tacticNames(model, tech) {
    const byShort = new Map(model.tactics.map(t => [t.shortname, t.name]));
    return (tech.tactics || []).map(s => byShort.get(s) || s);
  }

  function renderTechniques(tools, body) {
    tools.append(filterBox('Filter techniques', () => renderTabBody(renderTechniques)));
    const multi = state.results.length > 1;
    const rows = [];
    for (const r of state.results) for (const t of r.techniques.values()) {
      if (matches(t.tech, tacticNames(r.model, t.tech).join(' '))) rows.push({ r, t });
    }
    const order = { gap: 0, mitigated: 1, detected: 2, covered: 3 };
    body.append(table(rows, [
      multi && { key: 'domain', label: 'Domain', sort: x => domainLabel(x.r.domain), render: x => domainLabel(x.r.domain) },
      { key: 'id', label: 'ID', sort: x => x.t.tech.attackId, render: x => idLink(x.t.tech) },
      { key: 'name', label: 'Technique', sort: x => x.t.tech.name, render: x => x.t.tech.name },
      { key: 'tactics', label: 'Tactics', render: x => el('div', { class: 'tags' }, tacticNames(x.r.model, x.t.tech).map(n => el('span', { class: 'tag', text: n }))) },
      { key: 'roots', label: 'Used by', num: true, sort: x => x.t.roots.size, render: x => el('span', { title: rootNames(x.t, 50) }, String(x.t.roots.size), el('div', { class: 'small', text: rootNames(x.t, 3) })) },
      { key: 'mit', label: 'Mitigations', num: true, sort: x => x.t.mitigations.length, render: x => String(x.t.mitigations.length) },
      { key: 'det', label: 'Detections', num: true, sort: x => x.t.detections.length, render: x => String(x.t.detections.length) },
      { key: 'status', label: 'Coverage', sort: x => order[x.t.status], render: x => statusBadge(x.t.status) },
    ].filter(Boolean), {
      id: 'techniques', defaultSort: { key: 'roots', dir: 'desc' },
      onRow: x => openDrawer(() => techniqueDrawer(x.r.domain, x.t.tech.id)),
    }));
  }

  function renderTabBody(fn) {
    // re-render only the body (keeps focus in the filter box)
    const body = $('#tabBody');
    body.replaceChildren();
    fn(document.createElement('div'), body);
  }

  function postureTools(tools, kind, label, rerender) {
    const setKey = kind === 'mitigations' ? 'mitigations' : 'detections';
    const priKey = kind === 'mitigations' ? 'mitPriority' : 'detPriority';
    const applyTop = n => {
      for (const r of state.results) {
        for (const [id, p] of r[priKey]) if (p.rank != null && p.rank <= n) state.inPlace[setKey].add(r.domain + '|' + id);
      }
      update({ picker: false });
    };
    const reset = () => {
      for (const r of state.results) for (const id of r[kind].keys()) state.inPlace[setKey].delete(r.domain + '|' + id);
      update({ picker: false });
    };
    tools.append(
      filterBox('Filter ' + kind, rerender),
      el('button', { text: 'Mark top 5 ' + label, title: 'Simulate adding the five highest-priority items', on: { click: () => applyTop(5) } }),
      el('button', { text: 'Reset', title: 'Clear ' + label + ' for this profile', on: { click: reset } }),
      el('span', { class: 'hint', text: 'Priority: pick the item covering the most uncovered techniques, weighting techniques used by more selected '
        + (state.results.some(r => familyOf(r.domain) === 'atlas') ? 'threats' : 'adversaries') + ' higher, then repeat. Equal scores share a number.' }),
    );
  }

  function toggleInPlace(setKey, domain, id, on) {
    const k = domain + '|' + id;
    on ? state.inPlace[setKey].add(k) : state.inPlace[setKey].delete(k);
    update({ picker: false });
  }

  function priorityCols(setKey, priKey, checkLabel) {
    return [
      { key: 'pri', label: 'Priority', num: true,
        sort: x => { const p = x.r[priKey].get(x.id); return p.rank == null ? (x.on ? -1 : 9999 - x.e.techniques.size / 1000) : p.rank; },
        render: x => { const p = x.r[priKey].get(x.id); return x.on ? el('span', { class: 'small', text: 'in place' }) : p.rank == null ? el('span', { class: 'muted', text: '—' }) : '#' + p.tier; } },
      { key: 'on', label: checkLabel, render: x => {
        const cb = el('input', { type: 'checkbox', checked: x.on, 'aria-label': checkLabel + ': ' + x.e.obj.name });
        cb.addEventListener('change', () => toggleInPlace(setKey, x.r.domain, x.id, cb.checked));
        return cb;
      } },
      { key: 'id', label: 'ID', sort: x => x.e.obj.attackId, render: x => idLink(x.e.obj) },
    ];
  }

  function controlRows(r, mapKey, setKey) {
    return [...r[mapKey]].map(([id, e]) => ({ r, id, e, on: state.inPlace[setKey].has(r.domain + '|' + id) }))
      .filter(x => matches(x.e.obj));
  }

  function perDomain(body, fn) {
    const multi = state.results.length > 1;
    for (const r of state.results) {
      if (multi) body.append(el('h3', { class: 'domain-h', text: domainLabel(r.domain) + ' · ' + r.techniques.size + ' techniques' }));
      fn(r);
    }
  }

  /** ATLAS has no detection strategies or telemetry: say so instead of showing an empty table. */
  const noDetections = r => familyOf(r.domain) === 'atlas'
    ? el('p', { class: 'hint', text: 'ATLAS has no detection strategies. Its detection controls, such as AML.M0024 AI Telemetry Logging and Monitoring, '
      + 'are ATLAS mitigations, so its ' + plural(r.techniques.size, 'technique', 'techniques') + ' are covered on the Mitigations tab.' })
    : null;

  function renderMitigations(tools, body) {
    postureTools(tools, 'mitigations', 'in place', () => renderTabBody(renderMitigations));
    perDomain(body, r => {
      body.append(table(controlRows(r, 'mitigations', 'mitigations'), [
        ...priorityCols('mitigations', 'mitPriority', 'In place'),
        { key: 'name', label: 'Mitigation', sort: x => x.e.obj.name, render: x => x.e.obj.name },
        { key: 'covers', label: 'Techniques covered', num: true, sort: x => x.e.techniques.size, render: x => meter(x.e.techniques.size, r.techniques.size) },
        { key: 'adds', label: 'Adds', num: true, sort: x => x.r.mitPriority.get(x.id).adds, render: x => x.on ? '' : '+' + x.r.mitPriority.get(x.id).adds },
        { key: 'cum', label: 'Cumulative', num: true, sort: x => x.r.mitPriority.get(x.id).cumulative, render: x => pct(x.r.mitPriority.get(x.id).cumulative, 1) },
      ], {
        id: 'mitigations', defaultSort: { key: 'pri', dir: 'asc' },
        rowClass: x => x.on ? 'inplace' : '',
        onRow: x => openDrawer(() => mitigationDrawer(x.r.domain, x.id)),
      }));
      const none = [...r.techniques.values()].filter(t => !t.mitigations.length).length;
      if (none) body.append(el('p', { class: 'hint', text: none + ' technique' + (none === 1 ? ' has' : 's have') + ' no ' + familyName(r.domain) + ' mitigation'
        + (familyOf(r.domain) === 'atlas' ? '.' : ' (common for pre-compromise techniques). Detection is the only lever for those.') }));
    });
  }

  function renderDetections(tools, body) {
    postureTools(tools, 'detections', 'deployed', () => renderTabBody(renderDetections));
    perDomain(body, r => {
      if (noDetections(r)) { body.append(noDetections(r)); return; }
      body.append(table(controlRows(r, 'detections', 'detections'), [
        ...priorityCols('detections', 'detPriority', 'Deployed'),
        { key: 'name', label: 'Detection strategy', sort: x => x.e.obj.name, render: x => x.e.obj.name },
        { key: 'covers', label: 'Techniques covered', num: true, sort: x => x.e.techniques.size, render: x => meter(x.e.techniques.size, r.techniques.size) },
        { key: 'adds', label: 'Adds', num: true, sort: x => x.r.detPriority.get(x.id).adds, render: x => x.on ? '' : '+' + x.r.detPriority.get(x.id).adds },
        { key: 'cum', label: 'Cumulative', num: true, sort: x => x.r.detPriority.get(x.id).cumulative, render: x => pct(x.r.detPriority.get(x.id).cumulative, 1) },
        { key: 'an', label: 'Analytics', num: true, sort: x => x.e.analytics.length, render: x => String(x.e.analytics.length) },
        { key: 'dc', label: 'Data components', render: x => {
          const names = [...x.e.dataComponents].map(id => (r.model.byId.get(id) || entity(id) || {}).name).filter(Boolean).sort();
          return el('div', { class: 'tags' }, names.slice(0, 3).map(n => el('span', { class: 'tag', text: n })),
            names.length > 3 ? el('span', { class: 'tag', title: names.slice(3).join(', '), text: '+' + (names.length - 3) }) : null);
        } },
      ], {
        id: 'detections', defaultSort: { key: 'pri', dir: 'asc' },
        rowClass: x => x.on ? 'inplace' : '',
        onRow: x => openDrawer(() => detectionDrawer(x.r.domain, x.id)),
      }));
    });
  }

  function renderTelemetry(tools, body) {
    const unresolved = new Set(state.results.flatMap(r => [...r.unresolvedDataComponents]));
    tools.append(filterBox('Filter data components or log sources', () => renderTabBody(renderTelemetry)),
      el('span', { class: 'hint', text: 'The logs your detections need, ranked by how many profile techniques they help detect.' + (unresolved.size
        ? ` ${plural(unresolved.size, 'data component used by these analytics is', 'data components used by these analytics are')} not in the loaded ATT&CK data; pull Enterprise ATT&CK on the Data page to list them.`
        : '') }));
    perDomain(body, r => {
      if (noDetections(r)) { body.append(noDetections(r)); return; }
      const rows = [...r.dataComponents].map(([id, e]) => ({ r, id, e }))
        .filter(x => matches(x.e.obj, [...x.e.logSources.keys()].join(' ')));
      body.append(table(rows, [
        { key: 'id', label: 'ID', sort: x => x.e.obj.attackId, render: x => idLink(x.e.obj) },
        { key: 'name', label: 'Data component', sort: x => x.e.obj.name, render: x => x.e.obj.name },
        { key: 'tech', label: 'Techniques', num: true, sort: x => x.e.techniques.size, render: x => meter(x.e.techniques.size, r.techniques.size) },
        { key: 'ds', label: 'Strategies', num: true, sort: x => x.e.strategies.size, render: x => String(x.e.strategies.size) },
        { key: 'ls', label: 'Log sources', render: x => {
          const names = [...x.e.logSources.keys()].sort();
          return el('div', { class: 'tags' }, names.slice(0, 4).map(n => el('span', { class: 'tag mono', text: n })),
            names.length > 4 ? el('span', { class: 'tag', title: names.slice(4).join(', '), text: '+' + (names.length - 4) }) : null);
        } },
      ], { id: 'telemetry', defaultSort: { key: 'tech', dir: 'desc' }, onRow: x => openDrawer(() => dataComponentDrawer(x.r.domain, x.id)) }));
    });
  }

  function renderAssets(tools, body) {
    tools.append(filterBox('Filter assets', () => renderTabBody(renderAssets)),
      el('span', { class: 'hint', text: 'ICS assets targeted by techniques in this profile.' }));
    for (const r of state.results.filter(x => x.assets.size)) {
      const rows = [...r.assets].map(([id, e]) => ({ r, id, e })).filter(x => matches(x.e.obj));
      body.append(table(rows, [
        { key: 'id', label: 'ID', sort: x => x.e.obj.attackId, render: x => idLink(x.e.obj) },
        { key: 'name', label: 'Asset', sort: x => x.e.obj.name, render: x => x.e.obj.name },
        { key: 'tech', label: 'Techniques targeting it', num: true, sort: x => x.e.techniques.size, render: x => meter(x.e.techniques.size, r.techniques.size) },
        { key: 'plat', label: 'Platforms', render: x => el('div', { class: 'tags' }, (x.e.obj.platforms || []).map(p => el('span', { class: 'tag', text: p }))) },
      ], { id: 'assets', defaultSort: { key: 'tech', dir: 'desc' }, onRow: x => openDrawer(() => assetDrawer(x.r.domain, x.id)) }));
    }
  }

  // ---------- NIST 800-53 tab ----------

  const dataPageLink = text => el('a', { href: 'index.html', text });
  /** "16 IDs carried forward to their replacements, 1 not current" for one index. */
  const changedIds = ix => [ix.replaced.length ? plural(ix.replaced.length, 'ID', 'IDs') + ' carried forward to ' + (ix.replaced.length === 1 ? 'its replacement' : 'their replacements') : null,
    ix.unresolved.length ? fmtN(ix.unresolved.length) + ' not current' : null].filter(Boolean).join(', ');
  /** Domains (with their index) for which a result of this profile shows the mapping. */
  const shownIndexes = key => { const src = mappingSource(key); return src ? Object.entries(src.indexes).filter(([d, ix]) => ix.rowCount && state.results.some(r => r.domain === d && r[key])) : []; };
  /** Why a source's rows could not be read on this page load (null when they could, or were never pulled). */
  const mappingError = key => state.mappings.errors[MAP[key].id] || null;
  const withStop = t => (/[.!?]$/.test(t) ? t : t + '.');

  /** Provenance line for the mapping tab: dataset, ATT&CK version it targets, how it was matched to the stored release. */
  function mappingProvenance(key) {
    const shown = shownIndexes(key);
    if (!shown.length) return null;
    const m = mappingSource(key).meta;
    const parts = shown.map(([d, ix]) => { const changes = changedIds(ix); return domainTitle(d) + ' v' + ix.attackVersion + (changes ? ' (' + changes + ')' : ''); });
    return 'CTID mapping of NIST SP 800-53 Rev 5 to ATT&CK ' + (m.attackVersion || '?') + ', matched by ID to ' + parts.join(' and ') + '.';
  }

  /** "The NIST 800-53 mappings are not pulled", or why they could not be read (technique drawer). */
  function notPulledHint(key) {
    const err = mappingError(key);
    if (err) return el('p', { class: 'hint', text: 'The NIST 800-53 mappings could not be read (' + err + '). Reload the page to try again.' });
    return el('p', { class: 'hint' }, 'The NIST 800-53 mappings are not pulled. ', dataPageLink('Pull them on the Data page'), '.');
  }

  /** Why a result has no rows on the mapping tab, as a hint (null when it has the mapping). */
  function mappingNote(key, r) {
    const st = r.mappingStatus ? r.mappingStatus[key] : 'not-pulled';
    const name = 'NIST SP 800-53';
    if (st === 'ok') return null;
    if (st === 'not-this-domain') {
      if (familyOf(r.domain) === 'atlas' || r.domain === 'ics-attack') return el('p', { class: 'hint', text: 'No NIST 800-53 mappings exist for ' + domainTitle(r.domain) + '.' });
      return el('p', { class: 'hint', text: 'CTID maps NIST 800-53 to Enterprise ATT&CK only.' });
    }
    if (st === 'no-attack-data') return el('p', { class: 'hint', text: 'The pulled ' + name + ' mappings (' + mappingSource(key).meta.label + ') have no ' + domainTitle(r.domain) + ' entries.' });
    // reading failed: pulling again is not the remedy, so don't send the user to the Data page
    const err = mappingError(key);
    if (err) return el('p', { class: 'hint', text: 'The ' + name + ' mappings could not be read (' + err + '). Reload the page to try again.' });
    return el('p', { class: 'hint' }, 'The ' + name + ' mappings are not pulled yet. ', dataPageLink('Pull them on the Data page'), ' to see them here.');
  }

  /** The other loaded ATT&CK domain where a technique ID is current ('Mobile ATT&CK' for T1521.003), or null. */
  function currentElsewhere(attackId, domain) {
    for (const [d, m] of Object.entries(state.models)) {
      if (d === domain || !m || familyOf(d) !== 'attack') continue;
      if ((m.byKind.technique || []).some(t => t.attackId === attackId)) return domainTitle(d);
    }
    return null;
  }

  /**
   * IDs of CTID's that changed in the stored ATT&CK release: carried forward, or not current. The list is the
   * mapping file's, for the domains this profile shows the mapping for; the IDs whose carried-forward mappings
   * reach this profile (r.nist.carriedFrom) come first, under their own heading.
   */
  function changedIdsBlock(key) {
    const src = mappingSource(key);
    if (!src) return null;
    const reaching = [], others = [];
    for (const [d, ix] of shownIndexes(key)) {
      const where = domainTitle(d) + ' v' + ix.attackVersion;
      const r = resultFor(d);
      const reach = (r && r[key] && r[key].carriedFrom) || new Set();
      const keyed = (b, id) => { b.dataset.key = 'changed|' + key + '|' + d + '|' + id; return b; };
      for (const x of ix.replaced) (reach.has(x.from) ? reaching : others).push(el('li', {}, el('span', { class: 'mono', text: x.from }), ' ' + x.fromName + ': revoked; its replacement in ' + where + ' is ',
        keyed(techButton(d, state.models[d].byId.get(x.toId)), x.from), ' (' + plural(x.rows, 'mapping', 'mappings') + ' carried forward)'));
      for (const x of ix.unresolved) {
        const other = x.reason.startsWith('not in ') ? currentElsewhere(x.techniqueId, d) : null;
        others.push(el('li', {}, el('span', { class: 'mono', text: x.techniqueId }), ' ' + x.techniqueName + ': ' + x.reason
          + ' (' + (other ? 'a ' + other + ' technique; ' : '') + plural(x.rows, 'mapping', 'mappings') + ' not shown)'));
      }
    }
    const n = reaching.length + others.length;
    if (!n) return null;
    const reachText = reaching.length ? fmtN(reaching.length) + (reaching.length === 1 ? ' reaches' : ' reach') : 'none reaches';
    return el('details', { class: 'mapnote' },
      el('summary', { text: 'Technique IDs from ATT&CK ' + src.meta.attackVersion + ' that changed (' + fmtN(n) + ' in CTID\'s mapping; ' + reachText + ' this profile)' }),
      reaching.length ? [el('div', { class: 'kicker', text: 'Reaching this profile' }), el('ul', { class: 'refs' }, ...reaching)] : null,
      others.length ? [reaching.length ? el('div', { class: 'kicker', text: 'Not reaching this profile' }) : null, el('ul', { class: 'refs' }, ...others)] : null);
  }

  /** A short tag list of technique IDs (first n, then +N with the rest in the title). */
  function techTags(r, techIds, n = 4) {
    const techs = [...techIds].map(id => r.model.byId.get(id)).filter(Boolean).sort(byAttackId);
    return el('div', { class: 'tags' }, techs.slice(0, n).map(t => el('span', { class: 'tag mono', title: t.name, text: t.attackId })),
      techs.length > n ? el('span', { class: 'tag', title: techs.slice(n).map(t => t.attackId + ' ' + t.name).join(', '), text: '+' + (techs.length - n) }) : null);
  }

  /** Top related ATT&CK mitigations by overlap, as tags. */
  function mitigationTags(r, mits, n = 3) {
    const list = [...mits].map(([id, k]) => [r.model.byId.get(id), k]).filter(([m]) => m);
    return el('div', { class: 'tags' }, list.slice(0, n).map(([m, k]) => el('span', { class: 'tag', title: m.name + ': shares ' + plural(k, 'profile technique', 'profile techniques'), text: m.attackId + ' · ' + k })),
      list.length > n ? el('span', { class: 'tag', title: list.slice(n).map(([m, k]) => m.attackId + ' ' + m.name + ' (' + k + ')').join(', '), text: '+' + (list.length - n) }) : null);
  }
  const RELATED_NOTE = 'Worked out by ThreatSim from the profile techniques they share; not part of CTID\'s mapping.';

  function renderNist(tools, body) {
    // the box filters the control table only: offer it when some result has a control to list
    if (state.results.some(r => r.nist && r.nist.controls.size)) tools.append(filterBox('Filter controls or technique IDs', () => renderTabBody(renderNist), 150));
    const prov = mappingProvenance('nist');
    if (prov) tools.append(el('span', { class: 'hint', text: prov }));
    perDomain(body, r => {
      const note = mappingNote('nist', r);
      if (note) { body.append(note); return; }
      const n = r.nist;
      const total = r.techniques.size;
      const none = [...n.uncovered].map(id => r.model.byId.get(id)).sort(byAttackId);
      // techniques that count only through ThreatSim's via-parent rule: CTID maps no control to them directly
      const vp = n.viaParentOnly ? n.viaParentOnly.size : 0, cov = n.covered.size;
      const viaText = !vp ? '' : ' ' + (vp === cov ? (cov === 1 ? 'That technique counts' : 'All ' + fmtN(cov) + ' count') : 'Of the ' + fmtN(cov) + ' with a control, ' + fmtN(vp) + (vp === 1 ? ' counts' : ' count'))
        + ' only because ThreatSim gives a sub-technique the controls CTID mapped to its parent; CTID maps none to ' + (vp === 1 ? 'it' : 'them') + ' directly.';
      // why the others have none: CTID judged them not mappable, or its mapping has no row for them at all
      // (some added to ATT&CK after the release CTID mapped), as the workbook says
      const version = ctidAttackVersion('nist');
      const judged = none.filter(t => n.nonMappable.has(t.id)).length, absent = none.length - judged;
      const late = none.filter(t => !n.nonMappable.has(t.id) && SimEngine.addedAfterRelease(t, version)).length;
      const why = !none.length ? '' : judged === none.length ? ': CTID judged ' + (judged === 1 ? 'it' : 'them all') + ' not mappable to 800-53'
        : ': ' + (judged ? 'CTID judged ' + fmtN(judged) + ' not mappable to 800-53, and ' + fmtN(absent) + (absent === 1 ? ' is not' : ' are not')
          : absent === 1 ? 'it is not' : 'none of them is') + ' in CTID\'s mapping at all'
          + (late ? ' (' + (late === absent && absent > 1 ? 'all' : fmtN(late)) + ' added to ATT&CK after ' + version + ', the release CTID mapped)' : '');
      body.append(el('p', { class: 'hint map-cover', data: { covered: cov, total, none: none.length, nonMappable: n.nonMappable.size, absent, late, viaParent: vp } },
        fmtN(cov) + ' of ' + plural(total, 'profile technique has', 'profile techniques have') + ' at least one control'
        + (none.length ? '; ' + fmtN(none.length) + ' ' + (none.length === 1 ? 'has' : 'have') + ' none' : '') + why + '.' + viaText));
      if (none.length) {
        body.append(el('details', { class: 'mapnote' }, el('summary', { text: 'Profile techniques with no 800-53 control (' + none.length + ')' }),
          el('div', { class: 'tags', style: 'margin-top:6px' }, none.map(t => el('button', {
            class: 'tag tagbtn mono' + (n.nonMappable.has(t.id) ? ' nomap' : ''), text: t.attackId, data: { key: 'nocontrol|' + r.domain + '|' + t.id },
            title: t.name + (n.nonMappable.has(t.id) ? ' (CTID: not mappable' + (n.index.nonMappable.get(t.id) ? ': ' + n.index.nonMappable.get(t.id) : '') + ')' : ''),
            on: { click: () => openDrawer(() => techniqueDrawer(r.domain, t.id)) },
          })))));
      }
      const rows = [...n.controls].map(([id, c]) => ({ r, id, c, gaps: [...c.techniques].filter(t => r.techniques.get(t).status === 'gap').length }))
        .filter(x => matches(x.c.obj, [x.c.obj.family, x.c.obj.familyName, ...[...x.c.techniques].map(t => r.model.byId.get(t).attackId)].join(' ')));
      // no control at all for this profile: the sentence above says so (an empty table would read as "filtered out")
      if (!n.controls.size) return;
      const open = x => openDrawer(() => controlDrawer(x.r.domain, x.id));
      body.append(table(rows, [
        { key: 'id', label: 'Control', sort: x => x.id, render: x => el('button', { class: 'linkish mono', text: x.id, title: 'Open ' + x.id, on: { click: () => open(x) } }) },
        { key: 'name', label: 'Name', sort: x => x.c.obj.name, render: x => x.c.obj.name },
        { key: 'family', label: 'Family', sort: x => x.c.obj.familyName, render: x => el('span', { title: x.c.obj.family, text: x.c.obj.familyName }) },
        { key: 'tech', label: 'Profile techniques', num: true, sort: x => x.c.techniques.size, render: x => el('div', { title: x.c.viaParent.size ? x.c.viaParent.size + ' via the parent technique' : null }, meter(x.c.techniques.size, total)) },
        { key: 'gaps', label: 'Gaps it addresses', num: true, sort: x => x.gaps, render: x => String(x.gaps) },
        { key: 'mit', label: 'Related ATT&CK mitigations', title: 'ATT&CK mitigations of this profile that address the same techniques, with how many they share. ' + RELATED_NOTE,
          render: x => mitigationTags(r, x.c.mitigations) },
        { key: 'ids', label: 'Technique IDs', render: x => techTags(r, x.c.techniques) },
      ], { id: 'nist', defaultSort: { key: 'tech', dir: 'desc' }, onRow: open }));
    });
    append(body, [changedIdsBlock('nist')]);
  }

  // ---------- drawer ----------

  let drawerBuilder = null;
  let drawerReturnFocus = null;
  let drawerReturnPlace = null;   // where the opener was, for when a re-render replaced it (see placeOf)

  function openDrawer(builder) {
    hideTip();
    if (!drawerBuilder) { drawerReturnFocus = document.activeElement; drawerReturnPlace = placeOf(drawerReturnFocus); }
    drawerBuilder = builder;
    const d = $('#drawer');
    fillDrawer(d, builder);
    d.hidden = false;
    $('#scrim').hidden = false;
    d.scrollTop = 0;
    d.querySelector('.close').focus();
  }

  function fillDrawer(d, builder) {
    d.replaceChildren();
    append(d, [el('button', { class: 'close', 'aria-label': 'Close', text: 'Close', on: { click: closeDrawer } }), builder()]);
  }

  function refreshDrawer() {
    if (!drawerBuilder) return;
    const d = $('#drawer');
    const top = d.scrollTop;
    // the builder rebuilds every node: keep the disclosures the user opened and the control that had focus
    // (a switch by its data-key, anything else by its position among the drawer's controls)
    const open = [...d.querySelectorAll('details')].map(x => x.open);
    const active = d.contains(document.activeElement) ? document.activeElement : null;
    const key = active && active.dataset.key;
    const sameKey = root => (key ? [...root.querySelectorAll('[data-key]')].filter(x => x.dataset.key === key) : []);
    const keyAt = key ? sameKey(d).indexOf(active) : -1;
    const at = active ? [...d.querySelectorAll(FOCUSABLE)].indexOf(active) : -1;
    fillDrawer(d, drawerBuilder);
    const details = d.querySelectorAll('details');
    if (details.length === open.length) details.forEach((x, i) => { x.open = open[i]; });
    d.scrollTop = top;
    const target = (key && sameKey(d)[keyAt]) || (at >= 0 && d.querySelectorAll(FOCUSABLE)[at]) || null;
    if (target) target.focus({ preventScroll: true });
  }

  function closeDrawer() {
    $('#drawer').hidden = true;
    $('#scrim').hidden = true;
    drawerBuilder = null;
    const opener = drawerReturnFocus, place = drawerReturnPlace;
    drawerReturnFocus = drawerReturnPlace = null;
    if (!opener || opener === document.body) return;
    if (opener.isConnected) { opener.focus(); return; }
    // an In place switch in the drawer re-rendered the tab and replaced the opener: focus the control that
    // took its place (same row, same position), else the selected tab, so focus never drops to the page
    if (!focusQuiet(findPlace(place))) focusQuiet($('#tabs [aria-selected="true"]'));
  }

  const resultFor = domain => state.results.find(r => r.domain === domain);

  function drawerHead(kicker, obj, extra) {
    // NIST controls have no verified per-control page (the drawer links CTID's NIST page)
    const site = obj.kind === 'nist-control' ? null : AttackDB.FAMILIES[familyOf(obj.domain)].site;
    return [
      el('div', { class: 'kicker' }, kicker, ' · ', obj.url && site ? el('a', { href: obj.url, target: '_blank', rel: 'noopener',
        text: obj.attackId + ' on ' + site }) : obj.kind === 'nist-control' ? el('span', { class: 'mono', text: obj.attackId }) : obj.attackId),
      el('h2', { id: 'drawerTitle', text: obj.name }),
      extra || null,
    ];
  }

  function postureToggle(setKey, domain, id, label) {
    const cb = el('input', { type: 'checkbox', checked: state.inPlace[setKey].has(domain + '|' + id), data: { key: setKey + '|' + domain + '|' + id } });
    cb.addEventListener('change', () => { toggleInPlace(setKey, domain, id, cb.checked); refreshDrawer(); });
    return el('label', { class: 'toggle' }, cb, label);
  }

  /** ATLAS objects can name the matching ATT&CK object (e.g. an ATLAS entity for APT28 -> G0007). */
  const attackRefLine = o => (o.attackRef ? el('div', { class: 'kicker', style: 'margin-top:4px' }, 'ATT&CK: ',
    o.attackRef.url ? el('a', { href: o.attackRef.url, target: '_blank', rel: 'noopener', text: o.attackRef.id }) : o.attackRef.id) : null);

  /** ATLAS sources: the references its [[ref]] markers point at. */
  const referencesBlock = o => ((o.references || []).length ? el('details', { style: 'margin-top:10px' },
    el('summary', { text: 'Sources (' + o.references.length + ')' }),
    el('ul', { class: 'refs' }, ...o.references.map(r => el('li', {},
      r.url && /^https?:\/\//.test(r.url) ? el('a', { href: r.url, target: '_blank', rel: 'noopener', text: r.title || r.url }) : (r.title || r.id))))) : null);

  const techButton = (domain, tech) => el('button', { class: 'linkish', on: { click: () => openDrawer(() => techniqueDrawer(domain, tech.id)) } },
    el('span', { class: 'mono', text: tech.attackId }), ' ', tech.name);

  function analyticsBlock(model, analytics, hiddenCount) {
    return el('details', {},
      el('summary', { text: analytics.length + ' analytic' + (analytics.length === 1 ? '' : 's') + (hiddenCount ? ' (' + hiddenCount + ' hidden by platform filter)' : '') }),
      ...analytics.map(a => el('div', { class: 'item', style: 'margin-top:6px' },
        el('div', { class: 'hd' }, el('span', { class: 'mono', text: a.attackId }),
          el('div', { class: 'tags' }, (a.platforms || []).map(p => el('span', { class: 'tag', text: p })))),
        el('div', { class: 'md' }, md(a.description)),
        (a.logSources || []).length ? el('table', { class: 'ls' },
          el('thead', {}, el('tr', {}, el('th', { text: 'Data component' }), el('th', { text: 'Log source' }), el('th', { text: 'What to look for' }))),
          el('tbody', {}, ...a.logSources.map(l => el('tr', {},
            el('td', { text: (model.byId.get(l.dataComponent) || entity(l.dataComponent) || {}).name || '—' }),
            el('td', { class: 'mono', text: l.name || '—' }),
            el('td', { text: l.channel && l.channel !== 'None' ? l.channel : '—' }))))) : null,
      )));
  }

  function techniqueDrawer(domain, techId) {
    const model = state.models[domain];
    const tech = model.byId.get(techId);
    const r = resultFor(domain);
    const t = r && r.techniques.get(techId);
    const out = drawerHead((tech.isSubtechnique ? 'Sub-technique' : 'Technique') + ' · ' + domainLabel(domain), tech,
      el('div', { class: 'tags', style: 'margin-top:6px' },
        tacticNames(model, tech).map(n => el('span', { class: 'tag', text: n })),
        (tech.platforms || []).map(p => el('span', { class: 'tag', text: p })),
        tech.maturity ? el('span', { class: 'tag', title: 'ATLAS maturity: the strongest evidence of use', text: 'Maturity: ' + tech.maturity }) : null,
        t ? statusBadge(t.status) : null));
    out.push(attackRefLine(tech));
    if (tech.parent && model.byId.get(tech.parent)) {
      out.push(el('div', { class: 'kicker', style: 'margin-top:6px' }, 'Sub-technique of ', techButton(domain, model.byId.get(tech.parent))));
    }
    out.push(el('details', { style: 'margin-top:10px' }, el('summary', { text: 'Description' }), el('div', { class: 'md' }, md(tech.description))));
    out.push(referencesBlock(tech));

    if (t) {
      const byRoot = new Map();
      for (const g of SimEngine.procedures(t)) {
        if (!byRoot.has(g.root)) byRoot.set(g.root, []);
        byRoot.get(g.root).push(g);
      }
      const pathText = via => (via.length
        ? 'via ' + via.map(id => { const o = model.byId.get(id); return ({ campaign: 'campaign ', 'case-study': 'case study ' }[o.kind] || '') + o.name; }).join(' → ')
        : 'directly');
      out.push(el('section', {}, el('h3', { text: 'Used in this profile by' }), ...[...byRoot].map(([rootId, groups]) => {
        const root = model.byId.get(rootId);
        return el('div', { class: 'item' },
          el('div', { class: 'hd' }, el('strong', { text: root.name }), el('span', { class: 'mono muted', text: root.attackId })),
          ...groups.map(g => el('div', { style: 'margin-top:6px' },
            el('div', { class: 'kicker', text: g.paths.map(pathText).join(' · ') }),
            el('div', { class: 'md' }, md(g.description)))));
      })));
    }

    const mits = model.to(techId, 'mitigates', 'mitigation');
    out.push(el('section', {}, el('h3', { text: 'Mitigations (' + mits.length + ')' }),
      mits.length ? null : el('p', { class: 'hint', text: familyName(domain) + ' lists no mitigations for this technique.' }),
      ...mits.map(rel => {
        const m = model.byId.get(rel.source);
        return el('div', { class: 'item' },
          el('div', { class: 'hd' }, idLink(m),
            el('button', { class: 'linkish grow', text: m.name, on: { click: () => openDrawer(() => mitigationDrawer(domain, m.id)) } }),
            postureToggle('mitigations', domain, m.id, 'In place')),
          el('div', { class: 'md' }, md(rel.description)));
      })));

    const dets = model.to(techId, 'detects', 'detection-strategy');
    out.push(el('section', {}, el('h3', { text: 'Detection strategies (' + dets.length + ')' }),
      familyOf(domain) === 'atlas' ? el('p', { class: 'hint', text: 'ATLAS has no detection strategies; its detection controls are listed above as mitigations.' }) : null,
      ...dets.map(rel => {
        const ds = model.byId.get(rel.source);
        const all = (ds.analyticRefs || []).map(id => model.byId.get(id)).filter(a => a && a.active);
        const shown = all.filter(a => SimEngine.platformMatch(a.platforms, platformsFor(domain)));
        return el('div', { class: 'item' },
          el('div', { class: 'hd' }, idLink(ds),
            el('button', { class: 'linkish grow', text: ds.name, on: { click: () => openDrawer(() => detectionDrawer(domain, ds.id)) } }),
            postureToggle('detections', domain, ds.id, 'Deployed')),
          analyticsBlock(model, shown, all.length - shown.length));
      })));

    out.push(...mappingSections(domain, techId));

    const assets = model.from(techId, 'targets', 'asset');
    if (assets.length) {
      out.push(el('section', {}, el('h3', { text: 'Targeted assets (' + assets.length + ')' }),
        el('div', { class: 'tags' }, assets.map(rel => { const a = model.byId.get(rel.target); return el('span', { class: 'tag', title: a.attackId, text: a.name }); }))));
    }
    return out;
  }

  /** note(tech) returns markdown text, or a node to show as is. */
  function profileTechniqueList(domain, techIds, note) {
    const model = state.models[domain];
    const techs = [...techIds].map(id => model.byId.get(id)).sort(byAttackId);
    return techs.map(tech => {
      const n = note ? note(tech) : null;
      return el('div', { class: 'item' }, techButton(domain, tech), n instanceof Node ? n : n ? el('div', { class: 'md' }, md(n)) : null);
    });
  }

  /** The first `shown` items, the rest behind a "Show n more" disclosure. */
  const capped = (items, shown = 10) => (items.length > shown + 2
    ? [...items.slice(0, shown), el('details', {}, el('summary', { text: 'Show ' + (items.length - shown) + ' more' }), ...items.slice(shown))]
    : items);

  /** Related ATT&CK mitigations (by shared profile techniques) with their in-place switches. */
  function relatedMitigationItems(domain, mits, what) {
    const model = state.models[domain];
    return [...mits].map(([id, n]) => {
      const m = model.byId.get(id);
      if (!m) return null;
      return el('div', { class: 'item' },
        el('div', { class: 'hd' }, idLink(m),
          el('button', { class: 'linkish grow', text: m.name, on: { click: () => openDrawer(() => mitigationDrawer(domain, m.id)) } }),
          postureToggle('mitigations', domain, m.id, 'In place')),
        el('div', { class: 'kicker', text: 'Shares ' + plural(n, 'profile technique', 'profile techniques') + ' with ' + what }));
    }).filter(Boolean);
  }

  const ctidAttackVersion = key => (mappingSource(key) || { meta: {} }).meta.attackVersion || '?';
  /**
   * For an entry carried forward through revoked-by: "CTID mapped CM-5 to T1070.001 in ATT&CK 16.1; ATT&CK has
   * since replaced it with this technique." target names the record it now counts for (the parent, via parent).
   */
  const carriedNote = (e, key, subject, target = 'this technique') => {
    const ids = (e && e.fromAll) || [];
    return ids.length ? 'CTID mapped ' + subject + ' to ' + ids.join(', ') + ' in ATT&CK ' + ctidAttackVersion(key)
      + '; ATT&CK has since replaced ' + (ids.length === 1 ? 'it' : 'them') + ' with ' + target + '.' : null;
  };
  const entryFor = (ix, techId, capId) => (ix.byTech.get(techId) || []).find(e => e.capId === capId) || null;

  /** A NIST SP 800-53 Rev 5 control, from the CTID mapping. */
  function controlDrawer(domain, capId) {
    const src = mappingSource('nist');
    const ix = mappingIndex('nist', domain);
    const cap = ix && ix.capabilities.get(capId);
    const r = resultFor(domain);
    const c = r && r.nist ? r.nist.controls.get(capId) : null;
    const obj = c ? c.obj : { id: capId, attackId: capId, name: cap ? cap.name : capId, family: cap ? cap.group : '', familyName: cap ? cap.groupName : '', url: NIST_PAGE, kind: 'nist-control' };
    const out = drawerHead('NIST SP 800-53 Rev 5 control', obj, el('div', { class: 'tags', style: 'margin-top:6px' },
      obj.familyName ? el('span', { class: 'tag', title: 'Control family', text: (obj.family ? obj.family + ' · ' : '') + obj.familyName }) : null));
    const text = src && src.details.get(capId);
    if (text) {
      out.push(el('details', { style: 'margin-top:10px' }, el('summary', { text: 'Description' }),
        el('div', { class: 'md' }, ...text.split(/\n\s*\n/).map(t => el('p', { text: t.trim() })))));
    }
    if (cap) {
      out.push(el('p', { class: 'hint', text: 'CTID maps ' + capId + ' to ' + plural(cap.techniques.size, 'technique', 'techniques') + ' in ' + domainTitle(domain) + ' v' + ix.attackVersion
        + '. ThreatSim also counts a sub-technique for a control CTID mapped to its parent, unless CTID judged the sub-technique not mappable.' }));
    }
    if (c) {
      out.push(el('section', {}, el('h3', { text: 'Profile techniques it mitigates (' + c.techniques.size + ' of ' + r.techniques.size + ')' }),
        ...profileTechniqueList(domain, c.techniques, tech => {
          const t = r.techniques.get(tech.id);
          const parent = c.viaParent.has(tech.id) ? state.models[domain].byId.get(tech.parent) : null;
          // the entry CTID's mapping gives (to the parent, via parent): it may have been carried forward from older IDs
          const e = entryFor(ix, parent ? parent.id : tech.id, capId);
          const older = e && e.fromAll && e.fromAll.length ? e.fromAll : null;
          const comment = c.notes.get(tech.id);
          return el('div', { class: 'note-line' }, t ? statusBadge(t.status) : null,
            parent ? el('span', { class: 'tag via', text: 'via parent ' + parent.attackId, title: older
              ? 'CTID maps ' + capId + ' to ' + older.join(', ') + ' (ATT&CK ' + ctidAttackVersion('nist') + '), since replaced by ' + parent.attackId + ' ' + parent.name + ', the parent technique'
              : 'CTID maps ' + capId + ' to the parent technique ' + parent.attackId + ' ' + parent.name }) : null,
            older ? el('div', { class: 'kicker', text: carriedNote(e, 'nist', capId, parent ? 'the parent technique ' + parent.attackId : 'this technique') }) : null,
            comment ? el('div', { class: 'md' }, md(comment)) : null);
        })));
      if (c.mitigations.size) {
        out.push(el('section', {}, el('h3', { text: 'Related ATT&CK mitigations (' + c.mitigations.size + ')' }),
          el('p', { class: 'hint', text: 'ATT&CK mitigations of this profile that address the same techniques, most shared first. ' + RELATED_NOTE }),
          ...capped(relatedMitigationItems(domain, c.mitigations, capId))));
      }
    } else if (r) {
      out.push(el('p', { class: 'hint', text: 'None of this profile\'s techniques map to ' + capId + '.' }));
    }
    out.push(el('p', { class: 'small-print' }, 'Mapping: ', el('a', { href: NIST_PAGE, target: '_blank', rel: 'noopener', text: 'NIST 800-53 on the CTID Mappings Explorer' }),
      ' (Apache-2.0)' + (src ? ', ' + src.meta.label : '') + '. NIST SP 800-53 is a NIST publication.'));
    return out;
  }

  /** Technique drawer section for the CTID mapping (Enterprise: NIST). */
  function mappingSections(domain, techId) {
    const model = state.models[domain];
    const out = [];
    // counts only when the mapping is there to count from ("(0)" would read as "nothing is mapped")
    const heading = (text, ix, n) => el('h3', { text: text + (ix && ix.rowCount ? ' (' + n + ')' : '') });
    if (MAP.nist.domains.includes(domain)) {
      const ix = mappingIndex('nist', domain);
      const list = ix ? SimEngine.controlsFor(ix, model, techId) : [];
      const tech = model.byId.get(techId);
      const parent = tech.isSubtechnique && tech.parent ? model.byId.get(tech.parent) : null;
      const judged = ix ? ix.nonMappable.get(techId) : null;
      // a not-mappable sub-technique does not take its parent's controls (see SimEngine.controlsFor)
      const parentSkipped = ix && parent && !list.length && ix.nonMappable.has(techId) && (ix.byTech.get(parent.id) || []).length;
      out.push(el('section', {}, heading('NIST 800-53 controls', ix, list.length),
        !ix ? notPulledHint('nist') : !ix.rowCount ? el('p', { class: 'hint', text: 'The pulled NIST 800-53 mappings have no ' + domainTitle(domain) + ' entries.' })
          : !list.length ? el('p', { class: 'hint', text: ix.nonMappable.has(techId)
            ? 'CTID judged that no NIST 800-53 control maps to this technique' + (judged ? ': ' + withStop(judged) : '.')
              + (parentSkipped ? ' So ThreatSim does not count the controls CTID mapped to its parent ' + parent.attackId + ' for it.' : '')
            : 'CTID maps no NIST 800-53 Rev 5 control to this technique.' }) : null,
        ...capped(list.map(({ entry: e, viaParent }) => {
          const note = carriedNote(e, 'nist', e.capId, viaParent && parent ? 'the parent technique ' + parent.attackId : 'this technique');
          return el('div', { class: 'item' },
            el('div', { class: 'hd' }, el('span', { class: 'mono', text: e.capId }),
              el('button', { class: 'linkish grow', text: e.capName, on: { click: () => openDrawer(() => controlDrawer(domain, e.capId)) } }),
              viaParent && parent ? el('span', { class: 'tag via', title: 'CTID maps ' + e.capId + ' to the parent technique ' + parent.attackId + ' ' + parent.name, text: 'via parent ' + parent.attackId }) : null),
            note ? el('div', { class: 'kicker', text: note }) : null,
            e.comments ? el('div', { class: 'md' }, md(e.comments)) : null);
        }), 12)));
    }
    return out;
  }

  function mitigationDrawer(domain, id) {
    const model = state.models[domain];
    const m = model.byId.get(id);
    const r = resultFor(domain);
    const e = r && r.mitigations.get(id);
    const out = drawerHead('Mitigation · ' + domainLabel(domain), m, el('div', { style: 'margin-top:6px' }, postureToggle('mitigations', domain, id, 'In place')));
    if ((m.categories || []).length || (m.lifecyclePhases || []).length) {
      out.push(el('div', { class: 'tags', style: 'margin-top:8px' },
        (m.categories || []).map(c => el('span', { class: 'tag', title: 'Category', text: c })),
        (m.lifecyclePhases || []).map(p => el('span', { class: 'tag', title: 'AI lifecycle phase', text: p }))));
    }
    out.push(attackRefLine(m));
    out.push(el('div', { class: 'md', style: 'margin-top:10px' }, md(m.description)));
    out.push(referencesBlock(m));
    if (e) {
      out.push(el('section', {}, el('h3', { text: 'Profile techniques it addresses (' + e.techniques.size + ' of ' + r.techniques.size + ')' }),
        ...profileTechniqueList(domain, e.techniques, tech => e.guidance.get(tech.id))));
    }
    if (e && r.nist) {
      const ctl = [...r.nist.controls.values()].filter(c => c.mitigations.has(id)).sort((a, b) => b.mitigations.get(id) - a.mitigations.get(id) || byAttackId(a.obj, b.obj));
      out.push(el('section', {}, el('h3', { text: 'NIST 800-53 controls for the same techniques (' + ctl.length + ')' }),
        el('p', { class: 'hint', text: ctl.length ? 'Controls CTID mapped to the profile techniques this mitigation addresses, most shared first. ' + RELATED_NOTE
          : 'None of the NIST 800-53 controls in CTID\'s mapping covers the techniques this mitigation addresses in this profile.' }),
        ...capped(ctl.map(c => el('div', { class: 'item' },
          el('div', { class: 'hd' }, el('span', { class: 'mono', text: c.obj.id }),
            el('button', { class: 'linkish grow', text: c.obj.name, on: { click: () => openDrawer(() => controlDrawer(domain, c.obj.id)) } })),
          el('div', { class: 'kicker', text: 'Shares ' + plural(c.mitigations.get(id), 'profile technique', 'profile techniques') + ' with ' + m.attackId }))))));
    }
    return out;
  }

  function detectionDrawer(domain, id) {
    const model = state.models[domain];
    const ds = model.byId.get(id);
    const r = resultFor(domain);
    const e = r && r.detections.get(id);
    const all = (ds.analyticRefs || []).map(x => model.byId.get(x)).filter(a => a && a.active);
    const shown = all.filter(a => SimEngine.platformMatch(a.platforms, platformsFor(domain)));
    const out = drawerHead('Detection strategy · ' + domainLabel(domain), ds, el('div', { style: 'margin-top:6px' }, postureToggle('detections', domain, id, 'Deployed')));
    const analytics = el('section', {}, el('h3', { text: 'Analytics' }), analyticsBlock(model, shown, all.length - shown.length));
    analytics.querySelector('details').open = true;
    out.push(analytics);
    if (e) {
      out.push(el('section', {}, el('h3', { text: 'Profile techniques it detects (' + e.techniques.size + ')' }), ...profileTechniqueList(domain, e.techniques)));
    }
    return out;
  }

  function dataComponentDrawer(domain, id) {
    const model = state.models[domain];
    const dc = model.byId.get(id) || entity(id);   // may be defined only in another domain's bundle
    const e = resultFor(domain).dataComponents.get(id);
    const out = drawerHead('Data component · ' + domainLabel(domain), dc);
    out.push(el('div', { class: 'md', style: 'margin-top:10px' }, md(dc.description)));
    out.push(el('section', {}, el('h3', { text: 'Log sources used by these detections' }),
      el('table', { class: 'ls' }, el('tbody', {}, ...[...e.logSources].map(([name, channels]) => el('tr', {},
        el('td', { class: 'mono', text: name }),
        el('td', { text: [...channels].sort((a, b) => a.localeCompare(b)).slice(0, 6).join(' · ') + (channels.size > 6 ? ' · +' + (channels.size - 6) + ' more' : '') || '—' })))))));
    out.push(el('section', {}, el('h3', { text: 'Detection strategies relying on it (' + e.strategies.size + ')' }),
      ...[...e.strategies].map(sid => model.byId.get(sid)).sort(byAttackId).map(ds => el('div', { class: 'item' },
        el('button', { class: 'linkish', on: { click: () => openDrawer(() => detectionDrawer(domain, ds.id)) } }, el('span', { class: 'mono', text: ds.attackId }), ' ', ds.name)))));
    out.push(el('section', {}, el('h3', { text: 'Profile techniques (' + e.techniques.size + ')' }), ...profileTechniqueList(domain, e.techniques)));
    return out;
  }

  function assetDrawer(domain, id) {
    const model = state.models[domain];
    const a = model.byId.get(id);
    const e = resultFor(domain).assets.get(id);
    const out = drawerHead('ICS asset · ' + domainLabel(domain), a);
    out.push(el('div', { class: 'md', style: 'margin-top:10px' }, md(a.description)));
    out.push(el('section', {}, el('h3', { text: 'Profile techniques targeting it (' + e.techniques.size + ')' }), ...profileTechniqueList(domain, e.techniques)));
    return out;
  }

  /** What the matrix counts per technique: ATT&CK adversaries, or ATLAS threats (case studies, entities, software). */
  const whoPlural = domain => (familyOf(domain) === 'atlas' ? 'threats' : 'adversaries');

  /**
   * ATLAS facts for a case study, entity or software: short tags (type, dates, activity purpose), then
   * wrapping lines for attribution (with ATLAS's activity purpose), actor, target and reporting credit.
   */
  function atlasFacts(o) {
    const m = state.models[o.domain];
    const name = id => (m.byId.get(id) || {}).name || id;
    const out = [];
    const tags = pickMeta(o).filter(Boolean);
    if (tags.length) out.push(el('div', { class: 'tags', style: 'margin-top:6px' }, tags.map(f => el('span', { class: 'tag', text: f }))));
    const lines = [];
    const withPurpose = (id, r) => name(id) + (r.activityPurpose ? ' (' + r.activityPurpose + ')' : '');
    if (o.kind === 'case-study') {
      const attr = m.from(o.id, 'attributed-to');
      if (attr.length) lines.push(['Attributed to', attr.map(r => withPurpose(r.target, r)).join('; ')]);
      if (o.actor && !attr.some(r => name(r.target) === o.actor)) lines.push(['Actor', o.actor]);
      if (o.target) lines.push(['Target', o.target]);
      const rep = m.from(o.id, 'reported-by');
      if (o.reporter || rep.length) lines.push(['Reported by', o.reporter || rep.map(r => name(r.target)).join('; ')]);
    } else if (o.kind === 'entity') {
      const cs = m.to(o.id, 'attributed-to');
      if (cs.length) lines.push(['Case studies attributed to it', cs.map(r => withPurpose(r.source, r)).join('; ')]);
    }
    if (lines.length) out.push(el('div', { class: 'facts' }, lines.map(([k, v]) => el('div', {}, el('b', { text: k + ': ' }), v))));
    return out;
  }

  function entityDrawer(id, tab) {
    const o = entity(id);
    const out = drawerHead(tab.one + (o.softwareType ? ' (' + o.softwareType + ')' : '') + (familyOf(o.domain) === 'atlas' ? ' · ATLAS' : ''), o);
    const aliases = (o.aliases || []).filter(a => a !== o.name);
    if (aliases.length) out.push(el('div', { class: 'kicker', style: 'margin-top:4px', text: (o.kind === 'entity' ? 'Associated with ' : 'Also known as ') + aliases.join(', ') }));
    if (familyOf(o.domain) === 'atlas') out.push(...atlasFacts(o));
    out.push(attackRefLine(o));
    const contrib = state.results.map(r => {
      let n = 0;
      for (const t of r.techniques.values()) if (t.roots.has(id)) n++;
      return n ? domainLabel(r.domain) + ': ' + n + ' techniques' : null;
    }).filter(Boolean);
    if (contrib.length) out.push(el('p', { class: 'hint', text: 'Contributes ' + contrib.join(' · ') + ' to this profile.' }));
    out.push(el('div', { class: 'md', style: 'margin-top:10px' }, md(o.description)));
    out.push(referencesBlock(o));
    out.push(el('p', {}, el('button', { text: 'Remove from profile', on: { click: () => { state.selection[tab.key].delete(id); closeDrawer(); update(); } } })));
    return out;
  }

  // ---------- exports ----------

  function profileName() {
    const names = PICK_TABS.flatMap(t => [...state.selection[t.key]].map(id => (entity(id) || {}).name)).filter(Boolean);
    return names.length > 4 ? names.slice(0, 4).join(', ') + ' +' + (names.length - 4) : names.join(', ');
  }

  /** Reflect exportUi on the export button and the status line (the line keeps its height, so nothing moves). */
  function syncExportUi() {
    const btn = $('#exportWorkpaper');
    // aria-disabled rather than disabled, so keyboard focus stays on the button while it works
    btn.setAttribute('aria-disabled', String(exportUi.busy));
    btn.setAttribute('aria-busy', String(exportUi.busy));
    const status = $('#exportStatus');
    const text = exportUi.busy ? 'Building workpaper…' : exportUi.msg;
    status.textContent = text;
    status.title = text;
    status.classList.toggle('err', !exportUi.busy && exportUi.err);
  }

  /** One frame, so the busy label paints before the synchronous build; a timer covers hidden tabs. */
  const nextPaint = () => new Promise(resolve => {
    const t = setTimeout(resolve, 100);
    requestAnimationFrame(() => setTimeout(() => { clearTimeout(t); resolve(); }, 0));
  });

  /** [{ source, title, label, attackVersion, frameworkVersion, pulledAt, files }] for each pulled mapping source. */
  function mappingMetas() {
    const titles = typeof MappingsDB !== 'undefined' && Array.isArray(MappingsDB.SOURCES) ? MappingsDB.SOURCES : [];
    return Object.keys(MAP).map(mappingSource).filter(Boolean).map(({ meta }) => ({
      source: meta.source, title: (titles.find(t => t.id === meta.source) || {}).title || meta.source, label: meta.label,
      attackVersion: meta.attackVersion, frameworkVersion: meta.frameworkVersion, pulledAt: meta.pulledAt,
      files: (meta.files || []).map(f => Object.assign({}, f)),
    }));
  }

  async function exportWorkpaper(e) {
    // Ignore clicks while an export runs, and the second click of a double-click.
    if (exportUi.busy || (e && e.detail > 1)) return;
    // Snapshot what the workbook reads now: changes made while ExcelJS loads must not leak into this export.
    // state.results is safe by reference because analyze() replaces it rather than mutating it.
    const ctx = {
      results: state.results,
      inPlace: { mitigations: new Set(state.inPlace.mitigations), detections: new Set(state.inPlace.detections) },
      opts: Object.assign({}, state.opts, { platforms: new Set(state.opts.platforms) }),
      selection: Object.fromEntries(Object.entries(state.selection).map(([k, v]) => [k, new Set(v)])),
      showAll: state.ui.showAll,
      kinds: PICK_TABS, entity, domainLabel, domainInfo, activityPurposes: purposesOf,
      platformsByDomain: Object.fromEntries(state.results.map(r => [r.domain, [...platformsFor(r.domain)]])),
      // provenance of the CTID mappings pulled (r.nist travels on the results)
      mappings: mappingMetas(),
      generatedAt: new Date(),
    };
    Object.assign(exportUi, { busy: true, msg: '', err: false });
    syncExportUi();
    try {
      await nextPaint();
      const name = await Workpaper.download(ctx);
      exportUi.msg = 'Exported ' + name;
    } catch (err) {
      console.error(err);
      Object.assign(exportUi, { msg: 'Export failed: ' + err.message, err: true });
    } finally {
      exportUi.busy = false;
      syncExportUi();
    }
  }

  function exportCsv() {
    const q = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const lines = [['Domain', 'Technique ID', 'Technique', 'Tactics', 'Used by', 'Mitigations', 'Detection strategies', 'Mitigation in place', 'Detection deployed', 'Coverage'].map(q).join(',')];
    for (const r of state.results) {
      const m = r.model;
      for (const t of [...r.techniques.values()].sort((a, b) => byAttackId(a.tech, b.tech))) {
        const ctl = ids => ids.map(id => { const o = m.byId.get(id); return o.attackId + ' ' + o.name; }).join('; ');
        lines.push([domainLabel(r.domain), t.tech.attackId, t.tech.name, tacticNames(m, t.tech).join('; '), rootNames(t, 999),
          ctl(t.mitigations), ctl(t.detections), t.isMitigated ? 'yes' : 'no', t.isDetected ? 'yes' : 'no', STATUS[t.status].label].map(q).join(','));
      }
    }
    download('threatsim-techniques.csv', lines.join('\r\n'), 'text/csv');
  }

  function exportLayers() {
    const coverage = state.ui.colorMode === 'coverage';
    const colors = { covered: '#0ca30c', mitigated: '#fab219', detected: '#fab219', gap: '#d03b3b' };
    for (const r of state.results) {
      let max = 1;
      for (const t of r.techniques.values()) max = Math.max(max, t.roots.size);
      const entries = [];
      const parentsWithSubs = new Set();
      for (const t of r.techniques.values()) {
        if (t.tech.parent) parentsWithSubs.add(t.tech.parent);
        entries.push({
          techniqueID: t.tech.attackId,
          score: t.roots.size,
          color: coverage ? colors[t.status] : '',
          comment: 'Used by: ' + rootNames(t, 999) + ' | Coverage: ' + STATUS[t.status].label,
          enabled: true,
          showSubtechniques: false,
        });
      }
      for (const e of entries) {
        const tech = [...r.techniques.values()].find(t => t.tech.attackId === e.techniqueID).tech;
        if (parentsWithSubs.has(tech.id)) e.showSubtechniques = true;
      }
      for (const pid of parentsWithSubs) {
        if (r.techniques.has(pid)) continue;
        const p = r.model.byId.get(pid);
        if (p) entries.push({ techniqueID: p.attackId, enabled: true, showSubtechniques: true });
      }
      // ATLAS layers open in the ATLAS Navigator (domain atlas-atlas), as ATLAS publishes its own
      const atlas = familyOf(r.domain) === 'atlas';
      const layer = {
        name: 'ThreatSim: ' + profileName(),
        versions: atlas ? { navigator: '5.3.2', layer: '4.5' } : { attack: String(r.model.meta.version).split('.')[0], navigator: '5.1.0', layer: '4.5' },
        domain: atlas ? 'atlas-atlas' : r.domain,
        description: 'Generated by ThreatSim from ' + familyName(r.domain) + ' v' + r.model.meta.version + '. ' + (coverage ? 'Colored by simulated coverage.' : 'Score = number of selected ' + whoPlural(r.domain) + ' using the technique.'),
        sorting: 3,
        layout: { layout: 'side', showID: true, showName: true },
        hideDisabled: false,
        techniques: entries,
        gradient: { colors: ['#cde2fb', '#104281'], minValue: 0, maxValue: max },
        legendItems: coverage ? Object.entries(STATUS).filter(([k]) => k !== 'detected').map(([k, s]) => ({ label: k === 'mitigated' ? 'Partial (mitigated or detected)' : s.label, color: colors[k] })) : [],
        metadata: [{ name: 'profile', value: profileName() }].concat(atlas ? [{ name: 'atlas_data_version', value: String(r.model.meta.version) }] : []),
        selectTechniquesAcrossTactics: true,
        selectSubtechniquesWithParent: false,
      };
      download('threatsim-' + r.domain + '-layer.json', JSON.stringify(layer, null, 2), 'application/json');
    }
  }

  // ---------- boot ----------

  async function init() {
    let metas = [];
    try { metas = await AttackDB.getAllMeta(); } catch (e) { console.error(e); }
    if (!metas.length) { $('#noData').hidden = false; return; }

    const order = AttackDB.DOMAINS.map(d => d.id);
    metas.sort((a, b) => order.indexOf(a.domain) - order.indexOf(b.domain));
    for (const m of metas) state.models[m.domain] = await SimEngine.loadModel(m.domain);
    state.available = metas.map(m => m.domain).filter(d => state.models[d]);
    await loadMappings();

    if (!restore() || !state.domains.size) {
      state.domains = new Set(state.available.filter(d => (AttackDB.DOMAINS.find(x => x.id === d) || {}).enabled !== false));
      if (!state.domains.size) state.domains = new Set(state.available);
    }

    $('#app').hidden = false;
    $('#optSoftware').checked = state.opts.viaSoftware;
    $('#optCampaigns').checked = state.opts.viaCampaigns;
    $('#pickDesc').checked = state.ui.matchDesc;
    $('#optSoftware').addEventListener('change', e => { state.opts.viaSoftware = e.target.checked; update({ picker: false }); });
    $('#optCampaigns').addEventListener('change', e => { state.opts.viaCampaigns = e.target.checked; update({ picker: false }); });
    $('#platClear').addEventListener('click', () => { state.opts.platforms.clear(); renderPlatforms(); update({ picker: false }); });

    let t;
    $('#pickSearch').addEventListener('input', e => { state.ui.search = e.target.value; clearTimeout(t); t = setTimeout(renderPicker, 120); });
    $('#pickDesc').addEventListener('change', e => { state.ui.matchDesc = e.target.checked; persist(); renderPicker(); });
    $('#swType').addEventListener('change', e => { state.ui.swType = e.target.value; renderPicker(); });
    $('#swPlatform').addEventListener('change', e => { state.ui.swPlatform = e.target.value; renderPicker(); });
    $('#swCategory').addEventListener('change', e => { state.ui.swCategory = e.target.value; renderPicker(); });
    $('#csType').addEventListener('change', e => { state.ui.csType = e.target.value; renderPicker(); });
    $('#entType').addEventListener('change', e => { state.ui.entType = e.target.value; renderPicker(); });
    $('#purpose').addEventListener('change', e => { state.ui.purpose = e.target.value; renderPicker(); });
    $('#campSince').addEventListener('change', e => { state.ui.campSince = e.target.value; renderPicker(); });
    $('#pickAll').addEventListener('click', () => {
      const sel = state.selection[state.ui.pickTab];
      for (const { obj } of filteredCatalog()) sel.add(obj.id);
      update();
    });
    $('#pickNone').addEventListener('click', () => { state.selection[state.ui.pickTab].clear(); update(); });

    $('#exportWorkpaper').addEventListener('click', exportWorkpaper);
    $('#exportCsv').addEventListener('click', exportCsv);
    $('#exportNavigator').addEventListener('click', exportLayers);

    $('#scrim').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', e => {
      if (e.key !== 'Escape') return;
      if (drawerBuilder) closeDrawer(); else closeSpiderTip();
    });
    window.addEventListener('scroll', onScroll, { passive: true });

    renderDomains();
    renderPlatforms();
    renderScopeLabels();
    renderPickerFilters();
    update();
  }

  init();
})();
