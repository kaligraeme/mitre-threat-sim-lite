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

  const fmtN = n => (n ?? 0).toLocaleString();
  const plural = (n, one, many) => fmtN(n) + ' ' + (n === 1 ? one : many);
  const pct = (a, b) => b ? Math.round((a / b) * 100) + '%' : '0%';
  const domainInfo = id => AttackDB.DOMAINS.find(d => d.id === id) || { id, label: id, title: id, family: 'attack' };
  const domainLabel = id => domainInfo(id).label;          // Enterprise, ICS, ATLAS
  const domainTitle = id => domainInfo(id).title;          // Enterprise ATT&CK, ICS ATT&CK, ATLAS
  const familyOf = id => domainInfo(id).family;            // attack | atlas
  const familyName = id => AttackDB.FAMILIES[familyOf(id)].name;   // ATT&CK | ATLAS
  const byName = (a, b) => (a.name || '').localeCompare(b.name || '');
  const byAttackId = (a, b) => String(a.attackId).localeCompare(String(b.attackId), undefined, { numeric: true });

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
    },
    results: [],
    catalogs: null,
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
            colorMode: state.ui.colorMode, showAll: state.ui.showAll, matrixDomain: state.ui.matrixDomain, matchDesc: state.ui.matchDesc },
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

  // ---------- analysis ----------

  function analyze() {
    state.results = activeModels()
      .map(m => SimEngine.analyzeDomain(m, state.selection, Object.assign({ resolve: entity }, state.opts, { platforms: platformsFor(m.domain) })))
      .filter(r => r.roots.length);
    for (const r of state.results) {
      r.statusCounts = SimEngine.applyPosture(r, state.inPlace);
      r.mitPriority = SimEngine.prioritize(r.mitigations, state.inPlace.mitigations, r.domain, r.techniques);
      r.detPriority = SimEngine.prioritize(r.detections, state.inPlace.detections, r.domain, r.techniques);
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
    const t = totals();
    const tile = (lbl, val, sub) => el('div', { class: 'tile' },
      el('div', { class: 'lbl', text: lbl }), el('div', { class: 'val', text: val }), el('div', { class: 'sub', text: sub }));
    const partial = t.mitigated + t.detected;
    const seg = (n, color, label) => n ? el('span', { style: `flex:${n};background:${color}`, title: label + ': ' + n }) : null;
    const noPosture = !t.mitIn && !t.detIn;
    const hero = el('div', { class: 'tile hero' },
      el('div', { class: 'lbl', text: 'Techniques with no mitigation or detection in place' }),
      el('div', { class: 'val' }, fmtN(t.gap), el('small', { text: pct(t.gap, t.tech) + ' of ' + fmtN(t.tech) })),
      el('div', { class: 'stack', role: 'img', 'aria-label': `Covered ${t.covered}, partial ${partial}, no coverage ${t.gap}` },
        seg(t.covered, 'var(--good)', STATUS.covered.label),
        seg(partial, 'var(--warning)', 'Partial'),
        seg(t.gap, 'var(--critical)', STATUS.gap.label)),
      el('div', { class: 'legend' },
        el('span', {}, el('span', { class: 'sw', style: 'background:var(--good)' }), STATUS.covered.label + ' ' + fmtN(t.covered)),
        el('span', {}, el('span', { class: 'sw', style: 'background:var(--warning)' }), 'Partial ' + fmtN(partial) + ' (M ' + t.mitigated + ' · D ' + t.detected + ')'),
        el('span', {}, el('span', { class: 'sw', style: 'background:var(--critical)' }), STATUS.gap.label + ' ' + fmtN(t.gap))),
      noPosture ? el('div', { class: 'sub', style: 'margin-top:6px', text: 'Mark mitigations as in place and detections as deployed to simulate your coverage.' }) : null,
    );
    // ATLAS defines no detection strategies, so its techniques can only be mitigated
    const atlas = state.results.filter(r => familyOf(r.domain) === 'atlas').length;
    const atlasOnly = atlas === state.results.length;
    $('#kpis').replaceChildren(
      tile('Techniques in scope', fmtN(t.tech), fmtN(t.subs) + ' sub-techniques · ' + t.tacticsHit + ' of ' + t.tacticsAll + ' tactics'),
      tile('Mitigations', fmtN(t.mit), fmtN(t.mitIn) + ' in place'),
      tile('Detection strategies', fmtN(t.det), atlasOnly ? 'ATLAS has none; its detection controls are listed as mitigations'
        : fmtN(t.detIn) + ' deployed' + (atlas ? ' · ATT&CK only' : '')),
      tile('Data components', fmtN(t.dc), atlasOnly ? 'none: ATLAS defines no detection strategies'
        : 'telemetry the detections rely on' + (t.dcShared ? ` · ${fmtN(t.dcShared)} used by more than one domain` : '')),
      hero,
    );
  }

  const TABS = [
    { key: 'matrix', label: 'Matrix' },
    { key: 'techniques', label: 'Techniques', count: r => r.techniques.size },
    { key: 'mitigations', label: 'Mitigations', count: r => r.mitigations.size },
    { key: 'detections', label: 'Detections', count: r => r.detections.size },
    { key: 'telemetry', label: 'Telemetry', count: r => r.dataComponents.size },
    { key: 'assets', label: 'ICS assets', count: r => r.assets.size },
  ];

  function renderTabs() {
    const tabs = TABS.filter(t => t.key !== 'assets' || state.results.some(r => r.assets.size));
    if (!tabs.some(t => t.key === state.ui.tab)) state.ui.tab = 'matrix';
    $('#tabs').replaceChildren(...tabs.map(t => {
      const n = t.count ? state.results.reduce((s, r) => s + t.count(r), 0) : null;
      return el('button', {
        role: 'tab', 'aria-selected': String(state.ui.tab === t.key),
        on: { click: () => { state.ui.tab = t.key; state.ui.filter = ''; persist(); renderTabs(); renderTab(); } },
      }, t.label, n != null ? el('span', { class: 'count', text: ' ' + fmtN(n) }) : null);
    }));
  }

  function renderTab() {
    hideTip();
    const tools = $('#tabTools');
    const body = $('#tabBody');
    tools.replaceChildren();
    body.replaceChildren();
    ({ matrix: renderMatrix, techniques: renderTechniques, mitigations: renderMitigations,
       detections: renderDetections, telemetry: renderTelemetry, assets: renderAssets })[state.ui.tab](tools, body);
  }

  function filterBox(placeholder, rerender) {
    const i = el('input', { type: 'search', placeholder, value: state.ui.filter });
    i.addEventListener('input', () => { state.ui.filter = i.value; rerender(); });
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
      return el('button', { class: cls.join(' '), data: { tech: tech.id } },
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
      t ? el('div', { class: 'row', text: 'Coverage: ' + STATUS[t.status].label }) : null,
    );
    tip.hidden = false;
    const a = anchor.getBoundingClientRect();
    const w = tip.offsetWidth, h = tip.offsetHeight;
    let x = a.right + 8, y = a.top;
    if (x + w > innerWidth - 8) x = Math.max(8, a.left - w - 8);
    if (y + h > innerHeight - 8) y = innerHeight - h - 8;
    tip.style.left = x + 'px';
    tip.style.top = Math.max(8, y) + 'px';
  }
  function hideTip() { $('#tip').hidden = true; }

  // ---------- tables ----------

  /**
   * cols: [{key, label, num, sort:(row)=>v, render:(row)=>node|string}]
   * opts: {id, defaultSort:{key,dir}, onRow:(row)=>void, rowClass:(row)=>string}
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
        return (typeof x === 'string' ? x.localeCompare(y, undefined, { numeric: true }) : x - y) * dir;
      });
    }
    const head = el('tr', {}, ...cols.map(c => {
      const sorted = col && c.key === col.key;
      return el('th', {
        class: (c.num ? 'num ' : '') + (c.sort ? 'sortable' : ''),
        'aria-sort': sorted ? (s.dir === 'asc' ? 'ascending' : 'descending') : null,
        on: c.sort ? { click: () => {
          const cur = state.ui.sort[opts.id] || opts.defaultSort;
          state.ui.sort[opts.id] = { key: c.key, dir: cur.key === c.key && cur.dir === 'desc' ? 'asc' : (cur.key === c.key ? 'desc' : (c.num ? 'desc' : 'asc')) };
          renderTab();
        } } : null,
      }, c.label);
    }));
    const body = el('tbody', {}, ...rows.map(row => el('tr', {
      class: ((opts.onRow ? 'click ' : '') + (opts.rowClass ? opts.rowClass(row) : '')).trim() || null,
      on: opts.onRow ? { click: e => { if (!e.target.closest('input,a,button,label')) opts.onRow(row); } } : null,
    }, ...cols.map(c => el('td', { class: c.num ? 'num' : null }, c.render(row))))));
    if (!rows.length) body.append(el('tr', {}, el('td', { colspan: cols.length, class: 'empty', text: 'Nothing matches.' })));
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

  // ---------- drawer ----------

  let drawerBuilder = null;
  let drawerReturnFocus = null;

  function openDrawer(builder) {
    hideTip();
    if (!drawerBuilder) drawerReturnFocus = document.activeElement;
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
    fillDrawer(d, drawerBuilder);
    d.scrollTop = top;
  }

  function closeDrawer() {
    $('#drawer').hidden = true;
    $('#scrim').hidden = true;
    drawerBuilder = null;
    if (drawerReturnFocus && drawerReturnFocus.isConnected) drawerReturnFocus.focus();
  }

  const resultFor = domain => state.results.find(r => r.domain === domain);

  function drawerHead(kicker, obj, extra) {
    return [
      el('div', { class: 'kicker' }, kicker, ' · ', obj.url ? el('a', { href: obj.url, target: '_blank', rel: 'noopener',
        text: obj.attackId + ' on ' + AttackDB.FAMILIES[familyOf(obj.domain)].site }) : obj.attackId),
      el('h2', { id: 'drawerTitle', text: obj.name }),
      extra || null,
    ];
  }

  function postureToggle(setKey, domain, id, label) {
    const cb = el('input', { type: 'checkbox', checked: state.inPlace[setKey].has(domain + '|' + id) });
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

    const assets = model.from(techId, 'targets', 'asset');
    if (assets.length) {
      out.push(el('section', {}, el('h3', { text: 'Targeted assets (' + assets.length + ')' }),
        el('div', { class: 'tags' }, assets.map(rel => { const a = model.byId.get(rel.target); return el('span', { class: 'tag', title: a.attackId, text: a.name }); }))));
    }
    return out;
  }

  function profileTechniqueList(domain, techIds, note) {
    const model = state.models[domain];
    const techs = [...techIds].map(id => model.byId.get(id)).sort(byAttackId);
    return techs.map(tech => el('div', { class: 'item' }, techButton(domain, tech), note ? el('div', { class: 'md' }, md(note(tech))) : null));
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
    if (window.Auth && !Auth.session()) return;   // signed out: auth.js is sending this page to sign-in
    let metas = [];
    try { metas = await AttackDB.getAllMeta(); } catch (e) { console.error(e); }
    if (!metas.length) { $('#noData').hidden = false; return; }

    const order = AttackDB.DOMAINS.map(d => d.id);
    metas.sort((a, b) => order.indexOf(a.domain) - order.indexOf(b.domain));
    for (const m of metas) state.models[m.domain] = await SimEngine.loadModel(m.domain);
    state.available = metas.map(m => m.domain).filter(d => state.models[d]);

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
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && drawerBuilder) closeDrawer(); });
    window.addEventListener('scroll', hideTip, { passive: true });

    renderDomains();
    renderPlatforms();
    renderScopeLabels();
    renderPickerFilters();
    update();
  }

  init();
})();
