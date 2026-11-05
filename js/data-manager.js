/*
 * data-manager.js — UI for checking and pulling MITRE ATT&CK and ATLAS releases into AttackDB, and the CTID
 * control mappings (NIST SP 800-53 Rev 5) into MappingsDB. The two kinds share the selection, the Pull plan and
 * button, re-pull, history and Clear; the mappings are pulled after the knowledge bases.
 */
(function () {
  'use strict';

  const $ = sel => document.querySelector(sel);
  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else n.setAttribute(k, v);
    }
    for (const k of kids) n.append(k);
    return n;
  };

  const SELECTED_KEY = 'threatsim.selectedDomains';
  const KNOWN_KEY = 'threatsim.knownDomains';   // domains this page offered when the selection was saved
  const DISPLAY_KINDS = Object.keys(AttackDB.KIND_LABELS);
  const domainOf = id => AttackDB.DOMAINS.find(d => d.id === id) || { id, label: id, title: id, family: 'attack' };
  // CTID mapping sources (none if mappings-db.js failed to load: the page then works as before)
  const MDB = window.MappingsDB || null;
  const MAPS = MDB ? MDB.SOURCES : [];
  const mapOf = id => MAPS.find(s => s.id === id);
  const isMap = id => !!mapOf(id);
  const labelOf = id => (mapOf(id) ? mapOf(id).short : domainOf(id).label);

  const state = {
    upstream: null,          // result of fetchUpstreamIndex()
    meta: {},                // domain -> meta row
    mapUp: null,             // result of MappingsDB.fetchUpstreamIndex()
    mapChecked: false,       // the mapping file list has been asked for at least once
    mapMeta: {},             // mapping source -> meta row
    mapDbError: null,        // the mappings database could not be opened
    selected: loadSelected(),
    chosenVersion: {},       // domain or mapping source -> version string picked in the dropdown
    busy: false,
    stageMsg: {},            // domain or mapping source -> {text, cls} last pull message
  };

  function loadSelected() {
    const defaults = [...AttackDB.DOMAINS, ...MAPS].filter(d => d.enabled).map(d => d.id);
    try {
      const v = JSON.parse(localStorage.getItem(SELECTED_KEY));
      if (Array.isArray(v)) {
        let known = JSON.parse(localStorage.getItem(KNOWN_KEY));
        if (!Array.isArray(known)) known = ['enterprise-attack', 'ics-attack', 'mobile-attack'];   // saved before ATLAS was added
        // a domain added since the selection was saved starts switched on, like on a first visit
        return new Set([...v, ...defaults.filter(id => !known.includes(id))]);
      }
    } catch (_) { /* storage unavailable */ }
    return new Set(defaults);
  }
  function saveSelected() {
    try {
      localStorage.setItem(SELECTED_KEY, JSON.stringify([...state.selected]));
      localStorage.setItem(KNOWN_KEY, JSON.stringify([...AttackDB.DOMAINS, ...MAPS].map(d => d.id)));
    } catch (_) {}
  }

  const fmtDate = s => s ? new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  // ATLAS release dates are plain days ('2026-10-28'): show them as written, not shifted to the local time zone
  const fmtDay = s => s ? new Date(s).toLocaleDateString(undefined,
    /^\d{4}-\d{2}-\d{2}$/.test(s) ? { dateStyle: 'medium', timeZone: 'UTC' } : { dateStyle: 'medium' }) : '—';
  const fmtMB = n => (n / 1048576).toFixed(1) + ' MB';
  const fmtN = n => (n ?? 0).toLocaleString();
  const LISTING_MAX_AGE = 3600e3;   // reuse GitHub's CTID file listing for an hour on page loads (60 API calls/hour)

  // ---------- status per domain ----------

  function targetVersion(domainId) {
    const up = state.upstream && state.upstream.domains[domainId];
    if (!up) return null;
    const v = state.chosenVersion[domainId];
    return (v && up.versions.find(x => x.version === v)) || up.latest;
  }

  function domainStatus(domainId) {
    const meta = state.meta[domainId];
    const up = state.upstream && state.upstream.domains[domainId];
    if (!up) return meta ? { cls: 'muted', text: 'Stored v' + meta.version } : { cls: 'muted', text: 'Unknown' };
    if (!meta) return { cls: 'warn', text: 'Not pulled' };
    const c = AttackDB.compareVersions(up.latest.version, meta.version);
    if (c > 0) return { cls: 'warn', text: 'v' + up.latest.version + ' available' };
    return { cls: 'ok', text: 'Up to date' };
  }

  function needsPull(domainId) {
    const meta = state.meta[domainId];
    const target = targetVersion(domainId);
    if (!target) return false;
    if (!meta) return true;
    return meta.version !== target.version;
  }

  // ---------- status per mapping source ----------

  /**
   * Versions offered for a mapping source, newest first: the file list, plus the stored version when the list
   * lacks it (GitHub's listing unreadable and the built-in list older, or a file CTID has since removed), so the
   * page never takes an older built-in version for the latest.
   */
  function mapVersions(id) {
    const up = state.mapUp && state.mapUp.sources[id];
    if (!up) return null;
    const meta = state.mapMeta[id];
    if (!meta || up.versions.some(v => v.version === meta.version)) return up.versions;
    const stored = MDB.versionFromMeta(meta);
    return stored ? [...up.versions, stored].sort(MDB.compareVersions) : up.versions;
  }

  function mapTarget(id) {
    const versions = mapVersions(id);
    if (!versions) return null;
    const v = state.chosenVersion[id];
    return (v && versions.find(x => x.version === v)) || versions[0];
  }

  function mapStatus(id) {
    if (state.mapDbError) return { cls: 'err', text: 'Unavailable' };
    const meta = state.mapMeta[id];
    const versions = mapVersions(id);
    if (!versions) return meta ? { cls: 'muted', text: 'Stored' } : { cls: 'muted', text: 'Unknown' };
    if (!meta) return { cls: 'warn', text: 'Not pulled' };
    if (meta.version !== versions[0].version && MDB.compareVersions(versions[0], meta) < 0) return { cls: 'warn', text: 'Update available' };
    return { cls: 'ok', text: 'Up to date' };
  }

  function mapNeedsPull(id) {
    if (state.mapDbError) return false;
    const meta = state.mapMeta[id];
    const target = mapTarget(id);
    if (!target) return false;
    if (!meta) return true;
    // without a version picked, a stored version as new as the newest listed is current
    if (!state.chosenVersion[id] && MDB.compareVersions(meta, target) <= 0) return false;
    return meta.version !== target.version;
  }

  /** Selected domains whose release list could not be read, so their status is unknown. */
  const unchecked = () => AttackDB.DOMAINS.filter(d => state.selected.has(d.id) && state.upstream && !state.upstream.domains[d.id]);
  const uncheckedMaps = () => (state.mapDbError ? [] : MAPS.filter(s => state.selected.has(s.id) && state.mapChecked && !(state.mapUp && state.mapUp.sources[s.id])));

  /** Selected datasets to pull: ATT&CK and ATLAS domains first, then the mappings. */
  function pullPlan() {
    const force = $('#forceChk').checked;
    return [
      ...AttackDB.DOMAINS.filter(d => state.selected.has(d.id) && targetVersion(d.id)).filter(d => force || needsPull(d.id)),
      ...(state.mapDbError ? [] : MAPS.filter(s => state.selected.has(s.id) && mapTarget(s.id)).filter(s => force || mapNeedsPull(s.id))),
    ].map(d => d.id);
  }

  // ---------- rendering ----------

  /**
   * One source card: checkbox, title, status pill, Stored / Pulled / Latest / Pull rows, notes, progress, stage.
   * versions: [{value, text}] for the version picker (null when the release list is unknown).
   */
  function sourceCard({ id, label, title, status, stored, pulled, latest, versions, current, notes, unavailable }) {
    const chk = el('input', { type: 'checkbox', id: 'sel-' + id, 'aria-label': 'Include ' + label });
    chk.checked = state.selected.has(id);
    chk.disabled = state.busy || !!unavailable;
    chk.addEventListener('change', () => {
      chk.checked ? state.selected.add(id) : state.selected.delete(id);
      saveSelected();
      renderToolbar();
    });

    const sel = el('select', { 'aria-label': label + ' version to pull' });
    sel.disabled = state.busy || !versions || !!unavailable;
    if (versions) {
      for (const v of versions) sel.append(el('option', { value: v.value, text: v.text }));
      sel.value = current;
    } else {
      sel.append(el('option', { text: '—' }));
    }
    sel.addEventListener('change', () => {
      state.chosenVersion[id] = sel.value;
      renderToolbar();
    });

    const kv = el('dl', { class: 'kv' },
      el('dt', { text: 'Stored' }), el('dd', { text: stored }),
      el('dt', { text: 'Pulled' }), el('dd', { text: pulled }),
      el('dt', { text: 'Latest' }), el('dd', { text: latest }),
      el('dt', { text: 'Pull' }), el('dd', {}, sel),
    );

    const card = el('div', { class: 'card', id: 'card-' + id },
      el('div', { class: 'card-head' },
        chk,
        el('label', { for: 'sel-' + id }, el('h2', { text: title })),
        el('span', { class: 'pill ' + status.cls, text: status.text }),
      ),
      kv,
      ...notes.filter(Boolean).map(n => {
        const p = el('p', { class: 'card-note', text: n.text || n });
        if (n.cls) p.style.color = 'var(--' + n.cls + ')';
        return p;
      }),
      el('div', { class: 'progress', id: 'prog-' + id, hidden: '' }, el('div')),
      el('div', { class: 'stage', id: 'stage-' + id }),
    );
    const msg = state.stageMsg[id];
    if (msg) {
      const s = card.querySelector('.stage');
      s.textContent = msg.text;
      if (msg.cls) s.style.color = 'var(--' + msg.cls + ')';
    }
    if (!state.selected.has(id)) card.style.opacity = '.6';
    return card;
  }

  function renderCards() {
    $('#domainCards').replaceChildren(...AttackDB.DOMAINS.map(d => {
      const meta = state.meta[d.id];
      const up = state.upstream && state.upstream.domains[d.id];
      return sourceCard({
        id: d.id, label: d.label, title: d.title, status: domainStatus(d.id),
        stored: meta ? 'v' + meta.version + ' · released ' + fmtDay(meta.modified)
          + (meta.formatVersion ? ' · format ' + meta.formatVersion : '') : 'nothing yet',
        pulled: meta ? fmtDate(meta.pulledAt) : '—',
        latest: up ? 'v' + up.latest.version + ' · released ' + fmtDay(up.latest.modified) : '—',
        versions: up && up.versions.map((v, i) => ({ value: v.version, text: 'v' + v.version + (i === 0 ? ' (latest)' : '') })),
        current: up && (targetVersion(d.id) || up.latest).version,
        notes: [d.note],
      });
    }));
    renderMapCards();
  }

  function renderMapCards() {
    const host = $('#mappingCards');
    if (!host) return;
    const group = $('#mappingGroup');
    if (group) group.hidden = !MAPS.length;
    host.replaceChildren(...MAPS.map(s => {
      const meta = state.mapMeta[s.id];
      const versions = state.mapDbError ? null : mapVersions(s.id);
      const c = (meta && meta.counts) || {};
      const notes = [MDB.noteFor(s.id, meta ? meta.attackVersion : versions && versions[0].attackVersion, meta ? 'stored' : 'latest')];
      // the mappings join ATT&CK techniques by ID: without the stored knowledge base there is nothing to join
      if (!state.mapDbError && !state.meta['enterprise-attack'] && (meta || state.selected.has(s.id))) {
        notes.push({ cls: 'warn', text: "Enterprise ATT&CK isn't stored: the mappings can be pulled, but they can't be shown until Enterprise ATT&CK is pulled." });
      }
      return sourceCard({
        id: s.id, label: s.short, title: s.title, status: mapStatus(s.id), unavailable: !!state.mapDbError,
        stored: state.mapDbError ? 'unknown' : meta ? meta.label + ' · ' + fmtN(c.capabilities) + ' controls mapped' : 'nothing yet',
        pulled: meta ? fmtDate(meta.pulledAt) : '—',
        latest: versions ? versions[0].label : '—',
        versions: versions && versions.map((v, i) => ({ value: v.version, text: MDB.versionLabel(s.id, v.version)
          + (v.stored ? ' (stored)' : i === 0 ? ' (latest)' : '') })),
        current: versions && (mapTarget(s.id) || versions[0]).version,
        notes,
      });
    }));
    renderMapSourceNote();
  }

  /**
   * Where the mapping file list came from, and, when it isn't a current GitHub listing, which list is used and why:
   * an earlier copy of the listing (GitHub couldn't be read just now) or the built-in list (no copy, or the listing
   * or copy has no files of a source; the note names which source uses which).
   */
  function renderMapSourceNote() {
    const n = $('#mappingSource');
    if (!n) return;
    const link = el('a', { href: 'https://github.com/center-for-threat-informed-defense/mappings-explorer', target: '_blank', rel: 'noopener',
      text: 'center-for-threat-informed-defense/mappings-explorer' });
    const parts = ["Mapping files from the Center for Threat-Informed Defense's Mappings Explorer on GitHub (", link, ').'];
    const up = state.mapUp;
    let cls = '';
    if (state.mapDbError) {
      parts.push(' ' + state.mapDbError + " The mappings can't be pulled or shown in this browser until it can be opened.");
      cls = 'err';
    } else if (mapListStale()) {
      // the copy may lack a source's files (CTID moved a folder, the listing was cut short): say which list each uses
      const fromCopy = mapSourcesFrom('github-api'), builtIn = mapSourcesFrom('pinned');
      parts.push(" GitHub's file listing couldn't be read just now (" + up.readError + '), so the copy this browser read on '
        + fmtDate(up.listedAt) + ' is used' + (builtIn.length
          ? ' for ' + listText(fromCopy) + '; that copy has no ' + builtIn.join(' or ') + " files, so ThreatSim's built-in list of known "
            + listText(builtIn) + ' files is used. Newer files may exist.'
          : '; newer files may exist.'));
      cls = 'warn';
    } else if (mapListPinned()) {
      const names = mapSourcesFrom('pinned');
      parts.push(up.readError
        ? " GitHub's file listing couldn't be read (" + up.readError + '), so the built-in list of known files is used; newer files may exist.'
        : " GitHub's file listing has no " + names.join(' or ') + " files, so ThreatSim's built-in list of known " + listText(names)
          + ' files is used; newer files may exist.');
      cls = 'warn';
    }
    n.replaceChildren(...parts);
    n.style.color = cls ? 'var(--' + cls + ')' : '';
  }

  /** Some (selected) mapping source's versions come from the built-in list, not from GitHub's listing. */
  const mapListPinned = (onlySelected) => !state.mapDbError && !!state.mapUp
    && MAPS.some(s => (!onlySelected || state.selected.has(s.id)) && state.mapUp.sources[s.id] && state.mapUp.sources[s.id].discovery === 'pinned');

  /**
   * GitHub's listing couldn't be read just now, and this browser's earlier copy of it is used for some (selected)
   * mapping source (a source the copy has no files of uses the built-in list: mapListPinned).
   */
  const mapListStale = (onlySelected) => !state.mapDbError && !!state.mapUp && !!state.mapUp.stale
    && MAPS.some(s => (!onlySelected || state.selected.has(s.id)) && state.mapUp.sources[s.id] && state.mapUp.sources[s.id].discovery === 'github-api');

  /** Short names of the mapping sources whose versions come from GitHub's listing ('github-api') or the built-in list ('pinned'). */
  const mapSourcesFrom = discovery => MAPS.filter(s => state.mapUp.sources[s.id] && state.mapUp.sources[s.id].discovery === discovery).map(s => s.short);

  function renderToolbar() {
    const plan = pullPlan();
    const btn = $('#pullBtn');
    btn.disabled = state.busy || plan.length === 0;
    if (state.busy) btn.textContent = 'Pulling…';
    // a selected dataset whose release list couldn't be read: the plain label, as nothing can be called current
    // (it still pulls the mappings when they need it, and the status line says so)
    else if (!plan.some(id => !isMap(id)) && (!state.upstream || unchecked().length || uncheckedMaps().length)) btn.textContent = 'Pull';
    else if (plan.length === 0) btn.textContent = 'Pull (up to date)';
    else btn.textContent = 'Pull ' + plan.map(labelOf).join(' + ');
    $('#checkBtn').disabled = state.busy;
    $('#clearBtn').disabled = state.busy;
    $('#forceChk').disabled = state.busy;
    document.querySelectorAll('#domainCards .card, #mappingCards .card').forEach(c => {
      const id = c.id.slice(5);
      c.style.opacity = state.selected.has(id) ? '' : '.6';
    });
  }

  function renderCounts() {
    renderMapCounts();
    const t = $('#countsTable');
    const domains = AttackDB.DOMAINS.filter(d => state.meta[d.id]);
    if (!domains.length) {
      const maps = MAPS.some(s => state.mapMeta[s.id]);
      t.replaceChildren(el('tbody', {}, el('tr', {}, el('td', { class: 'empty',
        text: maps ? 'No ATT&CK or ATLAS data pulled yet.' : 'No data pulled yet. Press Pull.' }))));
      return;
    }
    const head = el('tr', {}, el('th', { text: 'Active records' }),
      ...domains.map(d => el('th', { class: 'num', text: d.label + ' v' + state.meta[d.id].version })));
    // skip kinds that are empty everywhere (e.g. data sources, deprecated upstream since v18)
    const kinds = [...DISPLAY_KINDS, 'relationships'].filter(k => domains.some(d => state.meta[d.id].counts[k]));
    const rows = kinds.map(k => el('tr', {},
      el('td', { text: AttackDB.KIND_LABELS[k] || 'Relationships' }),
      ...domains.map(d => el('td', { class: 'num', text: state.meta[d.id].counts[k] == null ? '—' : fmtN(state.meta[d.id].counts[k]) })),
    ));
    t.replaceChildren(el('thead', {}, head), el('tbody', {}, ...rows));
  }

  /** Mappings with a control (meta rows from before that count was kept: all rows but the not-mappable). */
  const mappedOf = c => (c.mapped != null ? c.mapped : (c.rows || 0) - (c.nonMappable || 0));

  /** What a mapping count holds: ' (5,264 distinct)' or ''. */
  const mappingDetail = c => (c.pairs != null && c.pairs < mappedOf(c) ? ' (' + fmtN(c.pairs) + ' distinct)' : '');

  function renderMapCounts() {
    const t = $('#mappingCountsTable');
    if (!t) return;
    const wrap = $('#mappingCountsWrap');
    if (wrap) wrap.hidden = !MAPS.length;   // mappings-db.js didn't load: the page is the knowledge-base page it was
    const stored = MAPS.filter(s => state.mapMeta[s.id]);
    if (!stored.length) {
      t.replaceChildren(el('tbody', {}, el('tr', {}, el('td', { class: 'empty',
        text: state.mapDbError ? 'The mappings database is unavailable.' : 'No control mappings pulled yet.' }))));
      return;
    }
    const dash = n => (n == null ? '—' : fmtN(n));
    t.replaceChildren(
      el('thead', {}, el('tr', {}, ...['Dataset', 'Version', 'Control mappings', 'Controls', 'ATT&CK techniques mapped',
        'Techniques judged not mappable', 'Control descriptions'].map((h, i) => el('th', { class: i > 1 ? 'num' : '', text: h })))),
      el('tbody', {}, ...stored.map(s => {
        const m = state.mapMeta[s.id], c = m.counts || {};
        return el('tr', {},
          el('td', { text: s.short }),
          el('td', { text: MDB.versionLabel(s.id, m.version) }),
          el('td', { class: 'num', text: fmtN(mappedOf(c)) + mappingDetail(c) }),
          el('td', { class: 'num', text: dash(c.capabilities) }),
          el('td', { class: 'num', text: dash(c.techniques) }),
          el('td', { class: 'num', text: dash(c.nonMappable) }),
          el('td', { class: 'num', text: dash(m.details) }),
        );
      })),
    );
  }

  /** ATT&CK / ATLAS and mapping pulls in one list, newest first. */
  async function renderHistory() {
    const [kb, maps] = await Promise.all([
      AttackDB.getHistory(25),
      MDB && !state.mapDbError ? MDB.getHistory(25).catch(() => []) : [],
    ]);
    const rows = [...kb, ...maps].sort((a, b) => String(b.pulledAt).localeCompare(String(a.pulledAt))).slice(0, 25);
    const t = $('#historyTable');
    if (!rows.length) {
      t.replaceChildren(el('tbody', {}, el('tr', {}, el('td', { class: 'empty', text: 'No pulls yet.' }))));
    } else {
      t.replaceChildren(
        el('thead', {}, el('tr', {}, ...['When', 'Dataset', 'Version', 'Previous', 'Objects', 'Relationships']
          .map((h, i) => el('th', { class: i > 3 ? 'num' : '', text: h })))),
        el('tbody', {}, ...rows.map(r => r.source ? el('tr', {},
          el('td', { text: fmtDate(r.pulledAt) }),
          el('td', { text: labelOf(r.source) }),
          el('td', { text: r.label || MDB.versionLabel(r.source, r.version) }),
          el('td', { text: r.previousVersion ? MDB.versionLabel(r.source, r.previousVersion) : '—' }),
          el('td', { class: 'num', text: fmtN(mappedOf(r.counts || {})) + ' mappings' }),
          el('td', { class: 'num', text: '—' }),
        ) : el('tr', {},
          el('td', { text: fmtDate(r.pulledAt) }),
          el('td', { text: labelOf(r.domain) }),
          el('td', { text: 'v' + r.version }),
          el('td', { text: r.previousVersion ? 'v' + r.previousVersion : '—' }),
          el('td', { class: 'num', text: fmtN(r.counts.totalObjects) }),
          el('td', { class: 'num', text: fmtN(r.counts.totalRelationships) }),
        ))),
      );
    }
    if (navigator.storage && navigator.storage.estimate) {
      try {
        const e = await navigator.storage.estimate();
        $('#storageInfo').textContent = 'Browser storage used: ' + fmtMB(e.usage || 0);
      } catch (_) {}
    }
  }

  function renderSearchFilters() {
    const dSel = $('#qDomain');
    dSel.replaceChildren(el('option', { value: '', text: 'All domains' }),
      ...AttackDB.DOMAINS.map(d => el('option', { value: d.id, text: d.label })));
    const kSel = $('#qKind');
    kSel.replaceChildren(el('option', { value: '', text: 'All types' }),
      ...DISPLAY_KINDS.map(k => el('option', { value: k, text: AttackDB.KIND_LABELS[k] })));
  }

  let searchSeq = 0;
  async function runSearch() {
    const seq = ++searchSeq;
    const q = $('#q').value;
    const t = $('#results');
    if (!q.trim()) { t.replaceChildren(); return; }
    const kind = $('#qKind').value;
    const rows = await AttackDB.search(q, {
      domain: $('#qDomain').value || undefined,
      kinds: kind ? [kind] : undefined,
      limit: 50,
    });
    if (seq !== searchSeq) return;
    if (!rows.length) {
      t.replaceChildren(el('tbody', {}, el('tr', {}, el('td', { class: 'empty', text: 'No matches in the local database.' }))));
      return;
    }
    const label = id => (AttackDB.DOMAINS.find(d => d.id === id) || { label: id }).label;
    t.replaceChildren(
      el('thead', {}, el('tr', {}, ...['ID', 'Name', 'Type', 'Domain'].map(h => el('th', { text: h })))),
      el('tbody', {}, ...rows.map(o => {
        const idCell = el('td', { class: 'mono' });
        if (o.url) idCell.append(el('a', { href: o.url, target: '_blank', rel: 'noopener', text: o.attackId || '—' }));
        else idCell.textContent = o.attackId || '—';
        const kindText = o.kind === 'software' ? 'Software (' + (o.softwareType || o.type) + ')'
          : o.kind === 'case-study' ? 'Case study' : o.kind === 'entity' ? 'Entity' : (AttackDB.KIND_LABELS[o.kind] || o.kind).replace(/s$/, '');
        return el('tr', {}, idCell, el('td', { text: o.name || '' }), el('td', { text: kindText }), el('td', { text: label(o.domain) }));
      })),
    );
  }

  function setGlobal(msg, cls) {
    const s = $('#globalStatus');
    s.textContent = msg || '';
    s.style.color = cls ? 'var(--' + cls + ')' : '';
  }

  // ---------- actions ----------

  async function refreshLocal() {
    const rows = await AttackDB.getAllMeta();
    state.meta = Object.fromEntries(rows.map(r => [r.domain, r]));
  }

  async function refreshMappings() {
    if (!MDB) return;
    try {
      await MDB.open();
      state.mapMeta = Object.fromEntries((await MDB.getAllMeta()).map(r => [r.source, r]));
      state.mapDbError = null;
    } catch (e) {
      state.mapDbError = e.message || String(e);
    }
  }

  /** Ask MITRE and CTID for their release lists. fresh: read GitHub's CTID file listing again, not this browser's copy. */
  async function checkUpstream(fresh) {
    setGlobal('Checking MITRE and CTID for new releases…');
    // the mapping file list never fails outright (it falls back to the built-in list), so read both together
    const readMaps = MDB && !state.mapDbError;
    const [kb, maps] = await Promise.allSettled([AttackDB.fetchUpstreamIndex(),
      readMaps ? MDB.fetchUpstreamIndex(fresh === true ? {} : { maxAge: LISTING_MAX_AGE }) : null]);
    let mapFailed = '';
    if (readMaps) {
      state.mapChecked = true;
      if (maps.status === 'fulfilled') state.mapUp = maps.value;
      else mapFailed = 'Could not read the CTID mapping file list (' + (maps.reason && maps.reason.message) + ').';
    }
    const mapOutdated = MAPS.filter(s => state.selected.has(s.id) && mapNeedsPull(s.id));
    const mapUnknown = uncheckedMaps();
    const when = 'Checked ' + fmtDate(new Date().toISOString());
    if (kb.status === 'fulfilled') {
      state.upstream = kb.value;
      const outdated = [...AttackDB.DOMAINS.filter(d => state.selected.has(d.id) && needsPull(d.id)).map(d => d.label), ...mapOutdated.map(s => s.short)];
      const unknown = [...unchecked().map(d => d.label), ...mapUnknown.map(s => s.short)];
      const failed = Object.entries(state.upstream.errors || {})
        .map(([fam, msg]) => 'Could not read the ' + (AttackDB.FAMILIES[fam] ? AttackDB.FAMILIES[fam].name : fam) + ' release list (' + msg + ').');
      if (mapFailed) failed.push(mapFailed);
      const dbBlocked = !!state.mapDbError && MAPS.some(s => state.selected.has(s.id));
      if (dbBlocked) failed.push("The CTID mappings can't be pulled: the mappings database in this browser can't be opened.");
      // with the built-in CTID file list, or an earlier copy of GitHub's, nothing says the stored mappings are the
      // newest: don't claim they are
      const pinned = mapListPinned(true) || mapListStale(true);
      let head;
      if (outdated.length) head = 'New data available for ' + outdated.join(', ') + '.';
      else if (unknown.length) head = when + '.';
      else if (pinned || dbBlocked) {
        const kbCurrent = AttackDB.DOMAINS.filter(d => state.selected.has(d.id)).map(d => d.label);
        const said = [];
        if (kbCurrent.length) said.push(listText(kbCurrent) + (kbCurrent.length > 1 ? ' are' : ' is') + ' current');
        if (pinned) said.push('newer CTID mappings may exist (' + (state.mapUp.readError ? "GitHub's file list couldn't be read" : "GitHub's file list is incomplete") + ')');
        head = when + (said.length ? ' — ' + said.join('; ') : '') + '.';
      } else head = when + ' — everything selected is current.';
      setGlobal([head, unknown.length ? unknown.join(', ') + ' could not be checked.' : '', ...failed].filter(Boolean).join(' '),
        failed.length ? 'err' : outdated.length ? 'warn' : pinned ? '' : 'ok');
    } else {
      // AttackDB joins the reasons of both lists with '; ' ('Failed to fetch; Failed to fetch'): say each once
      setGlobal(['Could not read the MITRE release lists: ' + withStop([...new Set(String(kb.reason && kb.reason.message).split('; '))].join('; ')),
        mapOutdated.length ? 'New data available for ' + mapOutdated.map(s => s.short).join(', ') + '.' : '', mapFailed,
        state.mapDbError && MAPS.some(s => state.selected.has(s.id)) ? "The CTID mappings can't be pulled: the mappings database in this browser can't be opened." : '']
        .filter(Boolean).join(' '), 'err');
    }
    renderCards();
    renderToolbar();
  }

  /** 'Enterprise, ICS and ATLAS' */
  const listText = xs => (xs.length > 1 ? xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1] : xs.join(''));
  /** A reason as a sentence of its own, so the next sentence doesn't run on from it. */
  const withStop = t => (/[.!?]$/.test(t) ? t : t + '.');

  async function download(url, onProgress) {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status + ' for ' + url);
    const total = Number(res.headers.get('content-length')) || 0;
    if (!res.body || !res.body.getReader) {
      const text = await res.text();
      onProgress(text.length, text.length);
      return text;
    }
    const reader = res.body.getReader();
    const chunks = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      onProgress(received, total);
    }
    const buf = new Uint8Array(received);
    let off = 0;
    for (const c of chunks) { buf.set(c, off); off += c.length; }
    return new TextDecoder('utf-8').decode(buf);
  }

  const nextFrame = () => new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)));

  async function pullDomain(domainId) {
    const target = targetVersion(domainId);
    const up = state.upstream.domains[domainId];
    const prog = $('#prog-' + domainId);
    const bar = prog.firstElementChild;
    const stage = $('#stage-' + domainId);
    const setStage = (t, cls) => {
      state.stageMsg[domainId] = { text: t, cls };
      stage.textContent = t;
      stage.style.color = cls ? 'var(--' + cls + ')' : '';
    };
    prog.hidden = false;
    prog.classList.remove('indeterminate');
    bar.style.width = '0';

    const text = await download(target.url, (got, total) => {
      if (total) {
        bar.style.width = Math.min(100, (got / total) * 100).toFixed(1) + '%';
        setStage('Downloading v' + target.version + ' — ' + fmtMB(got) + ' of ' + fmtMB(total));
      } else {
        prog.classList.add('indeterminate');
        setStage('Downloading v' + target.version + ' — ' + fmtMB(got));
      }
    });

    prog.classList.add('indeterminate');
    const atlas = domainOf(domainId).family === 'atlas';
    setStage('Parsing ' + fmtMB(text.length) + (atlas ? ' of YAML…' : ' of STIX…'));
    await nextFrame();
    let normalized;
    const formatMeta = {};
    if (atlas) {
      const doc = AttackDB.parseYaml(text);
      const v = doc && doc.collection && doc.collection.version != null ? String(doc.collection.version) : null;
      if (v !== target.version) throw new Error('File reports v' + v + ', expected v' + target.version);
      setStage('Normalizing ATLAS v' + v + '…');
      await nextFrame();
      normalized = AttackDB.normalizeAtlas(domainId, doc);
      formatMeta.formatVersion = String(doc['format-version']);
    } else {
      const bundle = JSON.parse(text);
      if (bundle.type !== 'bundle' || !Array.isArray(bundle.objects)) throw new Error('Not a STIX bundle');

      const collection = bundle.objects.find(o => o.type === 'x-mitre-collection');
      if (collection && collection.x_mitre_version && collection.x_mitre_version !== target.version) {
        throw new Error('Bundle reports v' + collection.x_mitre_version + ', expected v' + target.version);
      }

      setStage('Normalizing ' + fmtN(bundle.objects.length) + ' objects…');
      await nextFrame();
      normalized = AttackDB.normalizeBundle(domainId, bundle);
      formatMeta.attackSpecVersion = collection ? collection.x_mitre_attack_spec_version : null;
    }

    setStage('Writing to local database…');
    await nextFrame();
    const prev = state.meta[domainId];
    const metaRow = Object.assign({
      domain: domainId,
      version: target.version,
      modified: target.modified,
      url: target.url,
      collectionId: up.collectionId,
      pulledAt: new Date().toISOString(),
      bytes: text.length,
      previousVersion: prev ? prev.version : null,
      counts: normalized.counts,
    }, formatMeta);
    await AttackDB.replaceDomain(domainId, normalized, metaRow);
    state.meta[domainId] = metaRow;

    prog.classList.remove('indeterminate');
    bar.style.width = '100%';
    setStage('Stored v' + target.version + ': ' + fmtN(normalized.counts.totalObjects) + ' objects, ' +
      fmtN(normalized.counts.totalRelationships) + ' relationships.', 'ok');
  }

  /** One CTID mapping source: MappingsDB downloads, checks and stores it in one transaction. */
  async function pullMapping(id) {
    const target = mapTarget(id);
    const prog = $('#prog-' + id);
    const bar = prog.firstElementChild;
    const stage = $('#stage-' + id);
    const setStage = (t, cls) => {
      state.stageMsg[id] = { text: t, cls };
      stage.textContent = t;
      stage.style.color = cls ? 'var(--' + cls + ')' : '';
    };
    prog.hidden = false;
    prog.classList.remove('indeterminate');
    bar.style.width = '0';

    const meta = await MDB.pullSource(id, target, (text, fraction) => {
      if (fraction == null) prog.classList.add('indeterminate');
      else {
        prog.classList.remove('indeterminate');
        bar.style.width = (Math.min(1, Math.max(0, fraction)) * 100).toFixed(1) + '%';
      }
      setStage(text);
    });
    state.mapMeta[id] = meta;

    prog.classList.remove('indeterminate');
    bar.style.width = '100%';
    const c = meta.counts;
    // 'Stored Rev 5 · ATT&CK 16.1: 5,314 control–technique mappings (5,264 distinct) for 470 techniques across
    // 109 controls; 96 techniques judged not mappable; 118 control descriptions.'
    const plural = (n, word) => fmtN(n) + ' ' + word + (n === 1 ? '' : 's');
    setStage('Stored ' + meta.label + ': ' + fmtN(mappedOf(c)) + ' control–technique mappings'
      + mappingDetail(c) + ' for ' + plural(c.techniques, 'technique') + ' across ' + plural(c.capabilities, 'control')
      + (c.nonMappable ? '; ' + plural(c.nonMappable, 'technique') + ' judged not mappable' : '')
      + (meta.details ? '; ' + fmtN(meta.details) + ' control descriptions' : '; control descriptions unavailable' + (meta.detailsError ? ': ' + meta.detailsError : ''))
      + (c.skipped ? '; ' + fmtN(c.skipped) + ' malformed entries skipped' : '') + '.', 'ok');
  }

  async function pull() {
    const plan = pullPlan();
    if (!plan.length || state.busy) return;
    state.busy = true;
    renderCards();
    renderToolbar();
    setGlobal('Pulling ' + plan.length + ' dataset' + (plan.length > 1 ? 's' : '') + '…');
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});

    const failures = [];
    for (const id of plan) {
      try {
        if (isMap(id)) await pullMapping(id);
        else await pullDomain(id);
      } catch (e) {
        console.error(e);
        failures.push(id);
        state.stageMsg[id] = { text: 'Failed: ' + e.message, cls: 'err' };
      }
    }

    state.busy = false;
    renderCards();
    renderToolbar();
    renderCounts();
    await renderHistory().catch(() => {});   // so the history is current when "Pull complete." shows
    runSearch();
    setGlobal(failures.length
      ? 'Finished with errors (' + failures.length + ' failed). Existing data for failed datasets was left untouched.'
      : 'Pull complete.', failures.length ? 'err' : 'ok');
  }

  async function clearDb() {
    if (!confirm('Delete all locally stored data and pull history — the ATT&CK and ATLAS knowledge bases and the ' +
      'CTID control mappings (NIST 800-53)?')) return;
    const failed = [], cleared = [];
    try {
      await AttackDB.clearAll();
      state.meta = {};
      for (const d of AttackDB.DOMAINS) delete state.stageMsg[d.id];
      cleared.push('The ATT&CK and ATLAS data was cleared.');
    } catch (e) { failed.push('The ATT&CK and ATLAS database could not be cleared (' + e.message + ').'); }
    if (MDB) {
      try {
        await MDB.clearAll();   // opens the database again, in case it couldn't be opened before
        state.mapMeta = {};
        state.mapDbError = null;
        for (const s of MAPS) delete state.stageMsg[s.id];
        cleared.push('The mappings were cleared.');
      } catch (e) {
        failed.push(/^The mappings database/.test(e.message) ? e.message : 'The mappings could not be cleared (' + e.message + ').');
      }
    }
    renderCards();
    renderToolbar();
    renderCounts();
    await renderHistory().catch(() => {});
    runSearch();
    setGlobal(failed.length ? ['Could not clear everything.', ...failed, ...cleared].join(' ') : 'Local database cleared.',
      failed.length ? 'err' : '');
  }

  // ---------- boot ----------

  async function init() {
    renderSearchFilters();
    $('#pullBtn').addEventListener('click', pull);
    $('#checkBtn').addEventListener('click', () => checkUpstream(true));
    $('#clearBtn').addEventListener('click', clearDb);
    $('#forceChk').addEventListener('change', renderToolbar);
    let t;
    $('#q').addEventListener('input', () => { clearTimeout(t); t = setTimeout(runSearch, 150); });
    $('#qDomain').addEventListener('change', runSearch);
    $('#qKind').addEventListener('change', runSearch);

    try {
      await AttackDB.open();
      await refreshLocal();
    } catch (e) {
      setGlobal('Local database unavailable: ' + e.message, 'err');
    }
    await refreshMappings();
    renderCards();
    renderToolbar();
    renderCounts();
    renderHistory();
    await checkUpstream(false);
  }

  init();
})();
