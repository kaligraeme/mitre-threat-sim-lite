/* data-manager.js — UI for checking and pulling MITRE ATT&CK and ATLAS releases into AttackDB. */
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

  const state = {
    upstream: null,          // result of fetchUpstreamIndex()
    meta: {},                // domain -> meta row
    selected: loadSelected(),
    chosenVersion: {},       // domain -> version string picked in the dropdown
    busy: false,
    stageMsg: {},            // domain -> {text, cls} last pull message
  };

  function loadSelected() {
    const defaults = AttackDB.DOMAINS.filter(d => d.enabled).map(d => d.id);
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
      localStorage.setItem(KNOWN_KEY, JSON.stringify(AttackDB.DOMAINS.map(d => d.id)));
    } catch (_) {}
  }

  const fmtDate = s => s ? new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  // ATLAS release dates are plain days ('2026-10-28'): show them as written, not shifted to the local time zone
  const fmtDay = s => s ? new Date(s).toLocaleDateString(undefined,
    /^\d{4}-\d{2}-\d{2}$/.test(s) ? { dateStyle: 'medium', timeZone: 'UTC' } : { dateStyle: 'medium' }) : '—';
  const fmtMB = n => (n / 1048576).toFixed(1) + ' MB';
  const fmtN = n => (n ?? 0).toLocaleString();

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

  /** Selected domains whose release list could not be read, so their status is unknown. */
  const unchecked = () => AttackDB.DOMAINS.filter(d => state.selected.has(d.id) && state.upstream && !state.upstream.domains[d.id]);

  function pullPlan() {
    const force = $('#forceChk').checked;
    return AttackDB.DOMAINS
      .filter(d => state.selected.has(d.id) && targetVersion(d.id))
      .filter(d => force || needsPull(d.id))
      .map(d => d.id);
  }

  // ---------- rendering ----------

  function renderCards() {
    const host = $('#domainCards');
    host.replaceChildren();
    for (const d of AttackDB.DOMAINS) {
      const meta = state.meta[d.id];
      const up = state.upstream && state.upstream.domains[d.id];
      const st = domainStatus(d.id);

      const chk = el('input', { type: 'checkbox', id: 'sel-' + d.id, 'aria-label': 'Include ' + d.label });
      chk.checked = state.selected.has(d.id);
      chk.disabled = state.busy;
      chk.addEventListener('change', () => {
        chk.checked ? state.selected.add(d.id) : state.selected.delete(d.id);
        saveSelected();
        renderToolbar();
      });

      const sel = el('select', { 'aria-label': d.label + ' version to pull' });
      sel.disabled = state.busy || !up;
      if (up) {
        up.versions.forEach((v, i) => {
          const o = el('option', { value: v.version, text: 'v' + v.version + (i === 0 ? ' (latest)' : '') });
          sel.append(o);
        });
        sel.value = (targetVersion(d.id) || up.latest).version;
      } else {
        sel.append(el('option', { text: '—' }));
      }
      sel.addEventListener('change', () => {
        state.chosenVersion[d.id] = sel.value;
        renderToolbar();
      });

      const kv = el('dl', { class: 'kv' },
        el('dt', { text: 'Stored' }), el('dd', { text: meta ? 'v' + meta.version + ' · released ' + fmtDay(meta.modified)
          + (meta.formatVersion ? ' · format ' + meta.formatVersion : '') : 'nothing yet' }),
        el('dt', { text: 'Pulled' }), el('dd', { text: meta ? fmtDate(meta.pulledAt) : '—' }),
        el('dt', { text: 'Latest' }), el('dd', { text: up ? 'v' + up.latest.version + ' · released ' + fmtDay(up.latest.modified) : '—' }),
        el('dt', { text: 'Pull' }), el('dd', {}, sel),
      );

      const card = el('div', { class: 'card', id: 'card-' + d.id },
        el('div', { class: 'card-head' },
          chk,
          el('label', { for: 'sel-' + d.id }, el('h2', { text: d.title })),
          el('span', { class: 'pill ' + st.cls, text: st.text }),
        ),
        kv,
        d.note ? el('p', { class: 'card-note', text: d.note }) : '',
        el('div', { class: 'progress', id: 'prog-' + d.id, hidden: '' }, el('div')),
        el('div', { class: 'stage', id: 'stage-' + d.id }),
      );
      const msg = state.stageMsg[d.id];
      if (msg) {
        const s = card.querySelector('.stage');
        s.textContent = msg.text;
        if (msg.cls) s.style.color = 'var(--' + msg.cls + ')';
      }
      if (!state.selected.has(d.id)) card.style.opacity = '.6';
      host.append(card);
    }
  }

  function renderToolbar() {
    const plan = pullPlan();
    const btn = $('#pullBtn');
    btn.disabled = state.busy || !state.upstream || plan.length === 0;
    if (state.busy) btn.textContent = 'Pulling…';
    else if (!state.upstream) btn.textContent = 'Pull';
    else if (plan.length === 0) btn.textContent = unchecked().length ? 'Pull' : 'Pull (up to date)';
    else btn.textContent = 'Pull ' + plan.map(id => AttackDB.DOMAINS.find(d => d.id === id).label).join(' + ');
    $('#checkBtn').disabled = state.busy;
    $('#clearBtn').disabled = state.busy;
    $('#forceChk').disabled = state.busy;
    document.querySelectorAll('#domainCards .card').forEach(c => {
      const id = c.id.slice(5);
      c.style.opacity = state.selected.has(id) ? '' : '.6';
    });
  }

  function renderCounts() {
    const t = $('#countsTable');
    const domains = AttackDB.DOMAINS.filter(d => state.meta[d.id]);
    if (!domains.length) {
      t.replaceChildren(el('tbody', {}, el('tr', {}, el('td', { class: 'empty', text: 'No data pulled yet. Press Pull.' }))));
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

  async function renderHistory() {
    const rows = await AttackDB.getHistory(25);
    const t = $('#historyTable');
    if (!rows.length) {
      t.replaceChildren(el('tbody', {}, el('tr', {}, el('td', { class: 'empty', text: 'No pulls yet.' }))));
    } else {
      const label = id => (AttackDB.DOMAINS.find(d => d.id === id) || { label: id }).label;
      t.replaceChildren(
        el('thead', {}, el('tr', {}, ...['When', 'Domain', 'Version', 'Previous', 'Objects', 'Relationships']
          .map((h, i) => el('th', { class: i > 3 ? 'num' : '', text: h })))),
        el('tbody', {}, ...rows.map(r => el('tr', {},
          el('td', { text: fmtDate(r.pulledAt) }),
          el('td', { text: label(r.domain) }),
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

  async function checkUpstream() {
    setGlobal('Checking MITRE for new releases…');
    try {
      state.upstream = await AttackDB.fetchUpstreamIndex();
      const outdated = AttackDB.DOMAINS.filter(d => state.selected.has(d.id) && needsPull(d.id));
      const unknown = unchecked();
      const failed = Object.entries(state.upstream.errors || {})
        .map(([fam, msg]) => 'Could not read the ' + AttackDB.FAMILIES[fam].name + ' release list (' + msg + ').');
      setGlobal([outdated.length ? 'New data available for ' + outdated.map(d => d.label).join(', ') + '.'
        : unknown.length ? 'Checked ' + fmtDate(new Date().toISOString()) + '.'
          : 'Checked ' + fmtDate(new Date().toISOString()) + ' — everything selected is current.',
        unknown.length ? unknown.map(d => d.label).join(', ') + ' could not be checked.' : '',
        ...failed].filter(Boolean).join(' '),
        failed.length ? 'err' : outdated.length ? 'warn' : 'ok');
    } catch (e) {
      setGlobal('Could not read the MITRE release lists: ' + e.message, 'err');
    }
    renderCards();
    renderToolbar();
  }

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
        await pullDomain(id);
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
    renderHistory();
    runSearch();
    setGlobal(failures.length
      ? 'Finished with errors (' + failures.length + ' failed). Existing data for failed domains was left untouched.'
      : 'Pull complete.', failures.length ? 'err' : 'ok');
  }

  async function clearDb() {
    if (!confirm('Delete all locally stored ATT&CK and ATLAS data and pull history?')) return;
    await AttackDB.clearAll();
    state.meta = {};
    renderCards();
    renderToolbar();
    renderCounts();
    renderHistory();
    runSearch();
    setGlobal('Local database cleared.');
  }

  // ---------- boot ----------

  async function init() {
    renderSearchFilters();
    $('#pullBtn').addEventListener('click', pull);
    $('#checkBtn').addEventListener('click', checkUpstream);
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
    renderCards();
    renderToolbar();
    renderCounts();
    renderHistory();
    await checkUpstream();
  }

  init();
})();
