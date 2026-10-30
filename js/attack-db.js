/*
 * attack-db.js — local MITRE ATT&CK and ATLAS data instance (IndexedDB).
 *
 * Shared by every page of the threat simulator. Exposes a global `AttackDB`
 * (classic script, so pages also work when opened straight from file://).
 *
 * ATT&CK domains come from the STIX 2.1 bundles; ATLAS comes from its YAML export (format v6),
 * normalized into the same records so the simulator treats every domain alike.
 *
 * Stores
 *   meta           one row per domain: version, source URL, pulled-at, counts
 *   objects        normalized objects, key "<domain>|<id>" (STIX id, or ATLAS ID such as AML.T0051)
 *   relationships  normalized relationships, key "<domain>|<id>"
 *   raw            original objects (incl. relationships): {key, stix} or {key, atlas}
 *   history        append-only log of pulls
 */
(function (global) {
  'use strict';

  const DB_NAME = 'mitre-attack-db';
  const DB_VERSION = 1;

  const INDEX_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json';
  // ATLAS publishes YAML on GitHub. dist/ATLAS-latest.yaml is a git symlink (raw.githubusercontent.com
  // serves the link text), so releases are always read through the manifest.
  const ATLAS_RAW = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/';
  const ATLAS_MANIFEST_URL = ATLAS_RAW + 'manifest.yaml';
  const ATLAS_SITE = 'https://atlas.mitre.org/';

  // Knowledge bases: ATT&CK (several domains) and ATLAS (one).
  const FAMILIES = {
    attack: { name: 'ATT&CK', site: 'attack.mitre.org' },
    atlas: { name: 'ATLAS', site: 'atlas.mitre.org' },
  };

  // Domains the simulator works with. Mobile is available upstream but off by default.
  const DOMAINS = [
    { id: 'enterprise-attack', label: 'Enterprise', title: 'Enterprise ATT&CK', family: 'attack', collection: 'Enterprise ATT&CK', enabled: true },
    { id: 'ics-attack',        label: 'ICS',        title: 'ICS ATT&CK',        family: 'attack', collection: 'ICS ATT&CK',        enabled: true },
    { id: 'mobile-attack',     label: 'Mobile',     title: 'Mobile ATT&CK',     family: 'attack', collection: 'Mobile ATT&CK',     enabled: false },
    { id: 'atlas',             label: 'ATLAS',      title: 'ATLAS',             family: 'atlas',  collection: 'ATLAS',             enabled: true,
      note: 'Threats to AI systems. Case studies cover every release; entities and software start with v2026.10.' },
  ];

  // STIX type -> simulator "kind"
  const KIND_BY_TYPE = {
    'attack-pattern': 'technique',
    'intrusion-set': 'group',
    'malware': 'software',
    'tool': 'software',
    'campaign': 'campaign',
    'course-of-action': 'mitigation',
    'x-mitre-detection-strategy': 'detection-strategy',
    'x-mitre-analytic': 'analytic',
    'x-mitre-data-component': 'data-component',
    'x-mitre-data-source': 'data-source',
    'x-mitre-tactic': 'tactic',
    'x-mitre-asset': 'asset',
    'x-mitre-matrix': 'matrix',
    'x-mitre-collection': 'collection',
  };

  const KIND_LABELS = {
    'technique': 'Techniques',
    'group': 'Groups',
    'entity': 'Entities',
    'software': 'Software',
    'campaign': 'Campaigns',
    'case-study': 'Case studies',
    'mitigation': 'Mitigations',
    'detection-strategy': 'Detection strategies',
    'analytic': 'Analytics',
    'data-component': 'Data components',
    'data-source': 'Data sources',
    'tactic': 'Tactics',
    'asset': 'Assets',
    'matrix': 'Matrices',
  };

  let dbPromise = null;

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

  function open() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      const r = indexedDB.open(DB_NAME, DB_VERSION);
      r.onupgradeneeded = () => {
        const db = r.result;
        if (!db.objectStoreNames.contains('meta')) {
          db.createObjectStore('meta', { keyPath: 'domain' });
        }
        if (!db.objectStoreNames.contains('objects')) {
          const s = db.createObjectStore('objects', { keyPath: 'key' });
          s.createIndex('domain', 'domain');
          s.createIndex('domain_kind', ['domain', 'kind']);
          s.createIndex('attackId', 'attackId');
          s.createIndex('id', 'id');
        }
        if (!db.objectStoreNames.contains('relationships')) {
          const s = db.createObjectStore('relationships', { keyPath: 'key' });
          s.createIndex('domain', 'domain');
          s.createIndex('domain_source', ['domain', 'source']);
          s.createIndex('domain_target', ['domain', 'target']);
          s.createIndex('domain_relType', ['domain', 'relType']);
        }
        if (!db.objectStoreNames.contains('raw')) {
          db.createObjectStore('raw', { keyPath: 'key' });
        }
        if (!db.objectStoreNames.contains('history')) {
          db.createObjectStore('history', { keyPath: 'seq', autoIncrement: true });
        }
      };
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
      r.onblocked = () => reject(new Error('Database upgrade blocked — close other tabs of this app.'));
    });
    return dbPromise;
  }

  function domainRange(domain) {
    return IDBKeyRange.bound(domain + '|', domain + '|\uffff');
  }

  // ---------- normalization ----------

  // Older ICS and Mobile releases tag their IDs 'mitre-ics-attack' / 'mitre-mobile-attack'.
  const MITRE_SOURCES = ['mitre-attack', 'mitre-ics-attack', 'mitre-mobile-attack'];
  function mitreRef(o) {
    const refs = (o.external_references || []).filter(r => r.external_id && MITRE_SOURCES.includes(r.source_name));
    return refs.find(r => r.source_name === 'mitre-attack') || refs[0] || null;
  }

  function normalizeObject(domain, o) {
    const ref = mitreRef(o);
    const rec = {
      key: domain + '|' + o.id,
      domain,
      id: o.id,
      type: o.type,
      kind: KIND_BY_TYPE[o.type] || 'other',
      attackId: ref ? ref.external_id : null,
      url: ref ? ref.url || null : null,
      name: o.name || null,
      description: o.description || '',
      created: o.created || null,
      modified: o.modified || null,
      version: o.x_mitre_version || null,
      revoked: !!o.revoked,
      deprecated: !!o.x_mitre_deprecated,
      domains: o.x_mitre_domains || [domain],
      platforms: o.x_mitre_platforms || [],
    };
    rec.active = !rec.revoked && !rec.deprecated;

    switch (o.type) {
      case 'attack-pattern':
        rec.isSubtechnique = !!o.x_mitre_is_subtechnique;
        rec.tactics = (o.kill_chain_phases || []).map(p => p.phase_name);
        rec.parent = null; // filled from subtechnique-of relationships
        break;
      case 'intrusion-set':
      case 'campaign':
        rec.aliases = o.aliases || [];
        if (o.type === 'campaign') {
          rec.firstSeen = o.first_seen || null;
          rec.lastSeen = o.last_seen || null;
        }
        break;
      case 'malware':
      case 'tool':
        rec.softwareType = o.type;
        rec.aliases = o.x_mitre_aliases || [];
        break;
      case 'x-mitre-tactic':
        rec.shortname = o.x_mitre_shortname || null;
        break;
      case 'x-mitre-matrix':
        rec.tacticRefs = o.tactic_refs || [];
        break;
      case 'x-mitre-detection-strategy':
        rec.analyticRefs = o.x_mitre_analytic_refs || [];
        break;
      case 'x-mitre-analytic':
        rec.logSources = (o.x_mitre_log_source_references || []).map(l => ({
          dataComponent: l.x_mitre_data_component_ref || null,
          name: l.name || null,
          channel: l.channel || null,
        }));
        break;
      case 'x-mitre-data-component':
        rec.logSources = o.x_mitre_log_sources || [];
        rec.dataSource = o.x_mitre_data_source_ref || null;
        break;
      case 'x-mitre-asset':
        rec.sectors = o.x_mitre_sectors || [];
        break;
    }
    return rec;
  }

  function normalizeRelationship(domain, r, objIndex) {
    const s = objIndex.get(r.source_ref);
    const t = objIndex.get(r.target_ref);
    return {
      key: domain + '|' + r.id,
      domain,
      id: r.id,
      relType: r.relationship_type,
      source: r.source_ref,
      target: r.target_ref,
      sourceKind: s ? s.kind : null,
      targetKind: t ? t.kind : null,
      description: r.description || '',
      modified: r.modified || null,
      revoked: !!r.revoked,
      deprecated: !!r.x_mitre_deprecated,
      // usable for analysis: relationship and both endpoints are current
      active: !r.revoked && !r.x_mitre_deprecated && !!s && !!t && s.active && t.active,
    };
  }

  /** Turn a STIX bundle into {objects, relationships, counts}. */
  function normalizeBundle(domain, bundle) {
    const raw = bundle.objects || [];
    const objects = [];
    const rawRels = [];
    const objIndex = new Map();

    for (const o of raw) {
      if (o.type === 'relationship') { rawRels.push(o); continue; }
      const rec = normalizeObject(domain, o);
      objects.push(rec);
      objIndex.set(o.id, rec);
    }

    const relationships = rawRels.map(r => normalizeRelationship(domain, r, objIndex));

    for (const r of relationships) {
      if (r.relType === 'subtechnique-of' && !r.revoked && !r.deprecated) {
        const child = objIndex.get(r.source);
        if (child) child.parent = r.target;
      }
    }

    const counts = {};
    for (const o of objects) {
      if (!o.active) continue;
      counts[o.kind] = (counts[o.kind] || 0) + 1;
    }
    counts.relationships = relationships.filter(r => r.active).length;
    counts.totalObjects = objects.length;
    counts.totalRelationships = relationships.length;

    return { objects, relationships, raw, counts };
  }

  // ---------- ATLAS (YAML export, format v6) ----------

  /** YAML text -> plain data. CORE_SCHEMA has only JSON types, so dates stay strings. Needs js/vendor/js-yaml.min.js. */
  function parseYaml(text) {
    if (!global.jsyaml) throw new Error('YAML parser not loaded (js/vendor/js-yaml.min.js)');
    return global.jsyaml.load(text, { schema: global.jsyaml.CORE_SCHEMA });
  }

  // ATLAS sections and the kind each becomes here (case studies and entities keep their ATLAS names)
  const ATLAS_SECTIONS = [
    ['tactics', 'tactic'], ['techniques', 'technique'], ['mitigations', 'mitigation'],
    ['case-studies', 'case-study'], ['entities', 'entity'], ['software', 'software'],
  ];
  const ATLAS_ROUTES = {
    tactic: 'tactics', technique: 'techniques', mitigation: 'mitigations',
    'case-study': 'studies', entity: 'entities', software: 'software',
  };
  // ATLAS relationship types the simulator traverses, in the ATT&CK vocabulary it already uses.
  // Others keep their names (achieves, sequences, reported-by); reported-by is provenance, not attribution.
  const ATLAS_REL_TYPES = { employs: 'uses', implements: 'uses', uses: 'uses', specializes: 'subtechnique-of' };
  // ATLAS's own STIX export uses the lower-cased tactic name as the kill-chain phase
  const tacticSlug = name => String(name || '').toLowerCase().replace(/ /g, '-');

  /** Turn a parsed ATLAS v6 export into {objects, relationships, raw, rawField, counts}. */
  function normalizeAtlas(domain, doc) {
    if (!doc || typeof doc !== 'object' || !doc.collection || !doc.relationships) throw new Error('Not an ATLAS export');
    const format = String(doc['format-version'] || '');
    if (format.split('.')[0] !== '6') throw new Error('Unsupported ATLAS format ' + (format || '(none)') + ' (expected 6.x)');

    const objects = [];
    const raw = [];   // [id, original object]
    const objIndex = new Map();
    const record = (o, kind) => {
      const ref = o['attack-reference'];
      return {
        key: domain + '|' + o.id,
        domain,
        id: o.id,
        type: o['object-type'] || kind,
        kind,
        attackId: o.id,
        url: ATLAS_ROUTES[kind] ? ATLAS_SITE + ATLAS_ROUTES[kind] + '/' + o.id : null,
        name: o.name || null,
        description: o.description || '',
        created: o['created-date'] || null,
        modified: o['modified-date'] || null,
        version: null,
        revoked: false,
        deprecated: false,
        active: true,
        domains: [domain],
        platforms: [],
        references: (o.references || []).map(r => ({ id: r.id || null, title: r.title || null, url: r.url || null })),
        attackRef: ref && ref.id ? { id: ref.id, url: ref.url || null } : null,   // the matching ATT&CK object, if any
      };
    };
    const add = (rec, original) => {
      objects.push(rec);
      objIndex.set(rec.id, rec);
      raw.push([rec.id, original]);
    };

    add(Object.assign(record(doc.collection, 'collection'),
      { version: doc.collection.version != null ? String(doc.collection.version) : null, formatVersion: format }), doc.collection);
    if (doc.matrix) add(Object.assign(record(doc.matrix, 'matrix'), { tacticRefs: [] }), doc.matrix);

    for (const [section, kind] of ATLAS_SECTIONS) {
      for (const o of Object.values(doc[section] || {})) {
        if (!o || !o.id) continue;
        const rec = record(o, kind);
        switch (kind) {
          case 'tactic':
            rec.shortname = tacticSlug(o.name);
            break;
          case 'technique':
            rec.platforms = o.platforms || [];
            rec.maturity = o.maturity || null;
            rec.isSubtechnique = /^AML\.T\d+\.\d+$/.test(o.id);
            rec.parent = null;   // from specializes
            rec.tactics = [];    // from achieves
            break;
          case 'mitigation':
            rec.categories = o.categories || [];
            rec.lifecyclePhases = o['lifecycle-phases'] || [];
            break;
          case 'case-study':
            rec.caseType = o.type || null;   // Incident or Exercise
            rec.actor = o.actor || null;
            rec.target = o.target || null;
            rec.reporter = o.reporter || null;
            if (o['start-date']) {   // format 6.1: a period; no end date means it is still ongoing
              rec.firstSeen = o['start-date'];
              rec.lastSeen = o['end-date'] || null;
              rec.startPrecision = o['start-date-granularity'] || null;
              rec.endPrecision = o['end-date-granularity'] || null;
            } else {                 // format 6.0: a single date
              rec.firstSeen = rec.lastSeen = o.date || null;
              rec.startPrecision = rec.endPrecision = o['date-granularity'] || null;
            }
            break;
          case 'entity':
            rec.entityType = o['entity-type'] || null;
            rec.aliases = (o['associated-entities'] || []).map(a => a && a.name).filter(Boolean);
            break;
          case 'software':
            rec.softwareType = o['software-type'] ? String(o['software-type']).toLowerCase() : null;   // tool / malware, as ATT&CK
            rec.softwareCategories = o['software-categories'] || [];
            rec.aliases = o.aliases || [];
            break;
        }
        add(rec, o);
      }
    }

    const relationships = [];
    for (const [source, byType] of Object.entries(doc.relationships || {})) {
      for (const [atlasType, list] of Object.entries(byType || {})) {
        (list || []).forEach((r, i) => {
          if (!r || !r.target) return;
          const src = r.source || source;
          const s = objIndex.get(src);
          const t = objIndex.get(r.target);
          const id = [src, atlasType, r.target, i].join('|');   // ATLAS relationships have no ids of their own
          const rel = {
            key: domain + '|' + id,
            domain,
            id,
            relType: ATLAS_REL_TYPES[atlasType] || atlasType,
            atlasType,
            source: src,
            target: r.target,
            sourceKind: s ? s.kind : null,
            targetKind: t ? t.kind : null,
            description: r.description || '',
            modified: null,
            revoked: false,
            deprecated: false,
            active: !!s && !!t,
          };
          if (r.tactic) rel.tactic = r.tactic;   // case-study step: the tactic it served (ATLAS ID)
          if (r['step-id']) rel.stepId = r['step-id'];
          if (r['leads-to']) rel.leadsTo = r['leads-to'];
          if (r['activity-purpose']) rel.activityPurpose = r['activity-purpose'];
          if (r.position != null) rel.position = r.position;
          relationships.push(rel);
          raw.push([id, r]);
        });
      }
    }

    const matrix = objects.find(o => o.kind === 'matrix');
    for (const r of relationships) {
      if (!r.active) continue;
      const src = objIndex.get(r.source), tgt = objIndex.get(r.target);
      if (src.kind !== 'technique') continue;
      if (r.atlasType === 'specializes') { src.isSubtechnique = true; src.parent = r.target; }
      else if (r.atlasType === 'achieves' && tgt.kind === 'tactic' && !src.tactics.includes(tgt.shortname)) src.tactics.push(tgt.shortname);
    }
    // Releases before 2026.05 give sub-techniques no specializes link and no tactics: take the parent
    // from the ID (AML.T0043.000 -> AML.T0043) and its tactics, as later releases do explicitly.
    for (const o of objects) {
      if (o.kind !== 'technique' || !o.isSubtechnique) continue;
      if (!o.parent) {
        const p = objIndex.get(o.id.replace(/\.\d+$/, ''));
        if (p && p.kind === 'technique' && p.id !== o.id) o.parent = p.id;
      }
      if (!o.tactics.length && o.parent) o.tactics = [...objIndex.get(o.parent).tactics];
    }
    if (matrix) {
      matrix.tacticRefs = relationships.filter(r => r.active && r.atlasType === 'sequences' && r.source === matrix.id)
        .sort((a, b) => (a.position ?? 0) - (b.position ?? 0)).map(r => r.target);
    }

    const counts = {};
    for (const o of objects) {
      if (!o.active) continue;
      counts[o.kind] = (counts[o.kind] || 0) + 1;
    }
    counts.relationships = relationships.filter(r => r.active).length;
    counts.totalObjects = objects.length;
    counts.totalRelationships = relationships.length;

    return { objects, relationships, raw, rawField: 'atlas', counts };
  }

  // ---------- writes ----------

  /** Atomically replace everything stored for `domain`. */
  async function replaceDomain(domain, normalized, metaRow) {
    const db = await open();
    const tx = db.transaction(['objects', 'relationships', 'raw', 'meta', 'history'], 'readwrite');
    const objects = tx.objectStore('objects');
    const rels = tx.objectStore('relationships');
    const raw = tx.objectStore('raw');
    objects.delete(domainRange(domain));
    rels.delete(domainRange(domain));
    raw.delete(domainRange(domain));
    for (const o of normalized.objects) objects.put(o);
    for (const r of normalized.relationships) rels.put(r);
    if (normalized.rawField === 'atlas') for (const [id, o] of normalized.raw) raw.put({ key: domain + '|' + id, atlas: o });
    else for (const o of normalized.raw) raw.put({ key: domain + '|' + o.id, stix: o });
    tx.objectStore('meta').put(metaRow);
    tx.objectStore('history').add({
      domain,
      version: metaRow.version,
      previousVersion: metaRow.previousVersion || null,
      pulledAt: metaRow.pulledAt,
      counts: metaRow.counts,
    });
    await txDone(tx);
  }

  async function clearAll() {
    const db = await open();
    const stores = ['objects', 'relationships', 'raw', 'meta', 'history'];
    const tx = db.transaction(stores, 'readwrite');
    for (const n of stores) tx.objectStore(n).clear();
    await txDone(tx);
  }

  // ---------- reads (used by the dashboard pages) ----------

  async function getMeta(domain) {
    const db = await open();
    return req(db.transaction('meta').objectStore('meta').get(domain));
  }

  async function getAllMeta() {
    const db = await open();
    return req(db.transaction('meta').objectStore('meta').getAll());
  }

  async function getHistory(limit = 50) {
    const db = await open();
    const all = await req(db.transaction('history').objectStore('history').getAll());
    return all.reverse().slice(0, limit);
  }

  /** Objects of one kind in a domain. Pass {includeInactive:true} to keep revoked/deprecated. */
  async function getObjects(domain, kind, opts = {}) {
    const db = await open();
    const idx = db.transaction('objects').objectStore('objects').index('domain_kind');
    const rows = await req(idx.getAll([domain, kind]));
    return opts.includeInactive ? rows : rows.filter(r => r.active);
  }

  async function getObject(domain, stixId) {
    const db = await open();
    return req(db.transaction('objects').objectStore('objects').get(domain + '|' + stixId));
  }

  /** Everything stored for one domain, for pages that work in memory. */
  async function loadDomain(domain) {
    const db = await open();
    const tx = db.transaction(['meta', 'objects', 'relationships']);
    const range = domainRange(domain);
    const [meta, objects, relationships] = await Promise.all([
      req(tx.objectStore('meta').get(domain)),
      req(tx.objectStore('objects').getAll(range)),
      req(tx.objectStore('relationships').getAll(range)),
    ]);
    return { meta, objects, relationships };
  }

  /** Original STIX or ATLAS object (external references, citations, etc.). */
  async function getRaw(domain, id) {
    const db = await open();
    const row = await req(db.transaction('raw').objectStore('raw').get(domain + '|' + id));
    return row ? row.stix || row.atlas || null : null;
  }

  /** Look up by ATT&CK ID (e.g. "T1059.001", "G0007") across all or one domain. */
  async function findByAttackId(attackId, domain) {
    const db = await open();
    const rows = await req(db.transaction('objects').objectStore('objects').index('attackId').getAll(attackId));
    return domain ? rows.filter(r => r.domain === domain) : rows;
  }

  async function relationshipsFrom(domain, stixId, relType) {
    const db = await open();
    const idx = db.transaction('relationships').objectStore('relationships').index('domain_source');
    const rows = await req(idx.getAll([domain, stixId]));
    return rows.filter(r => r.active && (!relType || r.relType === relType));
  }

  async function relationshipsTo(domain, stixId, relType) {
    const db = await open();
    const idx = db.transaction('relationships').objectStore('relationships').index('domain_target');
    const rows = await req(idx.getAll([domain, stixId]));
    return rows.filter(r => r.active && (!relType || r.relType === relType));
  }

  async function relationshipsByType(domain, relType) {
    const db = await open();
    const idx = db.transaction('relationships').objectStore('relationships').index('domain_relType');
    const rows = await req(idx.getAll([domain, relType]));
    return rows.filter(r => r.active);
  }

  /** Case-insensitive search over name / ATT&CK ID / aliases. */
  async function search(text, { domain, kinds, limit = 50 } = {}) {
    const q = text.trim().toLowerCase();
    if (!q) return [];
    const db = await open();
    const store = db.transaction('objects').objectStore('objects');
    const rows = await req(domain ? store.index('domain').getAll(domain) : store.getAll());
    const out = [];
    for (const o of rows) {
      if (!o.active || !KIND_LABELS[o.kind] || (kinds && !kinds.includes(o.kind))) continue;
      const hay = [o.name, o.attackId, ...(o.aliases || [])].filter(Boolean).join(' ').toLowerCase();
      if (hay.includes(q)) out.push(o);
    }
    // exact ID / name matches first, then by ATT&CK ID
    const rank = o => ((o.attackId || '').toLowerCase() === q || (o.name || '').toLowerCase() === q) ? 0 : 1;
    out.sort((x, y) => rank(x) - rank(y) || String(x.attackId).localeCompare(String(y.attackId)));
    return out.slice(0, limit);
  }

  // ---------- upstream ----------

  function compareVersions(a, b) {
    const pa = String(a).split('.').map(Number);
    const pb = String(b).split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] || 0) - (pb[i] || 0);
      if (d) return d;
    }
    return 0;
  }

  /** ATT&CK: MITRE's index.json -> {domainId: {collectionId, latest, versions[]}} */
  async function fetchAttackIndex() {
    const res = await fetch(INDEX_URL, { cache: 'no-store' });
    if (!res.ok) throw new Error('index.json: HTTP ' + res.status);
    const idx = await res.json();
    const out = {};
    for (const d of DOMAINS.filter(x => x.family === 'attack')) {
      const col = (idx.collections || []).find(c => c.name === d.collection);
      if (!col) continue;
      const versions = [...col.versions].sort((a, b) => compareVersions(b.version, a.version));
      out[d.id] = { collectionId: col.id, latest: versions[0], versions };
    }
    return { modified: idx.modified, domains: out };
  }

  /** ATLAS: dist/manifest.yaml -> {collectionId, latest, versions[]}, one entry per release in format v6. */
  async function fetchAtlasIndex() {
    const res = await fetch(ATLAS_MANIFEST_URL, { cache: 'no-store' });
    if (!res.ok) throw new Error('ATLAS manifest: HTTP ' + res.status);
    const manifest = parseYaml(await res.text());
    if (!Array.isArray(manifest)) throw new Error('ATLAS manifest: unexpected format');
    const versions = [];
    for (const r of manifest) {
      if (!r || typeof r !== 'object' || !Array.isArray(r.versions)) continue;   // skip a malformed entry, keep the rest
      const v6 = r.versions.find(v => v && String(v['format-version']).split('.')[0] === '6');
      // paths are relative to dist/ (e.g. v6/ATLAS-2026.10.yaml); refuse anything else
      if (!r.release || !v6 || !/^[\w.-]+(\/[\w.-]+)*$/.test(String(v6.path)) || String(v6.path).includes('..')) continue;
      versions.push({ version: String(r.release), modified: r['release-date'] ? String(r['release-date']) : null,
        url: ATLAS_RAW + v6.path, formatVersion: String(v6['format-version']) });
    }
    if (!versions.length) throw new Error('ATLAS manifest lists no v6 files');
    versions.sort((a, b) => compareVersions(b.version, a.version));
    return { collectionId: 'ATLAS', latest: versions[0], versions };
  }

  /**
   * Latest releases of every domain: {modified, domains: {domainId: {collectionId, latest, versions[]}},
   * errors: {attack?, atlas?}}. One source failing still returns the other; both failing throws.
   */
  async function fetchUpstreamIndex() {
    const [attack, atlas] = await Promise.allSettled([fetchAttackIndex(), fetchAtlasIndex()]);
    const out = { modified: null, domains: {}, errors: {} };
    if (attack.status === 'fulfilled') Object.assign(out, { modified: attack.value.modified, domains: attack.value.domains });
    else out.errors.attack = attack.reason.message;
    if (atlas.status === 'fulfilled') out.domains.atlas = atlas.value;
    else out.errors.atlas = atlas.reason.message;
    if (!Object.keys(out.domains).length) throw new Error(Object.values(out.errors).join('; '));
    return out;
  }

  global.AttackDB = {
    DB_NAME, INDEX_URL, ATLAS_MANIFEST_URL, DOMAINS, FAMILIES, KIND_BY_TYPE, KIND_LABELS,
    open, normalizeBundle, normalizeAtlas, parseYaml, replaceDomain, clearAll,
    getMeta, getAllMeta, getHistory,
    getObjects, getObject, getRaw, findByAttackId, loadDomain,
    relationshipsFrom, relationshipsTo, relationshipsByType, search,
    fetchUpstreamIndex, compareVersions,
  };
})(window);
