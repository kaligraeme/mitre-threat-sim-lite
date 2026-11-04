/*
 * sim-engine.js — in-memory analysis for the threat simulator.
 *
 * Global `SimEngine`. Loads a domain from AttackDB into lookup maps, then maps a
 * threat profile (ATT&CK groups / software / campaigns, ATLAS case studies / entities /
 * software) to the techniques it uses, and from there to mitigations, detection
 * strategies, telemetry and (ICS) targeted assets, and (CTID mappings) to NIST SP 800-53
 * controls and CISA KEV CVEs. No DOM access here.
 */
(function (global) {
  'use strict';

  /** Build lookup maps for one domain. */
  async function loadModel(domain) {
    const { meta, objects, relationships } = await AttackDB.loadDomain(domain);
    if (!meta) return null;

    const byId = new Map();
    const byKind = {};
    for (const o of objects) {
      byId.set(o.id, o);
      if (!o.active) continue;
      (byKind[o.kind] = byKind[o.kind] || []).push(o);
    }

    const relsFrom = new Map();
    const relsTo = new Map();
    // revoked-by links are inactive (their source is revoked), so keep them separately: CTID mappings
    // name techniques by older ATT&CK IDs and are carried forward through them.
    const revokedBy = new Map();
    for (const r of relationships) {
      if (r.relType === 'revoked-by' && !r.revoked && !r.deprecated && !revokedBy.has(r.source)) revokedBy.set(r.source, r.target);
      if (!r.active) continue;
      if (!relsFrom.has(r.source)) relsFrom.set(r.source, []);
      if (!relsTo.has(r.target)) relsTo.set(r.target, []);
      relsFrom.get(r.source).push(r);
      relsTo.get(r.target).push(r);
    }

    // Tactic columns in matrix order.
    const matrix = (byKind.matrix || [])[0];
    const tactics = matrix
      ? matrix.tacticRefs.map(id => byId.get(id)).filter(t => t && t.active)
      : (byKind.tactic || []);

    const model = { domain, meta, byId, byKind, relsFrom, relsTo, tactics, revokedBy };
    model.from = (id, relType, kind) => (relsFrom.get(id) || [])
      .filter(r => r.relType === relType && (!kind || r.targetKind === kind));
    model.to = (id, relType, kind) => (relsTo.get(id) || [])
      .filter(r => r.relType === relType && (!kind || r.sourceKind === kind));
    return model;
  }

  // Roles by kind, so ATT&CK and ATLAS threats are walked alike.
  const ACTOR_KINDS = new Set(['group', 'entity']);            // can have campaigns attributed to them
  const CAMPAIGN_KINDS = new Set(['campaign', 'case-study']);  // attributed to an actor
  // Selection keys in the order their roots are listed.
  const SELECTION_ORDER = ['groups', 'campaigns', 'software', 'caseStudies', 'entities', 'atlasSoftware'];

  /** Campaigns and case studies attributed to an actor (ATLAS reported-by is provenance, so it never counts). */
  function attributedTo(model, id) {
    return model.to(id, 'attributed-to').filter(r => CAMPAIGN_KINDS.has(r.sourceKind))
      .map(r => model.byId.get(r.source)).filter(c => c && c.active);
  }

  /** Distinct techniques a threat uses directly, for the picker lists (an ATLAS case study can
   *  employ one technique in several attack-chain steps, which counts once). */
  function directTechniqueCount(model, id) {
    return new Set(model.from(id, 'uses', 'technique').map(r => r.target)).size;
  }

  /**
   * Why an ATLAS case study or entity is in the record, as ATLAS states it on attribution:
   * 'Adversarial Operation', 'Security Evaluation' or 'Unintended Consequence' (ATLAS: identity type
   * does not imply intent). Case study: its attributed-to links. Entity: the case studies attributed
   * to it, and its own uses links. Empty when ATLAS records none, and for ATT&CK objects.
   */
  function activityPurposes(model, obj) {
    const rels = obj.kind === 'case-study' ? model.from(obj.id, 'attributed-to')
      : obj.kind === 'entity' ? [...model.to(obj.id, 'attributed-to'), ...model.from(obj.id, 'uses')]
        : [];
    return [...new Set(rels.map(r => r.activityPurpose).filter(Boolean))].sort();
  }

  /**
   * Picker count: techniques a threat documents itself. ATLAS entities document theirs mostly
   * through the case studies attributed to them, so those count too; ATT&CK groups keep direct uses.
   */
  function documentedTechniqueCount(model, obj) {
    if (obj.kind !== 'entity') return directTechniqueCount(model, obj.id);
    const ids = new Set(model.from(obj.id, 'uses', 'technique').map(r => r.target));
    for (const c of attributedTo(model, obj.id)) for (const r of model.from(c.id, 'uses', 'technique')) ids.add(r.target);
    return ids.size;
  }

  function platformMatch(platforms, filter) {
    if (!filter || !filter.size) return true;
    if (!platforms || !platforms.length || platforms.includes('None')) return true;
    return platforms.some(p => filter.has(p));
  }

  /**
   * Analyze one domain.
   *  selection: { groups, software, campaigns, caseStudies, entities, atlasSoftware } Sets of ids;
   *    ids from other domains are skipped, and each root's role comes from its kind
   *  opts: { viaSoftware, viaCampaigns, platforms:Set }
   */
  function analyzeDomain(model, selection, opts) {
    const { byId } = model;
    const techniques = new Map();   // techId -> { tech, roots:Set, evidence:[] }
    const roots = [];               // selected entities found in this domain

    const addUse = (rootId, rel, via) => {
      const tech = byId.get(rel.target);
      if (!tech || !tech.active) return;
      let t = techniques.get(tech.id);
      if (!t) techniques.set(tech.id, t = { tech, roots: new Set(), evidence: [] });
      t.roots.add(rootId);
      t.evidence.push({ root: rootId, via, description: rel.description, sourceId: rel.source });
    };

    const softwareOf = id => model.from(id, 'uses', 'software').map(r => byId.get(r.target)).filter(s => s && s.active);

    const walk = (rootId, entityId, via) => {
      for (const r of model.from(entityId, 'uses', 'technique')) addUse(rootId, r, via);
      if (opts.viaSoftware) {
        for (const sw of softwareOf(entityId)) {
          for (const r of model.from(sw.id, 'uses', 'technique')) addUse(rootId, r, [...via, sw.id]);
        }
      }
    };

    const seen = new Set();
    for (const key of SELECTION_ORDER) {
      for (const id of selection[key] || []) {
        const ent = byId.get(id);
        if (!ent || !ent.active || seen.has(id)) continue;
        seen.add(id);
        roots.push(ent);
        walk(id, id, []);
        if (ACTOR_KINDS.has(ent.kind) && opts.viaCampaigns) {
          for (const camp of attributedTo(model, id)) walk(id, camp.id, [camp.id]);
        }
      }
    }

    // Platform filter
    for (const [id, t] of techniques) {
      if (!platformMatch(t.tech.platforms, opts.platforms)) techniques.delete(id);
    }

    // Mitigations, detection strategies, assets per technique
    const mitigations = new Map();  // id -> { obj, techniques:Set, guidance: Map techId->desc }
    const detections = new Map();   // id -> { obj, techniques:Set, analytics:[], dataComponents:Set }
    const dataComponents = new Map(); // id -> { obj, techniques:Set, strategies:Set, logSources: Map name->Set(channel) }
    const unresolvedDataComponents = new Set();   // STIX ids referenced by analytics but not in any loaded bundle
    const assets = new Map();       // id -> { obj, techniques:Set }

    for (const [techId, t] of techniques) {
      t.mitigations = [];
      t.detections = [];
      t.assets = [];

      for (const r of model.to(techId, 'mitigates', 'mitigation')) {
        const m = byId.get(r.source);
        let e = mitigations.get(m.id);
        if (!e) mitigations.set(m.id, e = { obj: m, techniques: new Set(), guidance: new Map() });
        e.techniques.add(techId);
        e.guidance.set(techId, r.description);
        t.mitigations.push(m.id);
      }

      for (const r of model.to(techId, 'detects', 'detection-strategy')) {
        const ds = byId.get(r.source);
        let e = detections.get(ds.id);
        if (!e) {
          const analytics = (ds.analyticRefs || []).map(id => byId.get(id))
            .filter(a => a && a.active && platformMatch(a.platforms, opts.platforms));
          const dcs = new Set();
          for (const a of analytics) for (const l of a.logSources || []) if (l.dataComponent) dcs.add(l.dataComponent);
          detections.set(ds.id, e = { obj: ds, techniques: new Set(), analytics, dataComponents: dcs });
        }
        e.techniques.add(techId);
        t.detections.push(ds.id);
      }

      for (const r of model.from(techId, 'targets', 'asset')) {
        const a = byId.get(r.target);
        let e = assets.get(a.id);
        if (!e) assets.set(a.id, e = { obj: a, techniques: new Set() });
        e.techniques.add(techId);
        t.assets.push(a.id);
      }
    }

    for (const [dsId, d] of detections) {
      for (const a of d.analytics) {
        for (const l of a.logSources || []) {
          // Data components are shared objects: an ICS analytic can reference one that only the
          // Enterprise bundle defines, so fall back to the other loaded domains (opts.resolve).
          const dc = byId.get(l.dataComponent) || (opts.resolve ? opts.resolve(l.dataComponent) : null);
          if (!dc) {
            if (l.dataComponent) unresolvedDataComponents.add(l.dataComponent);
            continue;
          }
          let e = dataComponents.get(dc.id);
          if (!e) dataComponents.set(dc.id, e = { obj: dc, techniques: new Set(), strategies: new Set(), logSources: new Map() });
          for (const tid of d.techniques) e.techniques.add(tid);
          e.strategies.add(dsId);
          const name = String(l.name || '').trim();   // a few ATT&CK names carry a trailing space
          if (name) {
            if (!e.logSources.has(name)) e.logSources.set(name, new Set());
            if (l.channel && l.channel !== 'None') e.logSources.get(name).add(l.channel);
          }
        }
      }
    }

    return { domain: model.domain, model, roots, techniques, mitigations, detections, dataComponents, assets, unresolvedDataComponents };
  }

  /**
   * Coverage under a defensive posture.
   *  inPlace: { mitigations:Set, detections:Set } of keys "<domain>|<id>"
   * Sets t.status on every technique: 'covered' | 'mitigated' | 'detected' | 'gap'.
   */
  function applyPosture(result, inPlace) {
    const d = result.domain;
    const counts = { covered: 0, mitigated: 0, detected: 0, gap: 0 };
    for (const t of result.techniques.values()) {
      const m = t.mitigations.some(id => inPlace.mitigations.has(d + '|' + id));
      const x = t.detections.some(id => inPlace.detections.has(d + '|' + id));
      t.isMitigated = m;
      t.isDetected = x;
      t.status = m && x ? 'covered' : m ? 'mitigated' : x ? 'detected' : 'gap';
      counts[t.status]++;
    }
    return counts;
  }

  /**
   * Greedy priority order: repeatedly pick the control whose still-uncovered
   * techniques carry the most weight, where a technique weighs as much as the
   * number of selected adversaries using it. Controls already in place count as
   * picked first. Exact ties go to the control with more reach, then more
   * documented procedure examples behind the techniques it adds, then the lower
   * ATT&CK ID, so the order never depends on the order adversaries were picked.
   *
   * Returns Map id -> { rank, tier, adds, score, cumulative }:
   *  rank  sequential pick order (null when in place or adding nothing); drives "Mark top 5"
   *  tier  shared rank for picks with equal score (1, 1, 1, 4, ...); what tables show
   *  adds  techniques newly covered; score  their weight; cumulative  share covered after this pick
   */
  function prioritize(entries, inPlaceKeys, domain, techniques) {
    const total = techniques.size || 1;
    const weight = tid => (techniques.get(tid) ? techniques.get(tid).roots.size : 1);
    const docs = new Map();   // merged procedure examples per technique (see procedures())
    const documented = tid => {
      if (!docs.has(tid)) { const t = techniques.get(tid); docs.set(tid, t ? procedures(t).length : 0); }
      return docs.get(tid);
    };
    const covered = new Set();
    const out = new Map();
    const remaining = [];
    for (const [id, e] of entries) {
      if (inPlaceKeys.has(domain + '|' + id)) {
        for (const t of e.techniques) covered.add(t);
      } else {
        remaining.push([id, e]);
      }
    }
    for (const [id] of entries) {
      if (inPlaceKeys.has(domain + '|' + id)) out.set(id, { rank: null, tier: null, adds: 0, score: 0, cumulative: covered.size / total });
    }
    const better = (a, b) => a.score - b.score || a.reach - b.reach || a.documented - b.documented
      || String(b.obj.attackId).localeCompare(String(a.obj.attackId), undefined, { numeric: true });
    let rank = 0, tier = 0, lastScore = null;
    while (remaining.length) {
      let best = null;
      remaining.forEach(([id, e], i) => {
        const c = { i, obj: e.obj, score: 0, adds: 0, documented: 0, reach: e.techniques.size };
        for (const t of e.techniques) {
          if (!covered.has(t)) { c.score += weight(t); c.adds++; c.documented += documented(t); }
        }
        if (!best || better(c, best) > 0) best = c;
      });
      const [id, e] = remaining.splice(best.i, 1)[0];
      for (const t of e.techniques) covered.add(t);
      let r = null, tr = null;
      if (best.adds > 0) {
        r = ++rank;
        tr = best.score === lastScore ? tier : (tier = r);
        lastScore = best.score;
      }
      out.set(id, { rank: r, tier: tr, adds: best.adds, score: best.score, cumulative: covered.size / total });
    }
    return out;
  }

  /**
   * A technique's procedure examples, merged when the same adversary reaches the same
   * source (itself, a campaign or a piece of software) and text by more than one path.
   * Returns [{ root, source, description, paths: [via arrays] }].
   */
  function procedures(t) {
    const out = new Map();
    for (const ev of t.evidence) {
      const source = ev.via.length ? ev.via[ev.via.length - 1] : ev.root;
      const k = ev.root + '|' + source + '|' + ev.description;
      let g = out.get(k);
      if (!g) out.set(k, g = { root: ev.root, source, description: ev.description, paths: [] });
      if (!g.paths.some(p => p.join('>') === ev.via.join('>'))) g.paths.push(ev.via);
    }
    return [...out.values()];
  }

  /** Techniques arranged for the matrix: per tactic, parents with nested sub-techniques. */
  function matrixColumns(result, { showAll }) {
    const { model, techniques } = result;
    const used = techniques;
    const allTech = model.byKind.technique || [];
    const subsByParent = new Map();
    for (const t of allTech) {
      if (t.isSubtechnique && t.parent) {
        if (!subsByParent.has(t.parent)) subsByParent.set(t.parent, []);
        subsByParent.get(t.parent).push(t);
      }
    }
    const byAttackId = (a, b) => String(a.attackId).localeCompare(String(b.attackId), undefined, { numeric: true });

    return model.tactics.map(tactic => {
      const parents = allTech.filter(t => !t.isSubtechnique && (t.tactics || []).includes(tactic.shortname));
      const rows = [];
      for (const p of parents.sort((a, b) => a.name.localeCompare(b.name))) {
        const subs = (subsByParent.get(p.id) || []).filter(s => (s.tactics || []).includes(tactic.shortname)).sort(byAttackId);
        const usedSubs = subs.filter(s => used.has(s.id));
        if (!showAll && !used.has(p.id) && !usedSubs.length) continue;
        rows.push({ tech: p, used: used.get(p.id) || null, subs: (showAll ? subs : usedSubs).map(s => ({ tech: s, used: used.get(s.id) || null })) });
      }
      const usedCount = rows.reduce((n, r) => n + (r.used ? 1 : 0) + r.subs.filter(s => s.used).length, 0);
      return { tactic, rows, usedCount };
    });
  }

  // ---------- external mappings: CTID Mappings Explorer (NIST SP 800-53 Rev 5, CISA KEV) ----------

  // Which ATT&CK domains each mapping covers. NIST rolls a parent technique's controls down to its
  // sub-techniques ("via parent"), except to one CTID judged not mappable; KEV matches the exact technique only.
  const MAPPING_SOURCES = {
    nist: { id: 'nist-800-53-r5', domains: ['enterprise-attack'] },
    kev: { id: 'kev', domains: ['enterprise-attack', 'mobile-attack'] },
  };
  const NIST_URL = 'https://ctid.mitre.org/mappings/external/nist/';   // CTID's NIST page (no verified per-control pages)
  const NVD_URL = 'https://nvd.nist.gov/vuln/detail/';
  const text = v => (typeof v === 'string' ? v.trim() : typeof v === 'number' ? String(v) : '');
  const httpUrls = v => (Array.isArray(v) ? v.filter(u => typeof u === 'string' && /^https?:\/\//i.test(u)) : []);
  // one shared collator: localeCompare with options builds a new one per call, which is slow in sorts
  const idOrder = new Intl.Collator(undefined, { numeric: true }).compare;
  const TITLES = { 'enterprise-attack': 'Enterprise ATT&CK', 'mobile-attack': 'Mobile ATT&CK', 'ics-attack': 'ICS ATT&CK' };
  /** 'Enterprise ATT&CK' for a domain id (AttackDB's title when loaded). */
  const domainTitle = d => {
    const x = typeof AttackDB !== 'undefined' && Array.isArray(AttackDB.DOMAINS) ? AttackDB.DOMAINS.find(y => y.id === d) : null;
    return (x && x.title) || TITLES[d] || 'ATT&CK';
  };

  /**
   * A CTID technique ID (ATT&CK 16.1) as a current record of this model: the active technique with that
   * ID, or the end of its revoked-by chain. Returns { tech, carried } or { reason }.
   */
  function resolveTechnique(model, techs, attackId) {
    const recs = techs.get(attackId) || [];
    const active = recs.find(o => o.active);
    if (active) return { tech: active, carried: false };
    // name the domain: an ID can be current in another domain (T1521.003 is a Mobile technique)
    if (!recs.length) return { reason: ('not in ' + domainTitle(model.domain) + ' v' + ((model.meta && model.meta.version) || '')).replace(/ v$/, '') };
    let cur = recs.find(o => o.revoked);
    if (!cur) return { reason: 'deprecated' };
    const seen = new Set();
    while (cur && !cur.active) {
      // a cycle, or a chain ending at a deprecated record, leaves nothing current to carry the mapping to
      if (seen.has(cur.id) || !cur.revoked) return { reason: 'revoked, no replacement' };
      seen.add(cur.id);
      const next = model.revokedBy ? model.revokedBy.get(cur.id) : null;
      cur = next ? model.byId.get(next) : null;
    }
    if (!cur || cur.kind !== 'technique') return { reason: 'revoked, no replacement' };
    return { tech: cur, carried: true };
  }

  /**
   * Index one mapping source's rows for one domain (rows in MappingsDB's shape), once per page load.
   * Returns { source, domain, attackVersion, rowCount, ctidTechniques,
   *   byTech: Map techSTIX -> [Entry], capabilities: Map capId -> {id, name, group, groupName, techniques:Set,
   *   mappings:[{tech, type, comments, from}], references:[url], unresolved:[...]}, nonMappable: Map techSTIX -> comment,
   *   nonMappableFrom: Map techSTIX -> Set of older CTID IDs a not-mappable judgment was carried forward from,
   *   replaced: [{from, fromName, to, toId, toName, rows}], unresolved: [{techniqueId, techniqueName, rows, reason}] }
   * Entry = { capId, capName, group, groupName, type, comments, references, from?, fromAll? } (from: the CTID ID it was
   *   carried forward from; fromAll: every such ID when several older techniques now share one record)
   */
  function indexMappings(model, rows) {
    rows = Array.isArray(rows) ? rows : [];
    const techs = new Map();   // ATT&CK ID -> technique records, inactive ones included
    for (const o of model.byId.values()) {
      if (o.kind !== 'technique' || !o.attackId) continue;
      if (!techs.has(o.attackId)) techs.set(o.attackId, []);
      techs.get(o.attackId).push(o);
    }
    const first = rows.find(r => r && r.source);
    const index = {
      source: first ? first.source : null, domain: model.domain, attackVersion: model.meta ? String(model.meta.version) : null,
      rowCount: 0, ctidTechniques: 0, byTech: new Map(), capabilities: new Map(), nonMappable: new Map(), nonMappableFrom: new Map(),
      replaced: [], unresolved: [],
    };
    const resolved = new Map(), replaced = new Map(), unresolved = new Map();
    const entries = new Map();   // techSTIX -> Map "capId|type" -> Entry
    const capability = row => {
      const id = row.capabilityId;
      let c = index.capabilities.get(id);
      if (!c) index.capabilities.set(id, c = { id, name: text(row.capabilityName) || id, group: text(row.group), groupName: text(row.groupName) || text(row.group),
        techniques: new Set(), mappings: [], references: [], unresolved: [] });
      for (const u of httpUrls(row.references)) if (!c.references.includes(u)) c.references.push(u);
      return c;
    };

    for (const row of rows) {
      if (!row || typeof row.techniqueId !== 'string' || !row.techniqueId.trim()) continue;
      index.rowCount++;
      const aid = row.techniqueId.trim();
      if (!resolved.has(aid)) resolved.set(aid, resolveTechnique(model, techs, aid));
      const res = resolved.get(aid);
      const cap = typeof row.capabilityId === 'string' && row.capabilityId.trim() && row.status !== 'non_mappable' ? capability(row) : null;
      const type = typeof row.mappingType === 'string' && row.mappingType ? row.mappingType : null;
      if (!res.tech) {
        if (!unresolved.has(aid)) unresolved.set(aid, { techniqueId: aid, techniqueName: text(row.techniqueName), rows: 0, reason: res.reason });
        unresolved.get(aid).rows++;
        if (cap) cap.unresolved.push({ techniqueId: aid, techniqueName: text(row.techniqueName), type, reason: res.reason });
        continue;
      }
      const techId = res.tech.id;
      if (res.carried) {
        if (!replaced.has(aid)) replaced.set(aid, { from: aid, fromName: text(row.techniqueName), to: res.tech.attackId, toId: techId, toName: res.tech.name, rows: 0 });
        replaced.get(aid).rows++;
      }
      if (!cap) {   // non_mappable: CTID judged that no control maps to this technique
        if (!index.nonMappable.get(techId)) index.nonMappable.set(techId, text(row.comments));
        // a judgment carried forward from an older ID (so the list of changed IDs can say it reaches a profile)
        if (res.carried) {
          if (!index.nonMappableFrom.has(techId)) index.nonMappableFrom.set(techId, new Set());
          index.nonMappableFrom.get(techId).add(aid);
        }
        continue;
      }
      const entry = { capId: cap.id, capName: cap.name, group: cap.group, groupName: cap.groupName, type,
        comments: text(row.comments), references: httpUrls(row.references) };
      if (res.carried) { entry.from = aid; entry.fromAll = [aid]; }
      if (!entries.has(techId)) entries.set(techId, new Map());
      const per = entries.get(techId);
      const k = cap.id + '|' + type;
      const prev = per.get(k);
      // one entry per capability and role; a mapping made to the technique itself beats one carried forward
      if (prev && (!prev.from || entry.from)) {
        if (!prev.comments && entry.comments) prev.comments = entry.comments;
        if (prev.from && entry.from && !prev.fromAll.includes(aid)) prev.fromAll.push(aid);
        continue;
      }
      per.set(k, entry);
    }

    for (const [techId, per] of entries) {
      const list = [...per.values()];
      index.byTech.set(techId, list);
      for (const e of list) {
        // older IDs in natural order (T1562, T1562.001, T1562.006)
        if (e.fromAll && e.fromAll.length > 1) { e.fromAll.sort(idOrder); e.from = e.fromAll[0]; }
        const c = index.capabilities.get(e.capId);
        c.techniques.add(techId);
        c.mappings.push({ tech: techId, type: e.type, comments: e.comments, from: e.from || null, fromAll: e.fromAll || [] });
      }
    }
    index.ctidTechniques = resolved.size;
    index.rank = new Map([...index.capabilities.keys()].sort(idOrder).map((id, i) => [id, i]));   // AC-2 before AC-10
    index.replaced = [...replaced.values()].sort((a, b) => idOrder(a.from, b.from));
    index.unresolved = [...unresolved.values()].sort((a, b) => idOrder(a.techniqueId, b.techniqueId));
    return index;
  }

  /**
   * NIST controls for one technique: its own, then its parent's not already listed ([{entry, viaParent}]).
   * The parent roll-up is ThreatSim's rule, so it gives way to CTID's own judgment: a sub-technique CTID
   * judged not mappable (and mapped no control to) gets none of its parent's controls.
   */
  function controlsFor(index, model, techId) {
    const out = [];
    const seen = new Set();
    const add = (list, viaParent) => {
      for (const e of list || []) if (!seen.has(e.capId)) { seen.add(e.capId); out.push({ entry: e, viaParent }); }
    };
    add(index.byTech.get(techId), false);
    if (!out.length && index.nonMappable.has(techId)) return out;
    const tech = model.byId.get(techId);
    if (tech && tech.isSubtechnique && tech.parent) add(index.byTech.get(tech.parent), true);
    return out;
  }

  /** KEV CVEs mapped to exactly this technique, one per CVE: [{capId, entry, types:Set, comments:[...]}]. */
  function cvesFor(index, techId) {
    const by = new Map();
    for (const e of index.byTech.get(techId) || []) {
      if (!by.has(e.capId)) by.set(e.capId, { capId: e.capId, entry: e, types: new Set(), comments: [] });
      const x = by.get(e.capId);
      if (e.type) x.types.add(e.type);
      if (e.comments && !x.comments.includes(e.comments)) x.comments.push(e.comments);
    }
    return [...by.values()];
  }

  /**
   * ATT&CK mitigations of the result sharing techniques with a control or CVE: Map mitSTIX -> n, most shared
   * first, then by ID (fixed-width M1234 IDs, so a plain comparison orders them). mitSets caches each
   * technique's distinct mitigations for one mapExternal run.
   */
  function relatedMitigations(r, techIds, mitSets) {
    const n = new Map();
    for (const tid of techIds) {
      let set = mitSets.get(tid);
      if (!set) { const t = r.techniques.get(tid); mitSets.set(tid, set = new Set(t ? t.mitigations : [])); }
      for (const m of set) n.set(m, (n.get(m) || 0) + 1);
    }
    const id = m => String((r.model.byId.get(m) || {}).attackId || '');
    return new Map([...n].sort((a, b) => b[1] - a[1] || (id(a[0]) < id(b[0]) ? -1 : id(a[0]) > id(b[0]) ? 1 : 0)));
  }

  /** entry.mitigations as a lazily built Map: tables show it for few rows, so most are never computed. */
  function lazyMitigations(entry, r, mitSets) {
    let cache = null;
    Object.defineProperty(entry, 'mitigations', { enumerable: true, configurable: true,
      get: () => cache || (cache = relatedMitigations(r, entry.techniques, mitSets)) });
  }

  /** Most profile techniques first, then by ID in the index's natural order (index.rank, computed once). */
  const bySizeThenId = (index, desc) => ([ia, a], [ib, b]) => b.techniques.size - a.techniques.size
    || (desc ? index.rank.get(ib) - index.rank.get(ia) : index.rank.get(ia) - index.rank.get(ib));

  /** Older CTID IDs whose carried-forward entries show in a result (for the list of changed IDs). */
  const addFrom = (set, e) => { for (const id of (e && e.fromAll) || []) set.add(id); };

  /**
   * covered: profile techniques with at least one control; viaParentOnly: those of them whose every control
   * comes through ThreatSim's via-parent rule (CTID maps none to the sub-technique itself); carriedFrom: the
   * older CTID technique IDs whose carried-forward mappings (or not-mappable judgments) reach this result.
   */
  function mapNist(r, index, mitSets) {
    const controls = new Map();
    const covered = new Set(), uncovered = new Set(), nonMappable = new Set(), viaParentOnly = new Set(), carriedFrom = new Set();
    for (const [techId, t] of r.techniques) {
      let direct = 0;
      for (const { entry: e, viaParent } of controlsFor(index, r.model, techId)) {
        if (!viaParent) direct++;
        addFrom(carriedFrom, e);
        let c = controls.get(e.capId);
        if (!c) {
          controls.set(e.capId, c = {
            obj: { id: e.capId, attackId: e.capId, name: e.capName, family: e.group, familyName: e.groupName, url: NIST_URL, kind: 'nist-control' },
            techniques: new Set(), viaParent: new Set(), notes: new Map(),
          });
          lazyMitigations(c, r, mitSets);
        }
        c.techniques.add(techId);
        if (viaParent) c.viaParent.add(techId);
        if (e.comments) c.notes.set(techId, e.comments);
        t.nist.push(e.capId);
      }
      if (t.nist.length) {
        covered.add(techId);
        if (!direct) viaParentOnly.add(techId);
      } else {
        uncovered.add(techId);
        if (index.nonMappable.has(techId)) {
          nonMappable.add(techId);
          for (const id of (index.nonMappableFrom && index.nonMappableFrom.get(techId)) || []) carriedFrom.add(id);
        }
      }
    }
    return { controls: new Map([...controls].sort(bySizeThenId(index, false))), covered, uncovered, nonMappable, viaParentOnly, carriedFrom, index };
  }

  function mapKev(r, index, mitSets) {
    const cves = new Map();
    const covered = new Set(), carriedFrom = new Set();
    for (const [techId, t] of r.techniques) {
      for (const e of index.byTech.get(techId) || []) addFrom(carriedFrom, e);
      for (const x of cvesFor(index, techId)) {
        let c = cves.get(x.capId);
        if (!c) {
          const cap = index.capabilities.get(x.capId);
          cves.set(x.capId, c = {
            obj: { id: x.capId, attackId: x.capId, name: x.entry.capName, type: x.entry.group, typeName: x.entry.groupName,
                   url: NVD_URL + encodeURIComponent(x.capId), kind: 'kev-cve' },
            techniques: new Set(), roles: new Map(), notes: new Map(), references: cap ? cap.references.slice() : [],
          });
          lazyMitigations(c, r, mitSets);
        }
        c.techniques.add(techId);
        c.roles.set(techId, new Set(x.types));
        if (x.comments.length) c.notes.set(techId, x.comments.join(' '));
        t.cves.push(x.capId);
      }
      if (t.cves.length) covered.add(techId);
    }
    return { cves: new Map([...cves].sort(bySizeThenId(index, true))), covered, carriedFrom, index };
  }

  /** 'ok' | 'not-pulled' | 'no-attack-data' (pulled, but no rows for this domain) | 'not-this-domain' */
  function mappingStatusFor(key, domain, index) {
    if (!MAPPING_SOURCES[key].domains.includes(domain)) return 'not-this-domain';
    if (!index) return 'not-pulled';
    return index.rowCount ? 'ok' : 'no-attack-data';
  }

  /**
   * Join the CTID mappings to an analyzed result. indexes: { nist, kev } built by indexMappings for this
   * result's domain (null when the source isn't pulled). Sets r.nist, r.kev, r.mappingStatus, and t.nist /
   * t.cves (IDs) on every technique entry. Recomputed on every analysis from indexes built once.
   */
  function mapExternal(r, indexes) {
    const pick = idx => (idx && idx.domain === r.domain ? idx : null);
    const nist = pick(indexes && indexes.nist), kev = pick(indexes && indexes.kev);
    r.mappingStatus = { nist: mappingStatusFor('nist', r.domain, nist), kev: mappingStatusFor('kev', r.domain, kev) };
    for (const t of r.techniques.values()) { t.nist = []; t.cves = []; }
    const mitSets = new Map();
    r.nist = r.mappingStatus.nist === 'ok' ? mapNist(r, nist, mitSets) : null;
    r.kev = r.mappingStatus.kev === 'ok' ? mapKev(r, kev, mitSets) : null;
    return r;
  }

  // Release day of each Enterprise ATT&CK version CTID maps to (the date of its STIX bundle). A technique created after
  // that day is not in that release. Checked against the real bundles: never wrong for these versions, and exact from
  // 14.1 on (before 14.1 a few techniques were created before a release and published after it, so the count is a floor).
  const ATTACK_RELEASED = { '8.2': '2021-01-27', '9.0': '2021-04-29', '10.1': '2021-11-10', '12.1': '2022-11-08',
    '14.1': '2023-11-14', '15.1': '2024-05-02', '16.1': '2024-11-12' };
  /** True when a technique record was added to ATT&CK after the given release (unknown release: false). */
  const addedAfterRelease = (tech, version) => !!(ATTACK_RELEASED[version] && tech && tech.created
    && String(tech.created).slice(0, 10) > ATTACK_RELEASED[version]);

  global.SimEngine = {
    loadModel, analyzeDomain, applyPosture, prioritize, procedures, matrixColumns,
    directTechniqueCount, documentedTechniqueCount, attributedTo, activityPurposes, platformMatch,
    indexMappings, mapExternal, controlsFor, cvesFor, MAPPING_SOURCES, ATTACK_RELEASED, addedAfterRelease,
    ACTOR_KINDS, CAMPAIGN_KINDS, SELECTION_ORDER,
  };
})(window);
