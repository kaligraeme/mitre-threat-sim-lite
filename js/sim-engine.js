/*
 * sim-engine.js — in-memory analysis for the threat simulator.
 *
 * Global `SimEngine`. Loads a domain from AttackDB into lookup maps, then maps a
 * threat profile (ATT&CK groups / software / campaigns, ATLAS case studies / entities /
 * software) to the techniques it uses, and from there to mitigations, detection
 * strategies, telemetry and (ICS) targeted assets. No DOM access here.
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
    for (const r of relationships) {
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

    const model = { domain, meta, byId, byKind, relsFrom, relsTo, tactics };
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

  global.SimEngine = {
    loadModel, analyzeDomain, applyPosture, prioritize, procedures, matrixColumns,
    directTechniqueCount, documentedTechniqueCount, attributedTo, activityPurposes, platformMatch,
    ACTOR_KINDS, CAMPAIGN_KINDS, SELECTION_ORDER,
  };
})(window);
