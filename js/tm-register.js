/*
 * tm-register.js — the Cyber Threat Modelling Register (.xlsx) for the Threat Modelling tab.
 *
 * Global `TMRegister`. build(result) -> Promise<Blob> writes a TMResult (the deliverable writers'
 * contract, produced by js/tm-engine.js) with ExcelJS, which the page has already loaded as the global
 * `ExcelJS`. The layout follows the CSA Guide to Cyber Threat Modelling register the user works from:
 *
 *   Threat Register               one row per threat event: ATT&CK rows, a grey separator row, AI rows
 *   Table of Attack (CSA)         the ATT&CK attack sequences
 *   AI Table of Attack (MAESTRO)  the AI attack sequences, with their MAESTRO layers
 *   STRIDE-LM Coverage            element x category walk: raised (X), applicable but not raised (o), n/a
 *   Threat Profile (<short>)      the Sectorial Threat Profile lenses
 *   AI Threat Profile (MAESTRO)   the MAESTRO layer lenses with their ATLAS techniques and case studies
 *   MAESTRO Coverage              AI element x MAESTRO layer
 *   About                         methodology, scope, verification, how to read severity, limits, sources
 *
 * Severity colours the S/n cell, so the register keeps its fixed columns. Cells are never merged (merged
 * cells break filtering and sorting, which is how a register is used) and hold text, not formulas. Every
 * ID and number printed comes from the result. Pure: no DOM access, no network.
 */
(function (global) {
  'use strict';

  const FILE_NAME = 'Cyber_Threat_Modelling_Register.xlsx';
  const XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

  const SHEET = {
    register: 'Threat Register', attack: 'Table of Attack (CSA)', aiAttack: 'AI Table of Attack (MAESTRO)',
    coverage: 'STRIDE-LM Coverage', aiProfile: 'AI Threat Profile (MAESTRO)', maestro: 'MAESTRO Coverage', about: 'About',
  };
  const EXCEL_NAME_MAX = 31;

  // The reference register's colours (light only: spreadsheet cells have no dark mode).
  const C = {
    header: 'FF2F5597', white: 'FFFFFFFF', black: 'FF000000', grid: 'FFBFBFBF', navy: 'FF1F3864', grey: 'FF808080',
    registerBand: ['FFEAF1FB', 'FFFFFFFF'],   // ATT&CK register rows: the band changes with each component
    tableBand: ['FFFFFFFF', 'FFEAF1FB'],      // Table of Attack and Threat Profile rows
    aiBand: ['FFEFE7F6', 'FFE3EEF8'],         // AI register rows and AI Table of Attack rows
    aiProfileBand: ['FFE3EEF8', 'FFEFE7F6'],  // AI Threat Profile rows
    separator: 'FFD9D9D9', raised: 'FFC6E0B4', open: 'FFFFF2CC', notApplicable: 'FFD9D9D9', layerOff: 'FFF2F2F2',
    extrapolated: 'FFFFF2CC',
  };
  const SEVERITY = {
    High: { fill: 'FFC00000', ink: 'FFFFFFFF' },
    Medium: { fill: 'FFED7D31', ink: 'FFFFFFFF' },
    Low: { fill: 'FFFFC000', ink: 'FF000000' },
  };

  // [header, width] per column, as in the reference.
  const REGISTER_COLS = [
    ['S/n', 6], ['Threats (STP)', 30], ['Techniques (MITRE ATT&CK / ATLAS)', 46], ['STRIDE-LM Threat', 20],
    ['Threat Actor', 26], ['Sequence of Attack', 54], ['Threat Event', 60], ['Component (DFD #)', 26],
    ['Mitigations', 52], ['Detections', 54],
  ];
  const ATTACK_COLS = [
    ['S/N', 6], ['Point of Entry', 30], ['Threat Actor(s)', 30], ['Sequence of Attack (DFD #)', 26],
    ['Threat Event', 78], ['Examples (real-world / ATT&CK / ATLAS)', 60],
  ];
  const AI_ATTACK_COLS = [
    ['S/N', 7], ['Point of Entry', 28], ['Threat Actor(s)', 28], ['MAESTRO layers', 16],
    ['Sequence of Attack (DFD #)', 22], ['Threat Event', 74], ['Examples (MITRE ATLAS case studies)', 52],
  ];
  const STRIDE = ['S', 'T', 'R', 'I', 'D', 'E', 'LM'];
  const COVERAGE_COLS = [['#', 5], ['Component', 30], ['Type', 10]]
    .concat(STRIDE.map(k => [k, 6]), [['Raised', 8], ['Notes', 46]]);
  const LAYERS = ['L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7'];
  const MAESTRO_COLS = [['#', 5], ['AI element', 30]].concat(LAYERS.map(k => [k, 6]), [['AI events', 9]]);
  const PROFILE_WIDTHS = [7, 34, 70, 50, 14];
  const AI_PROFILE_COLS = [
    ['Layer', 9], ['MAESTRO lens', 30], ['Threat summary', 58], ['Representative ATLAS techniques', 46],
    ['ATLAS case-study examples', 44],
  ];
  const AI_PROFILE_HEADER_ROW = 4;   // title, note, blank, then the table
  const ABOUT_WIDTH = 122;

  // MITRE pages per profile entry kind (ATT&CK groups / software / campaigns; ATLAS case studies / entities / software).
  const ATTACK_SITE = 'https://attack.mitre.org/';
  const ATLAS_SITE = 'https://atlas.mitre.org/';
  const ACTOR_PAGE = {
    attack: { group: 'groups', software: 'software', campaign: 'campaigns' },
    atlas: { 'case-study': 'studies', entity: 'entities', software: 'software' },
  };
  const KIND_NAME = { group: 'group', software: 'software', campaign: 'campaign', 'case-study': 'case study', entity: 'entity' };
  const SOURCE_KIND = { drawio: 'draw.io diagram', pptx: 'PowerPoint slide', json: 'model file', image: 'image' };
  const MAESTRO_URL = 'https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro';

  // ---------- text ----------

  const MAX_CELL = 32000;   // Excel's limit is 32,767 characters per cell

  /** Text that is valid XML 1.0 and fits in a cell, with line breaks as \n. */
  function clean(s) {
    if (s == null) return '';
    let t = String(s).replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g, '');
    t = typeof t.toWellFormed === 'function'
      ? t.toWellFormed()
      : t.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]|[\uD800-\uDFFF]/g, m => (m.length === 2 ? m : '\uFFFD'));
    if (t.length > MAX_CELL) {
      let cut = MAX_CELL - 1;
      if (/[\uD800-\uDBFF]/.test(t[cut - 1])) cut--;
      t = t.slice(0, cut) + '…';
    }
    return t;
  }

  const isObj = v => v != null && typeof v === 'object' && !Array.isArray(v);
  const obj = v => (isObj(v) ? v : {});
  const arr = v => (Array.isArray(v) ? v : []);
  const objs = v => arr(v).filter(isObj);
  /** Any value as text: strings as they are, numbers and booleans spelled out, lists comma-joined. */
  const txt = v => (v == null ? '' : typeof v === 'string' ? v
    : typeof v === 'number' || typeof v === 'boolean' ? String(v)
      : Array.isArray(v) ? v.map(txt).filter(Boolean).join(', ') : '');
  /** One line: labels and names whose line breaks come from the diagram's text wrapping. */
  const oneLine = v => txt(v).replace(/\s+/g, ' ').trim();
  const list = v => arr(v).map(txt).filter(Boolean);
  /** A finite number, or null: never a NaN in a numeric cell. */
  const num = v => (typeof v === 'number' && Number.isFinite(v) ? v
    : typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v)) ? Number(v) : null);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + 's'}`;
  const uniq = a => [...new Set(a)];
  const isAtlasId = id => /^AML\./i.test(id);
  const isTechniqueId = id => /^(AML\.)?T\d{4}(\.\d{3})?$/i.test(id);
  /** '5.6.0' -> '5.6' for running text (the reference's "ATLAS v5.6"); full versions stay in Sources. */
  const shortVersion = v => txt(v).trim().replace(/^v/i, '').replace(/^(\d+\.\d+)\.0$/, '$1');
  const fullVersion = v => txt(v).trim().replace(/^v/i, '');
  const withV = v => (v ? ' v' + v : '');

  function colLetter(n) {
    let s = '';
    while (n > 0) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - 1) / 26); }
    return s;
  }
  const quoteSheet = name => "'" + name.replace(/'/g, "''") + "'";

  /** 'D Mon YYYY' in UTC, or '' for a missing or invalid date. */
  function dateText(iso) {
    const d = new Date(txt(iso));
    if (!txt(iso) || Number.isNaN(d.getTime())) return '';
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return `${d.getUTCDate()} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
  }

  // ---------- reading the result ----------

  /**
   * The result with every part the writer reads guaranteed to be there (arrays of objects, objects),
   * plus the lookups it needs. Nothing is rewritten: a missing part simply reads as empty.
   */
  function prepare(result) {
    const r = obj(result);
    const model = obj(r.model);
    const profile = obj(r.profile);
    const R = {
      system: oneLine(r.system) || oneLine(model.name) || 'the system',
      generatedAt: r.generatedAt,
      model,
      source: obj(model.source),
      elements: objs(model.elements),
      zones: objs(model.zones),
      flows: objs(model.flows),
      profile: {
        label: oneLine(profile.label),
        short: oneLine(profile.short),
        actors: objs(profile.actors),
        knowledge: objs(profile.knowledge),
      },
      lenses: objs(r.lenses),
      aiProfile: objs(r.aiProfile),
      events: objs(r.events),
      locations: objs(r.locations),
      sequences: objs(r.sequences),
      coverage: objs(r.coverage),
      maestroCoverage: objs(r.maestroCoverage),
      stats: obj(r.stats),
      method: obj(r.method),
      warnings: uniq(list(r.warnings).concat(list(model.warnings))),
    };
    R.elementById = new Map(R.elements.map(e => [e.id, e]));
    R.zoneById = new Map(R.zones.map(z => [z.id, z]));
    R.attackEvents = bySn(R.events.filter(e => !e.ai));
    R.aiEvents = bySn(R.events.filter(e => e.ai));
    const atlas = R.profile.knowledge.find(k => k.domain === 'atlas');
    R.atlasVersion = atlas ? fullVersion(atlas.version) : '';
    R.attackKnowledge = R.profile.knowledge.filter(k => k.domain !== 'atlas');
    const actors = R.profile.actors;
    R.hasProfile = actors.length > 0;
    // The profile's ATT&CK entries (groups, software, campaigns). The engine builds the Sectorial Threat Profile
    // lenses from their techniques only: ATLAS entries (case studies, …) inform the AI pass.
    R.attackActors = actors.filter(a => actorDomain(a) === 'attack');
    // Lenses that list no technique model a generic attacker (the engine's lens for a run without a profile, or
    // with one that gives no ATT&CK technique to model the architecture with).
    R.genericLenses = !R.lenses.some(l => list(l.techniques).length);
    // How the ATT&CK pass is named in running text ("the UNC3886 pass", "the UNC3886 model above"): the ATT&CK
    // entries behind its lenses, else "ATT&CK".
    R.attackName = R.genericLenses ? '' : namePhrase(R.attackActors);
    R.pass = R.attackName || 'ATT&CK';
    // The whole profile, ATT&CK and ATLAS entries ('' without a profile: "the threat profile" in running text).
    R.profileName = namePhrase(actors) || (actors.length ? R.profile.short : '');
    // Who can carry out an infrastructure intrusion: the ATT&CK groups (software and campaigns are not actors).
    R.groups = R.attackActors.filter(a => a.kind !== 'software' && a.kind !== 'campaign');
    R.groupName = namePhrase(R.groups);
    R.groupsAreMany = actorNames(R.groups).length > 1;
    return R;
  }

  /** Register order: by S/n (the engine's order already), keeping the given order for any without one. */
  function bySn(events) {
    const key = ev => { const n = num(ev.sn); return n == null ? Infinity : n; };
    return events.map((ev, i) => [ev, i]).sort((a, b) => (key(a[0]) - key(b[0])) || a[1] - b[1]).map(x => x[0]);
  }

  const elementLabel = (R, id) => { const e = R.elementById.get(id); return e ? oneLine(e.label) : ''; };

  /** "<label> (#<dfd>) — <zone>" (the register's Component cell). */
  function componentText(R, ev) {
    const e = R.elementById.get(ev.element);
    const label = e ? oneLine(e.label) || oneLine(e.id) : oneLine(ev.element);
    const dfd = num(ev.dfd);
    const zone = e && e.zone != null ? R.zoneById.get(e.zone) : null;
    return `${label}${dfd != null ? ` (#${dfd})` : ''} — ${zone ? oneLine(zone.label) || 'Unnamed zone' : 'Outside defined zones'}`;
  }

  /** "T1190 – Exploit Public-Facing Application (Initial Access) ◆", one line per technique. */
  function techniquesText(ev) {
    return objs(ev.techniques).map(t => {
      const id = oneLine(t.id), name = oneLine(t.name), tactics = list(t.tactics);
      let s = id && name ? `${id} – ${name}` : id || name;
      if (tactics.length) s += ` (${tactics.join(', ')})`;
      if (t.attributed) s += ' ◆';
      if (t.atlas) s += ' [ATLAS]';
      return s;
    }).filter(Boolean).join('\n');
  }

  /** "1. step -> 2. step -> 3. step". */
  const sequenceText = steps => list(steps).map((s, i) => `${i + 1}. ${s}`).join(' -> ');

  /** One line per technique: "T1190: M1016 Vulnerability Scanning; …", or the event's note when nothing is mapped. */
  function mitigationsText(ev) {
    const entries = objs(ev.mitigations);
    if (!entries.length) return txt(ev.mitigationNote);
    const atlasTech = new Set(objs(ev.techniques).filter(t => t.atlas).map(t => t.id));
    return entries.map(m => {
      const tech = oneLine(m.technique);
      const items = objs(m.items).map(i => [oneLine(i.id), oneLine(i.name)].filter(Boolean).join(' ')).filter(Boolean);
      const kb = atlasTech.has(m.technique) || isAtlasId(tech) ? 'ATLAS' : 'ATT&CK';
      const body = items.length ? items.join('; ') : `No ${kb} mitigation mapped — apply compensating controls`;
      return tech ? `${tech}: ${body}` : body;
    }).join('\n');
  }

  /** One line per technique: "T1190: <strategies> | Data sources: <sources>", or the event's note. */
  function detectionsText(ev) {
    const entries = objs(ev.detections);
    if (!entries.length) return txt(ev.detectionNote);
    return entries.map(d => {
      const tech = oneLine(d.technique);
      const strategies = list(d.strategies), sources = list(d.dataSources);
      let body = strategies.length ? strategies.join('; ') : 'No detection strategy mapped';
      if (sources.length) body += ' | Data sources: ' + sources.join(', ');
      return tech ? `${tech}: ${body}` : body;
    }).join('\n');
  }

  /** "1 -> 22 -> 15" + blank line + "1 <label> -> 22 <label> -> 15 <label>" (the Table of Attack's sequence cell). */
  function pathText(R, seq) {
    const path = arr(seq.path);
    // Each step is paired with its path element before empty steps are dropped, so a gap never shifts a label.
    const pairs = arr(seq.steps).map((step, i) => [step, path[i]]).filter(([step]) => txt(step) !== '');
    if (!pairs.length) return '';
    const named = pairs.map(([step, id]) => {
      let label = elementLabel(R, id);
      if (!label) {
        const at = R.locations.find(l => !l.ai === !seq.ai && num(l.dfd) != null && num(l.dfd) === num(step));
        if (at) label = elementLabel(R, at.element);
      }
      return label ? `${txt(step)} ${label}` : txt(step);
    });
    return pairs.map(([step]) => txt(step)).join(' -> ') + '\n\n' + named.join(' -> ');
  }

  /**
   * A lens's techniques. The reference writes an ATLAS-only lens as "— (ATLAS: AML.T0035, …)": a list of
   * clean IDs that holds ATLAS IDs is written that way; anything else is joined as it is.
   */
  function lensTechniquesText(ids) {
    const all = list(ids);
    if (!all.length) return '—';
    if (!all.every(isTechniqueId) || !all.some(isAtlasId)) return all.join(', ');
    const attack = all.filter(id => !isAtlasId(id)), atlas = all.filter(isAtlasId);
    return `${attack.length ? attack.join(', ') : '—'} (ATLAS: ${atlas.join(', ')})`;
  }

  // ---------- profile wording ----------

  const actorDomain = a => (a.domain === 'atlas' || isAtlasId(txt(a.attackId)) ? 'atlas' : 'attack');

  const ATTACK_DOMAIN = { 'enterprise-attack': 'Enterprise', 'ics-attack': 'ICS', 'mobile-attack': 'Mobile' };
  /** 'Enterprise' for an ATT&CK knowledge entry, whatever its name says ('ATT&CK Enterprise', 'Enterprise', …). */
  const attackDomainName = k => ATTACK_DOMAIN[k.domain]
    || oneLine(k.name).replace(/^(MITRE\s+)?ATT&CK\s+(for\s+)?/i, '').replace(/\s+ATT&CK$/i, '') || oneLine(k.domain);

  // The result does not record which ATT&CK domain a cited technique is from, and ICS shares Enterprise's numbering
  // (T1691–T1695, T1701), so the domain is read from what the event carries. An ICS technique has ICS numbering
  // (T0xxx), an ICS-only tactic or an ICS mitigation (M08xx / M09xx); many Mobile ones have a Mobile-only mitigation
  // (M1001–M1012, M1014). No Enterprise technique has any of these (all 810 Enterprise and ICS techniques of
  // ATT&CK v20 checked), so a technique with none counts as Enterprise's when Enterprise data was loaded.
  const ICS_TACTICS = new Set(['Inhibit Response Function', 'Impair Process Control', 'Evasion']);
  function techniqueDomain(t, ev) {
    const id = oneLine(t.id);
    const mitigations = objs(ev.mitigations).filter(m => oneLine(m.technique) === id)
      .flatMap(m => objs(m.items).map(i => oneLine(i.id)));
    if (/^T0\d{3}(\.\d{3})?$/i.test(id) || list(t.tactics).some(x => ICS_TACTICS.has(oneLine(x)))
      || mitigations.some(m => /^M0[89]\d\d$/i.test(m))) return 'ics';
    return mitigations.some(m => /^M10(0[1-9]|1[0-24])$/i.test(m)) ? 'mobile' : '';
  }
  /** The loaded ATT&CK domains (knowledge entries) that the threat events' ATT&CK techniques come from. */
  function citedAttackDomains(R) {
    const found = new Set(R.events.flatMap(ev => objs(ev.techniques)
      .filter(t => oneLine(t.id) && !t.atlas && !isAtlasId(oneLine(t.id))).map(t => techniqueDomain(t, ev))));
    const kind = k => { const n = attackDomainName(k).toLowerCase(); return n === 'ics' || n === 'mobile' ? n : 'enterprise'; };
    const enterprise = R.attackKnowledge.some(k => kind(k) === 'enterprise');
    return R.attackKnowledge.filter(k => (kind(k) === 'enterprise' ? found.has('')
      : found.has(kind(k)) || (kind(k) === 'mobile' && found.has('') && !enterprise)));
  }

  /** "UNC3886 (MITRE ATT&CK group G1048)". */
  function actorPhrase(a) {
    const kb = actorDomain(a) === 'atlas' ? 'MITRE ATLAS' : 'MITRE ATT&CK';
    const what = [kb, KIND_NAME[a.kind] || '', oneLine(a.attackId)].filter(Boolean).join(' ');
    const name = oneLine(a.name);
    return name ? `${name} (${what})` : what;
  }

  /** The MITRE page for a profile entry, or '' when its kind or ID gives none. */
  function actorUrl(a) {
    const id = oneLine(a.attackId);
    const domain = actorDomain(a);
    const route = ACTOR_PAGE[domain][a.kind];
    if (!route || !/^[A-Za-z0-9.]+$/.test(id)) return '';
    return (domain === 'atlas' ? ATLAS_SITE : ATTACK_SITE) + route + '/' + id;
  }

  /** The entries' names (else IDs), each once. */
  const actorNames = actors => uniq(actors.map(a => oneLine(a.name) || oneLine(a.attackId)).filter(Boolean));

  /** Profile entries in running text: "UNC3886", "APT28 and APT29", "APT28, Sandworm Team and APT29", "A, B and 3 others". */
  function namePhrase(actors) {
    const names = actorNames(actors);
    if (names.length <= 1) return names[0] || '';
    if (names.length <= 3) return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
    return `${names.slice(0, 2).join(', ')} and ${names.length - 2} others`;
  }

  /**
   * "Threat Profile (<short>)", within Excel's 31 characters and without the characters it forbids. A short
   * name that does not fit gives way to a more compact form of the same profile before anything is cut: the
   * entries' names, the lead entry (ATT&CK first) and a count ("UNC3886 +1"), the IDs, the lead ID and a count.
   */
  function profileSheetName(R) {
    const room = EXCEL_NAME_MAX - 'Threat Profile ()'.length;
    const safe = s => clean(oneLine(s)).replace(/[[\]:*?/\\]/g, ' ').replace(/\s+/g, ' ').trim();
    const actors = R.profile.actors;
    const lead = R.attackActors[0] || actors[0] || {};
    const more = actors.length > 1 ? ` +${actors.length - 1}` : '';
    const all = key => (actors.every(a => oneLine(a[key])) ? actors.map(a => oneLine(a[key])).join(', ') : '');
    const forms = [R.profile.short, all('name'), oneLine(lead.name) && oneLine(lead.name) + more,
      all('attackId'), oneLine(lead.attackId) && oneLine(lead.attackId) + more].map(safe).filter(Boolean);
    let s = forms.find(f => f.length <= room) || forms[0] || '';
    if (s.length > room) {
      let cut = room - 1;
      if (/[\uD800-\uDBFF]/.test(s[cut - 1])) cut--;
      s = s.slice(0, cut).trimEnd() + '…';
    }
    return s ? `Threat Profile (${s})` : 'Threat Profile';
  }

  /**
   * The Threat Profile's technique column header: "Representative G1048 ATT&CK techniques". The lenses hold the
   * ATT&CK entries' techniques (ATLAS ones, when a hand-built profile has them, are bracketed as "(ATLAS: …)").
   */
  function profileTechniquesHeader(R) {
    const ids = R.attackName ? uniq(R.attackActors.map(a => oneLine(a.attackId)).filter(Boolean)) : [];
    return `Representative ${ids.length && ids.length <= 3 ? ids.join(', ') + ' ' : ''}ATT&CK techniques`;
  }

  /** Why an AI sheet is empty. */
  function noAiReason(R) {
    if (R.aiEvents.length) return '';
    if (!R.elements.some(e => e.ai === true)) return 'No AI elements were identified in this architecture.';
    return 'AI elements were identified, but the AI (MAESTRO / ATLAS) pass raised no threat events'
      + (R.warnings.length ? ' — see the warnings on the About sheet.' : '.');
  }

  /**
   * The zone that hosts the platform, which MAESTRO L4 (Deployment & Infrastructure) maps to, if the model has
   * one: a zone named "… infrastructure …" (not a PKI, nor a sector such as critical infrastructure) holding
   * processes, clusters or datastores, directly or in zones nested in it. { zone, covered, uncovered }: the labels
   * of those elements the ATT&CK pass raised threat events at, and of those it raised none at; or null.
   */
  function infrastructureZone(R) {
    const hosting = z => /\binfra(structure)?\b/i.test(txt(z.label))
      && !/public[\s-]*key|\bpki\b|critical\s+(national\s+|information\s+)?infra|\bcn?ii\b/i.test(txt(z.label));
    const raised = new Set(R.attackEvents.map(ev => txt(ev.element)));
    for (const zone of R.zones.filter(hosting)) {
      const inside = new Set([zone.id]);
      for (let grew = true; grew;) {
        grew = false;
        for (const z of R.zones) {
          if (z.parent != null && inside.has(z.parent) && !inside.has(z.id)) { inside.add(z.id); grew = true; }
        }
      }
      const hosted = R.elements.filter(e => e.zone != null && inside.has(e.zone) && ['process', 'cluster', 'datastore'].includes(e.type)
        && oneLine(e.label));
      if (!hosted.length) continue;
      const labels = covered => hosted.filter(e => raised.has(txt(e.id)) === covered).map(e => oneLine(e.label));
      return { zone, covered: labels(true), uncovered: labels(false) };
    }
    return null;
  }

  /** "a, b, c" ("a; b" when a label has a comma), at most `max` of them, then "and N more". */
  function labelList(labels, max) {
    const shown = labels.slice(0, max);
    const sep = labels.some(l => l.includes(',')) ? '; ' : ', ';
    return shown.join(sep) + (labels.length > max ? `${sep}and ${labels.length - max} more` : '');
  }

  // ---------- styles ----------

  const thin = { style: 'thin', color: { argb: C.grid } };
  const BOX = { top: thin, left: thin, bottom: thin, right: thin };
  const FONT = {
    head: { name: 'Calibri', size: 10, bold: true, color: { argb: C.white } },
    body: { name: 'Calibri', size: 9 },
    note: { name: 'Calibri', size: 9, italic: true },
    separator: { name: 'Calibri', size: 9, bold: true, italic: true, color: { argb: C.navy } },
    notApplicable: { name: 'Calibri', size: 8, color: { argb: C.grey } },
    sheetTitle: { name: 'Calibri', size: 12, bold: true, color: { argb: C.navy } },
    aboutTitle: { name: 'Calibri', size: 14, bold: true, color: { argb: C.navy } },
    aboutSection: { name: 'Calibri', size: 12, bold: true, color: { argb: C.navy } },
    aboutText: { name: 'Calibri', size: 10, color: { argb: C.black } },
  };
  const snFont = ink => ({ name: 'Calibri', size: 10, bold: true, color: { argb: ink } });
  const ALIGN = {
    centre: { horizontal: 'center', vertical: 'middle', wrapText: true },
    text: { horizontal: 'left', vertical: 'top', wrapText: true },
    about: { vertical: 'top', wrapText: true },
  };
  const fills = new Map();
  const solid = argb => {
    if (!fills.has(argb)) fills.set(argb, { type: 'pattern', pattern: 'solid', fgColor: { argb } });
    return fills.get(argb);
  };

  const HEAD = { font: FONT.head, fill: solid(C.header), alignment: ALIGN.centre, border: BOX };
  /** A table body cell: Calibri 9 on the row's band, wrapped, centred or top-left. */
  const body = (fill, centred) => ({ font: FONT.body, fill: solid(fill), alignment: centred ? ALIGN.centre : ALIGN.text, border: BOX });
  // Coverage cells keep the workbook's default font (Calibri 11), as in the reference.
  const plainCell = centred => ({ alignment: centred ? ALIGN.centre : ALIGN.text, border: BOX });
  const NOTE = { font: FONT.note, alignment: ALIGN.text };   // notes under a table (wrapped)
  const LEGEND = { font: FONT.note };                        // one-line legends and "nothing to show" rows
  const SEPARATOR = { font: FONT.separator, fill: solid(C.separator), border: BOX };

  /** Writes one cell. Text is cleaned; an empty string leaves the cell empty (styled). */
  function put(ws, row, col, value, style) {
    const cell = ws.getCell(row, col);
    if (typeof value === 'number') cell.value = Number.isFinite(value) ? value : null;
    else { const t = clean(txt(value)); cell.value = t === '' ? null : t; }
    if (style) Object.assign(cell, style);
    return cell;
  }

  /**
   * Column widths, as written to the sheet's <cols> (see build): ExcelJS drops a width of exactly 9,
   * its own default, which would leave such a column at Excel's 8.43.
   */
  const WIDTHS = new WeakMap();
  function widths(ws, list) {
    list.forEach((w, i) => { ws.getColumn(i + 1).width = w; });
    WIDTHS.set(ws, list);
  }

  /** Column widths and the header row: white bold on blue, centred, wrapped, 34 pt high. */
  function header(ws, row, cols) {
    widths(ws, cols.map(c => c[1]));
    cols.forEach(([title], i) => put(ws, row, i + 1, title, HEAD));
    ws.getRow(row).height = 34;
  }

  /** Sheet view: no gridlines; frozen header rows and key columns where the reference freezes them. */
  function view(ws, xSplit, ySplit) {
    ws.views = [ySplit
      ? { state: 'frozen', xSplit, ySplit, topLeftCell: colLetter(xSplit + 1) + (ySplit + 1), activeCell: 'A1', showGridLines: false }
      : { activeCell: 'A1', showGridLines: false }];
  }

  /**
   * Print setup (the reference has none; screen views are unaffected): landscape, one page wide, the
   * header row repeated on every page, and a footer with the system, sheet and page number. The repeated
   * row is written as the sheet's _xlnm.Print_Titles name when the workbook is saved (see build): ExcelJS
   * would not double an apostrophe in the sheet name ('Threat Profile (O''Brien)'), which breaks the name.
   */
  const TITLE_ROWS = new WeakMap();
  function print(ws, R, titleRow, paperSize) {
    ws.pageSetup = {
      orientation: 'landscape', paperSize, fitToPage: true, fitToWidth: 1, fitToHeight: 0,
      margins: { left: 0.4, right: 0.4, top: 0.5, bottom: 0.6, header: 0.3, footer: 0.3 },
    };
    if (titleRow) TITLE_ROWS.set(ws, titleRow);
    // '&' starts a footer code, so it is doubled; Excel allows 255 characters in all.
    const full = clean(R.system);
    let system = full.slice(0, 120);
    while (system.replace(/&/g, '&&').length > 200) system = system.slice(0, -1);
    if (system.length < full.length) system = system.replace(/[\uD800-\uDBFF]$/, '') + '…';
    ws.headerFooter = { oddFooter: `&L${system.replace(/&/g, '&&')} — &A&RPage &P of &N` };
  }
  const A4 = 9, A3 = 8;

  // ---------- sheets ----------

  /** Threat Register: ATT&CK rows banded per component, then the separator and the AI rows. */
  function writeRegister(ws, R) {
    header(ws, 1, REGISTER_COLS);
    let row = 2;
    if (!R.attackEvents.length) {
      put(ws, row++, 2, R.aiEvents.length ? 'No ATT&CK (STRIDE-LM) threat events were raised for this architecture.'
        : 'No threat events were raised for this architecture.', LEGEND);
    }
    let band = 1, at = null;
    for (const ev of R.attackEvents) {
      const here = txt(ev.element) + '#' + txt(ev.dfd);
      if (here !== at) { band = 1 - band; at = here; }
      eventRow(ws, row++, R, ev, C.registerBand[band]);
    }
    if (R.aiEvents.length) {
      const atlas = shortVersion(R.atlasVersion);
      const text = `AI THREAT ACTORS — identified via MAESTRO (L1–L7); TTPs from MITRE ATLAS${withV(atlas)}. `
        + `Rows below are the AI-surface extension to the ${R.pass} model above.`;
      for (let c = 1; c <= REGISTER_COLS.length; c++) put(ws, row, c, c === 2 ? text : null, SEPARATOR);
      ws.getRow(row++).height = 16;
      R.aiEvents.forEach((ev, i) => eventRow(ws, row++, R, ev, C.aiBand[i % 2]));
    }
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: row - 1, column: REGISTER_COLS.length } };
    view(ws, 2, 1);
    print(ws, R, 1, A3);
    return row - 1;
  }

  /** One threat event: severity colours the S/n cell, the rest of the row carries the band. */
  function eventRow(ws, row, R, ev, fill) {
    const sev = SEVERITY[ev.severity];
    put(ws, row, 1, num(ev.sn) != null ? num(ev.sn) : ev.sn,
      { font: snFont(sev ? sev.ink : C.black), fill: solid(sev ? sev.fill : fill), alignment: ALIGN.centre, border: BOX });
    const cells = [ev.threat, techniquesText(ev), ev.stride, ev.actor, sequenceText(ev.sequence), ev.event,
      componentText(R, ev), mitigationsText(ev), detectionsText(ev)];
    cells.forEach((v, i) => put(ws, row, i + 2, v, body(fill, false)));
  }

  /** Table of Attack (CSA) and its AI counterpart: one row per attack sequence. */
  function writeAttack(ws, R, ai) {
    const cols = ai ? AI_ATTACK_COLS : ATTACK_COLS;
    header(ws, 1, cols);
    const seqs = R.sequences.filter(s => !s.ai === !ai);
    if (!seqs.length) {
      put(ws, 2, 2, (ai && noAiReason(R)) || (ai ? 'No AI attack sequences were built for this architecture.'
        : 'No attack sequences were built for this architecture.'), LEGEND);
    }
    seqs.forEach((s, i) => {
      const fill = (ai ? C.aiBand : C.tableBand)[i % 2];
      const cells = ai
        ? [s.id, s.entry, s.actor, s.layers, pathText(R, s), s.narrative, s.examples]
        : [s.id, s.entry, s.actor, pathText(R, s), s.narrative, s.examples];
      cells.forEach((v, c) => put(ws, i + 2, c + 1, txt(v), body(fill, c === 0 || (ai && c === 3))));
    });
    view(ws, 0, 1);
    print(ws, R, 1, A4);
  }

  /** STRIDE-LM Coverage: each element against each category, with the legend under the table. */
  function writeCoverage(ws, R) {
    header(ws, 1, COVERAGE_COLS);
    if (!R.coverage.length) {
      put(ws, 2, 2, R.elements.length ? 'No STRIDE-LM coverage was recorded for this analysis.'
        : 'The decomposition has no elements, so there is no STRIDE-LM coverage to show.', LEGEND);
    }
    R.coverage.forEach((c, i) => {
      const row = i + 2;
      const e = R.elementById.get(c.element);
      const cells = obj(c.cells);
      put(ws, row, 1, num(c.dfd), plainCell(true));
      put(ws, row, 2, e ? oneLine(e.label) : oneLine(c.element), plainCell(false));
      put(ws, row, 3, e ? oneLine(e.type) : '', plainCell(true));
      STRIDE.forEach((k, j) => {
        const v = oneLine(cells[k]);
        const style = v === 'X' ? Object.assign({ fill: solid(C.raised) }, plainCell(true))
          : v === 'o' ? Object.assign({ fill: solid(C.open) }, plainCell(true))
            : v === 'n/a' ? Object.assign({ font: FONT.notApplicable, fill: solid(C.notApplicable) }, plainCell(true))
              : plainCell(true);
        put(ws, row, 4 + j, v, style);
      });
      const raised = num(c.raised) != null ? num(c.raised) : STRIDE.filter(k => oneLine(cells[k]) === 'X').length;
      put(ws, row, 11, raised, plainCell(true));
      put(ws, row, 12, txt(c.notes), { font: FONT.body, alignment: ALIGN.text, border: BOX });
    });
    if (R.coverage.length) {
      put(ws, R.coverage.length + 3, 2, 'X = threat event raised    o = applicable, not raised in this pass '
        + '(analyst-reviewable omission)    n/a = not applicable to this element type (STRIDE-per-element)', LEGEND);
    }
    view(ws, 3, 1);
    print(ws, R, 1, A4);
  }

  /** Threat Profile: the Sectorial Threat Profile lenses, with the profile's MITRE entries under them. */
  function writeProfile(ws, R) {
    const titles = ['ID', 'Threat (lens)', 'Evidence / public reporting', profileTechniquesHeader(R), 'Status'];
    header(ws, 1, titles.map((t, i) => [t, PROFILE_WIDTHS[i]]));
    if (!R.lenses.length) put(ws, 2, 2, 'No Sectorial Threat Profile lenses were built for this analysis.', LEGEND);
    R.lenses.forEach((l, i) => {
      const fill = C.tableBand[i % 2];
      const status = oneLine(l.status);
      put(ws, i + 2, 1, txt(l.id), body(fill, true));
      put(ws, i + 2, 2, txt(l.name), body(fill, false));
      put(ws, i + 2, 3, txt(l.evidence), body(fill, false));
      put(ws, i + 2, 4, lensTechniquesText(l.techniques), body(fill, false));
      put(ws, i + 2, 5, status, body(status === 'Extrapolated' ? C.extrapolated : fill, true));
    });
    if (R.lenses.length) {
      const one = R.lenses.length === 1;
      const marked = R.events.some(e => objs(e.techniques).some(t => t.attributed));
      const note = R.hasProfile
        ? `MITRE entries in this threat profile: ${R.profile.actors.map(actorPhrase).join('; ')}.`
          + (R.genericLenses ? ` ${one ? 'The lens above lists' : 'The lenses above list'} no technique from this profile, so `
            + `${one ? 'it models' : 'they model'} a generic attacker.` : '')
        : R.genericLenses ? `No threat profile was selected: ${one ? 'the lens models' : 'the lenses model'} a generic attacker`
          + `${marked ? '' : ', and no technique is marked ◆'}.`
          : 'No MITRE entry is recorded for this threat profile.';
      put(ws, R.lenses.length + 3, 2, note, NOTE);
    }
    view(ws, 0, 0);
    print(ws, R, 1, A4);
  }

  /** AI Threat Profile: title and note, the MAESTRO lenses, then the layer and adversary-class notes. */
  function writeAiProfile(ws, R) {
    const atlas = shortVersion(R.atlasVersion);
    put(ws, 1, 1, `AI threat actors — MAESTRO 7-layer framework (threat identification) + MITRE ATLAS${withV(atlas)} (TTPs)`,
      { font: FONT.sheetTitle });
    header(ws, AI_PROFILE_HEADER_ROW, AI_PROFILE_COLS);
    const reason = noAiReason(R) || (R.aiProfile.length ? '' : 'No MAESTRO lenses were built for this analysis.');
    if (reason) {
      // Under the header, unwrapped, as on the other empty sheets (wrapped in the 9-wide column A it would
      // stand as a narrow strip of one word per line).
      put(ws, AI_PROFILE_HEADER_ROW + 1, 2, reason, LEGEND);
    } else {
      const who = R.groupName ? ` (e.g. ${R.groupName})` : '';
      put(ws, 2, 1, `The AI attack surface is actor-agnostic: a capable threat actor${who} may layer these on the `
        + 'infrastructure intrusion in Figure 1, and a lone external user can reach L1/L3 threats through any exposed '
        + 'AI application with no network foothold. Adversary classes below are representative, not exhaustive.', NOTE);
      R.aiProfile.forEach((p, i) => {
        const row = AI_PROFILE_HEADER_ROW + 1 + i;
        const fill = C.aiProfileBand[i % 2];
        put(ws, row, 1, [oneLine(p.layer), oneLine(p.layerName)].filter(Boolean).join(' '), body(fill, true));
        put(ws, row, 2, txt(p.lens), body(fill, false));
        put(ws, row, 3, txt(p.summary), body(fill, false));
        put(ws, row, 4, list(p.techniques).join(', '), body(fill, false));
        put(ws, row, 5, Array.isArray(p.caseStudies) ? list(p.caseStudies).join('; ') : txt(p.caseStudies), body(fill, false));
      });
      const after = AI_PROFILE_HEADER_ROW + R.aiProfile.length + 2;
      // Covered only where the ATT&CK pass raised threat events (Figure 1's octagons).
      const infra = infrastructureZone(R);
      const l4 = infra && infra.covered.length ? 'covered by the infrastructure zone in Fig. 1'
        : infra ? `the infrastructure zone in Fig. 1, where the ${R.pass} pass raised no threat event`
          : R.attackEvents.length ? `covered by the ${R.pass} pass in Fig. 1` : `the ${R.pass} pass raised no threat event`;
      put(ws, after, 1, 'MAESTRO layers: L1 Foundation Models · L2 Data Operations · L3 Agent Frameworks · '
        + `L4 Deployment & Infrastructure (${l4}) · L5 Evaluation & Observability · `
        + 'L6 Security & Compliance (cross-cutting) · L7 Agent Ecosystem.', NOTE);
      put(ws, after + 1, 1, 'AI adversary classes: external user / prompt-injection adversary; indirect-injection '
        + 'adversary (poisoned-content author); model-extraction adversary (API consumer); AI supply-chain adversary '
        + '(model / dataset / tool / package); malicious or negligent insider; compromised or rogue agent / tool.', NOTE);
    }
    view(ws, 0, 0);
    print(ws, R, AI_PROFILE_HEADER_ROW, A4);
  }

  /** MAESTRO Coverage: each AI element against the seven layers. */
  function writeMaestro(ws, R) {
    header(ws, 1, MAESTRO_COLS);
    const rows = R.maestroCoverage;
    if (!rows.length) put(ws, 2, 2, noAiReason(R) || 'No MAESTRO coverage was recorded for this analysis.', LEGEND);
    rows.forEach((m, i) => {
      const row = i + 2;
      const layers = obj(m.layers);
      put(ws, row, 1, num(m.dfd), plainCell(true));
      put(ws, row, 2, elementLabel(R, m.element) || oneLine(m.element), plainCell(false));
      LAYERS.forEach((k, j) => put(ws, row, 3 + j, layers[k] === true ? 'X' : null,
        Object.assign({ fill: solid(layers[k] === true ? C.raised : C.layerOff) }, plainCell(true))));
      put(ws, row, 10, num(m.events), plainCell(true));
    });
    if (rows.length) {
      // The reference names the zone and what it hosts; the elements' own labels say that without inventing.
      // Only the elements the ATT&CK pass raised threat events at are covered; the others are named as gaps.
      const infra = infrastructureZone(R);
      const zone = infra && oneLine(infra.zone.label);
      const where = zone && (/^the\s/i.test(zone) ? zone : 'the ' + zone);
      const see = R.coverage.length ? ' — see the STRIDE-LM Coverage sheet.' : '.';
      const gaps = infra && infra.uncovered.length ? `; the pass raised no threat event at ${labelList(infra.uncovered, 8)}${see}` : '.';
      const l4 = !infra ? `is the hosting infrastructure, ${R.attackEvents.length ? `covered under the ${R.pass} pass.`
        : `where the ${R.pass} pass raised no threat event.`}`
        : infra.covered.length ? `maps to ${where}, covered under the ${R.pass} pass (${labelList(infra.covered, 8)})${gaps}`
          : `maps to ${where}, where the ${R.pass} pass raised no threat event${see}`;
      put(ws, rows.length + 3, 2, 'X = AI threat event(s) identified at this element for the MAESTRO layer. '
        + `L4 (Deployment & Infrastructure) ${l4}`, NOTE);
    }
    view(ws, 2, 1);
    print(ws, R, 1, A4);
  }

  // ---------- About ----------

  /**
   * The About sheet's lines: [kind, text], kind = title | section | text | blank. Written to be true for
   * any result: names and counts come from it, and nothing is said about an actor beyond what it records.
   */
  function aboutLines(R) {
    const P = R.profile, S = R.stats;
    const out = [];
    const title = t => out.push(['title', t]);
    const section = t => { if (out.length) out.push(['blank', '']); out.push(['section', t]); };
    const say = t => out.push(['text', '  ' + t]);
    const stat = (key, fallback) => (num(S[key]) != null ? num(S[key]) : fallback);
    /** "  (High 33, Medium 27, Low 5)": the stats' counts (else counted from the events), zeros left out. */
    const sevText = (events, ai) => {
      const counts = ['High', 'Medium', 'Low']
        .map(s => [s, stat(ai ? 'ai' + s : s.toLowerCase(), events.filter(e => e.severity === s).length)])
        .filter(([, n]) => n > 0);
      return counts.length ? `  (${counts.map(([s, n]) => `${s} ${n}`).join(', ')})` : '';
    };

    const nElements = stat('elements', R.elements.length);
    const nFlows = stat('flows', R.flows.length);
    const nZones = stat('zones', R.zones.length);
    const nLoc = stat('locations', R.locations.filter(l => !l.ai).length);
    const nAiLoc = stat('aiLocations', R.locations.filter(l => l.ai).length);
    const nEvents = stat('events', R.attackEvents.length);
    const nAi = stat('aiEvents', R.aiEvents.length);
    const attackSeqs = R.sequences.filter(s => !s.ai).length, aiSeqs = R.sequences.filter(s => s.ai).length;
    const atlas = shortVersion(R.atlasVersion), atlasFull = R.atlasVersion;
    const kbList = P.knowledge.map(k => (k.domain === 'atlas' ? 'ATLAS' : `ATT&CK ${attackDomainName(k)}`)
      + withV(fullVersion(k.version)));
    // The ATT&CK data loaded (every ID printed, the Threat Profile's lenses included, comes from it), and the
    // domains the threat events' techniques come from (what the events are mapped to).
    const attackDomains = R.attackKnowledge.map(k => `${oneLine(k.domain) || oneLine(k.name)}${withV(fullVersion(k.version))}`);
    const attackNames = uniq(citedAttackDomains(R).map(attackDomainName).filter(Boolean));
    // The techniques the threat events cite (both passes)
    const techs = R.events.flatMap(e => objs(e.techniques));
    const ids = uniq(techs.map(t => oneLine(t.id)).filter(Boolean));
    const atlasIds = ids.filter(id => isAtlasId(id) || techs.some(t => t.atlas && oneLine(t.id) === id));
    const attributed = uniq(techs.filter(t => t.attributed).map(t => oneLine(t.id)).filter(Boolean));
    const profileName = R.profileName || 'the threat profile';
    // ATLAS is a source only when the register prints something from it: an ATLAS technique, AI rows (their case
    // studies), an ATLAS entry in the threat profile, or an ATLAS ID among the lenses.
    const usesAtlas = atlasIds.length > 0 || R.aiEvents.length > 0 || P.actors.some(a => actorDomain(a) === 'atlas')
      || R.lenses.some(l => list(l.techniques).some(isAtlasId));
    const atlasMarked = atlasIds.length ? ' ATLAS techniques are marked [ATLAS].' : '';

    title(`Cyber Threat Modelling Register — ${R.system}`);
    out.push(['text', R.hasProfile ? `Threat profile: ${P.actors.map(actorPhrase).join('; ')}.`
      : 'Threat profile: none selected — the threat events model a generic attacker.']);

    // Methodology (CSA §3)
    section('Methodology');
    out.push(['text', 'Produced following the CSA Guide to Cyber Threat Modelling (Cyber Security Agency of Singapore), Section 3:']);
    const file = oneLine(R.source.file);
    const crown = R.elements.filter(e => e.crownJewel === true).map(e => oneLine(e.label)).filter(Boolean);
    const crownText = crown.length
      ? `crown jewels as marked in the decomposition: ${crown.slice(0, 10).join('; ')}${crown.length > 10 ? `; and ${crown.length - 10} more` : ''}.`
      : 'no element is marked as a crown jewel in the decomposition.';
    say(`3.1 Scope definition — the supplied architecture${file ? ` (${file})` : ''} defines the perimeter of ${R.system}; ${crownText}`);
    // How the decomposition was made: parsed from the file, read by Claude, or built by hand
    const how = oneLine(R.method.decomposition) || oneLine(R.source.method);
    const made = how === 'claude'
      ? `read by Claude from the supplied ${file ? `file ${file}` : 'diagram'}; check it against the source before relying on it`
      : how === 'manual' ? `built by hand in ThreatSim${R.source.kind === 'json' && file ? ` and loaded from ${file}` : ''}`
        : how === 'parsed' ? `parsed from the supplied ${SOURCE_KIND[R.source.kind] || 'diagram'}`
          : 'taken from the supplied system model';
    say(`3.2 System decomposition — ${plural(nElements, 'element')}, ${plural(nFlows, 'data flow')} and `
      + `${plural(nZones, 'trust zone')} ${made} (CSA Figures 3–5).`);
    // The lenses come from the profile's ATT&CK entries; lenses that list no technique model a generic attacker.
    const stpName = R.attackName || (R.hasProfile ? R.profileName : '');
    say('3.3 Threat identification — STRIDE-LM applied to every element, viewed through ' + (!R.lenses.length
      ? 'the component context (CSA Figure 12); no Sectorial Threat Profile lens was recorded.'
      : `${R.genericLenses ? 'a generic ' : `the ${stpName ? stpName + ' ' : ''}`}Sectorial Threat Profile `
        + `(${plural(R.lenses.length, 'lens', 'lenses')}) and the component context (CSA Figure 12).`));
    const attackCited = ids.length > atlasIds.length || !atlasIds.length;
    say('Attack modelling — each threat event mapped to '
      + (attackCited ? `MITRE ATT&CK${attackNames.length ? ` (${attackNames.join(', ')})` : ''}` : 'MITRE ATLAS')
      + `${attackCited && atlasIds.length ? ' and, for AI-specific steps, MITRE ATLAS' : ''}; `
      + (attackSeqs ? `${plural(attackSeqs, 'end-to-end attack sequence')} in the Table of Attack (CSA) sheet.`
        : 'no end-to-end attack sequence was built (see the Table of Attack (CSA) sheet).'));

    // The AI pass
    section('AI threat-actor extension');
    if (nAi) {
      const first = R.aiEvents.map(e => num(e.sn)).find(n => n != null);
      say('A second pass models AI threat actors using the MAESTRO 7-layer framework (Cloud Security Alliance) for threat '
        + `identification and MITRE ATLAS${withV(atlas)} for TTPs. It covers the AI-specific attack surface (prompt `
        + 'injection, data / model poisoning, model extraction, agentic tool abuse, AI supply chain) at '
        + `${plural(nAiLoc, 'AI-pipeline element')}, with ${plural(aiSeqs, 'AI attack sequence')}. See the AI rows in this `
        + `register${first != null ? ` (S/n ${first}+)` : ''}, the AI Table of Attack (MAESTRO), AI Threat Profile (MAESTRO) `
        + 'and MAESTRO Coverage sheets, and the AI figures in the DFD deck.');
      say(`The AI attack surface is actor-agnostic: ${R.groupName
        ? `${R.groupName} could layer these on ${R.groupsAreMany ? 'their' : 'its'}`
        : 'an attacker could layer these on an'} infrastructure intrusion, and a lone external user can reach L1/L3 threats `
        + 'via any exposed AI application with no network foothold.');
    } else {
      say(noAiReason(R).replace(/\.$/, '') + ', so the MAESTRO / ATLAS pass added no rows to this register.');
    }

    // Scope (counts from the result)
    section('Scope of this analysis');
    say(`Elements: ${nElements}   Data flows: ${nFlows}   Trust zones: ${nZones}   Threat-event locations: ${nLoc} (${R.pass}) + ${nAiLoc} (AI)`);
    say(`${R.pass} (STRIDE-LM) threat events: ${nEvents}${sevText(R.attackEvents, false)}`);
    say(`AI (MAESTRO/ATLAS) threat events: ${nAi}${sevText(R.aiEvents, true)}`);
    say(`Total: ${plural(nEvents + nAi, 'threat event')} across both passes.`);
    const statuses = uniq(R.lenses.map(l => oneLine(l.status).toLowerCase()).filter(Boolean))
      .map(st => `${R.lenses.filter(l => oneLine(l.status).toLowerCase() === st).length} ${st}`);
    say(`Sectorial Threat Profile items: ${R.lenses.length}${R.attackName ? ' ' + R.attackName : ''}`
      + `${statuses.length ? ` (${statuses.join(' + ')})` : ''} + ${plural(R.aiProfile.length, 'MAESTRO AI lens', 'MAESTRO AI lenses')}.`);
    say(R.hasProfile
      ? `◆ marks a technique MITRE attributes to ${P.label || P.actors.map(actorPhrase).join('; ')} — ${attributed.length} of the `
        + `${plural(ids.length, 'distinct technique')} in this register. Other techniques are STRIDE-LM-derived for this `
        + `architecture and not necessarily observed for ${profileName}.${atlasMarked}`
      : 'No threat profile was selected, so no technique is marked ◆ (attributed by MITRE to the profile): the techniques '
        + `are STRIDE-LM-derived for this architecture.${atlasMarked}`);

    // Verification: how many IDs, and where they came from
    section('ATT&CK / ATLAS verification');
    say(`${plural(ids.length - atlasIds.length, 'distinct ATT&CK technique ID')} and ${plural(atlasIds.length, 'distinct ATLAS technique ID')} `
      + 'appear in the threat events (both passes).');
    const when = dateText(R.generatedAt);
    const loaded = `the MITRE data loaded locally in ThreatSim${kbList.length ? ` (${kbList.join('; ')})` : ''} when the `
      + `analysis ran${when ? ` (generated ${when})` : ''}; none was typed in by hand.`;
    // Claude's drafts are checked for technique IDs only (TMEngine.applyEnrichment), so the claim is narrowed.
    say(R.method.enrichment === 'claude'
      ? `Every technique, mitigation and detection-strategy ID in the Techniques, Mitigations and Detections columns was taken from ${loaded} `
        + 'The threat-event text, attack steps and attack-sequence narratives were drafted with Claude and checked for technique '
        + 'IDs only (each must be one the event, or an event on the attack path, already cites): verify any other identifier they '
        + 'mention, such as a mitigation, group, software, case-study or CVE ID, before use.'
      : `Every technique, mitigation and detection-strategy ID printed was taken from ${loaded}`);
    const actorUrls = uniq(P.actors.map(actorUrl).filter(Boolean));
    const data = ['https://github.com/mitre/cti'].concat(usesAtlas ? ['https://github.com/mitre-atlas/atlas-data'] : []);
    say('Sources: ' + data.concat(actorUrls, usesAtlas ? ['https://atlas.mitre.org'] : []).join(' · '));

    // Severity (the engine's score, described without its thresholds). The profile's two factors apply to the
    // ATT&CK rows of a profiled run: the lens emphasising the category, and a cited technique MITRE attributes (◆).
    section('How to read severity');
    say('Severity colours the S/n cell (red High, orange Medium, yellow Low). It is a triage aid, not a risk rating. '
      + 'It scores the damage the STRIDE-LM category does if it lands, what is at stake on the element (crown jewel vs '
      + 'sensitive), ' + (R.attackName
      ? `how reachable the element is and, in the ATT&CK rows, whether the ${R.attackName} profile says attacks arrive this `
        + `way and whether MITRE attributes a cited technique to ${R.attackName} (marked ◆).`
      : 'and how reachable the element is.')
      + ' It carries no likelihood or control-effectiveness judgement — apply your own risk methodology (e.g. CSA CII risk '
      + 'assessment) before reporting.');

    // Assumptions and limits
    section('Assumptions and limits');
    // Authentication the decomposition leaves empty, or gives as an assumption ("… (assumed)", "(not stated)").
    const auth = R.elements.map(e => oneLine(obj(e.context).auth));
    const assumed = auth.filter(a => /\(assumed\)/i.test(a)).length;
    const unstated = auth.filter(a => !a || /\(not stated\)/i.test(a)).length;
    if (assumed || unstated) {
      const total = R.elements.length;
      // "assumed for 20 of the 31 elements", "not stated for all 5 elements", "assumed for 3 and not stated for 2 of the 9 elements"
      const share = assumed && unstated ? `assumed for ${assumed} and not stated for ${unstated} of the ${total} elements`
        : `${assumed ? 'assumed' : 'not stated'} for ${(assumed || unstated) < total ? `${assumed || unstated} of the ${total} elements`
          : total === 1 ? 'the only element' : `all ${total} elements`}`;
      const markers = ['(assumed)', '(not stated)'].filter(m => auth.some(a => a.toLowerCase().includes(m)));
      say(`Authentication was ${share} in the decomposition${markers.length ? ` (marked ${markers.map(m => `"${m}"`).join(' / ')} there)` : ''}; `
        + 'confirm it before relying on the threat events raised there.');
    }
    say(`Existing controls were not assessed. Mitigations listed are MITRE ATT&CK${atlasIds.length ? '/ATLAS' : ''} recommended `
      + 'controls, not a gap analysis of what is deployed.');
    const extrapolated = R.lenses.filter(l => oneLine(l.status) === 'Extrapolated');
    if (extrapolated.length) {
      const one = extrapolated.length === 1;
      const which = extrapolated.map(l => oneLine(l.id)).filter(Boolean).join(', ') || (one ? 'One lens' : 'Some lenses');
      say(`${which} ${one ? 'is' : 'are'} marked Extrapolated: `
        + (!R.genericLenses ? `${one ? 'it goes' : 'they go'} beyond what MITRE records for ${R.attackName || profileName}.`
          : R.hasProfile ? `${one ? 'it models' : 'they model'} a generic attacker, not behaviour MITRE records for the threat profile.`
            : `with no threat profile selected, ${one ? 'it models' : 'they model'} a generic attacker, not recorded behaviour.`)
        + ` Treat the threat events raised through ${one ? 'it' : 'them'} as hypotheses for analyst review.`);
    }
    say(R.method.enrichment === 'claude'
      ? 'Threat-event text was drafted with Claude from the decomposition, the threat profile and the local MITRE data; '
        + 'review it before use.'
      : 'Threat-event text was generated by ThreatSim from the decomposition, the threat profile and the local MITRE data '
        + '(no AI drafting).');
    say('This register is a first pass for analyst review, not a finished assessment. Scope definition (3.1) and full '
      + "attack-scenario integration remain the analyst's.");
    if (nAi) say('The MAESTRO / ATLAS AI pass is actor-agnostic: its adversary classes are representative, not a named group.');
    if (R.warnings.length) {
      say('Warnings raised by the analysis:');
      R.warnings.slice(0, 40).forEach(w => say(`  • ${oneLine(w)}`));
      if (R.warnings.length > 40) say(`  … and ${R.warnings.length - 40} more.`);
    }

    // Sources: one MITRE page per profile entry, then the frameworks and data
    section('Sources');
    for (const a of P.actors) {
      const url = actorUrl(a);
      const name = [oneLine(a.name), oneLine(a.attackId) ? `(${oneLine(a.attackId)})` : ''].filter(Boolean).join(' ');
      say(`• ${actorDomain(a) === 'atlas' ? 'MITRE ATLAS' : 'MITRE ATT&CK'} — ${name || 'profile entry'}${url ? ` — ${url}` : ''}`);
    }
    say(`• MITRE ATT&CK STIX data${attackDomains.length ? ` (${attackDomains.join(', ')})` : ''} — https://github.com/mitre/cti`);
    if (usesAtlas) say(`• MITRE ATLAS data and case studies${withV(atlasFull)} — https://github.com/mitre-atlas/atlas-data`);
    say('• CSA Singapore — Guide to Cyber Threat Modelling (Feb 2021) — https://www.csa.gov.sg');
    if (usesAtlas) say(`• MITRE ATLAS (Adversarial Threat Landscape for AI Systems)${withV(atlasFull)} — https://atlas.mitre.org`);
    // The MAESTRO pass runs on every analysis (its sheets say what it found); OWASP's lists inform the AI rows only.
    say(`• Cloud Security Alliance — MAESTRO agentic-AI threat modelling framework — ${MAESTRO_URL}`);
    if (nAi) say('• OWASP Top 10 for LLM Applications & for Agentic AI (2025) — https://genai.owasp.org');
    return out;
  }

  function writeAbout(ws, R) {
    widths(ws, [ABOUT_WIDTH]);
    const font = { title: FONT.aboutTitle, section: FONT.aboutSection, text: FONT.aboutText, blank: FONT.aboutText };
    aboutLines(R).forEach(([kind, text], i) => put(ws, i + 1, 1, text, { font: font[kind], alignment: ALIGN.about }));
    view(ws, 0, 0);
    print(ws, R, 0, A4);
  }

  // ---------- workbook ----------

  /** Builds the register and returns it as an .xlsx Blob. */
  async function build(result) {
    const ExcelJS = global.ExcelJS;
    if (!ExcelJS) throw new Error('ExcelJS is not loaded (js/vendor/exceljs.min.js)');
    const R = prepare(result);

    const wb = new ExcelJS.Workbook();
    const when = new Date(txt(R.generatedAt));
    const stamp = Number.isNaN(when.getTime()) ? new Date() : when;
    wb.creator = 'ThreatSim';
    wb.lastModifiedBy = 'ThreatSim';
    wb.created = stamp;
    wb.modified = stamp;
    wb.title = clean(`Cyber Threat Modelling Register — ${R.system}`);
    wb.subject = clean(`Threat profile: ${R.profile.label || 'none'}`);

    const register = wb.addWorksheet(SHEET.register);
    writeRegister(register, R);
    writeAttack(wb.addWorksheet(SHEET.attack), R, false);
    writeAttack(wb.addWorksheet(SHEET.aiAttack), R, true);
    writeCoverage(wb.addWorksheet(SHEET.coverage), R);
    writeProfile(wb.addWorksheet(profileSheetName(R)), R);
    writeAiProfile(wb.addWorksheet(SHEET.aiProfile), R);
    writeMaestro(wb.addWorksheet(SHEET.maestro), R);
    writeAbout(wb.addWorksheet(SHEET.about), R);

    // Two edits to the XML as ExcelJS writes it (the technique js/workpaper.js uses):
    // - the workbook's defined names: the sheet-local, hidden _xlnm._FilterDatabase name that Excel writes
    //   for an autofilter (and the reference has; LibreOffice shows the filter only with it), which ExcelJS
    //   cannot write, and each sheet's _xlnm.Print_Titles, with the sheet name quoted as Excel requires.
    // - each sheet's <cols> lists every column's width, one <col> each, as the reference does.
    const patches = new Map();
    /** A sheet-local name: "'Sheet name'!<range>", the name quoted (an apostrophe doubled) and XML-escaped. */
    const definedName = (name, ws, range, hidden) => {
      const ref = `${quoteSheet(ws.name)}!${range}`.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return `<definedName name="${name}" localSheetId="${wb.worksheets.indexOf(ws)}"${hidden ? ' hidden="1"' : ''}>${ref}</definedName>`;
    };
    const filter = register.autoFilter;
    const names = [definedName('_xlnm._FilterDatabase', register, `$A$1:$${colLetter(filter.to.column)}$${filter.to.row}`, true)]
      .concat(wb.worksheets.filter(ws => TITLE_ROWS.has(ws)).map(ws => {
        const row = TITLE_ROWS.get(ws);
        return definedName('_xlnm.Print_Titles', ws, `$${row}:$${row}`, false);
      }))
      .join('');
    patches.set('xl/workbook.xml', xml => (xml.includes('</definedNames>')
      ? xml.replace('</definedNames>', () => names + '</definedNames>')
      : xml.replace('</sheets>', () => '</sheets><definedNames>' + names + '</definedNames>')));   // their place in CT_Workbook
    for (const ws of wb.worksheets) {
      const list = WIDTHS.get(ws);
      if (!list) continue;
      const cols = '<cols>' + list.map((w, i) => `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`).join('') + '</cols>';
      patches.set(`xl/worksheets/sheet${ws.id}.xml`, xml => (/<cols>[\s\S]*?<\/cols>/.test(xml)
        ? xml.replace(/<cols>[\s\S]*?<\/cols>/, () => cols)
        : xml.replace('<sheetData', () => cols + '<sheetData')));
    }
    const xlsx = wb.xlsx;
    for (const method of ['addWorkbook', 'addWorksheets']) {
      const original = xlsx[method].bind(xlsx);
      xlsx[method] = async (zip, model) => {
        const append = zip.append;
        zip.append = function (data, options) {
          const patch = options && patches.get(options.name);
          return append.call(this, patch && typeof data === 'string' ? patch(data) : data, options);
        };
        try { return await original(zip, model); } finally { zip.append = append; }
      };
    }

    const buf = await xlsx.writeBuffer();
    return new Blob([buf], { type: XLSX_MIME });
  }

  global.TMRegister = { build, FILE_NAME };
})(window);
