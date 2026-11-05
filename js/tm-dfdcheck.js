/*
 * tm-dfdcheck.js — the DFD check: the method of the architecture-to-drawio-dfd skill (its dfd_drawio.py:
 * check_model, layout, validate, emit and preview), ported to the page. It checks that a decomposition's elements
 * are joined by data flows and drawn in trust zones, redraws its layout in CSA notation, and writes the draw.io DFD
 * the cyber-threat-modelling skill reads.
 *
 * Global `DfdCheck` (pure: no DOM, except toSvg):
 *   check(model, { fix = true, redraw = 'auto', redrawn = false }) -> { model, fixes, findings, notes, counts, changed, layout, held, tally }
 *     model is a TMParse model ({ zones[{id, label, parent, geometry}], elements[{id, label, type, zone, geometry,
 *     context, crownJewel, ai}], flows[{id, source, target, label, bidirectional}], page, source, notes, … }); it is
 *     left as it is. The result's model is a copy. With fix, the copy has the automatic fixes: an element moves to the
 *     zone its position is drawn in (one centred only on the border of the zone that would take it keeps its own: see
 *     zoneMismatches), and, when every element and zone has a position, the layout is redrawn the way the skill draws
 *     it. A picture Claude read (source.method 'claude') is always redrawn, as the skill lays out what it reads. Any
 *     other diagram keeps its own layout when the
 *     redrawn one would have more geometry problems in all (overlaps, straddled borders…) than it has as drawn: held then
 *     says what redrawing would add (redraw 'always' redraws anyway). A trust zone drawn smaller than MIN_ZONE_AREA is
 *     made that big, in a redrawn layout or a kept one, without anything coming to overlap (see stretch()). Connectivity
 *     and zone gaps are findings, never fixed: no data flow or zone membership the diagram doesn't show is ever made up.
 *     A finding is { level: 'error' | 'warning', code, text, fix, fixAll, refs: { elements, zones, flows }, count? }
 *     (fixAll: the fix said of several findings of the kind at once; count: how many it stands for, when it sums up
 *     overlaps not listed one by one); a fix is { code, text, would, refs } (would: the fix as it would be made, for
 *     offering it; a zone move also has element, from and to; an enlarged zone has zone). redrawn: the layout was redrawn
 *     earlier (the fixes stand), which the advice on what is left depends on. changed: whether the copy differs. tally:
 *     the geometry findings of each code as drawn and as redrawn, when a redraw was weighed. held: { added: { code: how
 *     many more }, cleared: how many other problems would go, count: how many more in all, page, text, short } (text: a
 *     sentence; short: for a button, "would add 3 problems"). A label's trailing ★ (the skill's crown-jewel mark, as
 *     toDrawio writes it) is read as the mark: a fix, unless the element is marked as a crown jewel already, when it goes
 *     without one (so toDrawio's file reads back unchanged).
 *   GEOMETRY, LAYOUT: the codes of the findings on where things are drawn, and of the fixes that redraw the layout.
 *   MIN_ZONE_AREA: the least area (px², as the draw.io file writes it) of a zone after the fixes.
 *   toDrawio(model) -> string   the skill's emit(): a draw.io file in CSA notation
 *   toContext(model) -> object  the component context the cyber-threat-modelling skill takes beside that file (its
 *     --context JSON, as in its examples/sample_component_context.json): { [id as the draw.io file writes it]: { label,
 *     type, purpose?, sensitivity?, auth?, trust?, crown_jewel?: 'yes' | 'no', ai?: 'yes' | 'no' } } for every element,
 *     with the values toDrawio writes as its properties (label without the ★); a context field that is empty is left
 *     out, so that skill's own wording for it applies. Give it the model given to toDrawio.
 *   toSvg(model, { document }) -> SVGElement   the skill's preview(), in SVG, sized to fit its container
 *
 * Where the draw.io file differs from the skill's emit(), on purpose: labels are HTML-escaped (the styles say html=1);
 * characters XML can't hold are left out of ids, and an id that is then "0" or "1" (draw.io's own root cells) or another
 * element's is written with a _ after it (or more); the host is ThreatSim; the cluster style has double=1 and the entity
 * style shape=csaActor (see STYLE); an element drawn large with a zone word in its name has a fill (see BOUNDARY_WORDS);
 * an element centred on the border of a zone it isn't in is written a pixel into its own (see offBorders()); a zone is
 * at least MIN_ZONE_AREA; and what has no position is placed by placeRest(). The layout differs by its settle step and
 * its push-apart budget (see layout()).
 */
(function (global) {
  'use strict';

  // ---------------------------------------------------------------- the skill's constants (dfd_drawio.py)

  const TYPES = ['entity', 'process', 'cluster', 'datastore'];
  const SIZE = { entity: [130, 64], process: [108, 108], cluster: [118, 118], datastore: [128, 86] };
  const BLUE = '#41719C', RED = '#FF0000', DARK_RED = '#C00000';
  // The skill's styles, with two additions so that the cyber-threat-modelling skill's parser, which reads a cell's
  // label, style and size only, takes each shape for its type: double=1 marks the double circle (draw.io ignores it on
  // doubleEllipse), and shape=csaActor the external entity (draw.io has no shape of that name and draws its plain
  // rectangle; that parser and TMParse read "actor" in a shape as an entity).
  const STYLE = {
    entity: `rounded=0;shape=csaActor;whiteSpace=wrap;html=1;fillColor=none;strokeColor=${BLUE};fontSize=11;`,
    process: `ellipse;whiteSpace=wrap;html=1;aspect=fixed;fillColor=none;strokeColor=${BLUE};fontSize=11;`,
    cluster: `ellipse;shape=doubleEllipse;double=1;whiteSpace=wrap;html=1;aspect=fixed;fillColor=none;strokeColor=${BLUE};fontSize=11;`,
    datastore: `shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;size=10;fillColor=none;strokeColor=${BLUE};fontSize=11;`,
  };
  const ZONE_STYLE = `rounded=0;whiteSpace=wrap;html=1;dashed=1;fillColor=none;strokeColor=${RED};strokeWidth=2;`
    + 'verticalAlign=bottom;align=center;fontStyle=1;fontSize=13;';
  const OUTER_STYLE = `rounded=0;whiteSpace=wrap;html=1;dashed=1;fillColor=none;strokeColor=${DARK_RED};strokeWidth=2;`
    + `verticalAlign=top;align=left;spacingLeft=8;fontStyle=3;fontColor=${DARK_RED};fontSize=13;`;
  const FLOW_STYLE = 'edgeStyle=none;rounded=0;html=1;fontSize=9;endArrow=block;endFill=1;';
  const PAD = 14, LABEL_BAND = 30, TOP_BAND = 30, GAP = 22;
  const PAGE_W = 2200;
  const CONTEXT = ['purpose', 'sensitivity', 'auth', 'trust'];
  // The cyber-threat-modelling skill's parser takes a dashed box under 20,000 px² for an element (unless its name has
  // a zone word): every zone is made at least this big, a margin over that, in whole pixels as the file writes them.
  const MIN_ZONE_AREA = 20400;
  // That parser also takes a box of 20,000 px² or more with no fill for a trust zone when its name has one of these words
  // (its _BOUNDARY_WORDS, matched anywhere in the name). Every CSA size is smaller, but a diagram that keeps its own
  // layout may draw an element that big ("Corporate Network Gateway"): toDrawio gives such an element draw.io's default
  // fill, so that parser reads it as the element it is.
  const BOUNDARY_WORDS = ['dmz', 'trust', 'boundary', 'zone', 'network', 'vlan', 'segment', 'internal', 'external', 'corporate',
    'cloud', 'on-prem', 'enclave', 'perimeter', 'vpc', 'subnet', 'tier', 'level'];
  const BOUNDARY_AREA = 20000;

  // the order findings are listed in, errors first (the panel groups them by code in this order)
  const ORDER = ['duplicate-id', 'unknown-parent', 'unknown-zone', 'bad-type', 'no-name', 'flow-end', 'flow-loop',
    'zone-mismatch', 'outside-own-zone', 'inside-other-zone', 'overlap',
    'no-elements', 'no-flows', 'no-zones', 'isolated', 'no-zone', 'empty-zone', 'unlabelled-flow', 'no-context',
    'no-crown-jewel', 'unnamed', 'unnamed-zone', 'duplicate-name', 'straddles', 'sticks-out', 'zones-overlap'];
  // the checks on where things are drawn: a redrawn layout may not add to them (see check())
  const GEOMETRY = ['outside-own-zone', 'inside-other-zone', 'overlap', 'straddles', 'sticks-out', 'zones-overlap'];
  // the fixes that redraw the layout
  const LAYOUT = ['layout', 'apart', 'inside', 'settled', 'enlarged'];
  // overlapping pairs listed one by one in a zone (or between two zones); the rest are counted in one finding
  const OVERLAPS_LISTED = 200;

  // TMParse's names for what had none, and its note on a slide's boundaries drawn as lines (it asks for the zones)
  const UNNAMED = /^Unnamed element( \d+)?$/;
  const UNNAMED_ZONE = 'Unnamed trust zone';
  const BOUNDARY_LINES = /draws its trust boundaries as \d+ dashed lines?, not as closed shapes/;
  const STAR = /\s*★\s*$/u;

  // ---------------------------------------------------------------- geometry (the skill's ctr, inside, overlap)

  const ctr = b => [b[0] + b[2] / 2, b[1] + b[3] / 2];
  const inside = (p, b, pad = 0) => b[0] - pad <= p[0] && p[0] <= b[0] + b[2] + pad && b[1] - pad <= p[1] && p[1] <= b[1] + b[3] + pad;
  const overlap = (a, b, gap = 0) => a[0] < b[0] + b[2] + gap && b[0] < a[0] + a[2] + gap && a[1] < b[1] + b[3] + gap && b[1] < a[1] + a[3] + gap;
  const within = (b, Z) => b[0] >= Z[0] && b[1] >= Z[1] && b[0] + b[2] <= Z[0] + Z[2] && b[1] + b[3] <= Z[1] + Z[3];
  /** A model's geometry as the skill's [x, y, w, h], or null when it has none (or none that can be drawn). */
  const boxOf = g => (g && typeof g === 'object' && [g.x, g.y, g.w, g.h].every(Number.isFinite) && g.w > 0 && g.h > 0 ? [g.x, g.y, g.w, g.h] : null);
  const geometry = b => ({ x: b[0], y: b[1], w: b[2], h: b[3] });
  const sizeOf = type => SIZE[type] || SIZE.process;
  /** A point inside a box and not on its border; and one on its border. */
  const interior = (p, b) => b[0] < p[0] && p[0] < b[0] + b[2] && b[1] < p[1] && p[1] < b[1] + b[3];
  const onBorder = (p, b) => inside(p, b) && !interior(p, b);

  const clone = v => JSON.parse(JSON.stringify(v));
  const list = v => (Array.isArray(v) ? v.filter(x => x && typeof x === 'object') : []);
  const text = v => (v == null ? '' : String(v));
  const plural = (n, one, many) => `${n.toLocaleString('en')} ${n === 1 ? one : many || one + 's'}`;
  const refs = (elements = [], zones = [], flows = []) => ({ elements, zones, flows });

  /** A model with its lists in place (a saved file or an unfinished model may lack one). */
  function plain(model) {
    const m = model && typeof model === 'object' ? model : {};
    m.zones = list(m.zones);
    m.elements = list(m.elements);
    m.flows = list(m.flows);
    for (const e of m.elements) if (!e.context || typeof e.context !== 'object') e.context = {};
    return m;
  }

  // ---------------------------------------------------------------- words

  const nameOf = e => text(e && e.label).trim();
  const called = e => (nameOf(e) ? `"${nameOf(e)}"` : 'an element with no name');
  const Called = e => (nameOf(e) ? `"${nameOf(e)}"` : 'An element with no name');
  const zoneName = z => (z ? `"${text(z.label).trim() || UNNAMED_ZONE}"` : '');
  /** "A", "A and B", "A, B and C" */
  const andList = a => (a.length > 1 ? `${a.slice(0, -1).join(', ')} and ${a[a.length - 1]}` : a.join(''));

  function namer(m) {
    const zones = new Map(m.zones.map(z => [z.id, z]));
    const elements = new Map(m.elements.map(e => [e.id, e]));
    const el = id => (elements.has(id) ? called(elements.get(id)) : `"${text(id)}"`);
    const zone = id => (zones.has(id) ? zoneName(zones.get(id)) : `"${text(id)}"`);
    const flow = f => {
      const label = text(f.label).trim();
      return `${label ? `"${label}" ` : ''}from ${el(f.source)} to ${el(f.target)}`;
    };
    return { el, zone, flow, zones, elements };
  }

  /**
   * Each zone's id with the ids of the zones it sits in (a Set, the zone first), worked out once for a check: an
   * element may sit in these, and a zone doesn't overlap them. A circle of parents ends where it closes.
   */
  function ancestry(m) {
    const byId = new Map(m.zones.map(z => [z.id, z]));
    const out = new Map();
    for (const z of m.zones) {
      if (out.has(z.id)) continue;   // (a repeated id: its last holder's parents, as the lookups by id have it)
      const s = new Set();
      for (let id = z.id; id && !s.has(id); id = (byId.get(id) || {}).parent) s.add(id);
      out.set(z.id, s);
    }
    return out;
  }
  /** The zones an element in zone zid may be drawn in: that zone and those round it (just the id, for an unknown one). */
  const allowedIn = (anc, zid) => (zid ? anc.get(zid) || new Set([zid]) : new Set());

  /**
   * The boxes the drawing uses (id -> [x, y, w, h]): each zone's and element's own, except where what holds it has none.
   * A zone inside one with no position (or inside one inside such a zone), and an element in such a zone or in one with
   * no position, are laid out with that zone (see placeRest()), as the page does when an edit leaves them without one;
   * their own positions are neither drawn nor checked.
   */
  function drawnBoxes(m) {
    const zb = new Map(), eb = new Map();
    const byId = new Map(m.zones.map(z => [z.id, z]));
    const all = m.zones.every(z => boxOf(z.geometry));
    const placed = new Map();
    const inPlace = id => {   // the zone and every zone round it have a position (a circle of parents ends where it closes)
      if (!all && !placed.has(id)) {
        let ok = true;
        for (let p = id, seen = new Set(); p && byId.has(p) && !seen.has(p); p = byId.get(p).parent) {
          seen.add(p);
          if (!boxOf(byId.get(p).geometry)) { ok = false; break; }
        }
        placed.set(id, ok);
      }
      return all || placed.get(id);
    };
    for (const z of m.zones) { const b = boxOf(z.geometry); if (b && inPlace(z.id)) zb.set(z.id, b); }
    for (const e of m.elements) { const b = boxOf(e.geometry); if (b && (!e.zone || !byId.has(e.zone) || inPlace(e.zone))) eb.set(e.id, b); }
    return { zb, eb };
  }

  // ---------------------------------------------------------------- structure (check_model, first part)

  /** The skill's structural checks. Returns how many errors were found: any stops the fixes, as they stop the skill. */
  function structure(m, add, say) {
    let errors = 0;
    const err = f => { errors++; add(Object.assign({ level: 'error' }, f)); };
    const ids = [...m.zones.map(z => ['zones', z.id]), ...m.elements.map(e => ['elements', e.id]), ...m.flows.map(f => ['flows', f.id])];
    const count = new Map();
    for (const [, id] of ids) count.set(text(id), (count.get(text(id)) || 0) + 1);
    for (const id of [...count].filter(([, n]) => n > 1).map(([id]) => id).sort()) {
      const r = refs();
      for (const [kind, x] of ids) if (text(x) === id && !r[kind].includes(x)) r[kind].push(x);
      const fix = 'Each zone, element and data flow needs an id of its own: read the diagram again, or fix the ids in the saved file.';
      err({ code: 'duplicate-id', text: `The id "${id}" is used more than once.`, fix, fixAll: fix, refs: r });
    }
    const zoneIds = new Set(m.zones.map(z => z.id));
    const elementIds = new Set(m.elements.map(e => e.id));
    for (const z of m.zones) {
      if (z.parent && !zoneIds.has(z.parent)) {
        err({ code: 'unknown-parent', text: `The trust zone ${zoneName(z)} is inside a zone that isn’t in the decomposition ("${text(z.parent)}").`,
          fix: 'Choose the zone it sits in, under Inside, or — none —.', fixAll: 'Choose the zone each sits in, under Inside, or — none —.', refs: refs([], [z.id]) });
      }
    }
    for (const e of m.elements) {
      if (!TYPES.includes(e.type)) {
        err({ code: 'bad-type', text: `${Called(e)} has the type "${text(e.type)}", which isn’t one of the CSA element types.`,
          fix: 'Choose its type: external entity, process, cluster of processes or data store.',
          fixAll: 'Choose the type of each: external entity, process, cluster of processes or data store.', refs: refs([e.id]) });
      }
      if (e.zone && !zoneIds.has(e.zone)) {
        err({ code: 'unknown-zone', text: `${Called(e)} is in a trust zone that isn’t in the decomposition ("${text(e.zone)}").`,
          fix: 'Choose its trust zone, or — none —.', fixAll: 'Choose the trust zone of each, or — none —.', refs: refs([e.id]) });
      }
      if (!nameOf(e)) {
        err({ code: 'no-name', text: 'An element has no name.', fix: 'Name it as the diagram does, so the register says what is at risk.',
          fixAll: 'Name each as the diagram does, so the register says what is at risk.', refs: refs([e.id]) });
      }
    }
    for (const f of m.flows) {
      for (const end of ['source', 'target']) {
        if (elementIds.has(f[end])) continue;
        const what = f[end] == null || f[end] === '' ? 'missing' : zoneIds.has(f[end]) ? `the trust zone ${say.zone(f[end])}, not an element` : `"${text(f[end])}", which isn’t an element`;
        err({ code: 'flow-end', text: `The data flow ${say.flow(f)} doesn’t join two elements: its ${end === 'source' ? 'start' : 'end'} is ${what}.`,
          fix: 'Data flows join elements, never zones: choose the element the diagram connects at each end, or remove the flow.',
          fixAll: 'Data flows join elements, never zones: choose the elements the diagram connects at the ends of each, or remove it.', refs: refs([], [], [f.id]) });
      }
      if (f.source === f.target) {
        err({ code: 'flow-loop', text: `The data flow ${say.flow(f)} joins an element to itself.`,
          fix: 'Choose the element at its other end, or remove it.', fixAll: 'Choose the element at the other end of each, or remove it.', refs: refs([], [], [f.id]) });
      }
      if (!text(f.label).trim()) {
        add({ level: 'warning', code: 'unlabelled-flow', text: `The data flow ${say.flow(f)} has no label.`,
          fix: 'Label it with the protocol or the data it carries (HTTPS, SQL, SMB): it sharpens the threats.',
          fixAll: 'Label each with the protocol or the data it carries (HTTPS, SQL, SMB): it sharpens the threats.', refs: refs([], [], [f.id]) });
      }
    }
    return errors;
  }

  // ---------------------------------------------------------------- zone membership by position (check_model, second part)

  /**
   * Each element drawn in a zone other than the one it is assigned to: the picture is the evidence, and an element
   * belongs to the innermost (smallest) zone containing its centre. A centre on a zone's border is evidence for neither
   * side of it: an element whose own zone holds its centre stays there when each smaller zone that holds it does so only
   * on its border (a firewall drawn on the boundary between its zone and the next, whatever their sizes, or on the edge
   * of a zone inside its own), and so does one in a zone of the same size as the smallest (the skill would go by list
   * order). An element without a position, or assigned to a zone that has none, can't be tested.
   */
  function zoneMismatches(m) {
    const { zb, eb } = drawnBoxes(m);
    const sized = m.zones.filter(z => zb.has(z.id)).map(z => [z, zb.get(z.id)]);
    const known = new Set(m.zones.map(z => z.id));
    const area = b => b[2] * b[3];
    const out = [];
    for (const e of m.elements) {
      const b = eb.get(e.id);
      const own = e.zone || null;
      if (!b || (own && (!known.has(own) || !zb.has(own)))) continue;
      const c = [b[0] + b[2] / 2, b[1] + b[3] / 2];
      const hits = sized.filter(([, Z]) => inside(c, Z)).sort((p, q) => area(p[1]) - area(q[1]));
      let to = hits.length ? hits[0][0].id : null;
      const mine = own && hits.find(([z]) => z.id === own);
      if (to !== own && mine && hits.every(([z, Z]) => z.id === own || area(Z) >= area(mine[1]) || !interior(c, Z))) to = own;
      if (to !== own) out.push({ element: e.id, from: own, to });
    }
    return out;
  }

  // ---------------------------------------------------------------- layout (the skill's layout())

  /** Whether every element and zone has a position, so the layout can be redrawn (the skill needs them all). */
  const complete = m => m.elements.length > 0 && [...m.zones, ...m.elements].every(x => boxOf(x.geometry));

  /**
   * A decomposition this check (or the skill) has laid out already: it starts at (20, 20) and every element is drawn at
   * a CSA size. Laying it out again would scale it once more (to 2,200 px from its own width, a little over that), so it
   * isn't: it is redrawn at the scale it has, and only to clear a problem it has (check() says when). A file saved from
   * the page, or the draw.io file it writes, reads back without new fixes; elements left overlapping in one (a file the
   * skill wrote with its errors left in) are still moved apart where there is room.
   */
  function laidOut(m) {
    const boxes = [...m.zones, ...m.elements].map(x => boxOf(x.geometry));
    if (!boxes.length || boxes.some(b => !b)) return false;
    const sizes = Object.values(SIZE);
    const csa = m.elements.every(e => { const b = boxOf(e.geometry); return sizes.some(([w, h]) => Math.abs(b[2] - w) < 0.01 && Math.abs(b[3] - h) < 0.01); });
    const x0 = Math.min(...boxes.map(b => b[0])), y0 = Math.min(...boxes.map(b => b[1]));
    return csa && Math.abs(x0 - 20) < 0.5 && Math.abs(y0 - 20) < 0.5;
  }

  /**
   * The scale of the skill's layout, for a page pageW wide. The skill scales from the width of the picture it read
   * (source.width), and so does this check for a picture Claude read (its page is the picture). A draw.io drawing or a
   * slide is scaled from its own width, its left edge to its right: draw.io's page is the drawing's right edge measured
   * from x = 0, so a drawing far out on the canvas would otherwise come out small and crowded. (Where the drawing
   * starts doesn't matter: the layout moves it to (20, 20) at the end.)
   */
  function scaleOf(m, pageW) {
    const pw = m.page && typeof m.page === 'object' ? Number(m.page.w) : NaN;
    if (m.source && typeof m.source === 'object' && m.source.method === 'claude' && Number.isFinite(pw) && pw > 0) return pageW / pw;
    const boxes = [...m.zones, ...m.elements].map(x => boxOf(x.geometry)).filter(Boolean);
    const x0 = Math.min(...boxes.map(b => b[0])), x1 = Math.max(...boxes.map(b => b[0] + b[2]));
    return pageW / Math.max(x1 - x0, 1);
  }

  /**
   * The skill's layout, operation for operation: scale by s (see scaleOf), each element at its type's CSA size on its
   * scaled centre; push apart the elements of a zone that overlap, keeping them inside the zone; enlarge each zone
   * (innermost first) that no longer holds what it holds; move it all so the page starts at (20, 20). Then, beyond the
   * skill, each zone smaller than MIN_ZONE_AREA is made that big (growSmall). Returns the boxes, the page, and what it
   * moved and enlarged. anc: ancestry(m).
   */
  function layout(m, s, anc = ancestry(m)) {
    const zones = new Map(m.zones.map(z => [z.id, [z.geometry.x * s, z.geometry.y * s, z.geometry.w * s, z.geometry.h * s]]));
    const holds = new Set(m.zones.map(z => z.parent).filter(Boolean));
    const els = new Map();
    for (const e of m.elements) {
      const [w, h] = sizeOf(e.type);
      const cx = (e.geometry.x + e.geometry.w / 2) * s, cy = (e.geometry.y + e.geometry.h / 2) * s;
      els.set(e.id, [cx - w / 2, cy - h / 2, w, h]);
    }
    const start = new Map([...els].map(([id, b]) => [id, b.slice()]));

    const inner = zid => {   // the room a zone has for its own elements
      const [x, y, w, h] = zones.get(zid);
      const top = holds.has(zid) ? TOP_BAND : PAD;
      return [x + PAD, y + top, w - 2 * PAD, h - top - LABEL_BAND];
    };

    // push apart the overlapping elements of each zone, then keep them inside it
    const groups = new Map();
    for (const e of m.elements) {
      const k = e.zone || null;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(e.id);
    }
    const apart = new Set();
    // Beyond the skill: a budget of comparisons for each zone (the skill's 400 rounds for a zone of about 316 elements) and
    // for the whole layout, so that a diagram crowded far past that (a crafted file) can't hold the page up for minutes.
    // What is left overlapping is said.
    let total = 6e7;
    const pushApart = (zid, ids, keepInside) => {
      let budget = 2e7;
      for (let round = 0; round < 400 && budget > 0 && total > 0; round++) {
        let moved = false;
        budget -= ids.length * (ids.length - 1) / 2;
        total -= ids.length * (ids.length - 1) / 2;
        for (let i = 0; i < ids.length; i++) {
          for (let j = i + 1; j < ids.length; j++) {
            const A = els.get(ids[i]), B = els.get(ids[j]);
            if (!overlap(A, B, GAP)) continue;
            const dx = Math.min(A[0] + A[2] + GAP - B[0], B[0] + B[2] + GAP - A[0]);
            const dy = Math.min(A[1] + A[3] + GAP - B[1], B[1] + B[3] + GAP - A[1]);
            const ca = ctr(A), cb = ctr(B);
            if (dx <= dy) {
              const d = (dx / 2 + 0.5) * (cb[0] >= ca[0] ? 1 : -1);
              A[0] -= d; B[0] += d;
            } else {
              const d = (dy / 2 + 0.5) * (cb[1] >= ca[1] ? 1 : -1);
              A[1] -= d; B[1] += d;
            }
            moved = true;
            apart.add(ids[i]).add(ids[j]);
          }
        }
        if (keepInside && zid !== null && zones.has(zid)) {
          const [ix, iy, iw, ih] = inner(zid);
          for (const id of ids) {
            const E = els.get(id);
            E[0] = iw >= E[2] ? Math.min(Math.max(E[0], ix), ix + iw - E[2]) : ix + (iw - E[2]) / 2;
            E[1] = ih >= E[3] ? Math.min(Math.max(E[1], iy), iy + ih - E[3]) : iy + (ih - E[3]) / 2;
          }
        }
        if (!moved) break;
      }
    };
    for (const [zid, ids] of groups) pushApart(zid, ids, true);

    // grow any zone its elements (or the zones inside it) no longer fit in, innermost first
    const depth = new Map();
    const firstById = new Map();   // (the skill's next(): the first zone with an id)
    for (const z of m.zones) if (!firstById.has(z.id)) firstById.set(z.id, z);
    for (const z of m.zones) {
      let d = 0;
      const seen = new Set();
      for (let p = z.parent; p && !seen.has(p);) {   // (the skill would loop for ever on a cycle)
        seen.add(p);
        d++;
        const q = firstById.get(p);
        p = q ? q.parent : null;
      }
      depth.set(z.id, d);
    }
    const kidsOf = new Map();
    for (const c of m.zones) {
      if (!c.parent) continue;
      if (!kidsOf.has(c.parent)) kidsOf.set(c.parent, []);
      kidsOf.get(c.parent).push(c);
    }
    const byDepth = m.zones.slice().sort((a, b) => depth.get(b.id) - depth.get(a.id));
    const enlarged = [];
    const enlarge = () => {
      for (const z of byDepth) {
        const zid = z.id;
        const own = (groups.get(zid) || []).map(id => els.get(id));
        const kids = (kidsOf.get(zid) || []).map(c => zones.get(c.id));
        if (!own.length && !kids.length) continue;
        // room round its own elements (the label band below, a title band above when it also holds zones);
        // the zones inside it only need to sit inside it
        const top = holds.has(zid) ? TOP_BAND : PAD;
        const need = own.map(b => [b[0] - PAD, b[1] - top, b[0] + b[2] + PAD, b[1] + b[3] + LABEL_BAND])
          .concat(kids.map(b => [b[0] - 2, b[1] - 2, b[0] + b[2] + 2, b[1] + b[3] + 2]));
        const x0 = Math.min(...need.map(n => n[0])), y0 = Math.min(...need.map(n => n[1]));
        const x1 = Math.max(...need.map(n => n[2])), y1 = Math.max(...need.map(n => n[3]));
        const X = zones.get(zid);
        const nx0 = Math.min(X[0], x0), ny0 = Math.min(X[1], y0);
        const nx1 = Math.max(X[0] + X[2], x1), ny1 = Math.max(X[1] + X[3], y1);
        if (nx0 !== X[0] || ny0 !== X[1] || nx1 !== X[0] + X[2] || ny1 !== X[1] + X[3]) {
          zones.set(zid, [nx0, ny0, nx1 - nx0, ny1 - ny0]);
          if (!enlarged.includes(zid)) enlarged.push(zid);
        }
      }
    };
    enlarge();

    /*
     * Beyond the skill. Pushing a zone's elements apart can push one into a zone drawn inside its own (or into a
     * neighbour that overlaps its zone), and a zone that grows can take one in. The skill's validate() then stops with an
     * error, for Claude to correct model.json; here there is no one to move a box. So such an element moves out of that
     * zone, the shortest way to a spot clear of it and still in its own zone; where there is no such spot, to a free spot
     * of its own zone, or one opened there with a stretch (see rooms()). The skill's push apart runs again, and the zones
     * grow to fit. An element outside every zone with no way out stays, and the check says so. A layout without the
     * fault is the skill's exactly.
     */
    const room = rooms(m, zones, els);
    const settled = new Set();
    const shifted = new Map();   // how far the stretches that made room moved each other element
    for (let round = 0; round < 50; round++) {
      const touched = new Set();
      for (const e of m.elements) {
        const b = els.get(e.id);
        const allowed = allowedIn(anc, e.zone || null);
        const wrong = c => m.zones.filter(z => !allowed.has(z.id) && inside(c, zones.get(z.id)));
        const hits = wrong(ctr(b));
        if (!hits.length) continue;
        // out of the largest of them, so out of the zones inside it too
        const Y = hits.map(z => zones.get(z.id)).sort((p, q) => q[2] * q[3] - p[2] * p[3])[0];
        const own = e.zone && zones.has(e.zone) ? zones.get(e.zone) : null;
        const cost = p => Math.abs(p[0] - b[0]) + Math.abs(p[1] - b[1]);
        const to = [[Y[0] - GAP - b[2], b[1]], [Y[0] + Y[2] + GAP, b[1]], [b[0], Y[1] - GAP - b[3]], [b[0], Y[1] + Y[3] + GAP]]
          .filter(p => { const c = [p[0] + b[2] / 2, p[1] + b[3] / 2]; return !wrong(c).length && (!own || inside(c, own)); })
          .sort((p, q) => cost(p) - cost(q))[0];
        if (!to) continue;
        b[0] = to[0];
        b[1] = to[1];
        settled.add(e.id);
        touched.add(e.zone || null);
      }
      if (!touched.size) break;
      for (const k of touched) pushApart(k, groups.get(k), true);
      enlarge();
    }
    // what is still in a zone it isn't in (no way out, or pushed back each round): a spot of its own zone, clear of
    // everything, where nothing pushes it again (the zones then grow to fit what they hold, which can't reach it)
    for (let pass = 0; pass < 2; pass++) {
      let placed = 0;
      for (const e of m.elements) {
        const b = els.get(e.id), allowed = allowedIn(anc, e.zone || null), c = ctr(b);
        if (!e.zone || !zones.has(e.zone) || !m.zones.some(z => !allowed.has(z.id) && inside(c, zones.get(z.id)))) continue;
        const was = new Map([...els].map(([id, x]) => [id, [x[0], x[1]]]));
        const spot = room.makeRoom(e.zone, b[2], b[3], b);
        if (!spot) continue;   // (its zone has no part of its own: it stays, and the check says where it is)
        for (const [id, x] of els) {
          const p = was.get(id), dx = x[0] - p[0], dy = x[1] - p[1];
          if (x !== b && (dx || dy)) { const s = shifted.get(id) || [0, 0]; shifted.set(id, [s[0] + dx, s[1] + dy]); }
        }
        b[0] = spot[0];
        b[1] = spot[1];
        settled.add(e.id);
        placed++;
      }
      if (!placed) break;
      enlarge();
    }
    // what kept to its zone without being pushed apart (or out of another) moved back inside it (a move made by a
    // stretch, to make room, aside)
    const moved = (id, b) => {
      const s = shifted.get(id), o = start.get(id);
      return s ? Math.abs(b[0] - s[0] - o[0]) > 1e-6 || Math.abs(b[1] - s[1] - o[1]) > 1e-6 : b[0] !== o[0] || b[1] !== o[1];
    };
    const back = [...els].filter(([id, b]) => !apart.has(id) && !settled.has(id) && moved(id, b)).map(([id]) => id);

    // move it all so the page starts at (20, 20)
    const all = [...zones.values(), ...els.values()];
    const ox = 20 - Math.min(...all.map(b => b[0])), oy = 20 - Math.min(...all.map(b => b[1]));
    for (const b of all) { b[0] += ox; b[1] += oy; }
    const small = growSmall(m, zones, els);   // (it keeps the page's start)
    const page = [Math.ceil(Math.max(...all.map(b => b[0] + b[2])) + 20), Math.ceil(Math.max(...all.map(b => b[1] + b[3])) + 20)];
    return { zones, els, page, scale: s, enlarged, small, apart: m.elements.map(e => e.id).filter(id => apart.has(id) && !settled.has(id)), inside: back,
      settled: m.elements.map(e => e.id).filter(id => settled.has(id)) };
  }

  // ---------------------------------------------------------------- making room without overlaps (beyond the skill)

  /**
   * A stretch: room made across the whole drawing at a line on one axis (0: x, 1: y), d wide. Every zone edge and every
   * element centre past the line moves on by d: a box wholly past it moves, a zone across it grows, and an element
   * across it moves with its centre (its centre decides which zone it is in). Each of those points keeps its order
   * along the axis, so every element stays in the zones it was in and out of the others, zones keep their nesting and
   * nothing comes to overlap (two elements, an element and a zone's border, or two zones: lineIn() keeps the line
   * clear of the zones' edges, so zones that only touch don't come to overlap). Only the centre of a zone across the
   * line moves by d/2, which matters only to a zone it partly overlaps.
   */
  function stretch(zones, els, axis, at, d) {
    for (const b of zones.values()) {
      if (b[axis] > at) b[axis] += d;
      else if (b[axis] + b[axis + 2] > at) b[axis + 2] += d;
    }
    for (const b of els.values()) if (b[axis] + b[axis + 2] / 2 > at) b[axis] += d;
  }

  /** A line in [lo, hi], at least 4 px from every zone edge on the axis, as near lo as there is one (else lo). */
  function lineIn(zones, axis, lo, hi) {
    const edges = [];   // (only those within 4 px of [lo, hi] can be too near a line in it)
    for (const b of zones.values()) for (const e of [b[axis], b[axis] + b[axis + 2]]) if (e > lo - 4 && e < hi + 4) edges.push(e);
    const clear = v => edges.every(e => Math.abs(e - v) >= 4);
    if (clear(lo)) return lo;
    let best = null;
    for (const e of edges) for (const v of [e - 4, e + 4]) if (v > lo && v <= hi && (best === null || v < best) && clear(v)) best = v;
    return best === null ? lo : best;
  }

  /** A length as the draw.io file writes it (whole pixels). */
  const px = v => Number(f0(v));

  /**
   * How the zones a stretch at a line could re-nest are nested by their centres, as a reader of the draw.io file nests
   * them (TMParse does): for each, the larger zones round its centre. A stretch keeps every element in its zones (see
   * stretch()), but the centre of a zone across the line moves by half the stretch, and such a zone grows (so may come
   * to be larger than one whose centre it holds): those are the zones across the line, and those with a centre in one.
   */
  function nesting(zones, axis, at) {
    const zl = [...zones];
    const across = zl.filter(([, b]) => b[axis] <= at && at < b[axis] + b[axis + 2]).map(([, b]) => b);
    const ids = zl.filter(([, b]) => across.includes(b) || across.some(A => inside(ctr(b), A))).map(([id]) => id);
    const now = () => ids.map(id => {
      const b = zones.get(id), c = ctr(b), a = b[2] * b[3];
      return zl.filter(([k, Z]) => k !== id && Z[2] * Z[3] > a && inside(c, Z)).map(([k]) => k).join('\n');
    }).join('\u0000');
    return now;
  }

  /** A line through a zone's centre on the axis: the nearest to it, inside the zone, with no zone edge between them or within 4 px. */
  function centreLine(zones, axis, b) {
    const c = b[axis] + b[axis + 2] / 2, lo = b[axis] + 1, hi = b[axis] + b[axis + 2] - 1;
    const edges = [];
    for (const Z of zones.values()) edges.push(Z[axis], Z[axis] + Z[axis + 2]);
    const ok = v => v >= lo && v <= hi && edges.every(e => Math.abs(e - v) >= 4 && !(Math.min(v, c) <= e && e <= Math.max(v, c)));
    if (ok(c)) return c;
    let best = null;
    for (const e of edges) for (const v of [e - 4, e + 4]) if (ok(v) && (best === null || Math.abs(v - c) < Math.abs(best - c))) best = v;
    return best;
  }

  /**
   * Each zone smaller than MIN_ZONE_AREA, as the file rounds it, made that big by a stretch on the axis that needs the
   * smaller increase (height on a tie): at a line in its bottom band, below the room for what it holds (or in its
   * right-hand margin), so what it holds stays where it is. Nothing comes to overlap and every element keeps its zones
   * (see stretch()). A zone's nesting by its centre is checked too (see nesting()): should a zone that hangs out of its
   * parent, or over another zone, see its centre cross a border, the stretch is made at a line through its centre instead
   * (its centre then keeps its side of every zone edge), then the same on the other axis; failing those, the first is
   * kept. Returns the ids of the zones it enlarged, in the model's order.
   */
  function growSmall(m, zones, els) {
    const grown = [];
    const copy = () => [[...zones].map(([k, b]) => [k, b.slice()]), [...els].map(([k, b]) => [k, b.slice()])];
    const restore = ([zs, es]) => { for (const [k, b] of zs) zones.get(k).splice(0, 4, ...b); for (const [k, b] of es) els.get(k).splice(0, 4, ...b); };
    for (const z of m.zones) {
      const b = zones.get(z.id);
      if (!b || grown.includes(z.id)) continue;
      for (let i = 0; i < 2; i++) {   // (twice only for a box under a pixel wide or high: its width first)
        const W = px(b[2]), H = px(b[3]);
        if (W * H >= MIN_ZONE_AREA) break;
        const side = Math.ceil(Math.sqrt(MIN_ZONE_AREA));
        const dh = W >= 1 ? Math.ceil(MIN_ZONE_AREA / W) - b[3] : Infinity;
        const dw = H >= 1 ? Math.ceil(MIN_ZONE_AREA / H) - b[2] : W >= 1 ? Infinity : side - b[2];
        const first = dh <= dw ? 1 : 0;
        const tries = [];
        for (const axis of [first, 1 - first]) {
          const d = axis ? dh : dw;
          if (!Number.isFinite(d)) continue;
          const end = b[axis] + b[axis + 2], size = b[axis + 2];
          tries.push([axis, d, lineIn(zones, axis, end - Math.min(axis ? LABEL_BAND / 2 : PAD, size / 2), end - Math.min(4, size / 4))]);
          const through = centreLine(zones, axis, b);
          if (through !== null) tries.push([axis, d, through]);
        }
        const start = copy();
        let done = false;
        for (const [axis, d, at] of tries) {
          restore(start);
          const nest = nesting(zones, axis, at), was = nest();
          stretch(zones, els, axis, at, d);
          if (nest() === was) { done = true; break; }
        }
        if (!done) { restore(start); stretch(zones, els, tries[0][0], tries[0][2], tries[0][1]); }
        if (!grown.includes(z.id)) grown.push(z.id);
      }
    }
    return grown;
  }

  // ---------------------------------------------------------------- validation (the skill's validate())

  /**
   * The skill's checks on where things are drawn (its validate(), first part): on the laid-out boxes, or, where the layout
   * wasn't redrawn, the positions there are. laid: the layout was redrawn (now, or earlier with the fixes standing),
   * which the advice depends on. said: elements whose zone is already said to be wrong (zone-mismatch), not said again.
   * Overlapping pairs are listed up to OVERLAPS_LISTED for each zone (or two zones); one finding counts the rest.
   * anc: ancestry(m).
   */
  function whereDrawn(m, add, say, laid, said = new Set(), anc = ancestry(m)) {
    const err = f => add(Object.assign({ level: 'error' }, f));
    const warn = f => add(Object.assign({ level: 'warning' }, f));
    const { zb, eb } = drawnBoxes(m);
    const straddles = (e, id) => warn({ code: 'straddles', text: `${Called(e)} straddles the border of the trust zone ${say.zone(id)}.`,
      fix: 'Check on the diagram which zone it is in: the DFD draws it in the zone it is assigned to.',
      fixAll: 'Check on the diagram which zone each is in: the DFD draws each in the zone it is assigned to.', refs: refs([e.id], [id]) });
    // an element sits in its own zone and in no deeper zone, without touching another element
    for (const e of m.elements) {
      const b = eb.get(e.id);
      if (!b) continue;
      const c = ctr(b);
      const own = e.zone || null;
      const ownBox = own ? zb.get(own) : null;
      const allowed = allowedIn(anc, own);
      // a centre in its own zone and on the border of another is on the boundary between them: it straddles that border
      // (a firewall drawn on a trust boundary), it isn't inside the other zone (zoneMismatches keeps its zone)
      const touching = id => !!ownBox && inside(c, ownBox) && onBorder(c, zb.get(id));
      const others = [...zb].filter(([id, Z]) => !allowed.has(id) && inside(c, Z)).map(([id]) => id);
      if (!said.has(e.id)) {
        if (ownBox && !inside(c, ownBox)) {
          err({ code: 'outside-own-zone', text: `${Called(e)} is drawn outside its trust zone ${say.zone(own)}.`,
            fix: 'Check its zone against the diagram: choose the zone it is drawn in, under Trust zone.',
            fixAll: 'Check their zones against the diagram: choose the zone each is drawn in, under Trust zone.', refs: refs([e.id], [own]) });
        }
        const extra = others.filter(id => !touching(id));
        if (extra.length) {
          err({ code: 'inside-other-zone', text: `${Called(e)} is drawn inside ${extra.length === 1 ? 'the trust zone' : 'the trust zones'} ${andList(extra.map(say.zone))}, which it isn’t assigned to.`,
            fix: laid ? 'The automatic layout found no clear spot for it in its own zone. Check its zone against the diagram; if it is right, undo the fixes to keep the diagram’s own layout.'
              : 'It is drawn where trust zones overlap. If one of them is inside the other, choose it under Inside; otherwise check its zone against the diagram, under Trust zone.',
            fixAll: laid ? 'The automatic layout found no clear spot for them in their own zones. Check their zones against the diagram; if they are right, undo the fixes to keep the diagram’s own layout.'
              : 'They are drawn where trust zones overlap. Where one zone is inside another, choose it under Inside; otherwise check their zones against the diagram, under Trust zone.',
            refs: refs([e.id], extra) });
        }
      }
      for (const [id, Z] of zb) {   // a shape on another zone's border reads as ambiguous
        if (!allowed.has(id) && overlap(b, Z) && !within(b, Z) && (!inside(c, Z) || (others.includes(id) && touching(id)))) straddles(e, id);
      }
      if (ownBox && !within(b, ownBox) && !said.has(e.id)) {
        warn({ code: 'sticks-out', text: `${Called(e)} sticks out of its trust zone ${say.zone(own)}.`,
          fix: 'Check its zone against the diagram. Only the drawing is affected: the threat model takes it as in its zone.',
          fixAll: 'Check their zones against the diagram. Only the drawing is affected: the threat model takes each as in its zone.', refs: refs([e.id], [own]) });
      }
    }
    const E = m.elements.filter(e => eb.has(e.id));
    const listed = new Map(), more = new Map();   // the zones of a pair -> pairs listed, pairs only counted
    const overlapFix = laid
      ? ['At the standard sizes there isn’t room for both where the diagram draws them, so the DFD draws them overlapping; the threat model isn’t affected. If they are the same component, remove one; or undo the fixes to keep the diagram’s own layout.',
        'At the standard sizes there isn’t room for each pair where the diagram draws them, so the DFD draws them overlapping; the threat model isn’t affected. Where a pair is one component, remove one of them; or undo the fixes to keep the diagram’s own layout.']
      : ['If they are the same component, remove one. Otherwise only the drawing is affected: the DFD draws them overlapping, and the threat model is the same.',
        'Where a pair is one component, remove one of them. Otherwise only the drawing is affected: the DFD draws them overlapping, and the threat model is the same.'];
    for (let i = 0; i < E.length; i++) {
      const A = eb.get(E[i].id);
      for (let j = i + 1; j < E.length; j++) {
        if (!overlap(A, eb.get(E[j].id), 4)) continue;
        const k = JSON.stringify([text(E[i].zone), text(E[j].zone)].sort());
        const n = listed.get(k) || 0;
        if (n >= OVERLAPS_LISTED) { more.set(k, (more.get(k) || 0) + 1); continue; }
        listed.set(k, n + 1);
        err({ code: 'overlap', text: `${Called(E[i])} and ${called(E[j])} overlap.`, fix: overlapFix[0], fixAll: overlapFix[1], refs: refs([E[i].id, E[j].id]) });
      }
    }
    for (const [k, n] of more) {
      const [za, zb2] = JSON.parse(k);
      const where = za === zb2 ? (za ? `in the trust zone ${say.zone(za)}` : 'outside the trust zones')
        : `across the trust zones ${andList([za, zb2].map(z => (z ? say.zone(z) : 'none')))}`;
      err({ code: 'overlap', count: n, text: `${plural(n, 'more pair')} of elements overlap ${where} (not listed one by one).`,
        fix: overlapFix[1], fixAll: overlapFix[1], refs: refs([], [za, zb2].filter(Boolean).filter((z, i, a) => a.indexOf(z) === i)) });
    }
    const Z = m.zones.filter(z => zb.has(z.id));
    const up = z => anc.get(z.id) || new Set([z.id]);
    for (let i = 0; i < Z.length; i++) {
      for (let j = i + 1; j < Z.length; j++) {
        const a = Z[i], b = Z[j];
        if (up(b).has(a.id) || up(a).has(b.id)) continue;
        if (overlap(zb.get(a.id), zb.get(b.id), -3)) {
          warn({ code: 'zones-overlap', text: `The trust zones ${zoneName(a)} and ${zoneName(b)} overlap.`,
            fix: 'If one is inside the other, choose it under Inside; otherwise check their borders against the diagram.',
            fixAll: 'Where one zone of a pair is inside the other, choose it under Inside; otherwise check their borders against the diagram.', refs: refs([], [a.id, b.id]) });
        }
      }
    }
  }

  /** How many geometry findings of each code a decomposition has as drawn (what the guard on a redraw weighs). */
  function tally(m, say, anc) {
    const n = Object.fromEntries(GEOMETRY.map(c => [c, 0]));
    whereDrawn(m, f => { n[f.code] += f.count || 1; }, say, false, new Set(), anc);
    return n;
  }

  /** The skill's validate(): where things are drawn, then what joins them and what they are (said, never fixed). */
  function validate(m, add, say, laid, said, anc) {
    const warn = f => add(Object.assign({ level: 'warning' }, f));
    whereDrawn(m, add, say, laid, said, anc);
    // connectivity and zones: said, never fixed (a flow or a zone the diagram doesn't show is never made up)
    const linked = new Set(m.flows.flatMap(f => [f.source, f.target]));
    const holding = new Set([...m.elements.map(e => e.zone), ...m.zones.map(z => z.parent)].filter(Boolean));
    for (const e of m.elements) {
      if (m.flows.length && !linked.has(e.id)) {
        warn({ code: 'isolated', text: `${Called(e)} has no data flow.`,
          fix: 'Add the data flows the diagram shows for it (Add a data flow), or remove it if it isn’t part of the system. The check never adds a flow itself.',
          fixAll: 'Add the data flows the diagram shows for each (Add a data flow), and remove any that aren’t part of the system. The check never adds a flow itself.', refs: refs([e.id]) });
      }
      // an external entity is outside the system's zones by nature (as TMParse.finish() has it; the skill warns of it)
      if (m.zones.length && !e.zone && e.type !== 'entity') {
        warn({ code: 'no-zone', text: `${Called(e)} is outside every trust zone.`,
          fix: 'Choose the zone it runs in, under Trust zone, so the threats that cross zones are found. The check only puts an element in the zone the diagram draws it in.',
          fixAll: 'Choose the zone each runs in, under Trust zone, so the threats that cross zones are found. The check only puts an element in the zone the diagram draws it in.',
          refs: refs([e.id]) });
      }
      if (!CONTEXT.some(k => text(e.context[k]).trim())) {
        warn({ code: 'no-context', text: `${Called(e)} has no context.`,
          fix: 'Fill in what it does, the data it holds, how it authenticates and how far it is trusted: until then its threats are generic and their severity understated.',
          fixAll: 'Fill in what each does, the data it holds, how it authenticates and how far it is trusted: until then their threats are generic and their severity understated.',
          refs: refs([e.id]) });
      }
    }
    for (const z of m.zones) {
      if (!holding.has(z.id)) {
        warn({ code: 'empty-zone', text: `The trust zone ${zoneName(z)} holds nothing.`,
          fix: 'Choose it under Trust zone for the elements the diagram draws in it, or remove it if the diagram doesn’t draw it as a trust boundary.',
          fixAll: 'Choose each under Trust zone for the elements the diagram draws in it, and remove any the diagram doesn’t draw as a trust boundary.', refs: refs([], [z.id]) });
      }
    }
    if (m.elements.length && !m.elements.some(e => e.crownJewel)) {
      const fix = 'Set Crown jewel to Yes on the elements whose loss would hurt most: until then the model works them out from the data each holds.';
      warn({ code: 'no-crown-jewel', text: 'No element is marked as a crown jewel.', fix, fixAll: fix, refs: refs() });
    }
  }

  /**
   * What the page checked before (TMParse.finish()'s CSA §3.2 checks, the editor's own), said once, here. Returns the
   * notes said as findings (a slide's boundaries drawn as lines: the no-zones warning), so they aren't said twice.
   */
  function overall(m, add, notes) {
    const warn = f => add(Object.assign({ level: 'warning' }, f.fixAll ? f : Object.assign(f, { fixAll: f.fix })));
    const used = [];
    if (!m.elements.length) {
      warn({ code: 'no-elements', text: 'There are no elements yet.', fix: 'Add the external entities, processes, clusters of processes and data stores (Add an element).', refs: refs() });
    }
    if (m.elements.length && !m.flows.length) {
      // a data flow joins two elements: with one, the first step is a second element
      warn({ code: 'no-flows', text: 'There are no data flows.',
        fix: m.elements.length < 2 ? 'Add a second element, then the data flows between them (Add an element): CSA §3.2 needs them, and the check never adds one itself.'
          : 'Draw the connections between the elements (Add a data flow): CSA §3.2 needs them, and the check never adds one itself.', refs: refs() });
    }
    if (m.elements.length && !m.zones.length) {
      // a slide that draws its trust boundaries as lines: TMParse's note says so, and names what look like its zones
      const note = notes.find(n => BOUNDARY_LINES.test(n));
      const lines = note && /^Slide (\d+) draws its trust boundaries as (\d+) dashed (lines?)/.exec(note);
      const named = note && /Names on the slide that look like zones: (.*)$/.exec(note);
      const names = named ? [...named[1].matchAll(/"([^"]*)"/g)].map(x => `"${x[1]}"`) : [];
      if (note) used.push(note);
      warn({ code: 'no-zones',
        text: !note ? 'There are no trust zones.'
          : `There are no trust zones: ${lines ? `slide ${lines[1]} draws its trust boundaries as ${lines[2]} dashed ${lines[3]}` : 'the slide draws its trust boundaries as dashed lines'}, `
            + `not as closed shapes, so none were read.${names.length ? ` Names on the slide that look like zones: ${andList(names)}${/…\.?\s*$/.test(named[1]) ? ' and more' : ''}.` : ''}`,
        fix: note ? 'Add the zones the slide draws (Add a zone) and choose each element’s zone, under Trust zone; or redraw each boundary as a closed dashed shape and upload the slide again.'
          : 'Add the trust zones the diagram draws (Add a zone): without trust boundaries, the threats that cross zones, the ones that matter most, can’t be told apart.',
        refs: refs() });
    }
    for (const e of m.elements) {
      if (UNNAMED.test(nameOf(e))) {
        warn({ code: 'unnamed', text: `${Called(e)} has no name in the diagram, so it was called that.`, fix: 'Name it, so the register says what is at risk.',
          fixAll: 'Name each, so the register says what is at risk.', refs: refs([e.id]) });
      }
    }
    for (const z of m.zones) {
      if (!text(z.label).trim() || text(z.label).trim() === UNNAMED_ZONE) {
        warn({ code: 'unnamed-zone', text: `A trust zone has no name${text(z.label).trim() ? ', so it was called "Unnamed trust zone"' : ''}.`,
          fix: 'Name it, so the register says where each element sits.', fixAll: 'Name each, so the register says where each element sits.', refs: refs([], [z.id]) });
      }
    }
    const byName = new Map();
    for (const e of m.elements) {
      const k = nameOf(e).toLowerCase();
      if (!k) continue;
      if (!byName.has(k)) byName.set(k, []);
      byName.get(k).push(e);
    }
    for (const same of byName.values()) {
      if (same.length < 2) continue;
      warn({ code: 'duplicate-name', text: `${plural(same.length, 'element')} share the name "${nameOf(same[0])}".`,
        fix: 'Give each a name of its own, so the register is unambiguous.', fixAll: 'Give each element a name of its own, so the register is unambiguous.', refs: refs(same.map(e => e.id)) });
    }
    return used;
  }

  // ---------------------------------------------------------------- the check

  // what a redrawn layout would add, in words
  const ADDED = {
    'outside-own-zone': n => `${plural(n, 'more element')} drawn outside ${n === 1 ? 'its' : 'their'} trust zone`,
    'inside-other-zone': n => `${plural(n, 'more element')} drawn inside a trust zone ${n === 1 ? 'it isn’t' : 'they aren’t'} assigned to`,
    overlap: n => `${plural(n, 'more pair')} of elements overlapping`,
    straddles: n => `${plural(n, 'more element')} straddling the border of a trust zone`,
    'sticks-out': n => `${plural(n, 'more element')} sticking out of ${n === 1 ? 'its' : 'their'} trust zone`,
    'zones-overlap': n => `${plural(n, 'more pair')} of trust zones overlapping`,
  };

  function check(input, opts = {}) {
    const fix = opts.fix !== false;
    const pageW = opts.pageWidth > 0 ? opts.pageWidth : PAGE_W;
    const m = plain(clone(input || {}));
    const notes = (Array.isArray(m.notes) ? m.notes : []).filter(n => typeof n === 'string');
    const found = [], fixes = [];
    let changed = false;
    const add = f => found.push(Object.assign(f, { index: found.length }));
    let say = namer(m);

    // the skill's crown-jewel mark, read back from a label ("Model Registry ★", as its draw.io file writes it). On an
    // element marked already (crown_jewel yes: the draw.io file this check writes, read back) it goes without a word.
    if (fix) {
      for (const e of m.elements) {
        if (e.crownJewel === false || typeof e.label !== 'string' || !STAR.test(e.label) || !e.label.replace(STAR, '').trim()) continue;
        const name = e.label.replace(STAR, '');
        e.label = name;
        changed = true;
        if (e.crownJewel === true) continue;
        e.crownJewel = true;
        fixes.push({ code: 'star', element: e.id, refs: refs([e.id]),
          text: `Read the ★ after "${name.trim()}" as the crown-jewel mark: the element is called "${name.trim()}" and is marked as a crown jewel.`,
          would: `read the ★ after "${name.trim()}" as the crown-jewel mark` });
      }
    }

    const broken = structure(m, add, say);

    // zone membership by position: fixed (or, when fixes are off or the model isn't sound, said)
    const moves = zoneMismatches(m);
    const said = new Set();
    if (fix && !broken) {
      for (const mv of moves) {
        const e = say.elements.get(mv.element);
        e.zone = mv.to;
        const [text, would] = !mv.from ? [`Put ${called(e)} in ${say.zone(mv.to)}, the trust zone the diagram draws it in.`, `put ${called(e)} in ${say.zone(mv.to)}, the trust zone the diagram draws it in`]
          : !mv.to ? [`Took ${called(e)} out of ${say.zone(mv.from)}: the diagram draws it outside every trust zone.`, `take ${called(e)} out of ${say.zone(mv.from)}, as the diagram draws it outside every trust zone`]
            : [`Moved ${called(e)} from ${say.zone(mv.from)} to ${say.zone(mv.to)}, the trust zone the diagram draws it in.`, `move ${called(e)} from ${say.zone(mv.from)} to ${say.zone(mv.to)}, the trust zone the diagram draws it in`];
        fixes.push(Object.assign({ code: 'zone', refs: refs([e.id], [mv.from, mv.to].filter(Boolean)) }, mv, { text, would }));
      }
    } else {
      for (const mv of moves) {
        const e = say.elements.get(mv.element);
        said.add(e.id);
        add({ level: 'error', code: 'zone-mismatch', refs: refs([e.id], [mv.from, mv.to].filter(Boolean)),
          text: mv.to ? `${Called(e)} is ${mv.from ? `in the trust zone ${say.zone(mv.from)}` : 'outside every trust zone'}, but the diagram draws it in ${say.zone(mv.to)}.`
            : `${Called(e)} is in the trust zone ${say.zone(mv.from)}, but the diagram draws it outside every trust zone.`,
          fix: mv.to ? `Put it in ${say.zone(mv.to)}, under Trust zone, unless the diagram is the one that’s wrong.`
            : 'Choose — none — under Trust zone, unless the diagram is the one that’s wrong.',
          fixAll: mv.to ? `Put them in ${say.zone(mv.to)}, under Trust zone, unless the diagram is the one that’s wrong.`
            : 'Choose — none — for each, under Trust zone, unless the diagram is the one that’s wrong.' });
      }
    }

    /*
     * The layout, redrawn as the skill draws it, when every element and zone has a position. The skill's own step after
     * this is Claude looking at the preview and correcting model.json until validate() is clean; here no one moves a box.
     * A picture Claude read is redrawn all the same (the skill always lays out what it reads: its icons, drawn small in
     * the picture, are only readable at the standard sizes), and what is left is listed. Any other diagram whose redrawn
     * layout would have more geometry problems in all than it has as drawn (a crowded diagram at the standard sizes)
     * keeps its own, and held says what redrawing it would add. One laid out already is redrawn (at its own scale) only to
     * clear a problem it has, adding none and leaving no elements overlapping: so the draw.io file this check writes, its
     * positions rounded to whole pixels, reads back with nothing to fix.
     */
    let laid = null, held = null, tallied = null;
    const anc = ancestry(m);
    const claude = !!m.source && typeof m.source === 'object' && m.source.method === 'claude';
    const zoneSize = zid => ({ code: 'zone-size', zone: zid, refs: refs([], [zid]),
      text: `Enlarged the trust zone ${say.zone(zid)}, drawn too small for tools that read the draw.io file to see it as a zone.`,
      would: `enlarge the trust zone ${say.zone(zid)}, drawn too small for tools that read the draw.io file to see it as a zone` });
    if (fix && !broken && complete(m)) {
      const again = laidOut(m);
      const always = opts.redraw === 'always' || (claude && !again);
      const L = layout(m, again ? 1 : scaleOf(m, pageW), anc);
      const drawn = { zones: m.zones.map(z => Object.assign({}, z, { geometry: geometry(L.zones.get(z.id)) })),
        elements: m.elements.map(e => Object.assign({}, e, { geometry: geometry(L.els.get(e.id)) })), flows: m.flows };
      const was = tally(m, say, anc), now = tally(drawn, say, anc);
      tallied = { drawn: was, redrawn: now };
      const added = GEOMETRY.filter(c => now[c] > was[c]).map(c => [c, now[c] - was[c]]);
      const cleared = GEOMETRY.reduce((n, c) => n + Math.max(0, was[c] - now[c]), 0);
      const rise = GEOMETRY.reduce((n, c) => n + now[c] - was[c], 0);
      if (rise > 0 && !always) {
        const overlapsOnly = added.length === 1 && added[0][0] === 'overlap' && !cleared;
        held = { added: Object.fromEntries(added), cleared, count: rise, page: L.page,
          text: `Redrawn in CSA notation, with each element at the standard size for its type, the diagram would have ${andList(added.map(([c, k]) => ADDED[c](k)))}`
            + `${cleared ? `, though ${plural(cleared, 'other problem')} would go: ${plural(rise, 'more problem')} in all` : ''}.`,
          short: `would add ${overlapsOnly ? plural(rise, 'overlap') : plural(rise, 'problem')}${cleared ? ' in all' : ''}` };
      } else if (again && !always && (added.length || !cleared || now.overlap > 0)) {
        // laid out already, and redrawing it would add a problem, clear nothing, or leave elements overlapping (a zone
        // too crowded for the standard sizes, which another redraw would only shuffle): it stays as it is
      } else {
        const before = [...m.zones, ...m.elements].map(x => boxOf(x.geometry));
        const after = [...m.zones.map(z => L.zones.get(z.id)), ...m.elements.map(e => L.els.get(e.id))];
        if (after.some((b, i) => b.some((v, k) => Math.abs(v - before[i][k]) > 0.01))) {
          laid = L;
          for (const z of m.zones) z.geometry = geometry(L.zones.get(z.id));
          for (const e of m.elements) e.geometry = geometry(L.els.get(e.id));
          m.page = { w: L.page[0], h: L.page[1] };
          const page = `${L.page[0].toLocaleString('en')} × ${L.page[1].toLocaleString('en')} px`;
          if (!again) {
            fixes.push({ code: 'layout', refs: refs(),
              text: `Redrew the diagram in CSA notation on a ${page} page: each element at the standard size for its type, centred where the diagram draws it.`,
              would: `redraw the diagram in CSA notation on a ${page} page, each element at the standard size for its type` });
          }
          if (L.apart.length) {
            const n = plural(L.apart.length, 'element');
            fixes.push(again ? { code: 'apart', refs: refs(L.apart), text: `Moved ${n} apart that overlapped or nearly touched.`, would: `move ${n} apart that overlap or nearly touch` }
              : { code: 'apart', refs: refs(L.apart), text: `Moved ${n} apart that would overlap or nearly touch at the standard sizes.`, would: `move ${n} apart that would overlap or nearly touch at the standard sizes` });
          }
          if (L.inside.length) {
            const n = plural(L.inside.length, 'element'), their = L.inside.length === 1 ? 'its trust zone' : 'their trust zones';
            fixes.push({ code: 'inside', refs: refs(L.inside), text: `Moved ${n} back inside ${their}.`, would: `move ${n} back inside ${their}` });
          }
          if (L.settled.length) {
            const one = L.settled.length === 1, n = plural(L.settled.length, 'element');
            fixes.push({ code: 'settled', refs: refs(L.settled),
              text: `Moved ${n} out of a trust zone ${one ? 'it isn’t' : 'they aren’t'} in, where moving the elements apart had put ${one ? 'it' : 'them'}.`,
              would: `move ${n} out of a trust zone ${one ? 'it isn’t' : 'they aren’t'} in, where moving the elements apart would put ${one ? 'it' : 'them'}` });
          }
          for (const zid of L.enlarged) {
            if (L.small.includes(zid)) continue;   // (said once, below)
            fixes.push({ code: 'enlarged', zone: zid, refs: refs([], [zid]), text: `Enlarged the trust zone ${say.zone(zid)} to fit what it holds.`,
              would: `enlarge the trust zone ${say.zone(zid)} to fit what it holds` });
          }
          for (const zid of L.small) fixes.push(zoneSize(zid));
        }
      }
    }
    if (fix && !broken && !laid) {
      // the layout kept as drawn (held back, laid out already, or not every position known): its small zones are made
      // bigger all the same, by the same stretch, so the draw.io file's readers take them for zones
      const { zb, eb } = drawnBoxes(m);   // (copies: boxOf makes each anew)
      const small = growSmall(m, zb, eb);
      if (small.length) {
        for (const z of m.zones) if (zb.has(z.id)) z.geometry = geometry(zb.get(z.id));
        for (const e of m.elements) if (eb.has(e.id)) e.geometry = geometry(eb.get(e.id));
        if (m.page && typeof m.page === 'object') {   // the page still holds the drawing
          const all = [...zb.values(), ...eb.values()];
          m.page = { w: Math.max(Number(m.page.w) || 0, ...all.map(b => b[0] + b[2])), h: Math.max(Number(m.page.h) || 0, ...all.map(b => b[1] + b[3])) };
        }
        for (const zid of small) fixes.push(zoneSize(zid));
      }
    }
    say = namer(m);

    validate(m, add, say, !!laid || !!opts.redrawn, said, anc);
    const used = overall(m, add, notes);

    const rank = new Map(ORDER.map((c, i) => [c, i]));
    const findings = found.sort((a, b) => (a.level === b.level ? 0 : a.level === 'error' ? -1 : 1)
      || (rank.has(a.code) ? rank.get(a.code) : 99) - (rank.has(b.code) ? rank.get(b.code) : 99) || a.index - b.index);
    for (const f of findings) delete f.index;
    const zoneOf = new Map(m.elements.map(e => [e.id, e.zone || null]));
    const sum = level => findings.reduce((n, f) => n + (f.level === level ? f.count || 1 : 0), 0);
    const counts = {
      zones: m.zones.length, elements: m.elements.length, flows: m.flows.length,
      crossing: m.flows.filter(f => zoneOf.has(f.source) && zoneOf.has(f.target) && zoneOf.get(f.source) !== zoneOf.get(f.target)).length,
      errors: sum('error'), warnings: sum('warning'), fixes: fixes.length,
    };
    return { model: m, fixes, findings, notes: notes.filter(n => !used.includes(n)), counts, changed: changed || fixes.length > 0, held, tally: tallied,
      layout: laid && { scale: laid.scale, enlarged: laid.enlarged, small: laid.small, apart: laid.apart, inside: laid.inside, settled: laid.settled, page: laid.page } };
  }

  // ---------------------------------------------------------------- where everything is drawn

  /**
   * A layout for a decomposition without every position (made by hand, or with elements added since): zones as boxes
   * in rows, each with its elements in a grid and the zones inside it below them, and the elements outside every zone
   * along the top. Only the preview and the draw.io file use it; the decomposition itself is left without positions.
   */
  function autoPlace(m, zones, els) {
    const CELL_W = 150, CELL_H = 140;   // the largest CSA shape, and room round it
    const ids = new Set(m.zones.map(z => z.id));
    const kidsOf = new Map(), ownOf = new Map();
    const push = (map, k, v) => { if (!map.has(k)) map.set(k, []); map.get(k).push(v); };
    for (const z of m.zones) push(kidsOf, ids.has(z.parent) && z.parent !== z.id ? z.parent : null, z);
    for (const e of m.elements) push(ownOf, ids.has(e.zone) ? e.zone : null, e);
    const size = new Map(), visiting = new Set();
    const grid = n => { const cols = n ? Math.max(1, Math.ceil(Math.sqrt(n))) : 0; return [cols, cols ? Math.ceil(n / cols) : 0]; };
    const kidsIn = id => (kidsOf.get(id) || []).filter(k => !visiting.has(k.id) && !zones.has(k.id));
    function measure(id) {
      if (size.has(id)) return size.get(id);
      visiting.add(id);
      const [cols, rows] = grid((ownOf.get(id) || []).length);
      const ks = kidsIn(id).map(k => measure(k.id));
      const kidsW = ks.reduce((a, s) => a + s[0], 0) + GAP * Math.max(0, ks.length - 1);
      const kidsH = ks.reduce((a, s) => Math.max(a, s[1]), 0);
      const top = ks.length ? TOP_BAND : PAD;
      const innerH = rows * CELL_H + (rows && ks.length ? GAP : 0) + kidsH;
      const s = [Math.max(cols * CELL_W, kidsW, 180) + 2 * PAD, top + Math.max(innerH, 60) + LABEL_BAND];
      visiting.delete(id);
      size.set(id, s);
      return s;
    }
    const cell = (e, x, y) => { const [w, h] = sizeOf(e.type); els.set(e.id, [x + (CELL_W - w) / 2, y + (CELL_H - h) / 2, w, h]); };
    function put(id, x, y) {
      const [w, h] = measure(id);
      zones.set(id, [x, y, w, h]);
      const own = ownOf.get(id) || [];
      const kids = kidsIn(id);
      const top = kids.length ? TOP_BAND : PAD;
      const [cols, rows] = grid(own.length);
      own.forEach((e, i) => cell(e, x + PAD + (i % cols) * CELL_W, y + top + Math.floor(i / cols) * CELL_H));
      let kx = x + PAD;
      const ky = y + top + rows * CELL_H + (rows && kids.length ? GAP : 0);
      for (const k of kids) { if (zones.has(k.id)) continue; put(k.id, kx, ky); kx += measure(k.id)[0] + GAP; }
    }
    let x = 20, y = 20, rowH = 0;
    for (const e of ownOf.get(null) || []) {
      if (x > 20 && x + CELL_W > PAGE_W) { x = 20; y += CELL_H; }
      cell(e, x, y);
      x += CELL_W;
    }
    if ((ownOf.get(null) || []).length) { x = 20; y += CELL_H + GAP; }
    const place = z => {
      if (zones.has(z.id)) return;
      const [w, h] = measure(z.id);
      if (x > 20 && x + w > PAGE_W) { x = 20; y += rowH + GAP; rowH = 0; }
      put(z.id, x, y);
      x += w + GAP;
      rowH = Math.max(rowH, h);
    };
    for (const z of kidsOf.get(null) || []) place(z);
    for (const z of m.zones) place(z);   // zones inside each other in a circle, which no walk from the top reaches
  }

  /**
   * Room for a box in a zone of a drawing (zones and els: id -> [x, y, w, h], changed in place), never made by growing a
   * zone over its neighbours. makeRoom(zid, w, h, self) gives a spot for a w x h box in zone zid, inside its room (as the
   * layout's: PAD in from the sides, a title band at the top when it holds zones, the label band at the bottom), clear by
   * GAP of every element (but self, the box being placed, if it is drawn already) and of every zone but zid and those
   * round it. The first free spot, in reading order on a 10 px grid; when there is none, room is opened in the zone with
   * a stretch (see stretch()): below what it holds (and right of it first, when it is narrower than the box), so every
   * other element stays in its zones and every zone keeps its nesting. That is checked after each stretch: should a zone
   * that partly overlaps another see a centre cross its border, the stretch is made again in the zone's bottom band,
   * then beside what it holds. A zone that partly overlaps this one (or one inside it) can grow with it on every such
   * line and keep the spot from opening: then the line is just before such a zone (which moves on, out of the way) or
   * just past it (the zone grows beyond it), on either axis. Failing all those, the first spot found is kept (nothing
   * overlaps more than it did); and where none opens at all (a zone that another covers, leaving it no part of its own),
   * makeRoom gives null and the drawing is left as it was.
   */
  function rooms(m, zones, els) {
    const ids = new Set(m.zones.map(z => z.id));
    const byId = new Map(m.zones.map(z => [z.id, z]));
    const parentOf = z => (z && ids.has(z.parent) && z.parent !== z.id ? z.parent : null);
    const holds = new Set(m.zones.map(parentOf).filter(Boolean));
    const roomOf = zid => {
      const Z = zones.get(zid), top = holds.has(zid) ? TOP_BAND : PAD;
      return [Z[0] + PAD, Z[1] + top, Z[2] - 2 * PAD, Z[3] - top - LABEL_BAND];
    };
    const takenIn = (zid, R, self) => {
      const round = new Set();
      for (let p = zid; p && !round.has(p); p = parentOf(byId.get(p))) round.add(p);
      return [...els.values(), ...m.zones.filter(c => !round.has(c.id) && zones.has(c.id)).map(c => zones.get(c.id))]
        .filter(t => t !== self && overlap(t, R, GAP));
    };
    const freeSpot = (zid, w, h, self) => {
      const R = roomOf(zid), taken = takenIn(zid, R, self);
      for (let y = R[1]; y + h <= R[1] + R[3]; y += 10) {
        const row = taken.filter(t => t[1] < y + h + GAP && y < t[1] + t[3] + GAP);
        for (let x = R[0]; x + w <= R[0] + R[2];) {
          const t = row.find(t => t[0] < x + w + GAP && x < t[0] + t[2] + GAP);
          if (!t) return [x, y, w, h];
          x = R[0] + 10 * Math.max(Math.floor((x - R[0]) / 10) + 1, Math.ceil((t[0] + t[2] + GAP - R[0]) / 10));   // (past it, on the grid)
        }
      }
      return null;
    };
    // what a stretch must keep: the zones round each element's centre, and the larger zones round each zone's centre
    const holding = self => {
      const zl = [...zones];
      const out = [];
      for (const b of els.values()) { if (b === self) continue; const c = ctr(b); out.push(zl.filter(([, Z]) => inside(c, Z)).map(([id]) => id).join('\n')); }
      for (const [id, b] of zl) { const c = ctr(b), a = b[2] * b[3]; out.push(zl.filter(([k, Z]) => k !== id && Z[2] * Z[3] > a && inside(c, Z)).map(([k]) => k).join('\n')); }
      return out.join('\u0000');
    };
    const copy = () => [new Map([...zones].map(([k, b]) => [k, b.slice()])), new Map([...els].map(([k, b]) => [k, b.slice()]))];
    const restore = ([zs, es]) => { for (const [k, b] of zs) zones.get(k).splice(0, 4, ...b); for (const [k, b] of es) els.get(k).splice(0, 4, ...b); };
    const makeRoom = (zid, w, h, self) => {
      let spot = freeSpot(zid, w, h, self);
      if (spot) return spot;
      const was = holding(self), start = copy();
      let kept = null;
      // below what the zone holds; else in its bottom band; else beside what it holds (in each, wider first if need be)
      for (const how of ['below', 'band', 'beside']) {
        restore(start);
        spot = null;
        for (let i = 0; !spot && i < 6; i++) {
          const Z = zones.get(zid), R = roomOf(zid), inR = takenIn(zid, R, self);
          const more = i < 2 ? 0 : (i - 1) * (Math.max(w, h) + 2 * GAP);   // (a stretch that opened no spot: a longer one)
          const right = Math.max(R[0], ...inR.map(t => t[0] + t[2]));
          const beside = how === 'beside' && i === 0 && R[3] >= h;
          if (R[2] < w || beside) {
            const lo = how === 'band' ? Z[0] + Z[2] - Math.min(PAD, Z[2] / 2) : Math.min(right + GAP / 2, Z[0] + Z[2] - 1);
            const at = lineIn(zones, 0, lo, Z[0] + Z[2] - 1);
            stretch(zones, els, 0, at, Math.max(w - R[2] + 10, beside ? at + GAP / 2 + 10 + w - (R[0] + R[2]) : 0, 10) + more);
          } else {
            const bottom = Math.max(R[1], ...inR.map(t => t[1] + t[3]));
            const lo = how === 'band' ? Z[1] + Z[3] - Math.min(LABEL_BAND / 2, Z[3] / 2) : Math.min(bottom + GAP / 2, Z[1] + Z[3] - 1);
            const at = lineIn(zones, 1, lo, Z[1] + Z[3] - 1);
            stretch(zones, els, 1, at, Math.max(10, at + GAP / 2 + 10 + h - (R[1] + R[3])) + more);
          }
          spot = freeSpot(zid, w, h, self);
        }
        if (!spot) continue;
        if (holding(self) === was) return spot;
        if (!kept) kept = [spot, copy()];
      }
      // a zone in the way that grows with this one on those lines: a line just before it (it moves on) or just past it
      // (this zone grows beyond it), clear of every zone edge by 4 px, the stretch long enough for the box beside what
      // the elements across the line reach
      restore(start);
      const Z0 = zones.get(zid), round = new Set();
      for (let p = zid; p && !round.has(p); p = parentOf(byId.get(p))) round.add(p);
      const lines = [];
      for (const [k, Y] of zones) {
        if (round.has(k) || !overlap(Y, Z0)) continue;
        for (const axis of [0, 1]) {
          for (const [v, step] of [[Y[axis] - 4, -1], [Y[axis] + Y[axis + 2] + 4, 1]]) {
            const at = clearNear(zones, axis, v, step, Z0[axis], Z0[axis] + Z0[axis + 2]);
            if (at !== null && !lines.some(l => l[0] === axis && l[1] === at)) lines.push([axis, at]);
          }
        }
      }
      for (const [axis, at] of lines) {
        restore(start);
        let before = 0, after = 0;
        for (const b of els.values()) {
          if (b === self || b[axis] >= at || b[axis] + b[axis + 2] <= at) continue;
          if (b[axis] + b[axis + 2] / 2 > at) after = Math.max(after, at - b[axis]); else before = Math.max(before, b[axis] + b[axis + 2] - at);
        }
        stretch(zones, els, axis, at, (axis ? h : w) + 2 * GAP + before + after + 20);
        spot = freeSpot(zid, w, h, self);
        if (!spot) continue;
        if (holding(self) === was) return spot;
        if (!kept) kept = [spot, copy()];
      }
      // (a zone that partly overlaps another saw a centre cross its border every way: the first, where nothing overlaps
      // more than it did; with no spot at all, nothing)
      restore(kept ? kept[1] : start);
      return kept ? kept[0] : null;
    };
    return { makeRoom, parentOf, ids };
  }

  /** A line on the axis from v on, step by step (1 px; at most 40), inside (lo, hi), at least 4 px from every zone edge; or null. */
  function clearNear(zones, axis, v, step, lo, hi) {
    const edges = [];
    for (const b of zones.values()) edges.push(b[axis], b[axis] + b[axis + 2]);
    for (let i = 0; i <= 40; i++, v += step) if (v > lo && v < hi && edges.every(e => Math.abs(e - v) >= 4)) return v;
    return null;
  }

  /**
   * What has no position in a decomposition that otherwise has them (an element added, or moved to a zone it isn't drawn
   * in; a zone added; or, see drawnBoxes(), what is in a zone with none): placed without moving anything over anything
   * else (see rooms()). An element goes to a spot in its zone; a zone, laid out as autoPlace() would with what it holds,
   * to a spot in the zone it sits in. A zone outside every other, and an element outside every zone, go in rows below the
   * drawing, once everything else has its place; and so does what no room could be made for (in a zone another covers).
   */
  function placeRest(m, zones, els) {
    const { makeRoom, parentOf, ids } = rooms(m, zones, els);
    const extent = () => [...zones.values(), ...els.values()];
    let rowX = 20, rowY = null, rowH = 0;
    const atBottom = (w, h) => {   // a row below the drawing
      if (rowY === null) rowY = Math.max(0, ...extent().map(b => b[1] + b[3])) + 40;
      if (rowX > 20 && rowX + w > Math.max(PAGE_W, ...extent().map(b => b[0] + b[2]))) { rowX = 20; rowY += rowH + GAP; rowH = 0; }
      const b = [rowX, rowY, w, h];
      rowX += w + GAP;
      rowH = Math.max(rowH, h);
      return b;
    };
    const placedZone = id => zones.has(id);
    // zones with no position, each with what it holds laid out as autoPlace() would: first those in a zone that has a
    // position (in it), then the outermost (in rows below the drawing), then any that only a circle of parents reaches
    const block = z => {
      const tree = new Set([z.id]);
      for (let grew = true; grew;) {
        grew = false;
        for (const c of m.zones) if (!tree.has(c.id) && !placedZone(c.id) && tree.has(parentOf(c))) { tree.add(c.id); grew = true; }
      }
      const sub = { zones: m.zones.filter(c => tree.has(c.id)).map(c => Object.assign({}, c, { parent: c.id === z.id ? null : c.parent })),
        elements: m.elements.filter(e => tree.has(e.zone) && !els.has(e.id)) };
      const zs = new Map(), es = new Map();
      autoPlace(sub, zs, es);
      return { zs, es, size: zs.get(z.id).slice(2) };
    };
    const put = ({ zs, es }, at) => {
      const dx = at[0] - 20, dy = at[1] - 20;
      for (const [id, b] of zs) zones.set(id, [b[0] + dx, b[1] + dy, b[2], b[3]]);
      for (const [id, b] of es) els.set(id, [b[0] + dx, b[1] + dy, b[2], b[3]]);
    };
    const inPlaced = m.zones.filter(z => !placedZone(z.id) && parentOf(z) && placedZone(parentOf(z)));
    const later = [];   // what no room could be made for: below the drawing, with the rest
    for (const z of inPlaced) {
      if (placedZone(z.id)) continue;
      const b = block(z), spot = makeRoom(parentOf(z), ...b.size);
      if (spot) put(b, spot); else later.push(b);
    }
    // elements with no position in a zone that has one: in a free spot of it
    for (const e of m.elements) {
      if (els.has(e.id) || !ids.has(e.zone) || !zones.has(e.zone)) continue;
      const spot = makeRoom(e.zone, ...sizeOf(e.type));
      if (spot) els.set(e.id, spot); else later.push(e);
    }
    for (const x of later) {
      if (x.zs) put(x, atBottom(...x.size)); else els.set(x.id, atBottom(...sizeOf(x.type)));
    }
    for (const z of m.zones) {
      if (placedZone(z.id) || (parentOf(z) && ids.has(parentOf(z)))) continue;
      const b = block(z);
      put(b, atBottom(...b.size));
    }
    for (const z of m.zones) {   // zones that only a circle of parents reaches
      if (placedZone(z.id)) continue;
      const zs = new Map(), es = new Map();
      autoPlace({ zones: [Object.assign({}, z, { parent: null })], elements: m.elements.filter(e => e.zone === z.id && !els.has(e.id)) }, zs, es);
      put({ zs, es }, atBottom(...zs.get(z.id).slice(2)));
    }
    // elements with no position outside every zone (or in one that isn't in the decomposition): below the drawing
    for (const e of m.elements) if (!els.has(e.id)) els.set(e.id, atBottom(...sizeOf(e.type)));
  }

  /**
   * Every zone's and element's box: the model's own when it has them all; the automatic layout when it has none;
   * else its own (as drawnBoxes() takes them), with what has no position placed round them (placeRest). auto says
   * which: '', 'all' or 'some'.
   */
  function boxesFor(m) {
    let zones = new Map(), els = new Map();
    let auto = '';
    if (complete(m)) {
      for (const z of m.zones) zones.set(z.id, boxOf(z.geometry));
      for (const e of m.elements) els.set(e.id, boxOf(e.geometry));
    } else {
      ({ zb: zones, eb: els } = drawnBoxes(m));
      if (!zones.size && !els.size) { autoPlace(m, zones, els); auto = 'all'; } else { placeRest(m, zones, els); auto = 'some'; }
    }
    const all = [...zones.values(), ...els.values()];
    // what was placed may reach above or left of the drawing: the page starts at (20, 20) as the layout's does
    // (one laid out here in full starts there exactly, so its draw.io file reads back as laid out, with nothing to fix)
    if (auto && all.length) {
      const dx = 20 - Math.min(...all.map(b => b[0])), dy = 20 - Math.min(...all.map(b => b[1]));
      const ox = auto === 'all' ? dx : Math.max(0, dx), oy = auto === 'all' ? dy : Math.max(0, dy);
      for (const b of all) { b[0] += ox; b[1] += oy; }
    }
    const page = all.length ? [Math.ceil(Math.max(...all.map(b => b[0] + b[2])) + 20), Math.ceil(Math.max(...all.map(b => b[1] + b[3])) + 20)] : [PAGE_W, 400];
    return { zones, els, page, auto };
  }

  // ---------------------------------------------------------------- draw.io (the skill's emit())

  /** Python's xml.sax.saxutils.quoteattr: escaped, in double quotes, or in single quotes when the value holds a double one. */
  function quoteattr(value) {
    let v = text(value).replace(/&/g, '&amp;').replace(/>/g, '&gt;').replace(/</g, '&lt;')
      .replace(/\n/g, '&#10;').replace(/\r/g, '&#13;').replace(/\t/g, '&#9;');
    if (v.includes('"')) v = v.includes("'") ? `"${v.replace(/"/g, '&quot;')}"` : `'${v}'`;
    else v = `"${v}"`;
    return v;
  }
  /** Python's f"{x:.0f}": the nearest whole number, a half to the even one. */
  function f0(x) {
    let r = Math.round(x);
    if (Math.abs(x % 1) === 0.5) r = 2 * Math.round(x / 2);
    return r === 0 && (x < 0 || Object.is(x, -0)) ? '-0' : String(r);
  }
  /**
   * A label as draw.io reads it. The CSA styles say html=1, so draw.io (and both readers, TMParse and the
   * cyber-threat-modelling skill's) take the label as HTML: '&', '<' and '>' are written as entities, or a label such as
   * "API <v2>" would lose its end. The skill's emit() writes them as they are; this is the one change to its XML.
   */
  const html = s => text(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  // characters XML 1.0 can't hold, even escaped
  const xmlSafe = s => text(s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g, '');
  const flag = v => (v === true ? 'yes' : v === false ? 'no' : '');

  /**
   * Each id as the draw.io file writes it: characters XML can't hold are left out, and an id that is then draw.io's own
   * root cell ("0" or "1"), another's id, or nothing, is written with a _ after it (or as many as it takes to be its
   * own). An id that needs neither keeps itself, so only the odd ones change ("0" is written "0_").
   */
  function fileIds(m) {
    const ids = [...new Set([...m.zones, ...m.elements, ...m.flows].map(x => text(x.id)).concat(m.flows.flatMap(f => [text(f.source), text(f.target)])))];
    const out = new Map(), taken = new Set(['0', '1']);
    for (const id of ids) if (id && xmlSafe(id) === id && !taken.has(id)) { out.set(id, id); taken.add(id); }
    for (const id of ids) {
      if (out.has(id)) continue;
      let n = xmlSafe(id);
      if (!n || taken.has(n)) { n += '_'; while (taken.has(n)) n += '_'; }
      out.set(id, n);
      taken.add(n);
    }
    return id => out.get(text(id)) || '_';
  }

  /**
   * Beyond the skill: an element centred on the border of a zone it isn't in, and in its own zone (a firewall drawn on the
   * boundary between its zone and the next, or on the edge of a zone inside its own: the check keeps it in its own zone,
   * see zoneMismatches), would be read by the file's readers in the smaller zone, or the one written first. So it is
   * written a pixel into its own zone, out of the other, where one pixel does it (not where two zones inside its own meet
   * on that border). The file's readers see the positions in whole pixels, so this is worked out on those.
   */
  function offBorders(m, zones, els) {
    const anc = ancestry(m);
    const round = b => b.map(px);
    const zr = [...zones].map(([id, b]) => [id, round(b)]);
    const steps = [[1, 0], [-1, 0], [0, 1], [0, -1], [1, 1], [1, -1], [-1, 1], [-1, -1]];
    for (const e of m.elements) {
      const own = e.zone || null;
      if (!own || !zones.has(own) || !els.has(e.id)) continue;
      const E = round(els.get(e.id)), c = ctr(E), O = round(zones.get(own)), allowed = allowedIn(anc, own);
      const others = zr.filter(([id, Z]) => !allowed.has(id) && inside(c, Z));
      if (!others.length || !inside(c, O) || others.some(([, Z]) => interior(c, Z))) continue;
      const free = p => inside(p, O) && !zr.some(([id, Z]) => !allowed.has(id) && inside(p, Z));
      const o = ctr(O), toward = ([dx, dy]) => -(dx * (o[0] - c[0]) + dy * (o[1] - c[1]));
      // what a step may add to the check's findings: an element now within 4 px, a zone now crossed, its own zone left
      const near = B => m.elements.filter(x => x.id !== e.id && els.has(x.id) && overlap(B, round(els.get(x.id)), 4)).map(x => x.id);
      const crossed = B => zr.filter(([id, Z]) => !allowed.has(id) && overlap(B, Z)).map(([id]) => id);
      const was = { near: new Set(near(E)), crossed: new Set(crossed(E)), within: within(E, O) };
      const adds = B => near(B).some(id => !was.near.has(id)) || crossed(B).some(id => !was.crossed.has(id)) || (was.within && !within(B, O));
      const at = ([dx, dy]) => [E[0] + dx, E[1] + dy, E[2], E[3]];
      const ok = steps.filter(([dx, dy]) => free([c[0] + dx, c[1] + dy]))
        .sort((p, q) => adds(at(p)) - adds(at(q)) || Math.abs(p[0]) + Math.abs(p[1]) - Math.abs(q[0]) - Math.abs(q[1]) || toward(p) - toward(q));
      // a step that adds nothing first; else the zone the model has still wins over a pixel of overlap
      if (ok.length) els.set(e.id, at(ok[0]));
    }
  }

  /** Whether the cyber-threat-modelling skill's parser would take an element's box, as the file writes it, for a trust zone. */
  const readAsZone = (label, b) => px(b[2]) * px(b[3]) >= BOUNDARY_AREA && BOUNDARY_WORDS.some(w => text(label).replace(/\s+/g, ' ').toLowerCase().includes(w));

  function toDrawio(model) {
    const m = plain(clone(model || {}));
    const { zones, els, page } = boxesFor(m);
    offBorders(m, zones, els);
    const holds = new Set(m.zones.map(z => z.parent).filter(Boolean));
    const fid = fileIds(m);
    const cid = id => quoteattr(fid(id));
    const qa = v => quoteattr(xmlSafe(v));
    const geo = b => `<mxGeometry x="${f0(b[0])}" y="${f0(b[1])}" width="${f0(b[2])}" height="${f0(b[3])}" as="geometry"/>`;
    const out = [];
    // outer containers first, so inner zones and elements draw (and select) on top
    const area = id => { const b = zones.get(id); return b[2] * b[3]; };
    for (const z of m.zones.slice().sort((a, b) => area(b.id) - area(a.id))) {
      const st = holds.has(z.id) ? OUTER_STYLE : ZONE_STYLE;
      out.push(`<mxCell id=${cid(z.id)} value=${qa(html(z.label))} style="${st}" vertex="1" parent="1">${geo(zones.get(z.id))}</mxCell>`);
    }
    for (const e of m.elements) {
      const type = TYPES.includes(e.type) ? e.type : 'process';
      const ctx = e.context;
      const label = text(e.label) + (e.crownJewel ? ' ★' : '');
      const attrs = [['label', html(label)], ['type', type], ['purpose', text(ctx.purpose)],
        ['sensitivity', text(ctx.sensitivity)], ['auth', text(ctx.auth)], ['trust', text(ctx.trust)],
        ['crown_jewel', flag(e.crownJewel)], ['ai', flag(e.ai)]];
      const a = attrs.filter(([k, v]) => v !== '' || k === 'label').map(([k, v]) => `${k}=${qa(v)}`).join(' ');
      // (an element drawn as big as a zone, with a zone word in its name: draw.io's default fill, so it isn't read as one)
      const st = readAsZone(xmlSafe(label), els.get(e.id)) ? STYLE[type].replace('fillColor=none;', 'fillColor=default;') : STYLE[type];
      out.push(`<object id=${cid(e.id)} ${a}><mxCell style="${st}" vertex="1" parent="1">${geo(els.get(e.id))}</mxCell></object>`);
    }
    for (const f of m.flows) {
      const st = FLOW_STYLE + (f.bidirectional ? 'startArrow=block;startFill=1;' : 'startArrow=none;');
      out.push(`<mxCell id=${cid(f.id)} value=${qa(html(f.label))} style="${st}" edge="1" parent="1" `
        + `source=${cid(f.source)} target=${cid(f.target)}><mxGeometry relative="1" as="geometry"/></mxCell>`);
    }
    const name = m.name || 'Data flow diagram';
    return '<mxfile host="ThreatSim" type="device">\n'
      + `  <diagram id="dfd" name=${qa(Array.from(text(name)).slice(0, 60).join(''))}>\n`
      + `    <mxGraphModel dx="${page[0]}" dy="${page[1]}" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" `
      + `fold="1" page="1" pageScale="1" pageWidth="${page[0]}" pageHeight="${page[1]}" math="0" shadow="0">\n`
      + '      <root>\n        <mxCell id="0"/>\n        <mxCell id="1" parent="0"/>\n        '
      + out.join('\n        ') + '\n      </root>\n    </mxGraphModel>\n  </diagram>\n</mxfile>\n';
  }

  /**
   * The component context the cyber-threat-modelling skill takes with the draw.io file (its --context JSON): that
   * skill's parser reads only each cell's label, style and size, so what toDrawio writes as an element's properties
   * reaches it this way. Keyed by the ids as the file writes them; the values as written there, the label without the
   * crown-jewel ★ (crown_jewel says it), crown_jewel and ai only when set. A context field left empty isn't written:
   * that skill words a threat with its own default for a missing one ("by defeating its authentication mechanism",
   * "sensitive data"), which an empty one would override with a gap. Nothing is added: that skill rates an element a
   * crown jewel by the words of its context (sensitivity: "restricted", "PII"…), not by the mark.
   */
  function toContext(model) {
    const m = plain(clone(model || {}));
    const fid = fileIds(m);
    return Object.fromEntries(m.elements.map(e => {
      const c = { label: xmlSafe(e.label), type: TYPES.includes(e.type) ? e.type : 'process' };
      for (const k of CONTEXT) { const v = xmlSafe(e.context[k]).trim(); if (v) c[k] = v; }
      if (flag(e.crownJewel)) c.crown_jewel = flag(e.crownJewel);
      if (flag(e.ai)) c.ai = flag(e.ai);
      return [fid(e.id), c];
    }));
  }

  // ---------------------------------------------------------------- the preview (the skill's preview(), in SVG)

  const FONT = 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  // The colours come from the page (--dfd-*, set for its light and dark themes); the skill's own are the fallbacks.
  const SVG_STYLE = `
    .dfd-paper { fill: var(--dfd-paper, #ffffff); }
    .dfd-zone { fill: none; stroke: var(--dfd-zone, ${RED}); stroke-width: 2; stroke-dasharray: 8 6; }
    .dfd-outer { fill: none; stroke: var(--dfd-outer, ${DARK_RED}); stroke-width: 2; stroke-dasharray: 8 6; }
    .dfd-zone-label { fill: var(--dfd-ink, #000000); font: bold 13px ${FONT}; }
    .dfd-outer-label { fill: var(--dfd-outer, ${DARK_RED}); font: italic bold 13px ${FONT}; }
    .dfd-flow { stroke: var(--dfd-flow, #000000); stroke-width: 1; }
    .dfd-arrow { fill: var(--dfd-flow, #000000); }
    .dfd-flow-back { fill: var(--dfd-paper, #ffffff); }
    .dfd-flow-label { fill: var(--dfd-flow-ink, #333333); font: 9px ${FONT}; }
    .dfd-shape { fill: var(--dfd-paper, #ffffff); stroke: var(--dfd-shape, ${BLUE}); stroke-width: 2; }
    .dfd-line { fill: none; stroke: var(--dfd-shape, ${BLUE}); stroke-width: 2; }
    .dfd-body { fill: var(--dfd-paper, #ffffff); }
    .dfd-label { fill: var(--dfd-ink, #000000); font: 11px ${FONT}; }`;

  let measurer = null;
  function textWidth(doc, s, size, bold) {
    try {
      if (!measurer) measurer = doc.createElement('canvas').getContext('2d');
      measurer.font = `${bold ? 'bold ' : ''}${size}px ${FONT}`;
      return measurer.measureText(s).width;
    } catch (_) {
      return s.length * size * 0.55;
    }
  }
  /** The skill's wrap(): words in lines no wider than width (a word wider than that stands alone). */
  function wrap(doc, s, width, size, bold) {
    const lines = [];
    let cur = '';
    for (const w of text(s).split(/\s+/).filter(Boolean)) {
      const t = (cur + ' ' + w).trim();
      if (textWidth(doc, t, size, bold) <= width || !cur) cur = t;
      else { lines.push(cur); cur = w; }
    }
    return cur ? lines.concat([cur]) : lines;
  }

  function toSvg(model, opts = {}) {
    const doc = opts.document || global.document;
    const NS = 'http://www.w3.org/2000/svg';
    const m = plain(clone(model || {}));
    const { zones, els, page } = boxesFor(m);
    const node = (tag, attrs, parent) => {
      const n = doc.createElementNS(NS, tag);
      for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
      if (parent) parent.append(n);
      return n;
    };
    const r1 = v => Math.round(v * 10) / 10;
    const svg = node('svg', { viewBox: `0 0 ${page[0]} ${page[1]}`, width: '100%', class: 'dfd-svg', role: 'img',
      'aria-label': `Data-flow diagram in CSA notation: ${plural(m.zones.length, 'trust zone')}, ${plural(m.elements.length, 'element')}, ${plural(m.flows.length, 'data flow')}.` });
    svg.style.height = 'auto';
    svg.style.maxWidth = `${page[0]}px`;   // fitted to its container, never drawn larger than it is
    node('title', {}, svg).textContent = m.name ? `${m.name}: data-flow diagram` : 'Data-flow diagram';
    node('style', {}, svg).textContent = SVG_STYLE;
    node('rect', { class: 'dfd-paper', x: 0, y: 0, width: page[0], height: page[1] }, svg);

    const holds = new Set(m.zones.map(z => z.parent).filter(Boolean));
    const area = id => zones.get(id)[2] * zones.get(id)[3];
    const say = (parent, cls, x, y, s, anchor) => { const t = node('text', { class: cls, x: r1(x), y: r1(y) }, parent); if (anchor) t.setAttribute('text-anchor', anchor); t.textContent = s; return t; };
    const zoneLayer = node('g', { class: 'dfd-zones' }, svg);
    for (const z of m.zones.slice().sort((a, b) => area(b.id) - area(a.id))) {
      const b = zones.get(z.id);
      const outer = holds.has(z.id);
      node('rect', { class: outer ? 'dfd-outer' : 'dfd-zone', x: r1(b[0]), y: r1(b[1]), width: r1(b[2]), height: r1(b[3]) }, zoneLayer);
      const lines = wrap(doc, text(z.label), b[2] - 16, 13, true);
      if (outer) {
        if (lines.length) say(zoneLayer, 'dfd-outer-label', b[0] + 8, b[1] + 6 + 12, lines[0]);
      } else {
        const last = lines.slice(-2);
        last.forEach((l, i) => say(zoneLayer, 'dfd-zone-label', b[0] + b[2] / 2, b[1] + b[3] - 8 - 16 * (last.length - i) + 12, l, 'middle'));
      }
    }
    // where the line from a box's centre toward (qx, qy) leaves the box
    const clip = (box, qx, qy) => {
      const [cx, cy] = ctr(box);
      const dx = qx - cx, dy = qy - cy;
      if (!dx && !dy) return [cx, cy];
      const t = Math.min(dx ? (box[2] / 2) / Math.abs(dx) : 1e9, dy ? (box[3] / 2) / Math.abs(dy) : 1e9);
      return [cx + dx * t, cy + dy * t];
    };
    const flowLayer = node('g', { class: 'dfd-flows' }, svg);
    for (const f of m.flows) {
      const A = els.get(f.source), B = els.get(f.target);
      if (!A || !B) continue;
      const [ax, ay] = ctr(A), [bx, by] = ctr(B);
      const p1 = clip(A, bx, by), p2 = clip(B, ax, ay);
      node('line', { class: 'dfd-flow', x1: r1(p1[0]), y1: r1(p1[1]), x2: r1(p2[0]), y2: r1(p2[1]) }, flowLayer);
      for (const [tip, from, on] of [[p2, p1, true], [p1, p2, !!f.bidirectional]]) {
        if (!on) continue;
        const ang = Math.atan2(tip[1] - from[1], tip[0] - from[0]);
        const pts = [tip, [tip[0] - 9 * Math.cos(ang - 0.4), tip[1] - 9 * Math.sin(ang - 0.4)], [tip[0] - 9 * Math.cos(ang + 0.4), tip[1] - 9 * Math.sin(ang + 0.4)]];
        node('polygon', { class: 'dfd-arrow', points: pts.map(p => `${r1(p[0])},${r1(p[1])}`).join(' ') }, flowLayer);
      }
      const label = text(f.label).trim();
      if (label) {
        const mx = (p1[0] + p2[0]) / 2, my = (p1[1] + p2[1]) / 2;
        const tw = textWidth(doc, label, 9, false);
        node('rect', { class: 'dfd-flow-back', x: r1(mx - tw / 2 - 1), y: r1(my - 6), width: r1(tw + 2), height: 12 }, flowLayer);
        say(flowLayer, 'dfd-flow-label', mx, my + 3, label, 'middle');
      }
    }
    const elementLayer = node('g', { class: 'dfd-elements' }, svg);
    for (const e of m.elements) {
      const [x, y, w, h] = els.get(e.id);
      const g = node('g', { class: `dfd-element dfd-${TYPES.includes(e.type) ? e.type : 'process'}` }, elementLayer);
      if (e.type === 'process' || e.type === 'cluster' || !TYPES.includes(e.type)) {
        node('ellipse', { class: 'dfd-shape', cx: r1(x + w / 2), cy: r1(y + h / 2), rx: r1(w / 2), ry: r1(h / 2) }, g);
        if (e.type === 'cluster') node('ellipse', { class: 'dfd-line', cx: r1(x + w / 2), cy: r1(y + h / 2), rx: r1(w / 2 - 6), ry: r1(h / 2 - 6) }, g);
      } else if (e.type === 'entity') {
        node('rect', { class: 'dfd-shape', x: r1(x), y: r1(y), width: r1(w), height: r1(h) }, g);
      } else {   // a data store: a cylinder
        node('rect', { class: 'dfd-body', x: r1(x), y: r1(y + 10), width: r1(w), height: r1(h - 20) }, g);
        node('path', { class: 'dfd-line', d: `M${r1(x)},${r1(y + 10)}V${r1(y + h - 10)}M${r1(x + w)},${r1(y + 10)}V${r1(y + h - 10)}` }, g);
        node('ellipse', { class: 'dfd-shape', cx: r1(x + w / 2), cy: r1(y + 10), rx: r1(w / 2), ry: 10 }, g);
        node('path', { class: 'dfd-line', d: `M${r1(x)},${r1(y + h - 10)}A${r1(w / 2)},10 0 0 0 ${r1(x + w)},${r1(y + h - 10)}` }, g);
      }
      const lines = wrap(doc, text(e.label) + (e.crownJewel ? ' ★' : ''), w - 12, 11, false).slice(0, 5);
      const ty = y + h / 2 - 7 * lines.length + (e.type === 'datastore' ? 5 : 0);
      lines.forEach((l, i) => say(g, 'dfd-label', x + w / 2, ty + 14 * i + 11, l, 'middle'));
    }
    return svg;
  }

  global.DfdCheck = { check, toDrawio, toContext, toSvg, TYPES, SIZE, PAGE_W, MIN_ZONE_AREA, CODES: ORDER.slice(), GEOMETRY: GEOMETRY.slice(), LAYOUT: LAYOUT.slice() };
})(window);
