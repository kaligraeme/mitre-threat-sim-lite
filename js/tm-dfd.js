/*
 * tm-dfd.js — the data-flow diagram with identified threats (CSA Guide to Cyber Threat Modelling
 * §3.2–3.3), written as a PowerPoint deck in the design of the reference deliverable.
 *
 * Global `TMDfd`: build(result) -> Promise<Blob>, FILE_NAME. Uses PptxGenJS 4 (vendored in js/vendor,
 * global `PptxGenJS`). Pure: reads the threat-model result (see the Threat Modelling contract) and
 * returns the file; no DOM access beyond what the library needs, no network.
 *
 * Slides, in the reference deck's order:
 *   Figure 1       the DFD enumerated with every ATT&CK threat-event location (red octagon, number n)
 *   Figure 2…      one attack-modelling slide per ATT&CK attack sequence: the path over the faded DFD
 *   Figure k       AI threat actors: the same DFD with the AI (MAESTRO / ATLAS) locations only
 *   Figure k+1…    one attack-modelling slide per AI attack sequence
 * The AI slides are left out when there are no AI locations.
 *
 * Layout. When the decomposition has geometry it is kept: zones and elements are fitted into the
 * drawing area with one uniform scale and each element is drawn at the standard size on its scaled
 * centre. Without geometry (a decomposition made by hand) the zones are laid out here in rows —
 * untrusted on top, internal in the middle, infrastructure at the bottom. Trust boundaries are red
 * dashed curves between adjacent zones when the zones tile the diagram, or each zone's dashed outline
 * when they don't, so a boundary is drawn wherever a flow changes trust zone.
 *
 * All measures are in inches. Text is measured with Calibri's advance widths, so labels are broken
 * and sized to stay inside their shapes instead of being left to the renderer.
 */
(function (global) {
  'use strict';

  const FILE_NAME = 'Dataflow_Diagram_with_Threats.pptx';
  const PPTX_MIME = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';

  /* ------------------------------------------------------------------------------------------------
   * Design tokens, measured from the reference deck (22 x 12.375 in, Calibri)
   * ---------------------------------------------------------------------------------------------- */

  const SLIDE_W = 22;
  const SLIDE_H = 12.375;
  const FONT = 'Calibri';

  const COLOR = {
    text: '000000',
    subtitle: '404040',
    element: '41719C',        // element outlines
    boundary: 'FF0000',       // trust boundaries
    accent: 'C00000',         // parent-zone label, attack path
    threat: 'FF0000',         // threat-event octagon
    threatText: 'FFFF00',
    layer: 'FFFFFF',          // MAESTRO layer line on AI octagons
    jewel: 'FFFF00',
    jewelLine: '548235',
    white: 'FFFFFF',
  };
  // Attack-sequence slides fade everything that is not on the path.
  const FADED = {
    line: 'BFBFBF', text: 'A6A6A6', flow: 'D0D0D0', boundary: 'F4B6B6',
    threat: 'F6D0D0', threatText: 'FFFFFF', jewel: 'F2F2F2', jewelLine: 'BFBFBF',
  };

  // Standard element sizes (CSA notation): external entity = rectangle, process = circle,
  // cluster of processes = two concentric circles, data store = cylinder.
  const SIZE = {
    entity: { w: 1.30, h: 0.64 },
    process: { w: 1.08, h: 1.08 },
    cluster: { w: 1.18, h: 1.18 },
    datastore: { w: 1.28, h: 0.86 },
  };
  const TYPES = Object.keys(SIZE);
  const CLUSTER_INNER = 1.02 / 1.18;     // inner circle of a cluster, relative to the outer one
  const OCT = 1.12;                      // threat-event octagon
  const STAR = { w: 0.24, h: 0.23 };     // crown jewel
  const INSET = 0.03;                    // text inset inside element shapes
  const ELEMENT_LINE = 1;                // pt
  const PATH_LINE = 1.75;                // pt, elements on the attack path
  const ARROW_LINE = 3.25;               // pt, attack-path arrows

  const AREA = { l: 0.2, r: 21.9, t: 0.8, b: 12.2 };            // drawing area below the title
  const LEGEND = { x: 14.55, y: 0.8, w: 7.3, h: 2.24 };          // the block the legend occupies
  const LEGEND_BOTTOM = LEGEND.y + LEGEND.h;
  // A trust boundary may run this far up into the legend's block, below the profile line's
  // descenders (the reference's row boundary runs along its bottom edge, 0.04 in up at most).
  const LEGEND_GRAZE = 0.045;
  const TOP_BAND = { x: 0, y: 0, w: SLIDE_W, h: AREA.t };        // title and subtitle
  const TILE_TOL = 0.3;                  // zones this close (in) touch: the edge between them is one boundary
  const MERGE_TOL = TILE_TOL + 0.05;     // zone edges this close are drawn as one curve

  // Ids for areas the decomposition doesn't name (characters no real id is made of).
  const PRIVATE = String.fromCharCode(0xE000);
  const OUTSIDE = `${PRIVATE}outside`;
  const OWN = `${PRIVATE}own`;

  /* ------------------------------------------------------------------------------------------------
   * Text: cleaning, Calibri metrics, wrapping and fitting
   * ---------------------------------------------------------------------------------------------- */

  // Characters XML 1.0 can't carry and lone surrogates are dropped; any run of whitespace (line
  // breaks included) becomes one space.
  const BAD_CHARS = /[\u{0}-\u{8}\u{B}\u{C}\u{E}-\u{1F}\u{7F}\u{D800}-\u{DFFF}\u{FFFE}\u{FFFF}]/gu;
  function clean(s) {
    if (s == null) return '';
    return String(s).replace(BAD_CHARS, '').replace(/\s+/g, ' ').trim();
  }
  /** A shape name: the object's id, made safe. */
  const nameOf = s => clean(String(s).split(PRIVATE).join(' ')).slice(0, 120);

  // Advance widths of Calibri (Carlito is metric-compatible) in 1/1000 em for U+0020..U+007E.
  const W_REGULAR = [
    226, 326, 401, 498, 507, 715, 682, 221, 303, 303, 498, 498, 250, 306, 252, 386, 507, 507, 507, 507,
    507, 507, 507, 507, 507, 507, 268, 268, 498, 498, 498, 463, 894, 579, 544, 533, 615, 488, 459, 631,
    623, 252, 319, 520, 420, 855, 646, 662, 517, 673, 543, 459, 487, 642, 567, 890, 519, 487, 468, 307,
    386, 307, 498, 498, 291, 479, 525, 423, 525, 498, 305, 471, 525, 229, 239, 455, 229, 799, 525, 527,
    525, 525, 349, 391, 335, 525, 452, 715, 433, 453, 395, 314, 460, 314, 498];
  const W_BOLD = [
    226, 326, 438, 498, 507, 729, 705, 233, 312, 312, 498, 498, 258, 306, 267, 430, 507, 507, 507, 507,
    507, 507, 507, 507, 507, 507, 276, 276, 498, 498, 498, 463, 898, 606, 561, 529, 630, 488, 459, 637,
    631, 267, 331, 547, 423, 874, 659, 676, 532, 686, 563, 473, 495, 653, 591, 906, 551, 520, 478, 325,
    430, 325, 498, 498, 300, 494, 537, 418, 537, 503, 316, 474, 537, 246, 255, 480, 246, 813, 537, 538,
    537, 537, 355, 399, 347, 537, 473, 745, 459, 474, 397, 344, 475, 344, 498];
  const W_OTHER = {
    '–': [498, 498], '—': [905, 905], '·': [252, 268], '…': [690, 711], '→': [905, 905], '‘': [250, 258],
    '’': [250, 258], '“': [418, 435], '”': [418, 435], '§': [498, 498], '•': [498, 498], 'é': [498, 503],
  };
  function charWidth(ch, bold) {
    const c = ch.codePointAt(0);
    if (c >= 32 && c <= 126) return (bold ? W_BOLD : W_REGULAR)[c - 32];
    const o = W_OTHER[ch];
    if (o) return o[bold ? 1 : 0];
    if (c >= 0x1F000) return 1250;        // emoji, drawn by a fallback font
    if (c >= 0x2E80) return 1000;         // CJK and other full-width scripts
    return bold ? 580 : 560;              // anything else: a little wider than average, to be safe
  }
  /** Width of one line of text, in inches. */
  function textWidth(s, pt, bold) {
    let u = 0;
    for (const ch of s) u += charWidth(ch, bold);
    return (u / 1000) * pt / 72;
  }
  /** Height of one line (Calibri's line spacing is 1.22 em), in inches. */
  const lineHeight = (pt, spacing = 1) => (pt * 1.22 * spacing) / 72;

  /** Shortens text to the widest prefix that fits maxW, ending with "…" (always, when forced). */
  function ellipsize(s, maxW, pt, bold, force = false) {
    if (!force && textWidth(s, pt, bold) <= maxW) return s;
    const chars = Array.from(s);
    let lo = 0;
    let hi = chars.length;
    while (lo < hi) {                       // the longest prefix whose "prefix…" fits
      const mid = Math.ceil((lo + hi) / 2);
      if (textWidth(chars.slice(0, mid).join('').trimEnd() + '…', pt, bold) <= maxW) lo = mid;
      else hi = mid - 1;
    }
    return chars.slice(0, lo).join('').trimEnd() + '…';
  }

  // Where a line may break: between words, and after a hyphen inside a word ("supply-" / "chain"),
  // which is how the reference wraps its threat titles.
  function chunks(text) {
    const out = [];
    for (const word of text.split(' ')) {
      if (!word) continue;
      word.split(/(?<=[A-Za-z0-9]-)(?=[A-Za-z])/).forEach((part, i) => out.push({ t: part, space: i === 0 }));
    }
    return out;
  }

  /** Splits a word wider than maxW into pieces that fit. */
  function hardBreak(word, maxW, pt, bold) {
    const out = [];
    let cur = '';
    let w = 0;
    for (const ch of word) {
      const cw = (charWidth(ch, bold) / 1000) * pt / 72;
      if (cur && w + cw > maxW) { out.push(cur); cur = ''; w = 0; }
      cur += ch;
      w += cw;
    }
    if (cur) out.push(cur);
    return out;
  }

  /** Greedy wrap: lines no wider than maxW and no longer than maxChars characters. */
  function wrap(text, maxW, pt, bold, maxChars = Infinity) {
    const lines = [];
    const push = s => {
      if (textWidth(s, pt, bold) > maxW) lines.push(...hardBreak(s, maxW, pt, bold));
      else lines.push(s);
    };
    let cur = '';
    for (const c of chunks(text)) {
      const next = cur ? cur + (c.space ? ' ' : '') + c.t : c.t;
      if (cur && (textWidth(next, pt, bold) > maxW || next.length > maxChars)) {
        push(cur);
        cur = c.t;
      } else {
        cur = next;
      }
    }
    if (cur) push(cur);
    return lines;
  }

  /** Keeps the first `max` lines; the last one kept ends with "…" when lines were dropped. */
  function truncateLines(lines, max, maxW, pt, bold) {
    if (lines.length <= max) return lines;
    const out = lines.slice(0, Math.max(1, max));
    out[out.length - 1] = ellipsize(out[out.length - 1], maxW, pt, bold, true);
    return out;
  }

  /**
   * A label shortened to fit maxW. A list of actors ("APT28 (G0007), APT29 (G0016), …") keeps its
   * first whole entries and counts the rest ("… and 9 more"); anything else is cut with "…".
   */
  function fitList(label, maxW, pt, bold) {
    if (textWidth(label, pt, bold) <= maxW) return label;
    const items = label.split(', ');
    if (items.length > 1 && items.every(t => /\S \([A-Z][\w.]*\d\)$/.test(t))) {
      for (let n = items.length - 1; n >= 1; n--) {
        const t = `${items.slice(0, n).join(', ')} and ${items.length - n} more`;
        if (textWidth(t, pt, bold) <= maxW) return t;
      }
    }
    return ellipsize(label, maxW, pt, bold);
  }

  /** For each word, whether a line break after it would fall inside brackets: "(Gov | Cloud)". */
  function insideBrackets(words) {
    let depth = 0;
    return words.map(w => {
      for (const ch of w) {
        if (ch === '(' || ch === '[') depth++;
        else if ((ch === ')' || ch === ']') && depth > 0) depth--;
      }
      return depth > 0;
    });
  }

  /**
   * Splits words into exactly k lines no wider than maxW: breaking inside brackets as seldom as
   * possible ("(Gov Cloud)" stays whole where it fits a line), then with the widest line as narrow
   * as possible; among equally good splits the earlier lines are the longer, as the reference's
   * wrapped labels read ("(WAF, DDoS," / "API)"). Null when no split fits.
   */
  function balance(words, k, pt, bold, maxW) {
    const n = words.length;
    const sp = textWidth(' ', pt, bold);
    const pre = [0];
    words.forEach((w, i) => pre.push(pre[i] + textWidth(w, pt, bold)));
    const inside = insideBrackets(words);
    const width = (i, j) => pre[j] - pre[i] + sp * (j - i - 1);      // words i..j-1 on one line
    // best[l][j]: [breaks inside brackets, widest line] for the first j words on l lines.
    const none = [Infinity, Infinity];
    const best = Array.from({ length: k + 1 }, () => new Array(n + 1).fill(none));
    const cut = Array.from({ length: k + 1 }, () => new Array(n + 1).fill(0));
    best[0][0] = [0, 0];
    for (let l = 1; l <= k; l++) {
      for (let j = l; j <= n; j++) {
        // Latest line start first, so a tie keeps the later start (the longer earlier lines).
        for (let i = j - 1; i >= l - 1; i--) {
          const w = width(i, j);
          if (w > maxW + 1e-9) break;                       // starting earlier only widens it
          const prev = best[l - 1][i];
          if (prev[0] === Infinity) continue;
          const v = [prev[0] + (j < n && inside[j - 1] ? 1 : 0), Math.max(prev[1], w)];
          const cur = best[l][j];
          if (v[0] < cur[0] || (v[0] === cur[0] && v[1] < cur[1] - 1e-9)) { best[l][j] = v; cut[l][j] = i; }
        }
      }
    }
    if (best[k][n][0] === Infinity) return null;
    const lines = [];
    let j = n;
    for (let l = k; l >= 1; l--) {
      const i = cut[l][j];
      lines.unshift(words.slice(i, j).join(' '));
      j = i;
    }
    return { lines, breaks: best[k][n][0] };
  }

  /** The text rectangle PowerPoint gives an element shape (its preset's text box, less the inset). */
  function textArea(type, f) {
    const s = SIZE[type];
    if (type === 'entity') return { w: s.w * f - 2 * INSET, h: s.h * f - 2 * INSET };
    if (type === 'datastore') {
      // A can's text box starts below its top ellipse: from 2·ss/8 to h − ss/8.
      return { w: s.w * f - 2 * INSET, h: (s.h - (3 * Math.min(s.w, s.h)) / 8) * f - 2 * INSET };
    }
    const d = (type === 'cluster' ? s.w * CLUSTER_INNER : s.w) * f;   // an ellipse's text box is its inscribed square
    return { w: d * Math.SQRT1_2 - 2 * INSET, h: d * Math.SQRT1_2 - 2 * INSET };
  }

  /**
   * The lines and size of an element label. As in the reference, a label of two or more words is
   * set on at least two balanced lines; it gets smaller only when it doesn't fit, and is cut with
   * "…" as a last resort.
   */
  function fitLabel(label, type, f, bold) {
    const base = (type === 'cluster' ? 8.5 : 9) * Math.max(f, 0.6);
    const area = textArea(type, f);
    if (!label || area.w <= 0 || area.h <= 0) return { pt: base, lines: [] };
    const words = label.split(' ');
    // A split into k lines needs the words' total width to fit k lines: checking that first keeps
    // the balancing (quadratic in the words) for labels that can fit at all.
    const unit = textWidth(label, 1, bold);
    const space = textWidth(' ', 1, bold);
    for (let pt = base; pt >= 5 - 1e-9; pt -= 0.5) {
      const maxLines = Math.floor(area.h / lineHeight(pt) + 1e-6);
      // The fewest lines that fit, unless more lines keep a bracketed group whole.
      let pick = null;
      for (let k = Math.min(words.length, 2); k <= Math.min(words.length, maxLines); k++) {
        if ((unit - (k - 1) * space) * pt > k * area.w + 1e-9) continue;
        const b = balance(words, k, pt, bold, area.w);
        if (b && (!pick || b.breaks < pick.breaks)) pick = b;
        if (pick && !pick.breaks) break;
      }
      if (pick) return { pt, lines: pick.lines };
    }
    // Still too long: the smallest size that leaves room for a line, cut with "…".
    const pt = Math.max(2, Math.min(5, (area.h * 72) / 1.22));
    const maxLines = Math.max(1, Math.floor(area.h / lineHeight(pt) + 1e-6));
    return { pt, lines: truncateLines(wrap(label, area.w, pt, bold), maxLines, area.w, pt, bold) };
  }

  // Octagon overlay: the reference sets 9 pt and wraps titles at 14 characters (16 at 8 pt), at most
  // 6 lines at 9 pt (7 at 8 pt), getting smaller when crowded (down to 5 pt before anything is cut).
  // Every line must also sit inside the octagon at its own height, where the cut corners narrow it.
  const OCT_SIZES = [9, 8.5, 8, 7.5, 7, 6.6, 6.2, 5.8, 5.4, 5];
  const OCT_SPACING = 0.92;
  const OCT_EDGE = 0.04;                   // clearance between the text and the octagon's edge

  /** Width of an octagon of size s at height y below its top. */
  function chord(y, s) {
    const c = s * 0.29289;
    if (y < c) return s - 2 * (c - y);
    if (y > s - c) return s - 2 * (y - (s - c));
    return s;
  }
  /** Lines centred vertically in the octagon: their total height and each one's available width. */
  function octagonSlots(lines, s) {
    const heights = lines.map(l => lineHeight(l.pt, OCT_SPACING));
    const total = heights.reduce((a, b) => a + b, 0);
    let y = (s - total) / 2;
    return {
      total,
      widths: heights.map(h => {
        const w = Math.min(chord(y, s), chord(y + h, s)) - 2 * OCT_EDGE * (s / OCT);
        y += h;
        return w;
      }),
    };
  }
  function fitsOctagon(lines, s) {
    const slots = octagonSlots(lines, s);
    if (slots.total > s - 0.12 * (s / OCT)) return false;
    return lines.every((l, i) => textWidth(l.t, l.pt, true) <= slots.widths[i]);
  }

  /** The overlay lines for an octagon: the MAESTRO layer line (AI), then the titles one per line. */
  function fitOctagon(titles, head, s) {
    const k = s / OCT;
    const build = (base, wf) => {
      const pt = base * k;
      const hpt = (base + 0.5) * k;
      const maxChars = Math.floor(126 / base);
      const lines = [];
      if (head) wrap(head, s * wf, hpt, true).forEach(t => lines.push({ t, pt: hpt, head: true }));
      for (const title of titles) wrap(title, s * wf, pt, true, maxChars).forEach(t => lines.push({ t, pt }));
      return lines;
    };
    for (const base of OCT_SIZES) {
      const maxLines = Math.floor(57 / base);
      for (const wf of [0.9, 0.78, 0.66]) {
        const lines = build(base, wf);
        if (lines.length > maxLines) break;          // narrower wrapping only adds lines
        if (fitsOctagon(lines, s)) return lines;
      }
    }
    // Too much for the octagon even at the smallest size: keep the lines that fit, end with "…".
    const base = OCT_SIZES[OCT_SIZES.length - 1];
    const all = build(base, 0.84);
    let n = Math.min(all.length, Math.floor(57 / base));
    while (n > 1 && octagonSlots(all.slice(0, n), s).total > s - 0.12 * k) n--;
    const kept = all.slice(0, n).map(l => Object.assign({}, l));
    const slots = octagonSlots(kept, s);
    kept.forEach((l, i) => {
      const last = i === kept.length - 1 && n < all.length;
      l.t = ellipsize(l.t, slots.widths[i], l.pt, true, last);
    });
    return kept;
  }

  /* ------------------------------------------------------------------------------------------------
   * Geometry helpers
   * ---------------------------------------------------------------------------------------------- */

  const unionRects = rs => {
    const xs = rs.filter(Boolean);
    if (!xs.length) return null;
    const x = Math.min(...xs.map(r => r.x));
    const y = Math.min(...xs.map(r => r.y));
    return { x, y, w: Math.max(...xs.map(r => r.x + r.w)) - x, h: Math.max(...xs.map(r => r.y + r.h)) - y };
  };
  const inflate = (r, d) => ({ x: r.x - d, y: r.y - d, w: r.w + 2 * d, h: r.h + 2 * d });
  const rectsHit = (a, b, m = 0) => a.x < b.x + b.w + m && b.x < a.x + a.w + m && a.y < b.y + b.h + m && b.y < a.y + a.h + m;
  /** The gap between two rectangles (0 when they touch or overlap). */
  const boxGap = (a, b) => Math.hypot(Math.max(0, Math.max(a.x, b.x) - Math.min(a.x + a.w, b.x + b.w)),
    Math.max(0, Math.max(a.y, b.y) - Math.min(a.y + a.h, b.y + b.h)));
  function interArea(a, b) {
    const w = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
    const h = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
    return w > 0 && h > 0 ? w * h : 0;
  }

  // Convex shapes for exact collision tests: { pts } polygon (a segment is a two-point polygon) or
  // { c, r } circle; each carries its bounding box, and polygons their separating axes.
  const SQ = Math.SQRT1_2;
  const BOX_AXES = [[0, 1], [1, 0]];
  const OCT_AXES = [[0, 1], [1, 0], [SQ, SQ], [SQ, -SQ]];
  const boxShape = r => ({ pts: [[r.x, r.y], [r.x + r.w, r.y], [r.x + r.w, r.y + r.h], [r.x, r.y + r.h]], box: r, axes: BOX_AXES });
  const circleShape = (cx, cy, r) => ({ c: [cx, cy], r, box: { x: cx - r, y: cy - r, w: 2 * r, h: 2 * r } });
  function octagonShape(x, y, s) {
    const c = s * 0.29289;
    return {
      pts: [[x + c, y], [x + s - c, y], [x + s, y + c], [x + s, y + s - c], [x + s - c, y + s], [x + c, y + s],
        [x, y + s - c], [x, y + c]],
      box: { x, y, w: s, h: s },
      axes: OCT_AXES,
      octAt: { x, y, s },
    };
  }
  function segmentShape(a, b) {
    return {
      pts: [a, b],
      box: { x: Math.min(a[0], b[0]), y: Math.min(a[1], b[1]), w: Math.abs(b[0] - a[0]), h: Math.abs(b[1] - a[1]) },
    };
  }
  /** A polygon's distinct edge normals (parallel edges share one), computed once per shape. */
  function axesOf(shape) {
    if (shape.axes) return shape.axes;
    const pts = shape.pts;
    const out = [];
    for (let i = 0; i < pts.length; i++) {
      const [x1, y1] = pts[i];
      const [x2, y2] = pts[(i + 1) % pts.length];
      const l = Math.hypot(x2 - x1, y2 - y1);
      if (l < 1e-12) continue;
      let ax = -(y2 - y1) / l;
      let ay = (x2 - x1) / l;
      if (ax < -1e-12 || (Math.abs(ax) <= 1e-12 && ay < 0)) { ax = -ax; ay = -ay; }
      if (!out.some(([u, v]) => Math.abs(u - ax) < 1e-9 && Math.abs(v - ay) < 1e-9)) out.push([ax, ay]);
    }
    shape.axes = out;
    return out;
  }
  function project(s, ax, ay) {
    if (s.r != null) {
      const p = s.c[0] * ax + s.c[1] * ay;
      return [p - s.r, p + s.r];
    }
    let lo = Infinity;
    let hi = -Infinity;
    for (const [x, y] of s.pts) {
      const p = x * ax + y * ay;
      if (p < lo) lo = p;
      if (p > hi) hi = p;
    }
    return [lo, hi];
  }
  /** True when two convex shapes are closer than margin (separating-axis test). */
  function collide(a, b, margin = 0) {
    if (!rectsHit(a.box, b.box, margin)) return false;
    if (a.r != null && b.r != null) return Math.hypot(a.c[0] - b.c[0], a.c[1] - b.c[1]) < a.r + b.r + margin;
    // A box and a segment: past their bounding boxes, only the segment's normal can part them.
    const seg = a.pts && a.pts.length === 2 ? a : b.pts && b.pts.length === 2 ? b : null;
    const other = seg === a ? b : a;
    if (seg && other.axes === BOX_AXES) {
      const [p, q] = seg.pts;
      const nx = p[1] - q[1];
      const ny = q[0] - p[0];
      const l = Math.hypot(nx, ny);
      if (l < 1e-12) return true;
      const r = other.box;
      const half = (Math.abs(nx) * r.w + Math.abs(ny) * r.h) / (2 * l);
      return Math.abs((p[0] - r.x - r.w / 2) * nx + (p[1] - r.y - r.h / 2) * ny) / l < half + margin;
    }
    // A shape with a simple body inside it (a cylinder's): touching the body is touching the shape.
    if ((b.core && collide(a, b.core, margin)) || (a.core && collide(a.core, b, margin))) return true;
    if (a.axes === BOX_AXES && b.axes === BOX_AXES) return true;     // their axes are the bounding boxes'
    if (a.r != null) [a, b] = [b, a];
    const apart = ([a0, a1], [b0, b1]) => a1 + margin <= b0 || b1 + margin <= a0;
    if (axesOf(a).some(([ax, ay], i) => apart(ownProjection(a, i), project(b, ax, ay)))) return false;
    if (b.r != null) {
      let best = null;
      let bd = Infinity;
      for (const p of a.pts) {
        const d = Math.hypot(p[0] - b.c[0], p[1] - b.c[1]);
        if (d < bd) { bd = d; best = p; }
      }
      if (bd <= 1e-12) return true;
      const ax = (best[0] - b.c[0]) / bd;
      const ay = (best[1] - b.c[1]) / bd;
      return !apart(project(a, ax, ay), project(b, ax, ay));
    }
    return !axesOf(b).some(([ax, ay], i) => apart(project(a, ax, ay), ownProjection(b, i)));
  }
  /** A shape's extent along its own i-th axis (kept on the shape: elements are tested many times). */
  function ownProjection(sh, i) {
    const cache = sh.proj || (sh.proj = []);
    if (!cache[i]) {
      const [ax, ay] = axesOf(sh)[i];
      cache[i] = project(sh, ax, ay);
    }
    return cache[i];
  }
  /** An octagon grown by m all round (the same shape: its sides all move out by m). */
  const grown = (o, m) => octagonShape(o.octAt.x - m, o.octAt.y - m, o.octAt.s + 2 * m);
  // How far a flow line keeps from an octagon's edge, so it doesn't seem to touch it.
  const CLEAR = 0.05;
  /**
   * collide() for an octagon at (x, y) of size s and any shape, worked out directly on the octagon's
   * own axes (the octagon search makes many of these): exact for boxes and octagons; for other
   * shapes a quick answer when it is clear, else collide().
   */
  function octagonHits(x, y, s, sh, m) {
    const b = sh.box;
    if (!(b.x < x + s + m && x < b.x + b.w + m && b.y < y + s + m && y < b.y + b.h + m)) return false;
    const c = s * 0.29289;
    const d = m * Math.SQRT2;
    if (sh.octAt) {
      const o = sh.octAt;
      const c2 = o.s * 0.29289;
      return !(x + y + 2 * s - c + d <= o.x + o.y + c2 || o.x + o.y + 2 * o.s - c2 + d <= x + y + c
        || x - y + s - c + d <= o.x - o.y - o.s + c2 || o.x - o.y + o.s - c2 + d <= x - y - s + c);
    }
    if (sh.pts && sh.pts.length === 2) {
      // A segment: the diagonal axes on its ends, then its normal (the octagon's half-width across it).
      const [p, q] = sh.pts;
      const s1 = p[0] + p[1];
      const s2 = q[0] + q[1];
      const d1 = p[0] - p[1];
      const d2 = q[0] - q[1];
      if (Math.max(s1, s2) + d <= x + y + c || x + y + 2 * s - c + d <= Math.min(s1, s2)
        || Math.max(d1, d2) + d <= x - y - s + c || x - y + s - c + d <= Math.min(d1, d2)) return false;
      const nx = p[1] - q[1];
      const ny = q[0] - p[0];
      const l = Math.hypot(nx, ny);
      if (l < 1e-12) return true;
      const ax = Math.abs(nx) / l;
      const ay = Math.abs(ny) / l;
      const half = Math.max(ax * (s / 2 - c) + ay * (s / 2), ax * (s / 2) + ay * (s / 2 - c));
      return Math.abs((p[0] - x - s / 2) * nx + (p[1] - y - s / 2) * ny) / l < half + m;
    }
    // The diagonal axes against the shape's bounding box: apart there means apart.
    if (b.x + b.w + b.y + b.h + d <= x + y + c || x + y + 2 * s - c + d <= b.x + b.y
      || b.x + b.w - b.y + d <= x - y - s + c || x - y + s - c + d <= b.x - b.y - b.h) return false;
    if (sh.axes === BOX_AXES) return true;      // a box has no other axes
    if (sh.core && octagonHits(x, y, s, sh.core, m)) return true;
    return collide(octagonShape(x, y, s), sh, m);
  }
  const onSlide = r => r.x >= 0.05 - 1e-6 && r.y >= AREA.t - 0.02 && r.x + r.w <= SLIDE_W - 0.04 && r.y + r.h <= SLIDE_H - 0.05;

  /* ------------------------------------------------------------------------------------------------
   * The result, normalised: everything a slide needs, with nothing missing or malformed
   * ---------------------------------------------------------------------------------------------- */

  const list = v => (Array.isArray(v) ? v.filter(x => x && typeof x === 'object') : []);
  const finite = v => v !== null && v !== '' && v !== undefined && typeof v !== 'boolean' && Number.isFinite(Number(v));
  function geometryOf(g) {
    if (!g || typeof g !== 'object' || !['x', 'y', 'w', 'h'].every(k => finite(g[k]))) return null;
    const r = { x: Number(g.x), y: Number(g.y), w: Number(g.w), h: Number(g.h) };
    return r.w >= 0 && r.h >= 0 ? r : null;
  }
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  function prepare(result) {
    const r = result && typeof result === 'object' ? result : {};
    const m = r.model && typeof r.model === 'object' ? r.model : {};

    const zones = [];
    const zoneById = new Map();
    for (const z of list(m.zones)) {
      if (z.id == null || zoneById.has(String(z.id))) continue;
      const zone = { id: String(z.id), label: clean(z.label), parent: z.parent == null ? null : String(z.parent),
        geometry: geometryOf(z.geometry), index: zones.length };
      zones.push(zone);
      zoneById.set(zone.id, zone);
    }
    // Parents must exist and must not loop.
    for (const z of zones) if (z.parent && !zoneById.has(z.parent)) z.parent = null;
    for (const z of zones) {
      const seen = new Set([z.id]);
      for (let p = z.parent; p; p = zoneById.get(p).parent) {
        if (seen.has(p)) { z.parent = null; break; }
        seen.add(p);
      }
    }

    const elements = [];
    const elementById = new Map();
    for (const e of list(m.elements)) {
      if (e.id == null || elementById.has(String(e.id))) continue;
      const el = {
        id: String(e.id), label: clean(e.label), type: TYPES.includes(e.type) ? e.type : 'process',
        zone: e.zone != null && zoneById.has(String(e.zone)) ? String(e.zone) : null,
        geometry: geometryOf(e.geometry), crown: e.crownJewel === true, index: elements.length,
      };
      elements.push(el);
      elementById.set(el.id, el);
    }

    const flows = list(m.flows)
      .filter(f => elementById.has(String(f.source)) && elementById.has(String(f.target)))
      .map((f, i) => ({ id: f.id == null ? `flow ${i + 1}` : String(f.id), source: String(f.source),
        target: String(f.target), label: clean(f.label), both: f.bidirectional === true }));

    const events = list(r.events);
    const eventBySn = new Map(events.map(e => [String(e.sn), e]));
    const locations = list(r.locations)
      .filter(l => elementById.has(String(l.element)) && finite(l.dfd))
      .map(l => {
        let titles = (Array.isArray(l.titles) ? l.titles : []).map(clean).filter(Boolean);
        if (!titles.length && Array.isArray(l.events)) {
          titles = l.events.map(sn => eventBySn.get(String(sn))).filter(Boolean).map(e => clean(e.title)).filter(Boolean);
        }
        return { dfd: clean(l.dfd), num: Number(l.dfd), element: String(l.element), ai: l.ai === true,
          titles, layers: clean(l.layers) };
      })
      .sort((a, b) => (a.ai ? 1 : 0) - (b.ai ? 1 : 0) || a.num - b.num);
    // Each location gets an octagon slot: an element's first location in a pass shares one slot
    // across the passes (same place on every figure); a second one in the same pass gets its own.
    for (const pass of [false, true]) {
      const n = new Map();
      for (const l of locations.filter(x => x.ai === pass)) {
        const j = n.get(l.element) || 0;
        n.set(l.element, j + 1);
        l.slot = `${l.element}\u0000${j}`;
      }
    }
    const sequences = list(r.sequences).map(s => ({
      id: clean(s.id), ai: s.ai === true, title: clean(s.title), entry: clean(s.entry), actor: clean(s.actor),
      steps: (Array.isArray(s.steps) ? s.steps : []).map(clean).filter(Boolean),
      path: (Array.isArray(s.path) ? s.path : []).filter(p => p != null).map(p => String(p)),
      narrative: clean(s.narrative), layers: clean(s.layers),
    }));

    const profile = r.profile && typeof r.profile === 'object' ? r.profile : {};
    const atkEvents = events.filter(e => e.ai !== true);
    const aiEvents = events.filter(e => e.ai === true);
    const bySeverity = (xs, s) => xs.filter(e => e.severity === s).length;
    const st = r.stats && typeof r.stats === 'object' ? r.stats : {};
    const pick = (v, d) => (finite(v) ? Number(v) : d);
    const stats = {
      elements: pick(st.elements, elements.length),
      flows: pick(st.flows, flows.length),
      zones: pick(st.zones, zones.filter(z => !zones.some(c => c.parent === z.id)).length),
      events: pick(st.events, atkEvents.length),
      high: pick(st.high, bySeverity(atkEvents, 'High')),
      medium: pick(st.medium, bySeverity(atkEvents, 'Medium')),
      low: pick(st.low, bySeverity(atkEvents, 'Low')),
      aiEvents: pick(st.aiEvents, aiEvents.length),
      aiHigh: pick(st.aiHigh, bySeverity(aiEvents, 'High')),
      aiMedium: pick(st.aiMedium, bySeverity(aiEvents, 'Medium')),
      aiLow: pick(st.aiLow, bySeverity(aiEvents, 'Low')),
      aiLocations: pick(st.aiLocations, new Set(locations.filter(l => l.ai).map(l => l.element)).size),
    };

    return {
      system: clean(r.system) || clean(m.name),
      // A profile with no actors is the engine's generic attacker (no threat profile was built).
      profile: { label: clean(profile.label), short: clean(profile.short) || clean(profile.label),
        generic: Array.isArray(profile.actors) && profile.actors.length === 0,
        actors: list(profile.actors).map(a => ({ id: clean(a.attackId), name: clean(a.name) })).filter(a => a.id || a.name) },
      knowledge: list(profile.knowledge).map(k => ({ domain: clean(k.domain), name: clean(k.name), version: clean(k.version) })),
      zones, zoneById, elements, elementById, flows, locations, sequences, stats,
      hasGeometry: elements.length > 0 && elements.every(e => e.geometry),
      hasZones: zones.length > 0,
    };
  }
  /** Whether `text` names `token` as a whole word or ID ("G0016" in "APT29 (G0016)", not in "G00160"). */
  function mentions(text, token) {
    if (!token) return false;
    const t = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(?:^|[^\\p{L}\\p{N}_.])${t}(?![\\p{L}\\p{N}_.])`, 'u').test(text);
  }
  /**
   * Whom an ATT&CK attack sequence's figure names: the profile's actors its threat actor names (the engine
   * writes them "Name (ID), …"), written as the profile label writes them, with a short form for a long title.
   * The whole profile when it names all or none of them; null for a generic attacker.
   */
  function sequenceActors(D, seq) {
    if (D.profile.generic) return null;
    const named = D.profile.actors.filter(a => (a.id ? mentions(seq.actor, a.id) : mentions(seq.actor, a.name)));
    if (!named.length || named.length === D.profile.actors.length) return { label: D.profile.label, short: D.profile.short };
    const names = named.map(a => a.name || a.id);
    return {
      label: named.map(a => (a.name && a.id ? `${a.name} (${a.id})` : a.name || a.id)).join(', '),
      short: names.length === 1 ? names[0] : names.length === 2 ? names.join(' and ') : `${names[0]} +${names.length - 1}`,
    };
  }
  const ancestorsOf = (D, z) => {
    const out = [];
    for (let p = z.parent; p && out.length < 50; p = D.zoneById.get(p).parent) out.push(p);
    return out;
  };

  /* ------------------------------------------------------------------------------------------------
   * Layout: element boxes, zone rectangles, and whether the zones tile the diagram
   * ---------------------------------------------------------------------------------------------- */

  /** An element drawn at its (scaled) standard size, centred on (cx, cy). */
  function elementBox(e, cx, cy, f) {
    const s = SIZE[e.type];
    const w = s.w * f;
    const h = s.h * f;
    const box = { id: e.id, el: e, type: e.type, x: cx - w / 2, y: cy - h / 2, w, h, cx, cy };
    box.shape = e.type === 'process' || e.type === 'cluster' ? circleShape(cx, cy, w / 2)
      : e.type === 'datastore' ? canShape(box) : boxShape(box);
    box.star = e.crown ? starBox(box, f) : null;
    return box;
  }
  /** A cylinder's outline: PowerPoint's can is a rectangle between two half-ellipses of height ss/4. */
  function canShape(b) {
    const ry = Math.min(b.w, b.h) / 8;
    const rx = b.w / 2;
    const pts = [];
    for (let i = 0; i <= 8; i++) {
      const a = Math.PI + (Math.PI * i) / 8;
      pts.push([b.cx + rx * Math.cos(a), b.y + ry + ry * Math.sin(a)]);
    }
    for (let i = 0; i <= 8; i++) {
      const a = (Math.PI * i) / 8;
      pts.push([b.cx + rx * Math.cos(a), b.y + b.h - ry + ry * Math.sin(a)]);
    }
    // Its body between the two ends, for quick tests.
    return { pts, box: { x: b.x, y: b.y, w: b.w, h: b.h }, core: boxShape({ x: b.x, y: b.y + ry, w: b.w, h: b.h - 2 * ry }) };
  }
  /** Crown jewel: on the top of a cylinder or rectangle, on the upper-left rim of a circle (reference). */
  function starBox(b, f) {
    const k = Math.max(f, 0.7);
    const w = STAR.w * k;
    const h = STAR.h * k;
    if (b.type === 'datastore') return { x: b.x + b.w * 0.703, y: b.y + 0.015 * f, w, h };
    if (b.type === 'entity') return { x: b.x + b.w * 0.72, y: b.y - h / 2, w, h };
    const r = b.w / 2;
    return { x: b.cx - r * 0.67 - w / 2, y: b.cy - r * 0.72 - h / 2, w, h };
  }

  /** How much element sizes must shrink so that no two elements overlap (1 = standard size). */
  function shrinkFactor(centres) {
    let f = 1;
    const gap = 0.12;
    for (let i = 0; i < centres.length; i++) {
      for (let j = i + 1; j < centres.length; j++) {
        const a = centres[i];
        const b = centres[j];
        const sa = SIZE[a.type];
        const sb = SIZE[b.type];
        const need = Math.max((Math.abs(b.cx - a.cx) - gap) / ((sa.w + sb.w) / 2),
          (Math.abs(b.cy - a.cy) - gap) / ((sa.h + sb.h) / 2));
        if (need < f) f = need;
      }
    }
    return Math.max(0.45, Math.min(1, f));
  }

  /**
   * Zones tile the diagram when every element is in a leaf zone, the leaf zones don't overlap and
   * each one touches another, all connected. Then the edges they share are the trust boundaries.
   */
  function tiles(zones, boxes) {
    const leaves = zones.filter(z => z.leaf);
    if (leaves.length < 2) return false;
    const leafIds = new Set(leaves.map(z => z.id));
    if ([...boxes.values()].some(b => !leafIds.has(b.zoneId))) return false;
    for (let i = 0; i < leaves.length; i++) {
      for (let j = i + 1; j < leaves.length; j++) {
        const a = leaves[i].rect;
        const b = leaves[j].rect;
        if (interArea(a, b) > 0.05 * Math.min(a.w * a.h, b.w * b.h)) return false;
      }
    }
    return groupsOf(leaves).length === 1;
  }
  /** Zones that share an edge (within TILE_TOL). */
  function adjacent(A, B) {
    const yOver = Math.min(A.y + A.h, B.y + B.h) - Math.max(A.y, B.y);
    const xOver = Math.min(A.x + A.w, B.x + B.w) - Math.max(A.x, B.x);
    return (yOver > 0.2 && (Math.abs(A.x + A.w - B.x) <= TILE_TOL || Math.abs(B.x + B.w - A.x) <= TILE_TOL))
      || (xOver > 0.2 && (Math.abs(A.y + A.h - B.y) <= TILE_TOL || Math.abs(B.y + B.h - A.y) <= TILE_TOL));
  }
  /** Zones grouped by shared edges (connected components), in the zones' order. */
  function groupsOf(zones) {
    const seen = new Set();
    const groups = [];
    for (const start of zones) {
      if (seen.has(start)) continue;
      seen.add(start);
      const group = [start];
      for (let i = 0; i < group.length; i++) {
        for (const o of zones) if (!seen.has(o) && adjacent(group[i].rect, o.rect)) { seen.add(o); group.push(o); }
      }
      groups.push(group);
    }
    return groups;
  }

  /** Layout that keeps the decomposition's own geometry. */
  function layoutFromGeometry(D) {
    // Source-space rectangles: zones as given, or around their members when they have none.
    const src = new Map();
    for (const z of D.zones) if (z.geometry) src.set(z.id, z.geometry);
    const pad = (D.elements.reduce((a, e) => a + e.geometry.h, 0) / D.elements.length || 60) * 0.5;
    const deepestFirst = [...D.zones].sort((a, b) => ancestorsOf(D, b).length - ancestorsOf(D, a).length);
    for (const z of deepestFirst) {
      if (src.has(z.id)) continue;
      const parts = D.elements.filter(e => e.zone === z.id).map(e => inflate(e.geometry, pad))
        .concat(D.zones.filter(c => c.parent === z.id && src.has(c.id)).map(c => inflate(src.get(c.id), pad / 2)));
      const u = unionRects(parts);
      if (u) src.set(z.id, u);
    }
    const scaleFor = (bb, area) => {
      const s = Math.min(bb.w > 1e-9 ? (area.r - area.l) / bb.w : Infinity, bb.h > 1e-9 ? (area.b - area.t) / bb.h : Infinity);
      return Number.isFinite(s) ? s : 1;
    };
    // Zones leave room around their elements; an element outside every zone gets room for its
    // drawn size and an octagon at its upper right (the room depends on the scale, so iterate).
    const loose = D.elements.filter(e => !e.zone);
    const extent = area => {
      let bb = unionRects([...src.values(), ...D.elements.map(e => e.geometry)]);
      for (let i = 0; i < 4 && loose.length; i++) {
        const s = scaleFor(bb, area);
        bb = unionRects([...src.values(), ...D.elements.map(e => e.geometry), ...loose.map(e => {
          const g = e.geometry;
          const hw = SIZE[e.type].w / 2;
          const hh = SIZE[e.type].h / 2;
          return { x: g.x + g.w / 2 - (hw + 0.3) / s, y: g.y + g.h / 2 - (hh + 0.75) / s,
            w: (2 * hw + 1.75) / s, h: (2 * hh + 1.05) / s };
        })]);
      }
      return bb;
    };

    // The diagram at scale s (the largest that fits the area when not given), centred across the
    // area with its top at the area's top, then moved down by dy.
    const fit = (area, sGiven, dy = 0) => {
      const bb = extent(area);
      const aw = area.r - area.l;
      const ah = area.b - area.t;
      const s = sGiven || scaleFor(bb, area);
      const ox = area.l + (aw - bb.w * s) / 2 - bb.x * s;
      const oy = (bb.h > 1e-9 ? area.t : area.t + ah / 2) - bb.y * s + dy;
      const centres = D.elements.map(e => ({ e, type: e.type, cx: ox + (e.geometry.x + e.geometry.w / 2) * s,
        cy: oy + (e.geometry.y + e.geometry.h / 2) * s }));
      const f = shrinkFactor(centres);
      const boxes = new Map(centres.map(c => [c.e.id, elementBox(c.e, c.cx, c.cy, f)]));
      for (const b of boxes.values()) b.zoneId = b.el.zone;
      const rects = new Map([...src].map(([id, g]) => [id, { x: ox + g.x * s, y: oy + g.y * s, w: g.w * s, h: g.h * s }]));
      return { f, boxes, rects, s, bottom: oy + (bb.y + bb.h) * s };
    };
    const zonesOf = T => {
      const zones = [];
      for (const z of D.zones) {
        const rect = T.rects.get(z.id);
        if (rect) zones.push({ id: z.id, name: z.id, label: z.label, parent: z.parent, rect });
      }
      for (const z of zones) {
        z.leaf = !zones.some(c => c.parent === z.id);
        z.depth = ancestorsOf(D, D.zoneById.get(z.id)).length;
      }
      return zones;
    };

    // Keep the legend clear of what is drawn: elements, crown jewels and parent-zone labels must not
    // go under it, and a trust boundary, as it will be drawn (bow included), may only graze its
    // bottom edge. Returns how far the diagram must move down to clear the legend (0 when clear).
    const overLegend = r => ({ x: Math.min(r.x + r.w, LEGEND.x + LEGEND.w) - Math.max(r.x, LEGEND.x),
      y: Math.min(r.y + r.h, LEGEND_BOTTOM) - Math.max(r.y, LEGEND.y) });
    const legendNeed = T => {
      let need = 0;
      const solid = r => {
        const o = overLegend(r);
        if (o.x > 0.02 && o.y > -0.08) need = Math.max(need, LEGEND_BOTTOM + 0.08 - r.y);
      };
      for (const b of T.boxes.values()) {
        solid(b);
        if (b.star) solid(b.star);
      }
      for (const z of D.zones) {
        const r = T.rects.get(z.id);
        if (r && z.label && D.zones.some(c => c.parent === z.id)) {
          solid({ x: r.x + 0.1, y: r.y + 0.1, w: textWidth(z.label, 10.5, true) + 0.08, h: lineHeight(10.5) + 0.02 });
        }
      }
      const zones = zonesOf(T);
      for (const bd of boundaryShapes({ zones, boxes: T.boxes, tiled: tiles(zones, T.boxes) }, null)) {
        need = Math.max(need, LEGEND_BOTTOM - LEGEND_GRAZE - highestWithin(boundaryInk(bd), LEGEND.x, LEGEND.x + LEGEND.w));
      }
      return need;
    };
    let L = fit(AREA);
    if (legendNeed(L) > 0) {
      // A sliver: move the diagram down. More: the largest scale at which the diagram, moved down
      // as far as it must, still fits; and failing that, the whole diagram below the legend.
      let found = null;
      for (let s = L.s; !found && s > 0.3 * L.s; s *= 0.98) {
        const T = fit(AREA, s);
        const d = legendNeed(T);
        if (T.bottom + d <= AREA.b + 1e-6) found = d > 0 ? fit(AREA, s, d) : T;
      }
      const below = fit(Object.assign({}, AREA, { t: LEGEND_BOTTOM + 0.15 }));
      L = found && found.s >= below.s ? found : below;
    }

    const zones = zonesOf(L);
    return { f: L.f, boxes: L.boxes, zones, tiled: tiles(zones, L.boxes) };
  }

  /* --------------------------------------------------------------- automatic layout (no geometry) */

  // Rows of trust zones, as in the reference figure: untrusted on top, internal in the middle,
  // infrastructure at the bottom.
  const anyWord = list => new RegExp(`\\b(${list.join('|')})\\b`, 'i');
  const TOP_WORDS = anyWord(['internet', 'external', 'public', 'untrusted', 'dmz', 'demilitari[sz]ed', 'perimeter',
    'partners?', 'third[- ]part(y|ies)', 'vendors?', 'suppliers?', 'customers?', 'users?', 'remote', 'guests?', 'outside', 'wan']);
  const MIDDLE_WORDS = anyWord(['internal', 'trusted', 'corporate', 'enterprise', 'private', 'intranet', 'business', 'application']);
  const BOTTOM_WORDS = anyWord(['infrastructure', 'infra', 'network', 'platform', 'hosting', 'data ?cent(er|re)s?',
    'datacent(er|re)s?', 'hypervisors?', 'virtuali[sz]ation', 'compute', 'hardware', 'physical', 'facilit(y|ies)', 'storage',
    'substrate', 'underlay', 'backbone', 'iaas']);
  function rowOf(label) {
    if (TOP_WORDS.test(label)) return 0;
    if (MIDDLE_WORDS.test(label)) return 1;
    if (BOTTOM_WORDS.test(label)) return 2;
    return 1;
  }

  /** Longest-path rank of each element along the flows (cycles broken), so flows run left to right. */
  function flowRanks(D) {
    const adj = new Map(D.elements.map(e => [e.id, []]));
    for (const f of D.flows) if (f.source !== f.target) adj.get(f.source).push(f.target);
    const state = new Map();
    const post = [];
    const back = new Set();
    for (const e of D.elements) {
      if (state.get(e.id)) continue;
      state.set(e.id, 1);
      const stack = [[e.id, 0]];
      while (stack.length) {
        const top = stack[stack.length - 1];
        const next = adj.get(top[0]);
        if (top[1] < next.length) {
          const v = next[top[1]++];
          const sv = state.get(v) || 0;
          if (sv === 0) { state.set(v, 1); stack.push([v, 0]); } else if (sv === 1) back.add(top[0] + '\u0000' + v);
        } else {
          state.set(top[0], 2);
          post.push(top[0]);
          stack.pop();
        }
      }
    }
    const rank = new Map(D.elements.map(e => [e.id, 0]));
    for (const u of post.reverse()) {
      for (const v of adj.get(u)) {
        if (!back.has(u + '\u0000' + v)) rank.set(v, Math.max(rank.get(v), rank.get(u) + 1));
      }
    }
    return rank;
  }

  const AUTO = {
    cellOct: 3.0,       // column width for an element with a threat octagon beside it
    cellPlain: 1.75,    // … and for one without
    pitch: 1.75,        // vertical distance between element rows
    top: 1.3,           // block top to the first element centre (room for the octagon above right)
    bottom: 1.1,        // last element centre to the block bottom (room for the zone label)
    parentLabel: 0.32,  // extra room under a parent zone's label
    padX: 0.15,
    gapX: 0.04,         // between neighbouring zones
    gapY: 0.1,          // between rows of zones
  };

  /** Layout for a decomposition without geometry: rows of zones, elements in a grid in each zone. */
  function layoutAuto(D, withOctagon) {
    const rank = flowRanks(D);
    const meanRank = els => (els.length ? els.reduce((a, e) => a + rank.get(e.id), 0) / els.length : 0);
    const rootOf = z => {
      const a = ancestorsOf(D, z);
      return a.length ? D.zoneById.get(a[a.length - 1]) : z;
    };

    // Blocks: one per zone with elements of its own, plus one for elements outside every zone.
    const blocks = [];
    for (const z of D.zones) {
      const members = D.elements.filter(e => e.zone === z.id);
      if (members.length) blocks.push({ zone: z, root: rootOf(z), members, label: z.label });
    }
    const outside = D.elements.filter(e => !e.zone);
    if (outside.length) blocks.push({ zone: null, root: null, members: outside, label: D.hasZones ? 'Outside defined zones' : '' });
    for (const b of blocks) {
      b.members.sort((x, y) => rank.get(x.id) - rank.get(y.id) || x.index - y.index);
      b.rank = meanRank(b.members);
    }

    // Groups (a top-level zone with everything inside it) go to a row by the top-level zone's label.
    const groups = new Map();
    for (const b of blocks) {
      const key = b.root ? b.root.id : OUTSIDE;
      if (!groups.has(key)) {
        groups.set(key, { root: b.root, blocks: [], row: b.root ? rowOf(b.root.label || b.label) : 0,
          index: b.root ? b.root.index : -1 });
      }
      groups.get(key).blocks.push(b);
      b.group = groups.get(key);
    }
    for (const g of groups.values()) {
      g.blocks.sort((x, y) => x.rank - y.rank || (x.zone ? x.zone.index : -1) - (y.zone ? y.zone.index : -1));
      g.rank = meanRank(g.blocks.flatMap(b => b.members));
    }
    const order = (a, b) => (a.root ? 1 : 0) - (b.root ? 1 : 0) || a.rank - b.rank || a.index - b.index;
    let rows = [0, 1, 2].map(r => [...groups.values()].filter(g => g.row === r).sort(order));

    // Natural (unscaled) block sizes for a number of columns (members fill down, then right).
    const cellW = e => (withOctagon.has(e.id) ? AUTO.cellOct : AUTO.cellPlain);
    const shape = (b, cols) => {
      b.cols = Math.max(1, Math.min(cols, b.members.length));
      b.rows = Math.ceil(b.members.length / b.cols);
      b.cols = Math.ceil(b.members.length / b.rows);
      b.colW = [];
      b.members.forEach((e, i) => {
        const c = Math.floor(i / b.rows);
        b.colW[c] = Math.max(b.colW[c] || 0, cellW(e));
      });
      b.w = b.colW.reduce((a, w) => a + w, 0) + 2 * AUTO.padX;
      // A parent zone's label sits over the group's first block, which leaves room for it.
      b.under = b.group.blocks[0] === b && !!(b.root && b.root.label && b.zone !== b.root);
      b.h = AUTO.top + AUTO.pitch * (b.rows - 1) + AUTO.bottom + (b.under ? AUTO.parentLabel : 0);
    };
    const rowBlocks = row => row.flatMap(g => g.blocks);
    const rowW = row => rowBlocks(row).reduce((a, b) => a + b.w, 0) + AUTO.gapX * Math.max(0, rowBlocks(row).length - 1);
    const rowH = row => Math.max(0, ...rowBlocks(row).map(b => b.h));
    const fullW = AREA.r - AREA.l;
    const besideW = LEGEND.x - 0.25 - AREA.l;            // the first row may sit left of the legend

    // Top and bottom rows lie flat (one element row per zone); the middle row stands (one column).
    rows.forEach((row, r) => rowBlocks(row).forEach(b => shape(b, r === 1 ? 1 : b.members.length)));
    // Untrusted zones that don't fit beside the legend move, most downstream first, to the end of the
    // middle row (as "External – Third Parties" does in the reference).
    while (rows[0].length > 1 && rowW(rows[0]) > besideW) {
      const g = rows[0].pop();
      g.blocks.forEach(b => shape(b, 1));
      rows[1].push(g);
    }
    rows = rows.filter(row => row.length);
    // A row too wide even with every zone narrowed to one column is split in two.
    for (let i = 0; i < rows.length; i++) {
      if (rowW(rows[i]) <= fullW) continue;
      rowBlocks(rows[i]).forEach(b => shape(b, 1));
      if (rowW(rows[i]) > fullW && rows[i].length > 1) {
        const half = Math.ceil(rows[i].length / 2);
        rows.splice(i + 1, 0, rows[i].slice(half));
        rows[i] = rows[i].slice(0, half);
        i--;
      }
    }

    // The scale the diagram needs to fit; zones then take the columns that let it be largest.
    const beside = () => rows.length > 0 && rowW(rows[0]) <= besideW;
    const topY = () => (beside() ? AREA.t : LEGEND_BOTTOM + 0.15);
    const totalH = () => rows.reduce((a, row) => a + rowH(row), 0) + AUTO.gapY * Math.max(0, rows.length - 1);
    const scale = () => {
      let f = Math.min(1, (AREA.b - topY()) / Math.max(totalH(), 1e-9),
        ...rows.map((row, i) => (i === 0 && beside() ? besideW : fullW) / Math.max(rowW(row), 1e-9)));
      // Beside the legend, the rows after the first must still fit below it.
      if (beside() && rows.length > 1) {
        f = Math.min(f, (AREA.b - LEGEND_BOTTOM - 0.1) / Math.max(totalH() - rowH(rows[0]) - AUTO.gapY, 1e-9));
      }
      return f;
    };
    for (let guard = 0; guard < 400; guard++) {
      const now = scale();
      let best = null;
      for (const b of rows.flatMap(rowBlocks)) {
        for (const d of [1, -1]) {
          const save = b.cols;
          if (save + d < 1 || save + d > b.members.length) continue;
          shape(b, save + d);
          if (b.cols !== save) {
            const s = scale();
            if (s > now + 1e-6 && (!best || s > best.s)) best = { b, cols: b.cols, s };
          }
          shape(b, save);
        }
      }
      if (!best) break;
      shape(best.b, best.cols);
    }

    // Place: rows fill the height (up to 30% more than they need), zones fill each row's width.
    const arrange = () => {
      rows.forEach(row => rowBlocks(row).forEach(b => shape(b, b.cols)));
      const f = scale();
      const top = topY();
      // A first row beside the legend is at least as tall as the legend, so the next row clears it.
      const heights = rows.map((row, i) => Math.max(rowH(row) * f, i === 0 && beside() ? LEGEND_BOTTOM + 0.06 - AREA.t : 0));
      const used = heights.reduce((a, h) => a + h, 0) + AUTO.gapY * f * Math.max(0, rows.length - 1);
      const grow = Math.min(0.3, Math.max(0, AREA.b - top - used) / Math.max(used, 1e-9));
      const boxes = new Map();
      let y = top;
      rows.forEach((row, i) => {
        const h = heights[i] * (1 + grow);
        const width = i === 0 && beside() ? besideW : fullW;
        const bs = rowBlocks(row);
        const natural = bs.reduce((a, b) => a + b.w * f, 0);
        const stretch = (width - AUTO.gapX * (bs.length - 1)) / Math.max(natural, 1e-9);
        let x = AREA.l;
        for (const b of bs) {
          b.rect = { x, y, w: b.w * f * stretch, h };
          placeMembers(b, f, boxes);
          x += b.rect.w + AUTO.gapX;
        }
        y += h + AUTO.gapY * f;
      });
      return { f, boxes };
    };

    // Then tidy the order: swap neighbouring zones, and neighbouring elements in a zone, while that
    // lowers the flows' crossings, their runs through other elements, right-to-left runs and length.
    const links = D.flows.filter(fl => fl.source !== fl.target);
    const cross = (p, q, r, t) => {
      const o = (a, b, c) => Math.sign((b.cx - a.cx) * (c.cy - a.cy) - (b.cy - a.cy) * (c.cx - a.cx));
      return o(p, q, r) * o(p, q, t) < 0 && o(r, t, p) * o(r, t, q) < 0;
    };
    // Does the centre-to-centre line a→b pass through box o (Liang–Barsky clip)?
    const crossesBox = (a, b, o) => {
      const dx = b.cx - a.cx;
      const dy = b.cy - a.cy;
      let t0 = 0;
      let t1 = 1;
      for (const [p, q] of [[-dx, a.cx - (o.x - 0.05)], [dx, o.x + o.w + 0.05 - a.cx], [-dy, a.cy - (o.y - 0.05)], [dy, o.y + o.h + 0.05 - a.cy]]) {
        if (Math.abs(p) < 1e-12) { if (q < 0) return false; continue; }
        const t = q / p;
        if (p < 0) { if (t > t1) return false; if (t > t0) t0 = t; } else { if (t < t0) return false; if (t < t1) t1 = t; }
      }
      return t0 <= t1;
    };
    const tangle = () => {
      const { boxes } = arrange();
      const segs = links.map(fl => ({ a: boxes.get(fl.source), b: boxes.get(fl.target), both: fl.both }));
      let c = 0;
      segs.forEach((g, i) => {
        c += Math.hypot(g.b.cx - g.a.cx, g.b.cy - g.a.cy) * 0.02;
        if (!g.both && g.b.cx < g.a.cx - 0.5) c += 0.3;
        for (let j = i + 1; j < segs.length; j++) {
          const h = segs[j];
          if (g.a !== h.a && g.a !== h.b && g.b !== h.a && g.b !== h.b && cross(g.a, g.b, h.a, h.b)) c += 1;
        }
        for (const o of boxes.values()) if (o !== g.a && o !== g.b && crossesBox(g.a, g.b, o)) c += 2;
      });
      return c;
    };
    const swaps = [];
    rows.forEach(row => {
      for (let i = row[0] && !row[0].root ? 1 : 0; i < row.length - 1; i++) swaps.push([row, i]);   // the outside area stays first
      row.forEach(g => {
        for (let i = 0; i < g.blocks.length - 1; i++) swaps.push([g.blocks, i]);
        g.blocks.forEach(b => { for (let i = 0; i < b.members.length - 1; i++) swaps.push([b.members, i]); });
      });
    });
    let current = links.length ? tangle() : 0;
    // Evaluations: bounded, the same on every machine, and fewer for very large diagrams (each one
    // costs about flows × (flows / 2 + elements)).
    let budget = Math.min(600, Math.floor(1e7 / Math.max(1, links.length * (links.length / 2 + D.elements.length))));
    for (let pass = 0; pass < 8 && links.length && budget > 0; pass++) {
      let better = false;
      for (const [arr, i] of swaps) {
        if (--budget < 0) break;
        [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
        const c = tangle();
        if (c < current - 1e-6) { current = c; better = true; } else [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
      }
      if (!better) break;
    }
    const { f, boxes } = arrange();

    // Zones as drawn: each block is a leaf (a zone that also holds zones gets a leaf of its own for
    // its own elements); a zone with blocks inside it is a parent spanning them.
    const zones = [];
    for (const b of blocks) {
      const holdsZones = b.zone && blocks.some(o => o.zone && ancestorsOf(D, o.zone).includes(b.zone.id));
      b.id = !b.zone ? OUTSIDE : holdsZones ? b.zone.id + OWN : b.zone.id;
      zones.push({ id: b.id, name: b.zone ? b.zone.id : 'outside', label: b.label, rect: b.rect, leaf: true,
        parent: !b.zone ? null : holdsZones ? b.zone.id : b.zone.parent });
      for (const e of b.members) boxes.get(e.id).zoneId = b.id;
    }
    for (const z of D.zones) {
      const inner = blocks.filter(b => b.zone && b.zone !== z && ancestorsOf(D, b.zone).includes(z.id));
      if (!inner.length) continue;
      const own = blocks.find(b => b.zone === z);
      zones.push({ id: z.id, name: z.id, label: z.label, parent: z.parent, leaf: false,
        rect: unionRects(inner.concat(own ? [own] : []).map(b => b.rect)) });
    }
    for (const z of zones) {
      let d = 0;
      for (let p = z.parent; p && d < 50; p = (D.zoneById.get(p) || {}).parent) d++;
      z.depth = d;
    }
    return { f, boxes, zones, tiled: tiles(zones, boxes) };

    function placeMembers(b, f, out) {
      const inner = b.rect.w - 2 * AUTO.padX * f;
      const natural = b.colW.reduce((a, w) => a + w, 0);
      let x = b.rect.x + AUTO.padX * f;
      const cols = b.colW.map(w => {
        const col = { x, w: (inner * w) / natural, oct: w === AUTO.cellOct };
        x += col.w;
        return col;
      });
      const yTop = b.rect.y + (AUTO.top + (b.under ? AUTO.parentLabel : 0)) * f;
      const yBottom = Math.max(yTop, b.rect.y + b.rect.h - AUTO.bottom * f);
      b.members.forEach((e, i) => {
        const col = cols[Math.floor(i / b.rows)];
        const r = i % b.rows;
        // An element with an octagon sits left in its column, leaving the octagon room on the right.
        const cx = col.oct ? col.x + 0.85 * f + (col.w - AUTO.cellOct * f) * 0.3 : col.x + col.w / 2;
        const cy = b.rows === 1 ? (yTop + yBottom) / 2 : yTop + ((yBottom - yTop) * r) / (b.rows - 1);
        out.set(e.id, elementBox(e, cx, cy, f));
      });
    }
  }

  /* ------------------------------------------------------------------------------------------------
   * Trust boundaries
   * ---------------------------------------------------------------------------------------------- */

  /**
   * Trust boundaries. Zones that touch share one gentle dashed curve along each line where they
   * meet — vertical between zones side by side, long horizontal ones between rows — and the outer
   * edge of the diagram is not drawn (the reference). When the zones don't tile the diagram, the
   * outer edge is drawn too wherever a flow crosses it (an element outside every zone), a zone that
   * touches no other zone gets its full outline as a dashed rounded rectangle, and a zone that holds
   * elements besides its zones is outlined around them: a boundary wherever a flow changes trust
   * zone, and each one drawn once.
   */
  function boundaryShapes(L, flows) {
    const out = [];
    const valid = z => z.rect.w > 0 && z.rect.h > 0;
    const leaves = L.zones.filter(z => z.leaf && valid(z));
    const groups = groupsOf(leaves);
    if (!L.tiled) {
      const own = new Set([...L.boxes.values()].map(b => b.zoneId));
      L.zones.filter(z => !z.leaf && own.has(z.id) && valid(z)).sort((a, b) => a.depth - b.depth)
        .forEach(z => out.push({ kind: 'outline', rect: inflate(z.rect, 0.06) }));
      // (the area for elements outside every zone is not a trust zone: it gets no outline)
      groups.filter(g => g.length === 1 && g[0].id !== OUTSIDE).forEach(g => out.push({ kind: 'outline', rect: g[0].rect }));
    }
    const linked = groups.filter(g => g.length > 1).flat();
    if (!linked.length) return out;
    const bb = unionRects(linked.map(z => z.rect));
    const edgeTol = 0.12;
    const inner = { h: [], v: [] };
    const outer = { h: [], v: [] };
    for (const { rect: r } of linked) {
      const R = r.x + r.w;
      const B = r.y + r.h;
      (r.y > bb.y + edgeTol ? inner : outer).h.push({ at: r.y, a: r.x, b: R });
      (B < bb.y + bb.h - edgeTol ? inner : outer).h.push({ at: B, a: r.x, b: R });
      (r.x > bb.x + edgeTol ? inner : outer).v.push({ at: r.x, a: r.y, b: B });
      (R < bb.x + bb.w - edgeTol ? inner : outer).v.push({ at: R, a: r.y, b: B });
    }
    // Edges on (nearly) one line merge into one boundary midway between them (zones count as
    // touching up to TILE_TOL apart, so their edges merge at least that far); along a row the zones'
    // small gaps are bridged, but vertical runs in different rows stay separate curves.
    const merge = (edges, bridge) => {
      const lines = [];
      for (const e of [...edges].sort((p, q) => p.at - q.at)) {
        const line = lines.find(l => Math.abs(l.mean - e.at) <= MERGE_TOL);
        if (line) {
          line.edges.push(e);
          line.mean = line.edges.reduce((sum, x) => sum + x.at, 0) / line.edges.length;
        } else {
          lines.push({ mean: e.at, edges: [e] });
        }
      }
      const runs = [];
      for (const line of lines) {
        const own = [];
        for (const e of [...line.edges].sort((p, q) => p.a - q.a)) {
          const last = own[own.length - 1];
          if (last && e.a <= last.b + bridge) { last.b = Math.max(last.b, e.b); last.edges.push(e); } else own.push({ a: e.a, b: e.b, edges: [e] });
        }
        for (const run of own) runs.push({ at: run.edges.reduce((sum, x) => sum + x.at, 0) / run.edges.length, a: run.a, b: run.b });
      }
      return runs;
    };
    const curves = [];
    for (const h of merge(inner.h, MERGE_TOL)) curves.push(curve('h', h.at, h.a, h.b));
    for (const v of merge(inner.v, 0.02)) curves.push(curve('v', v.at, v.a, v.b));
    if (!L.tiled) {
      // The outer edge, where a flow crosses it (from an element outside every zone); without
      // flows (while laying out) any edge may be.
      const segs = flows ? flows.flatMap(fl => fl.pts.slice(1).map((q, i) => [fl.pts[i], q])) : null;
      const crossed = (dir, run) => {
        if (!segs) return true;
        const p = dir === 'h' ? [run.a, run.at] : [run.at, run.a];
        const q = dir === 'h' ? [run.b, run.at] : [run.at, run.b];
        return segs.some(([a, b]) => segmentsCross(a, b, p, q));
      };
      for (const h of merge(outer.h, MERGE_TOL)) if (crossed('h', h)) curves.push(curve('h', h.at, h.a, h.b));
      for (const v of merge(outer.v, 0.02)) if (crossed('v', v)) curves.push(curve('v', v.at, v.a, v.b));
    }
    return out.concat(curves.filter(c => c.len > 0.3));
  }
  /** Do segments ab and pq cross (touching counts)? */
  function segmentsCross(a, b, p, q) {
    const o = (u, v, w) => {
      const d = (v[0] - u[0]) * (w[1] - u[1]) - (v[1] - u[1]) * (w[0] - u[0]);
      return Math.abs(d) < 1e-12 ? 0 : Math.sign(d);
    };
    const on = (u, v, w) => Math.min(u[0], v[0]) - 1e-9 <= w[0] && w[0] <= Math.max(u[0], v[0]) + 1e-9
      && Math.min(u[1], v[1]) - 1e-9 <= w[1] && w[1] <= Math.max(u[1], v[1]) + 1e-9;
    const d1 = o(p, q, a);
    const d2 = o(p, q, b);
    const d3 = o(a, b, p);
    const d4 = o(a, b, q);
    if (d1 * d2 < 0 && d3 * d4 < 0) return true;
    return (d1 === 0 && on(p, q, a)) || (d2 === 0 && on(p, q, b)) || (d3 === 0 && on(a, b, p)) || (d4 === 0 && on(a, b, q));
  }
  /** A boundary bowing gently: left for vertical lines, up for horizontal ones (as the reference). */
  function curve(dir, at, a, b) {
    const len = b - a;
    const amp = dir === 'v' ? Math.min(0.28, Math.max(0.12, 0.1 * len)) : Math.min(0.12, Math.max(0.05, 0.005 * len));
    const pts = [];
    for (let i = 0; i <= 48; i++) {
      const t = i / 48;
      const bow = amp * (1 - Math.sin(Math.PI * t));
      pts.push(dir === 'v' ? { x: bow, y: len * t } : { x: len * t, y: bow });
    }
    const rect = dir === 'v' ? { x: at - amp / 2, y: a, w: amp, h: len } : { x: a, y: at - amp / 2, w: len, h: amp };
    // A few chords of the curve, for "does this cross a boundary" tests.
    const poly = [];
    for (let i = 0; i <= 8; i++) poly.push([rect.x + pts[i * 6].x, rect.y + pts[i * 6].y]);
    return { kind: 'curve', dir, at, a, b, rect, pts, poly, len };
  }

  /* ------------------------------------------------------------------------------------------------
   * Flows, labels and threat octagons: placed once, shared by every slide
   * ---------------------------------------------------------------------------------------------- */

  /**
   * A grid of buckets over the slide, to find what lies near a box without testing everything in
   * the diagram: add(value, box), remove(value), query(box, margin) -> the values whose box comes
   * within margin of it. Each placement search then costs what is near it, not the diagram's size.
   */
  function spatialIndex(cell = 0.6) {
    const cols = Math.ceil(SLIDE_W / cell) + 2;
    const rows = Math.ceil(SLIDE_H / cell) + 2;
    const buckets = [];
    const entries = new Map();
    let stamp = 0;
    const at = (v, n) => Math.min(n - 1, Math.max(0, Math.floor(v / cell) + 1));
    const cells = (box, m, fn) => {
      const i1 = at(box.x + box.w + m, cols);
      const j1 = at(box.y + box.h + m, rows);
      for (let i = at(box.x - m, cols); i <= i1; i++) {
        for (let j = at(box.y - m, rows); j <= j1; j++) fn(i * rows + j);
      }
    };
    return {
      add(v, box) {
        const e = { v, box, stamp: 0 };
        entries.set(v, e);
        cells(box, 0, key => (buckets[key] || (buckets[key] = [])).push(e));
      },
      remove(v) {
        const e = entries.get(v);
        if (!e) return;
        entries.delete(v);
        cells(e.box, 0, key => {
          const i = buckets[key].indexOf(e);
          if (i >= 0) buckets[key].splice(i, 1);
        });
      },
      query(box, m = 0) {
        const out = [];
        stamp++;
        cells(box, m, key => {
          for (const e of buckets[key] || []) {
            if (e.stamp === stamp) continue;
            e.stamp = stamp;
            if (rectsHit(e.box, box, m)) out.push(e.v);
          }
        });
        return out;
      },
    };
  }

  /**
   * What routes and placements are tested against, indexed by place: `solids` (the elements and
   * their crown jewels, with their owner; the legend and the title, owner null), the flows' legs,
   * the trust boundaries' pieces, the labels and octagons placed so far and the attack sequences'
   * hops.
   */
  function sceneOf(L) {
    const scene = { solids: spatialIndex(), legs: spatialIndex(), labels: spatialIndex(), hops: spatialIndex(),
      octagons: spatialIndex() };
    for (const r of [LEGEND, TOP_BAND]) scene.solids.add({ owner: null, shape: boxShape(r) }, r);
    for (const o of L.boxes.values()) {
      scene.solids.add({ owner: o, shape: o.shape }, o.shape.box);
      if (o.star) scene.solids.add({ owner: o, shape: boxShape(o.star) }, o.star);
    }
    setBounds(scene, []);
    return scene;
  }
  function setBounds(scene, bounds) {
    scene.boundList = bounds;
    scene.bounds = spatialIndex();
    bounds.forEach((bd, i) => boundarySegments(bd).forEach(sg => scene.bounds.add({ i, sg }, sg.box)));
    scene.boundLines = bounds.flatMap(boundaryLines);
  }
  /** Gives a flow its route (and its legs in the scene: where an arrowhead sits on each). */
  function setRoute(scene, fl, pts) {
    for (const leg of fl.legs || []) scene.legs.remove(leg);
    fl.pts = pts;
    fl.segs = segmentsOf(pts);
    // `head`: the leg ending in the arrowhead; `tail`: the first leg, where the flow is seen to come
    // from (and its second arrowhead when both ways).
    fl.legs = fl.segs.map((sg, i) => ({ fl, i, sg, head: i === fl.segs.length - 1, tail: i === 0 }));
    for (const leg of fl.legs) scene.legs.add(leg, leg.sg.box);
    return fl;
  }

  /** Where a ray from p (inside the element) along unit d leaves the element's outline. */
  function exitDistance(b, p, d) {
    const sh = b.shape;
    if (sh.r != null) {
      const ox = p[0] - sh.c[0];
      const oy = p[1] - sh.c[1];
      const k = d[0] * ox + d[1] * oy;
      const disc = k * k - (ox * ox + oy * oy - sh.r * sh.r);
      return disc > 0 ? Math.max(0, -k + Math.sqrt(disc)) : 0;
    }
    // Convex polygon: the first edge the ray leaves through.
    const pts = sh.pts;
    const cx = pts.reduce((a, q) => a + q[0], 0) / pts.length;
    const cy = pts.reduce((a, q) => a + q[1], 0) / pts.length;
    let t = Infinity;
    for (let i = 0; i < pts.length; i++) {
      const p1 = pts[i];
      const p2 = pts[(i + 1) % pts.length];
      let n = [-(p2[1] - p1[1]), p2[0] - p1[0]];
      if (Math.hypot(n[0], n[1]) < 1e-12) continue;
      if (n[0] * (cx - p1[0]) + n[1] * (cy - p1[1]) > 0) n = [-n[0], -n[1]];      // outward
      const nd = n[0] * d[0] + n[1] * d[1];
      if (nd > 1e-12) t = Math.min(t, (n[0] * (p1[0] - p[0]) + n[1] * (p1[1] - p[1])) / nd);
    }
    return Number.isFinite(t) ? Math.max(0, t) : 0;
  }

  /** A straight segment between two elements, clipped to their outlines with a small gap. */
  function linkSegment(a, b, offset, gap) {
    const dx = b.cx - a.cx;
    const dy = b.cy - a.cy;
    const len = Math.hypot(dx, dy);
    if (len < 1e-6) return null;
    const u = [dx / len, dy / len];
    const o = [-u[1] * offset, u[0] * offset];
    const p0 = [a.cx + o[0], a.cy + o[1]];
    const p1 = [b.cx + o[0], b.cy + o[1]];
    const t0 = exitDistance(a, p0, u) + gap;
    const t1 = exitDistance(b, p1, [-u[0], -u[1]]) + gap;
    const s = [p0[0] + u[0] * t0, p0[1] + u[1] * t0];
    const e = [p1[0] - u[0] * t1, p1[1] - u[1] * t1];
    if ((e[0] - s[0]) * u[0] + (e[1] - s[1]) * u[1] < 0.06) return null;   // elements touch: nothing to draw
    return { s, e, u };
  }

  const segmentsOf = pts => pts.slice(1).map((q, i) => segmentShape(pts[i], q));
  const routeLength = pts => pts.slice(1).reduce((a, q, i) => a + Math.hypot(q[0] - pts[i][0], q[1] - pts[i][1]), 0);
  const routeOnSlide = pts => pts.every(q => q[0] > 0.05 && q[0] < SLIDE_W - 0.05 && q[1] > AREA.t && q[1] < SLIDE_H - 0.05);

  /**
   * An elbow route through the two element centres, clipped to their outlines; null when a bend
   * falls inside either element.
   */
  function clipRoute(c, a, b, gap) {
    const pts = c.filter((q, i) => i === 0 || Math.hypot(q[0] - c[i - 1][0], q[1] - c[i - 1][1]) > 1e-6);
    if (pts.length < 2) return null;
    const unit = (p, q) => {
      const l = Math.hypot(q[0] - p[0], q[1] - p[1]);
      return [(q[0] - p[0]) / l, (q[1] - p[1]) / l, l];
    };
    const [dx, dy, l0] = unit(pts[0], pts[1]);
    const t0 = exitDistance(a, pts[0], [dx, dy]) + gap;
    const n = pts.length;
    const [ex, ey, l1] = unit(pts[n - 1], pts[n - 2]);
    const t1 = exitDistance(b, pts[n - 1], [ex, ey]) + gap;
    if (t0 > l0 - 0.08 || t1 > l1 - 0.08) return null;
    const out = pts.map(q => q.slice());
    out[0] = [pts[0][0] + dx * t0, pts[0][1] + dy * t0];
    out[n - 1] = [pts[n - 1][0] + ex * t1, pts[n - 1][1] + ey * t1];
    return n === 2 && routeLength(out) < 0.06 ? null : out;
  }

  /** Length of the segment pq inside a convex polygon (Cyrus–Beck clipping). */
  function insideLength(p, q, pts) {
    const dx = q[0] - p[0];
    const dy = q[1] - p[1];
    let area = 0;
    for (let i = 0; i < pts.length; i++) {
      const a = pts[i];
      const b = pts[(i + 1) % pts.length];
      area += a[0] * b[1] - b[0] * a[1];
    }
    const sgn = area > 0 ? 1 : -1;
    let t0 = 0;
    let t1 = 1;
    for (let i = 0; i < pts.length; i++) {
      const a = pts[i];
      const b = pts[(i + 1) % pts.length];
      const nx = -(b[1] - a[1]) * sgn;          // inward normal of the edge
      const ny = (b[0] - a[0]) * sgn;
      const num = (p[0] - a[0]) * nx + (p[1] - a[1]) * ny;
      const den = dx * nx + dy * ny;
      if (Math.abs(den) < 1e-12) {
        if (num < 0) return 0;
        continue;
      }
      const t = -num / den;
      if (den > 0) t0 = Math.max(t0, t); else t1 = Math.min(t1, t);
      if (t0 >= t1) return 0;
    }
    return (t1 - t0) * Math.hypot(dx, dy);
  }

  /** The straight pieces a trust boundary is drawn along (a curve's chords, an outline's sides). */
  function boundarySegments(bd) {
    if (!bd.segs) {
      if (bd.kind === 'curve') {
        bd.segs = bd.poly.slice(1).map((p, i) => segmentShape(bd.poly[i], p));
      } else {
        const r = bd.rect;
        const c = [[r.x, r.y], [r.x + r.w, r.y], [r.x + r.w, r.y + r.h], [r.x, r.y + r.h]];
        bd.segs = c.map((p, i) => segmentShape(p, c[(i + 1) % 4]));
      }
    }
    return bd.segs;
  }
  /** The line a boundary is drawn along, as points (a curve's own points, an outline's corners). */
  function boundaryInk(bd) {
    if (bd.kind === 'curve') return bd.pts.map(p => [bd.rect.x + p.x, bd.rect.y + p.y]);
    const r = bd.rect;
    return [[r.x, r.y], [r.x + r.w, r.y], [r.x + r.w, r.y + r.h], [r.x, r.y + r.h], [r.x, r.y]];
  }
  /** The highest point (least y) of a polyline between x0 and x1; Infinity when it doesn't go there. */
  function highestWithin(pts, x0, x1) {
    let top = Infinity;
    for (let i = 1; i < pts.length; i++) {
      const p = pts[i - 1];
      const q = pts[i];
      const lo = Math.max(x0, Math.min(p[0], q[0]));
      const hi = Math.min(x1, Math.max(p[0], q[0]));
      if (lo > hi) continue;
      const yAt = x => (Math.abs(q[0] - p[0]) < 1e-9 ? Math.min(p[1], q[1]) : p[1] + ((q[1] - p[1]) * (x - p[0])) / (q[0] - p[0]));
      top = Math.min(top, yAt(lo), yAt(hi));
    }
    return top;
  }
  /** The lines a boundary runs along: { dir: 'h' | 'v', at, a, b }. */
  function boundaryLines(bd) {
    if (bd.kind === 'curve') return [{ dir: bd.dir, at: bd.at, a: bd.a, b: bd.b }];
    const r = bd.rect;
    return [{ dir: 'h', at: r.y, a: r.x, b: r.x + r.w }, { dir: 'h', at: r.y + r.h, a: r.x, b: r.x + r.w },
      { dir: 'v', at: r.x, a: r.y, b: r.y + r.h }, { dir: 'v', at: r.x + r.w, a: r.y, b: r.y + r.h }];
  }
  /** A segment's axis: { dir, at, a, b } when it is horizontal or vertical, else null. */
  function axisOf(p, q) {
    if (Math.abs(q[1] - p[1]) < 1e-6) return { dir: 'h', at: p[1], a: Math.min(p[0], q[0]), b: Math.max(p[0], q[0]) };
    if (Math.abs(q[0] - p[0]) < 1e-6) return { dir: 'v', at: p[0], a: Math.min(p[1], q[1]), b: Math.max(p[1], q[1]) };
    return null;
  }
  /** How long two axis-aligned lines run together (within `near` of each other). */
  function runTogether(m, n, near) {
    if (!m || !n || m.dir !== n.dir || Math.abs(m.at - n.at) > near) return 0;
    return Math.max(0, Math.min(m.b, n.b) - Math.max(m.a, n.a));
  }

  /**
   * Orthogonal routes between two elements' centres: one bend; two, along a line beside or between
   * them; or three, leaving one element sideways first (as the reference routes "Mgmt").
   */
  function elbowRoutes(a, b, offset, rich) {
    const A = [a.cx, a.cy];
    const B = [b.cx, b.cy];
    const out = [[A, [B[0], A[1]], B], [A, [A[0], B[1]], B]];
    const ys = [];
    const xs = [];
    for (const d of [0.15, 0.3, 0.5, 0.8]) {
      ys.push(Math.max(a.y + a.h, b.y + b.h) + d, Math.min(a.y, b.y) - d);
      xs.push(Math.max(a.x + a.w, b.x + b.w) + d, Math.min(a.x, b.x) - d);
    }
    const gapY = a.y + a.h < b.y ? [a.y + a.h, b.y] : b.y + b.h < a.y ? [b.y + b.h, a.y] : null;
    const gapX = a.x + a.w < b.x ? [a.x + a.w, b.x] : b.x + b.w < a.x ? [b.x + b.w, a.x] : null;
    for (const t of rich ? [0.5, 0.25, 0.75, 0.15, 0.35, 0.65, 0.85] : [0.5]) {
      if (gapY) ys.push(gapY[0] + (gapY[1] - gapY[0]) * t);
      if (gapX) xs.push(gapX[0] + (gapX[1] - gapX[0]) * t);
    }
    for (const y of ys) out.push([A, [A[0], y + offset], [B[0], y + offset], B]);
    for (const x of xs) out.push([A, [x + offset, A[1]], [x + offset, B[1]], B]);
    if (!rich) return out;
    for (const y of ys) {
      for (const xa of [a.x - 0.35, a.x + a.w + 0.35]) out.push([A, [xa, A[1]], [xa, y + offset], [B[0], y + offset], B]);
      for (const xb of [b.x - 0.35, b.x + b.w + 0.35]) out.push([A, [A[0], y + offset], [xb, y + offset], [xb, B[1]], B]);
    }
    for (const x of xs) {
      for (const ya of [a.y - 0.35, a.y + a.h + 0.35]) out.push([A, [A[0], ya], [x + offset, ya], [x + offset, B[1]], B]);
      for (const yb of [b.y - 0.35, b.y + b.h + 0.35]) out.push([A, [x + offset, A[1]], [x + offset, yb], [B[0], yb], B]);
    }
    return out;
  }

  /**
   * The cost of a flow route. Running through another element, back through its own ends or under
   * the legend rules a route out. With `full` (once the octagons are placed), what it covers or
   * crosses counts too: octagons (by how much of the line they hide) and their numbers, zone labels,
   * trust boundaries (a long diagonal across several, or running along one), and other flows
   * (crossing; running along one, though a bus into the same element costs little). Then its
   * length and bends. `self` is the flow the route is for (its current legs don't count). Stops
   * counting once the cost reaches `bound`.
   */
  function routeCost(pts, a, b, scene, full, self, bound = Infinity) {
    const segs = segmentsOf(pts);
    let cost = routeLength(pts) * (full ? 0.5 : 1) + (pts.length - 2) * (full ? 0.8 : 0.5);
    // An elbow that wraps round to leave its source, or enter its target, on the far side.
    const n = pts.length;
    if (n > 2) {
      const away = (p, from, to) => (p[0] - from.cx) * (to.cx - from.cx) + (p[1] - from.cy) * (to.cy - from.cy) < -1e-6;
      if (away(pts[1], a, b)) cost += 1.5;
      if (away(pts[n - 2], b, a)) cost += 1.5;
    }
    segs.forEach((sg, i) => {
      for (const o of scene.solids.query(sg.box, 0.05)) if (o.owner !== a && o.owner !== b && collide(sg, o.shape, 0.05)) cost += 100;
      if (i > 0 && collide(sg, a.shape, 0.02)) cost += 100;
      if (i < segs.length - 1 && collide(sg, b.shape, 0.02)) cost += 100;
    });
    if (!full || cost >= bound) return cost;
    const crossed = new Set();
    for (const sg of segs) {
      if (cost >= bound) return cost;
      const [p, q] = sg.pts;
      const axis = axisOf(p, q);
      for (const o of scene.octagons.query(sg.box, CLEAR)) {
        const inside = insideLength(p, q, grown(o.oct, CLEAR).pts);
        if (inside > 0.01) cost += 3 + inside * 20;
        if (collide(sg, o.num, 0.03)) cost += 6;
      }
      // A label crossed reads badly; one a line runs along, struck through, much worse.
      for (const z of scene.labels.query(sg.box, 0.02)) {
        if (collide(sg, z.shape, 0.02)) cost += (z.parent ? 1 : 1.5) + 10 * Math.max(0, insideLength(p, q, z.shape.pts) - 0.35);
      }
      for (const x of scene.bounds.query(sg.box, 0.02)) {
        if (!crossed.has(x.i) && segmentsCross(p, q, x.sg.pts[0], x.sg.pts[1])) crossed.add(x.i);
      }
      if (axis) for (const ln of scene.boundLines) cost += runTogether(axis, ln, 0.15) * 3;
      for (const leg of scene.legs.query(sg.box, 0.1)) {
        if (leg.fl === self) continue;
        const [r, t] = leg.sg.pts;
        if (segmentsCross(p, q, r, t)) cost += 0.4;
        const together = runTogether(axis, axisOf(r, t), 0.08);
        if (together > 0) cost += together * ([leg.fl.a, leg.fl.b].some(o => o === a || o === b) ? 1.5 : 6);
      }
    }
    cost += crossed.size * 0.6;
    // A long diagonal across several boundaries reads badly (the reference routes "Mgmt" round).
    const [p, q] = [pts[0], pts[pts.length - 1]];
    if (pts.length === 2 && Math.abs(q[0] - p[0]) > 0.3 && Math.abs(q[1] - p[1]) > 0.3 && crossed.size >= 2) cost += 3.5;
    return cost;
  }

  /**
   * A flow's route from source to target: a straight line, or — when that would run through another
   * element — an elbow with one or two right-angle bends, as the reference routes such flows.
   */
  function routeFlow(a, b, offset, scene) {
    const straight = linkSegment(a, b, offset, 0.03);
    const straightCost = straight ? routeCost([straight.s, straight.e], a, b, scene, false) : Infinity;
    if (straight && straightCost < 100) return [straight.s, straight.e];
    let best = null;
    for (const c of elbowRoutes(a, b, offset, false)) {
      const pts = clipRoute(c, a, b, 0.03);
      if (!pts || !routeOnSlide(pts)) continue;
      const cost = routeCost(pts, a, b, scene, false);
      if (!best || cost < best.cost) best = { cost, pts };
    }
    if (best && best.cost < straightCost) return best.pts;
    return straight ? [straight.s, straight.e] : null;
  }

  /** Data-flow routes; several between the same two elements are drawn side by side. */
  function flowSegments(D, L, scene) {
    const pairKey = f => [f.source, f.target].sort().join('\u0000');
    const count = new Map();
    for (const f of D.flows) if (f.source !== f.target) count.set(pairKey(f), (count.get(pairKey(f)) || 0) + 1);
    const seen = new Map();
    const out = [];
    for (const f of D.flows) {
      const a = L.boxes.get(f.source);
      const b = L.boxes.get(f.target);
      if (!a || !b || f.source === f.target) continue;
      const key = pairKey(f);
      const k = seen.get(key) || 0;
      seen.set(key, k + 1);
      // One side for the pair whichever way each flow runs, so parallel flows don't cross.
      const offset = (k - (count.get(key) - 1) / 2) * 0.14 * (f.source < f.target ? 1 : -1);
      const pts = routeFlow(a, b, offset, scene);
      if (pts) out.push(setRoute(scene, { flow: f, a, b, offset }, pts));
    }
    return out;
  }

  /**
   * Second pass over the routes, once the octagons are placed: a flow that runs under an octagon
   * (one that found no clear spot), or cuts diagonally across several boundaries, moves sideways a
   * little or takes an elbow when that is clearly better (the reference routes "Mgmt" so). Returns
   * the flows that moved, with their old routes.
   */
  function rerouteFlows(flows, scene) {
    const changed = [];
    let budget = 6000;                               // route costings: bounded on very large diagrams
    for (const fl of flows) {
      if (budget <= 0) break;
      budget--;
      const now = routeCost(fl.pts, fl.a, fl.b, scene, true, fl);
      const clean = routeLength(fl.pts) * 0.5 + (fl.pts.length - 2) * 0.8;
      if (now - clean < 1.5) continue;                 // nothing much in its way
      const cands = [];
      for (const d of [0.12, -0.12, 0.24, -0.24, 0.36, -0.36]) {
        const line = linkSegment(fl.a, fl.b, fl.offset + d, 0.03);
        if (line) cands.push({ pts: [line.s, line.e], extra: Math.abs(d) * 1.5 });
      }
      for (const r of elbowRoutes(fl.a, fl.b, fl.offset, true)) cands.push({ pts: clipRoute(r, fl.a, fl.b, 0.03), extra: 0 });
      // No detours: a route stays beside the two elements and is not much longer than the line.
      const span = inflate(unionRects([fl.a, fl.b]), 0.6);
      const direct = Math.hypot(fl.b.cx - fl.a.cx, fl.b.cy - fl.a.cy);
      const within = pts => pts.every(q => q[0] >= span.x && q[0] <= span.x + span.w && q[1] >= span.y && q[1] <= span.y + span.h);
      let best = null;
      for (const { pts, extra } of cands) {
        if (!pts || !routeOnSlide(pts) || !within(pts) || routeLength(pts) > 1.5 * direct + 0.6) continue;
        if (pts.length > 4 && !monotone(pts)) continue;           // no S-bends round an obstacle
        budget--;
        const cost = routeCost(pts, fl.a, fl.b, scene, true, fl, (best ? best.cost : now - 1) - extra) + extra;
        if (!best || cost < best.cost) best = { cost, pts };
      }
      if (best && best.cost < now - 1) {
        changed.push({ fl, old: fl.segs });
        setRoute(scene, fl, best.pts);
      }
    }
    return changed;
  }

  /** Does a route move only one way along each axis (no doubling back)? */
  function monotone(pts) {
    return [0, 1].every(k => {
      let sign = 0;
      for (let i = 1; i < pts.length; i++) {
        const d = pts[i][k] - pts[i - 1][k];
        if (Math.abs(d) < 1e-6) continue;
        if (sign && Math.sign(d) !== sign) return false;
        sign = Math.sign(d);
      }
      return true;
    });
  }

  /** The legs a flow label may sit along: legs no other flow runs along first, longest first. */
  function labelLegs(fl, scene) {
    const legs = fl.segs.map((sg, i) => {
      const [s, e] = sg.pts;
      const len = Math.hypot(e[0] - s[0], e[1] - s[1]) || 1;
      const axis = axisOf(s, e);
      let shared = 0;
      if (axis) {
        for (const x of scene.legs.query(sg.box, 0.08)) if (x.fl !== fl) shared += runTogether(axis, axisOf(x.sg.pts[0], x.sg.pts[1]), 0.08);
      }
      return { i, s, e, len, u: [(e[0] - s[0]) / len, (e[1] - s[1]) / len], shared: shared > 0.3 * len };
    });
    const usable = legs.filter(l => l.len > 0.35);
    return (usable.length ? usable : legs).sort((p, q) => (p.shared ? 1 : 0) - (q.shared ? 1 : 0) || q.len - p.len);
  }

  /** Zone labels: 11 pt bold at the bottom centre of each leaf zone (moved aside to clear elements). */
  function placeZoneLabels(L, scene) {
    const out = [];
    for (const z of L.zones) {
      if (!z.label) continue;
      const r = z.rect;
      if (!z.leaf) {
        // A parent zone: 10.5 pt bold italic in accent red at its top left, no box of its own.
        const pt = 10.5;
        const maxW = Math.max(0.5, r.w - 0.2);
        const t = ellipsize(z.label, maxW, pt, true);
        const box = { x: r.x + 0.1, y: r.y + 0.1, w: Math.min(maxW, textWidth(t, pt, true) + 0.08), h: lineHeight(pt) + 0.02 };
        out.push({ zone: z, parent: true, box, lines: [t], pt });
        continue;
      }
      let pt = 11;
      const maxW = Math.max(0.4, r.w - 0.2);
      let lines = [z.label];
      if (textWidth(z.label, pt, true) > maxW) {
        lines = wrap(z.label, maxW, pt, true);
        if (lines.length > 2) {
          pt = 9;
          lines = truncateLines(wrap(z.label, maxW, pt, true), 2, maxW, pt, true);
        }
      }
      const w = Math.min(maxW, Math.max(...lines.map(l => textWidth(l, pt, true))) + 0.1);
      const h = lines.length * lineHeight(pt) + 0.04;
      const yb = r.y + r.h - 0.08 - h;
      // Bottom centre as in the reference, else further along the bottom, else at the top.
      const cands = [0.5, 0.35, 0.65, 0.2, 0.8, 0, 1].map(t => ({ x: r.x + 0.1 + (r.w - 0.2 - w) * t, y: yb }))
        .concat([{ x: r.x + (r.w - w) / 2, y: r.y + 0.1 }]);
      let best = null;
      cands.forEach((c, i) => {
        const box = { x: c.x, y: c.y, w, h };
        const shape = boxShape(box);
        const legs = scene.legs.query(box).filter(x => collide(shape, x.sg, 0)).length;
        const bounds = new Set(scene.bounds.query(box, 0.02).filter(x => collide(shape, x.sg, 0.02)).map(x => x.i)).size;
        let cost = i * 1.2 + legs * 3 + bounds * 3;
        if (scene.solids.query(box, 0.04).some(o => collide(shape, o.shape, 0.04)) || out.some(o => rectsHit(o.box, box, 0.04))) cost += 1000;
        if (!best || cost < best.cost) best = { cost, box };
      });
      out.push({ zone: z, parent: false, box: best.box, lines, pt });
    }
    for (const z of out) scene.labels.add({ zone: true, parent: z.parent, shape: boxShape(z.box) }, z.box);
    return out;
  }

  /**
   * The octagon size, and the spots the reference gives it: right of its element and a little above
   * it (most), or right of it aligned with its top (where a flow leaves the first, as for 7).
   */
  const octagonSize = L => OCT * Math.min(1, Math.max(L.f, 0.65));
  // What breaking a hard limit costs an octagon's spot: more than any spot clear of them could.
  const HARD = 1e5;
  const idealSpots = (b, s) => [
    { x: b.x + b.w + 0.15, y: b.cy - 0.62 * (s / OCT) - s / 2, extra: 0 },
    { x: b.x + b.w + 0.15, y: b.y - 0.08 * (s / OCT), extra: 0.4 },
  ];

  /** The elements each attack sequence walks: its path, or else the elements of its steps. */
  function pathIds(D, L, seq) {
    const path = seq.path.filter(id => L.boxes.has(id));
    if (path.length) return path;
    return seq.steps.map(n => (D.locations.find(l => l.ai === seq.ai && l.dfd === n) || {}).element)
      .filter(id => id && L.boxes.has(id));
  }
  /** The straight hops of every attack sequence (where its arrows will be drawn), into the scene. */
  function sequenceHops(D, L, scene) {
    for (const seq of D.sequences) {
      const path = pathIds(D, L, seq);
      const steps = new Set(seq.steps);
      for (let i = 1; i < path.length; i++) {
        if (path[i] === path[i - 1]) continue;
        const seg = linkSegment(L.boxes.get(path[i - 1]), L.boxes.get(path[i]), 0, 0.1);
        if (seg) {
          const sg = segmentShape(seg.s, seg.e);
          scene.hops.add({ sg, ai: seq.ai, steps }, sg.box);
        }
      }
    }
  }

  /**
   * Threat octagons, one per slot (see prepare), beside their elements: as near as possible to the
   * reference's spots (see idealSpots); clear of elements, labels, other octagons and their numbers,
   * the title and the legend; read as their own element's (clearly nearer to it than to any other:
   * that outweighs the rest); inside the element's zone where possible; and covering as little of
   * any flow as it can (a hidden flow costs more than leaving the zone, a hidden end of one most of
   * all), nor of the attack sequences' hops. Candidates are tried nearest the ideal spots first:
   * finely near them, just beside the element all round it, and coarsely further out; then very
   * finely near the ideal spots when nothing clear was found there, and finely around the best. A
   * search tries at most `cap` of the coarse ones (it only runs out on very crowded diagrams).
   */
  function octagonPlacer(D, L, scene) {
    const s = octagonSize(L);
    const k = s / OCT;
    // How much reading as its own element's counts against other costs: in a crowd (elements shrunk
    // to fit) an octagon must be free to go further for a clear spot.
    const keen = L.f >= 0.6 ? 1 : 0.2;
    const numW = 0.34 * k;
    const numH = 0.28 * k;
    const placed = scene.octagons;                 // { slot, oct, num }: the octagons as placed
    const entries = new Map();                     // slot -> its entry in `placed`
    const out = new Map();                         // slot -> { x, y, s, num, ideal }
    const slotLocs = new Map();
    for (const l of D.locations) slotLocs.set(l.slot, (slotLocs.get(l.slot) || []).concat([l]));
    const zoneRect = new Map(L.zones.map(z => [z.id, z.rect]));
    const leaves = L.zones.filter(z => z.leaf).map(z => z.rect);
    const clampX = x => Math.min(Math.max(x, 0.05 + numW), SLIDE_W - 0.04 - s);
    const clampY = y => Math.min(Math.max(y, AREA.t + 0.1 * k + 0.01), SLIDE_H - 0.05 - s);
    // The number is right-aligned above-left of the octagon: only its digits need room.
    const digitsOf = slot => Math.min(numW, Math.max(...slotLocs.get(slot).map(m => textWidth(m.dfd, 12 * k, false))) + 0.02);
    const shapesAt = (x, y, digits) => {
      const oct = octagonShape(x, y, s);
      const num = boxShape({ x: x - digits, y: y - 0.06 * k, w: digits, h: 0.2 * k });
      return { oct, num, box: unionRects([oct.box, num.box]) };
    };

    /** The cost of the octagon at c for q (Infinity as soon as it can't beat `bound`). */
    const costAt = (c, q, bound) => {
      const { x, y } = c;
      const num = boxShape({ x: x - q.digits, y: y - 0.06 * k, w: q.digits, h: 0.2 * k });
      const area = { x: x - q.digits, y: y - 0.06 * k, w: s + q.digits, h: s + 0.06 * k };
      let cost = c.d * 5;
      // Inside its own zone where possible. Read as its element's: close to it, and clearly nearer
      // to it than to any other element (the register names locations by these numbers, so that
      // outweighs hiding some flow). The cheap terms first: every term adds, so a spot is dropped
      // as soon as it can't beat `bound`.
      const box = { x, y, w: s, h: s };
      const own = boxGap(box, q.b);
      cost += Math.max(0, own - 0.45) * 25 + Math.max(0, own - 0.6) * 250 * keen;
      if (q.home) cost += 30 * (1 - interArea(box, q.home) / (s * s));
      else for (const r of leaves) cost += (30 * interArea(box, r)) / (s * s);
      if (cost >= bound) return Infinity;
      // Hard limits, weighted by how bad breaking them would be.
      for (const o of scene.solids.query(area, 0.02)) {
        if (octagonHits(x, y, s, o.shape, 0.02)) cost += 3 * HARD;
        else if (collide(num, o.shape, o.owner ? 0.02 : 0)) cost += o.owner ? HARD : 3 * HARD;
        if (cost >= bound) return Infinity;
      }
      for (const p of placed.query(area, 0.06)) {
        if (octagonHits(x, y, s, p.oct, 0.06)) cost += 3 * HARD;
        else if (octagonHits(p.oct.octAt.x, p.oct.octAt.y, s, num, 0.02) || octagonHits(x, y, s, p.num, 0.02)
          || collide(num, p.num, 0.02)) cost += HARD;
        if (cost >= bound) return Infinity;
      }
      for (const o of scene.labels.query(area, 0.04)) {
        if (octagonHits(x, y, s, o.shape, 0.04) || collide(num, o.shape, 0.02)) cost += HARD;
        if (cost >= bound) return Infinity;
      }
      let tie = 0;                                   // how far another element is from being clearly farther
      for (const o of scene.solids.query(box, own + 0.1)) {
        if (o.owner && o.owner !== q.b && o.shape === o.owner.shape) tie = Math.max(tie, own + 0.1 - boxGap(box, o.owner));
      }
      cost += tie * 400 * keen;
      if (cost >= bound) return Infinity;
      const oct = octagonShape(x, y, s);
      // Flow lines under it (or grazing it) are hidden: by how much, and either end of one (its
      // arrowhead, or where it comes from) most of all.
      const near = grown(oct, CLEAR);
      for (const leg of scene.legs.query(near.box)) {
        const [p, r] = leg.sg.pts;
        const inside = insideLength(p, r, near.pts);
        if (inside <= 0.005) continue;
        cost += 4 + 30 * inside;
        const len = Math.hypot(r[0] - p[0], r[1] - p[1]) || 1;
        const f = Math.min(0.3, len) / len;
        if (leg.head && insideLength([r[0] - (r[0] - p[0]) * f, r[1] - (r[1] - p[1]) * f], r, near.pts) > 0) cost += 10;
        if (leg.tail && insideLength(p, [p[0] + (r[0] - p[0]) * f, p[1] + (r[1] - p[1]) * f], near.pts) > 0) cost += 10;
      }
      if (cost >= bound) return Infinity;
      for (const leg of scene.legs.query(num.box, 0.03)) if (collide(num, leg.sg, 0.03)) cost += 6;
      const crossed = new Set();
      for (const z of scene.bounds.query(box, 0.02)) if (!crossed.has(z.i) && octagonHits(x, y, s, z.sg, 0.02)) crossed.add(z.i);
      cost += crossed.size * 2;
      // An attack sequence's arrows: a lit octagon also leaves room beside them for their step markers.
      const room = grown(oct, 0.2);
      for (const h of scene.hops.query(room.box)) {
        cost += q.lit(h) ? insideLength(h.sg.pts[0], h.sg.pts[1], room.pts) * 3 : insideLength(h.sg.pts[0], h.sg.pts[1], oct.pts);
      }
      return cost;
    };

    const search = (l, b, reach, step, cap, fine, seed) => {
      const ideals = idealSpots(b, s);
      const mine = slotLocs.get(l.slot);
      const q = {
        b, home: zoneRect.get(b.zoneId), digits: digitsOf(l.slot),
        lit: h => mine.some(m => m.ai === h.ai && h.steps.has(m.dfd)),
      };
      const key = (x, y) => Math.min(...ideals.map(p => Math.hypot(x - p.x, y - p.y) + p.extra));
      const at = (x, y) => {
        const cx = clampX(x);
        const cy = clampY(y);
        return { x: cx, y: cy, d: key(cx, cy) };
      };
      const cands = [];
      for (const p of ideals) for (let i = -3; i <= 3; i++) for (let j = -3; j <= 3; j++) cands.push(at(p.x + i * 0.1, p.y + j * 0.1));
      // Spots just beside the element, all round it (the coarse grid can step over a narrow one); on
      // its right, also far enough out for the number above left of the octagon to clear it.
      const gap = 0.12 * k;
      for (let t = b.y - s + 0.1; t <= b.y + b.h - 0.1; t += 0.1) {
        cands.push(at(b.x + b.w + gap, t), at(b.x + b.w + gap + q.digits + 0.06, t), at(b.x - s - gap, t));
      }
      for (let t = b.x - s + 0.1; t <= b.x + b.w - 0.1; t += 0.1) cands.push(at(t, b.y - s - gap), at(t, b.y + b.h + gap));
      const a = ideals[0];
      for (let i = Math.floor((b.x - s - reach - a.x) / step); i <= Math.ceil((b.x + b.w + reach - a.x) / step); i++) {
        for (let j = Math.floor((b.y - s - reach - a.y) / step); j <= Math.ceil((b.y + b.h + reach - a.y) / step); j++) {
          cands.push(at(a.x + i * step, a.y + j * step));
        }
      }
      cands.sort((p, r) => p.d - r.d);
      let best = null;
      const consider = c => {
        const cost = costAt(c, q, best ? best.cost : Infinity);
        if (!best || cost < best.cost) best = { cost, x: c.x, y: c.y, d: c.d };
      };
      const sweep = list => {
        for (const c of list) {
          if (best && c.d * 5 >= best.cost) break;      // nothing farther can do better
          consider(c);
        }
      };
      if (seed) consider(at(seed.x, seed.y));
      sweep(cands.slice(0, cap));
      // The clear spot beside an element can be narrower than the grid (squeezed between two
      // obstacles): when nothing clear was found near the ideal spots, look there again, finely.
      if (fine && (best.d > 0.25 || best.cost >= HARD)) {
        const seen = new Set();
        const grid = [];
        for (const p of ideals) {
          for (let i = -6; i <= 6; i++) {
            for (let j = -6; j <= 6; j++) {
              const c = at(p.x + i * 0.025, p.y + j * 0.025);
              const id = `${Math.round(c.x * 400)},${Math.round(c.y * 400)}`;
              if (!seen.has(id)) { seen.add(id); grid.push(c); }
            }
          }
        }
        sweep(grid.sort((p, r) => p.d - r.d));
      }
      for (const g of [0.05, 0.025]) {
        const { x, y } = best;
        for (let i = -2; i <= 2; i++) for (let j = -2; j <= 2; j++) if (i || j) consider(at(x + i * g, y + j * g));
      }
      best.ideal = ideals[0];
      return best;
    };

    const unplace = slot => {
      placed.remove(entries.get(slot));
      entries.delete(slot);
      out.delete(slot);
    };
    /** Places (or moves) one slot's octagon; one already placed moves only to a better spot. */
    const place = l => {
      const b = L.boxes.get(l.element);
      const old = out.get(l.slot);
      unplace(l.slot);
      let best = search(l, b, 1.3, 0.25, 500, true, old);
      if (best.cost >= HARD) {
        const far = search(l, b, 3, 0.3, keen < 1 ? 400 : 1200, false);
        if (far.cost < best.cost) best = far;
      }
      const shapes = shapesAt(best.x, best.y, digitsOf(l.slot));
      const entry = { slot: l.slot, oct: shapes.oct, num: shapes.num };
      placed.add(entry, shapes.box);
      entries.set(l.slot, entry);
      out.set(l.slot, { x: best.x, y: best.y, s, num: { x: best.x - numW, y: best.y - 0.1 * k, w: numW, h: numH }, ideal: best.ideal });
    };
    const placeAll = async () => {
      let lap = Date.now();
      for (const l of D.locations) {
        if (out.has(l.slot)) continue;
        place(l);
        if (Date.now() - lap > 40) {
          await pause();
          lap = Date.now();
        }
      }
    };
    /**
     * Places again the octagons that moved routes now run under (`now`: their new legs), or that a
     * route has left room for at their ideal spot (`old`: the legs it left), at most `cap` of them.
     */
    const placeNear = (now, old, cap = 40) => {
      let n = 0;
      for (const l of D.locations) {
        const o = out.get(l.slot);
        if (!o || slotLocs.get(l.slot)[0] !== l || n >= cap) continue;
        const spot = { x: o.x, y: o.y, w: s, h: s };
        const ideal = Object.assign({}, spot, o.ideal);
        const away = Math.hypot(o.x - o.ideal.x, o.y - o.ideal.y) > 0.1;
        if (now.some(sg => rectsHit(sg.box, spot, 0.05)) || (away && old.some(sg => rectsHit(sg.box, ideal, 0.05)))) {
          place(l);
          n++;
        }
      }
    };
    return { s, out, placed, place, placeAll, placeNear, slotLocs, digitsOf };
  }

  /**
   * Flow labels: 7.5 pt beside each line near its middle, clear of elements, octagons, labels, trust
   * boundaries and other flows (placed after the octagons: a label can slide along its line, an
   * octagon can't). A label never goes on an element or an octagon: when every spot along its line
   * is blocked by an octagon, that octagon moves.
   */
  async function placeFlowLabels(flows, L, scene, placer) {
    const pt = 7.5 * Math.max(L.f, 0.8);
    const ts = [0.5, 0.44, 0.56, 0.38, 0.62, 0.32, 0.68, 0.26, 0.74, 0.2, 0.8, 0.14, 0.86, 0.08, 0.92];
    const offsets = [[1, 0.04], [-1, 0.04], [1, 0.22], [-1, 0.22], [1, 0.45], [-1, 0.45], [1, 0.75], [-1, 0.75], [0, 0]];

    const search = fl => {
      const legs = labelLegs(fl, scene);
      let best = null;
      // One line where it fits (two at most); when nothing is clear, a narrower two-line wrap.
      for (const [maxW, extra] of [[1.9, 0], [1.0, 4]]) {
        const lines = truncateLines(wrap(fl.flow.label, maxW, pt, false), 2, maxW, pt, false);
        const w = Math.max(...lines.map(l => textWidth(l, pt, false))) + 0.1;
        const h = lines.length * lineHeight(pt) + 0.02;
        legs.forEach((leg, li) => {
          // Normals: below first for flat lines, right first for steep ones (as the reference).
          let n = [-leg.u[1], leg.u[0]];
          if (Math.abs(leg.u[0]) >= Math.abs(leg.u[1]) ? n[1] < 0 : n[0] < 0) n = [-n[0], -n[1]];
          const half = (w / 2) * Math.abs(n[0]) + (h / 2) * Math.abs(n[1]);
          ts.forEach((t, ti) => {
            const px = leg.s[0] + (leg.e[0] - leg.s[0]) * t;
            const py = leg.s[1] + (leg.e[1] - leg.s[1]) * t;
            offsets.forEach(([side, gap], si) => {
              let cost = extra + li * 3 + ti * 0.8 + si + (side === 0 ? 6 : 0);
              if (best && cost >= best.cost) return;
              const cx = px + side * n[0] * (half + gap);
              const cy = py + side * n[1] * (half + gap);
              const box = { x: cx - w / 2, y: cy - h / 2, w, h };
              const shape = boxShape(box);
              const over = () => best && cost >= best.cost;
              if (!onSlide(box)) cost += 3000;
              for (const o of scene.solids.query(box, 0.03)) if (collide(shape, o.shape, 0.03) && (cost += 2000) && over()) return;
              for (const o of placer.placed.query(box, 0.03)) {
                if ((octagonHits(o.oct.octAt.x, o.oct.octAt.y, o.oct.octAt.s, shape, 0.03) || collide(shape, o.num, 0.03)) && (cost += 2000) && over()) return;
              }
              for (const o of scene.labels.query(box, 0.03)) if (collide(shape, o.shape, 0.03) && (cost += 1000) && over()) return;
              for (const x of scene.legs.query(box)) if (!(x.fl === fl && x.i === leg.i) && collide(shape, x.sg, 0)) cost += 3;
              const crossed = new Set();
              for (const x of scene.bounds.query(box, 0.02)) if (!crossed.has(x.i) && collide(shape, x.sg, 0.02)) crossed.add(x.i);
              cost += crossed.size * 6;
              if (!best || cost < best.cost) best = { cost, box, lines };
            });
          });
        });
        if (best.cost < 1000) break;
      }
      return best;
    };

    let lap = Date.now();
    for (const fl of flows) {
      if (!fl.flow.label) continue;
      if (Date.now() - lap > 40) {
        await pause();
        lap = Date.now();
      }
      let best = search(fl);
      if (best.cost >= 1000) {
        // Blocked everywhere. If octagons are what's in the way (not an element, the legend or the
        // slide edge), move them clear of this label (and of every label placed so far).
        const shape = boxShape(best.box);
        const blockers = placer.placed.query(best.box, 0.03).filter(o => octagonHits(o.oct.octAt.x, o.oct.octAt.y, o.oct.octAt.s, shape, 0.03) || collide(shape, o.num, 0.03));
        const stuck = !onSlide(best.box) || scene.solids.query(best.box, 0.03).some(o => collide(shape, o.shape, 0.03));
        if (blockers.length && !stuck) {
          const hold = { shape };
          scene.labels.add(hold, best.box);
          for (const o of blockers) placer.place(placer.slotLocs.get(o.slot)[0]);
          scene.labels.remove(hold);
          best = search(fl);
        }
      }
      fl.label = { box: best.box, lines: best.lines, pt };
      scene.labels.add({ shape: boxShape(best.box) }, best.box);
    }
  }

  /** Lets the page breathe between the heavier steps (the build runs on the main thread). */
  function pause() {
    return new Promise(resolve => {
      if (typeof MessageChannel === 'function') {
        const ch = new MessageChannel();
        ch.port1.onmessage = () => resolve();
        ch.port2.postMessage(0);
      } else {
        setTimeout(resolve, 0);
      }
    });
  }

  /** Everything the slides share. */
  async function plan(result) {
    const D = prepare(result);
    const withOctagon = new Set(D.locations.map(l => l.element));
    const L = D.hasGeometry ? layoutFromGeometry(D) : layoutAuto(D, withOctagon);
    await pause();
    // Lines first; then boundaries and zone labels, each clear of what came before. A line that
    // cuts diagonally across several boundaries may then take an elbow (as "Mgmt" does in the
    // reference), before the octagons are placed beside it; then the octagons, and a route that
    // still runs under one moves, and the octagons near it are placed again; the flow labels last.
    const scene = sceneOf(L);
    const flows = flowSegments(D, L, scene);
    setBounds(scene, boundaryShapes(L, flows));
    const zoneLabels = placeZoneLabels(L, scene);
    const rerouted = rerouteFlows(flows, scene);
    if (rerouted.length && !L.tiled) setBounds(scene, boundaryShapes(L, flows));
    sequenceHops(D, L, scene);
    const placer = octagonPlacer(D, L, scene);
    await placer.placeAll();
    await pause();
    for (let pass = 0; pass < 2; pass++) {
      const changed = rerouteFlows(flows, scene);
      if (!changed.length) break;
      if (!L.tiled) setBounds(scene, boundaryShapes(L, flows));
      placer.placeNear(changed.flatMap(c => c.fl.segs), changed.flatMap(c => c.old));
      await pause();
    }
    await placeFlowLabels(flows, L, scene, placer);
    const octagons = placer.out;
    const octText = new Map();
    for (const l of D.locations) octText.set(l, fitOctagon(l.titles, l.ai ? l.layers : '', octagons.get(l.slot).s));
    return { D, L, bounds: scene.boundList, zoneLabels, flows, octagons, octText, placer, scene, labels: new Map() };
  }

  /* ------------------------------------------------------------------------------------------------
   * Drawing
   * ---------------------------------------------------------------------------------------------- */

  /** Options shared by every text box. */
  const TEXT = { fontFace: FONT, margin: 0, isTextBox: true, valign: 'top' };
  const runs = (lines, opts) => lines.map((t, i) => ({ text: t, options: Object.assign({}, opts, { breakLine: i < lines.length - 1 }) }));

  const TITLE_W = 21.5;
  const TITLE_MIN = 12;                  // pt: a long title gets smaller down to this, then is cut
  /** A title with a variable part that is shortened (see fitList) so the fixed words still show. */
  const fitTitle = (head, part, tail) => head
    + fitList(part, Math.max(1, TITLE_W - textWidth(head + tail, TITLE_MIN, true)), TITLE_MIN, true) + tail;
  function addTitle(slide, text) {
    const w = TITLE_W;
    let pt = 17;
    while (pt > TITLE_MIN && textWidth(text, pt, true) > w) pt -= 0.5;
    slide.addText(ellipsize(text, w, pt, true), Object.assign({}, TEXT, {
      x: 0.25, y: 0.12, w, h: 0.4, fontSize: pt, bold: true, color: COLOR.text, objectName: 'Title',
    }));
  }
  function addSubtitle(slide, text) {
    const w = 21.5;
    let pt = 10;
    while (pt > 8 && textWidth(text, pt, false) > w) pt -= 0.5;
    slide.addText(ellipsize(text, w, pt, false), Object.assign({}, TEXT, {
      x: 0.25, y: 0.5, w, h: 0.3, fontSize: pt, italic: true, color: COLOR.subtitle, objectName: 'Subtitle',
    }));
  }

  /** One element: its shape with the label inside, and its crown jewel. */
  function drawElement(slide, P, b, look) {
    const onPath = !!(look.path && look.path.has(b.id));
    const faded = look.faded && !onPath;
    const lineColor = faded ? FADED.line : COLOR.element;
    const width = onPath ? PATH_LINE : ELEMENT_LINE;
    const key = `${b.id}\u0000${onPath}`;
    if (!P.labels.has(key)) P.labels.set(key, fitLabel(b.el.label, b.type, P.L.f, onPath));
    const label = P.labels.get(key);
    const name = `Element ${nameOf(b.id)}`;
    const opts = {
      fontFace: FONT, fontSize: label.pt, color: faded ? FADED.text : COLOR.text, bold: onPath, align: 'center',
      valign: 'middle', margin: INSET * 72, line: { color: lineColor, width },
    };
    const body = label.lines.length ? runs(label.lines, { align: 'center' }) : '';
    if (b.type === 'cluster') {
      slide.addShape('ellipse', { x: b.x, y: b.y, w: b.w, h: b.h, line: { color: lineColor, width }, objectName: name });
      const d = b.w * CLUSTER_INNER;
      slide.addText(body, Object.assign(opts, { shape: 'ellipse', x: b.cx - d / 2, y: b.cy - d / 2, w: d, h: d, objectName: `${name} inner` }));
    } else {
      const shape = b.type === 'entity' ? 'rect' : b.type === 'datastore' ? 'can' : 'ellipse';
      slide.addText(body, Object.assign(opts, { shape, x: b.x, y: b.y, w: b.w, h: b.h, objectName: name }));
    }
    if (b.star) {
      slide.addShape('star5', Object.assign({}, b.star, {
        fill: { color: faded ? FADED.jewel : COLOR.jewel },
        line: { color: faded ? FADED.jewelLine : COLOR.jewelLine, width: 0.75 },
        objectName: `Crown jewel ${nameOf(b.id)}`,
      }));
    }
  }

  function drawCurve(slide, c, color, name = 'Trust boundary') {
    slide.addShape('custGeom', {
      x: c.rect.x, y: c.rect.y, w: c.rect.w, h: c.rect.h, points: c.pts,
      line: { color, width: 2, dashType: 'dash' }, objectName: name,
    });
  }

  /** A straight line from s to e with the arrowhead at e (and at s too when both). */
  function addLine(slide, s, e, color, width, both, name) {
    // PptxGenJS draws a line from its box's top left to bottom right; the flips put the start at s,
    // so the tail end (endArrowType) lands on e. Checked by rendering all four directions.
    slide.addShape('line', {
      x: Math.min(s[0], e[0]), y: Math.min(s[1], e[1]), w: Math.abs(e[0] - s[0]), h: Math.abs(e[1] - s[1]),
      flipH: e[0] < s[0], flipV: e[1] < s[1],
      line: { color, width, endArrowType: 'triangle', beginArrowType: both ? 'triangle' : null },
      objectName: name,
    });
  }

  /** A flow's route: a line, or an elbow drawn as one freeform with the same arrowheads. */
  function addRoute(slide, pts, color, width, both, name) {
    const xs = pts.map(q => q[0]);
    const ys = pts.map(q => q[1]);
    const x = Math.min(...xs);
    const y = Math.min(...ys);
    const w = Math.max(...xs) - x;
    const h = Math.max(...ys) - y;
    if (pts.length === 2 || w < 1e-3 || h < 1e-3) {
      addLine(slide, pts[0], pts[pts.length - 1], color, width, both, name);
      return;
    }
    slide.addShape('custGeom', {
      x, y, w, h, points: pts.map((q, i) => (i ? { x: q[0] - x, y: q[1] - y } : { x: q[0] - x, y: q[1] - y, moveTo: true })),
      line: { color, width, endArrowType: 'triangle', beginArrowType: both ? 'triangle' : null }, objectName: name,
    });
  }

  /** A threat octagon with its titles, and its number above left; faded unless lit. */
  function drawOctagon(slide, P, l, lit) {
    const o = P.octagons.get(l.slot);
    const lines = P.octText.get(l);
    const name = `Threat location ${nameOf(l.dfd)}`;
    slide.addShape('octagon', {
      x: o.x, y: o.y, w: o.s, h: o.s, fill: { color: lit ? COLOR.threat : FADED.threat }, line: { type: 'none' },
      objectName: name,
    });
    if (lines.length) {
      const k = o.s / OCT;
      slide.addText(lines.map((ln, i) => ({
        text: ln.t,
        options: {
          fontSize: ln.pt, bold: true, align: 'center', breakLine: i < lines.length - 1,
          color: lit ? (ln.head ? COLOR.layer : COLOR.threatText) : FADED.threatText,
        },
      })), Object.assign({}, TEXT, {
        x: o.x + 0.034 * k, y: o.y + 0.056 * k, w: o.s - 0.068 * k, h: o.s - 0.112 * k, valign: 'middle',
        wrap: false, lineSpacingMultiple: OCT_SPACING, objectName: `${name} text`,
      }));
    }
    slide.addText(l.dfd, Object.assign({}, TEXT, {
      x: o.num.x, y: o.num.y, w: o.num.w, h: o.num.h, fontSize: 12 * (o.s / OCT), align: 'right',
      color: lit ? COLOR.text : FADED.text, objectName: `${name} number`,
    }));
  }

  /**
   * The DFD on a slide. look: { ai, faded, path: Set of element ids, steps: Set of DFD numbers }.
   * Returns the octagons of the pass: { loc, o, lit }. On an attack-sequence slide the lit ones are
   * left for drawPath, which draws them over the arrows.
   */
  function drawDiagram(slide, P, look) {
    const boundary = look.faded ? FADED.boundary : COLOR.boundary;
    for (const bd of P.bounds) {
      if (bd.kind === 'curve') {
        drawCurve(slide, bd, boundary);
      } else {
        slide.addShape('roundRect', {
          x: bd.rect.x, y: bd.rect.y, w: bd.rect.w, h: bd.rect.h, rectRadius: Math.min(0.18, bd.rect.w / 4, bd.rect.h / 4),
          line: { color: boundary, width: 2, dashType: 'dash' }, objectName: 'Trust boundary',
        });
      }
    }
    for (const z of P.zoneLabels) {
      const color = z.parent ? (look.faded ? FADED.boundary : COLOR.accent) : (look.faded ? FADED.text : COLOR.text);
      slide.addText(runs(z.lines, { align: z.parent ? 'left' : 'center' }), Object.assign({}, TEXT, {
        x: z.box.x, y: z.box.y, w: z.box.w, h: z.box.h, fontSize: z.pt, bold: true, italic: z.parent, color,
        objectName: `${z.parent ? 'Parent zone label' : 'Zone label'} ${nameOf(z.zone.name)}`,
      }));
    }
    for (const fl of P.flows) {
      addRoute(slide, fl.pts, look.faded ? FADED.flow : COLOR.text, 1, fl.flow.both, `Flow ${nameOf(fl.flow.id)}`);
      if (fl.label) {
        slide.addText(runs(fl.label.lines, { align: 'center' }), Object.assign({}, TEXT, {
          x: fl.label.box.x, y: fl.label.box.y, w: fl.label.box.w, h: fl.label.box.h, fontSize: fl.label.pt,
          color: look.faded ? FADED.text : COLOR.text, objectName: `Flow label ${nameOf(fl.flow.id)}`,
        }));
      }
    }
    for (const b of P.L.boxes.values()) drawElement(slide, P, b, look);

    const drawn = [];
    for (const l of P.D.locations.filter(x => x.ai === look.ai)) {
      const lit = !look.faded || look.steps.has(l.dfd);
      if (!(lit && look.faded)) drawOctagon(slide, P, l, lit);
      drawn.push({ loc: l, o: P.octagons.get(l.slot), lit });
    }
    return drawn;
  }

  /* ------------------------------------------------------------------------------------- legend */

  function knowledgeVersions(D) {
    const attack = D.knowledge.filter(k => /attack/i.test(k.domain) && k.version);
    const atlas = D.knowledge.find(k => /atlas/i.test(k.domain) && k.version);
    let atk = '';
    if (attack.length) {
      const versions = [...new Set(attack.map(k => k.version))];
      atk = versions.length === 1 ? `ATT&CK ${versions[0]}`
        : 'ATT&CK ' + attack.map(k => `${k.name.replace(/^ATT&CK\s*/i, '') || k.domain} ${k.version}`).join(', ');
    }
    return { atk, atlas: atlas ? atlas.version : '' };
  }
  /** "F1–F12" when the flow labels carry the source architecture's flow numbers. */
  function flowNumbers(D) {
    const nums = D.flows.map(f => /^F(\d+)\b/.exec(f.label)).filter(Boolean).map(m => Number(m[1]));
    if (!nums.length) return '';
    const lo = Math.min(...nums);
    const hi = Math.max(...nums);
    return lo === hi ? `F${lo}` : `F${lo}–F${hi}`;
  }
  /** The legend's last line, 8.5 pt (7 at least); a long `label` part is shortened, the rest kept. */
  function profileLine(slide, y, head, label = '', tail = '') {
    let pt = 8.5;
    const full = () => head + label + tail;
    while (pt > 7 && textWidth(full(), pt, false) > LEGEND.w) pt -= 0.5;
    if (label && textWidth(full(), pt, false) > LEGEND.w) {
      label = fitList(label, Math.max(1, LEGEND.w - textWidth(head + tail, pt, false)), pt, false);
    }
    slide.addText(ellipsize(full(), LEGEND.w, pt, false), Object.assign({}, TEXT, {
      x: LEGEND.x, y, w: LEGEND.w, h: 0.22, fontSize: pt, italic: true, color: COLOR.subtitle, objectName: 'Legend profile',
    }));
  }

  /** The legend at top right, item for item as the reference (the AI figure has its own wording). */
  function drawLegend(slide, P, ai) {
    const D = P.D;
    const text = (t, x, y, w, h, o = {}) => slide.addText(t, Object.assign({}, TEXT, {
      x, y, w, h, fontSize: 9, color: COLOR.text, objectName: 'Legend text',
    }, o));
    const outline = { color: COLOR.element, width: 1 };
    text('Legend', 14.55, 0.8, 3.0, 0.26, { fontSize: 11, bold: true, objectName: 'Legend' });
    slide.addShape('rect', { x: 14.625, y: 1.15, w: 0.55, h: 0.26, line: outline, objectName: 'Legend entity' });
    text('External entity', 15.3, 1.18, 1.9, 0.22);
    slide.addShape('ellipse', { x: 14.73, y: 1.54, w: 0.34, h: 0.34, line: outline, objectName: 'Legend process' });
    text('Process', 15.3, 1.61, 1.9, 0.22);
    slide.addShape('ellipse', { x: 14.72, y: 1.96, w: 0.36, h: 0.36, line: outline, objectName: 'Legend cluster' });
    slide.addShape('ellipse', { x: 14.77, y: 2.01, w: 0.26, h: 0.26, line: outline, objectName: 'Legend cluster' });
    text('Cluster of processes', 15.3, 2.04, 1.9, 0.22);
    slide.addShape('can', { x: 14.7, y: 2.43, w: 0.4, h: 0.32, line: outline, objectName: 'Legend data store' });
    text('Data store', 15.3, 2.49, 1.9, 0.22);

    addLine(slide, [17.15, 1.28], [17.65, 1.28], COLOR.text, 1, true, 'Legend flow');
    const fn = flowNumbers(D);
    text(fn ? (ai ? `Data flow (${fn} in the source architecture)` : `Data flow (${fn} = flow number in the source architecture)`) : 'Data flow',
      17.8, 1.18, 4.0, 0.22);
    drawCurve(slide, curve('v', 17.45, 1.54, 1.9), COLOR.boundary, 'Legend trust boundary');
    text('Trust boundary', 17.8, 1.61, 4.0, 0.22);

    const v = knowledgeVersions(D);
    if (!ai) {
      slide.addText('Threat', Object.assign({}, TEXT, {
        shape: 'octagon', x: 17.2, y: 1.94, w: 0.4, h: 0.4, fill: { color: COLOR.threat }, line: { type: 'none' },
        fontSize: 6, bold: true, color: COLOR.threatText, align: 'center', valign: 'middle', isTextBox: false,
        objectName: 'Legend threat',
      }));
      text('n', 16.98, 1.86, 0.2, 0.2, { align: 'right' });
      text('Threat event location. n = DFD number, used in the threat register (Component column) and the table of attack (Sequence of Attack)',
        17.8, 1.98, 3.95, 0.36);
      slide.addShape('star5', { x: 17.27, y: 2.465, w: 0.26, h: 0.25, fill: { color: COLOR.jewel },
        line: { color: COLOR.jewelLine, width: 0.75 }, objectName: 'Legend crown jewel' });
      text('Crown jewel (per source architecture)', 17.8, 2.49, 4.0, 0.22);
      const kb = [v.atk ? `MITRE ${v.atk}` : 'MITRE ATT&CK', v.atlas ? `ATLAS ${v.atlas}` : ''].filter(Boolean).join(' and ');
      const label = D.profile.generic ? 'none (generic attacker)' : D.profile.label;
      if (label) profileLine(slide, 2.82, 'Threat profile: ', label, `  ·  STRIDE-LM  ·  ${kb}`);
      else profileLine(slide, 2.82, `STRIDE-LM  ·  ${kb}`);
    } else {
      slide.addShape('octagon', { x: 17.15, y: 1.93, w: 0.5, h: 0.5, fill: { color: COLOR.threat }, line: { type: 'none' },
        objectName: 'Legend threat' });
      slide.addText([
        { text: 'Lx', options: { fontSize: 7, bold: true, color: COLOR.layer, align: 'center', breakLine: true } },
        { text: 'Threat', options: { fontSize: 6, bold: true, color: COLOR.threatText, align: 'center' } },
      ], Object.assign({}, TEXT, { x: 17.17, y: 1.96, w: 0.46, h: 0.46, valign: 'middle', objectName: 'Legend threat text' }));
      text('n', 16.98, 1.9, 0.2, 0.2, { align: 'right' });
      const first = Math.min(...D.locations.filter(l => l.ai).map(l => l.num));
      const range = Number.isFinite(first) ? ` (${first}+)` : '';
      text(`AI threat-event location. n = DFD number${range}; white Lx = MAESTRO layer(s). `
        + 'Used in the register and the AI table of attack.', 17.82, 1.96, 3.95, 0.52);
      const atlas = v.atlas ? ` v${v.atlas}` : '';
      profileLine(slide, 2.76, `AI threats identified via MAESTRO L1–L7; TTPs from MITRE ATLAS${atlas}; AI attack surface is actor-agnostic.`);
    }
  }

  /* ------------------------------------------------------------------------------ attack paths */

  const pathOf = (P, seq) => pathIds(P.D, P.L, seq);

  /** Half an element's width across a line running along unit u through its centre. */
  function halfAcross(b, u) {
    if (b.shape.r != null) return b.shape.r;
    return (Math.abs(u[1]) * b.w + Math.abs(u[0]) * b.h) / 2;
  }

  /** The ink of an octagon's number (right-aligned in its box above left of the octagon). */
  function numberInk(l, o) {
    const k = o.s / OCT;
    const w = textWidth(l.dfd, 12 * k, false);
    return { x: o.num.x + o.num.w - w, y: o.num.y + 0.03 * k, w, h: 0.2 * k };
  }

  /**
   * Thick arrows element to element in step order, each with a marker S1, S2… near its middle, and
   * the lit octagons drawn over the arrows (an arrow passes beneath one rather than through its
   * text). An arrow moves aside a little where that keeps it off a lit octagon; a marker sits where
   * it covers no octagon, number, element of the path or other marker. `drawn` are the slide's
   * octagons ({ loc, o, lit }). Returns what the sequence text must not cover.
   */
  function drawPath(slide, P, path, drawn) {
    const hops = [];
    for (let i = 1; i < path.length; i++) if (path[i] !== path[i - 1]) hops.push([path[i - 1], path[i]]);
    const lit = drawn.filter(d => d.lit);
    const litOcts = lit.map(d => octagonShape(d.o.x, d.o.y, d.o.s));
    const pathShapes = path.map(id => P.L.boxes.get(id).shape);
    const numbers = drawn.map(d => ({ shape: boxShape(numberInk(d.loc, d.o)), w: d.lit ? 3 : 1 }));
    // What a marker should not cover, and how much each matters.
    const cover = [];
    for (const d of drawn) {
      const w = d.lit ? 6 : 1.5;
      cover.push({ shape: octagonShape(d.o.x, d.o.y, d.o.s), w }, { shape: boxShape(numberInk(d.loc, d.o)), w });
    }
    for (const b of P.L.boxes.values()) cover.push({ shape: b.shape, w: path.includes(b.id) ? 4 : 1.5 });
    const r = 0.17;
    // Where along an arrow its marker sits (near the middle), and what it then covers.
    const markerSpot = (seg, markers) => {
      let at = null;
      [0.5, 0.42, 0.58, 0.34, 0.66, 0.26, 0.74].forEach(t => {
        const c = circleShape(seg.s[0] + (seg.e[0] - seg.s[0]) * t, seg.s[1] + (seg.e[1] - seg.s[1]) * t, r);
        let cost = Math.abs(t - 0.5) * 3;
        for (const m of markers) if (collide(c, m, 0.04)) cost += 10;
        for (const x of cover) if (collide(c, x.shape, 0.02)) cost += x.w;
        if (!at || cost < at.cost - 1e-9) at = { cost, c };
      });
      return at;
    };
    const arrows = [];                   // { seg, n }: n numbers the hop (one between touching elements isn't drawn)
    const repeats = new Map();
    hops.forEach(([a, b], h) => {
      const A = P.L.boxes.get(a);
      const B = P.L.boxes.get(b);
      // An arrow moved aside still starts and ends on its elements: square on their outlines, well
      // inside their width across it (small elements leave little room).
      const len = Math.hypot(B.cx - A.cx, B.cy - A.cy) || 1;
      const u = [(B.cx - A.cx) / len, (B.cy - A.cy) / len];
      const room = 0.75 * Math.min(halfAcross(A, u), halfAcross(B, u));
      // A hop repeated between the same two elements is drawn beside the earlier one.
      const key = [a, b].sort().join('\u0000');
      const k = repeats.get(key) || 0;
      repeats.set(key, k + 1);
      const base = k ? (k % 2 ? 1 : -1) * Math.min(Math.ceil(k / 2) * 0.18, room) : 0;
      let best = null;
      for (const d of [0, 0.5, -0.5, 1, -1].map(f => f * Math.min(0.3, room))) {
        if (d && Math.abs(base + d) > room) continue;
        const seg = linkSegment(A, B, base + d, 0.1);
        if (!seg) continue;
        const line = segmentShape(seg.s, seg.e);
        let cost = Math.abs(d) * 2 + litOcts.reduce((sum, o) => sum + insideLength(seg.s, seg.e, o.pts) * 10, 0);
        for (const x of numbers) if (collide(line, x.shape, 0.02)) cost += x.w;
        cost += markerSpot(seg, []).cost;
        if (!best || cost < best.cost - 1e-9) best = { cost, seg };
      }
      if (best) arrows.push({ seg: best.seg, n: h + 1 });
    });
    for (const { seg, n } of arrows) addLine(slide, seg.s, seg.e, COLOR.accent, ARROW_LINE, false, `Attack step S${n}`);
    for (const d of lit) drawOctagon(slide, P, d.loc, true);

    const shapes = [];
    const markers = [];
    for (const { seg, n } of arrows) {
      const at = markerSpot(seg, markers);
      markers.push(at.c);
      shapes.push(segmentShape(seg.s, seg.e), at.c);
      slide.addText(`S${n}`, Object.assign({}, TEXT, {
        shape: 'ellipse', x: at.c.c[0] - r, y: at.c.c[1] - r, w: 2 * r, h: 2 * r, fill: { color: COLOR.white },
        line: { color: COLOR.accent, width: 1.5 }, fontSize: 8, bold: true, color: COLOR.accent,
        align: 'center', valign: 'middle', isTextBox: false, objectName: `Attack step S${n} marker`,
      }));
    }
    return shapes.concat(litOcts, pathShapes);
  }

  /** The attack-sequence text block's paragraphs, and its height at a width. */
  function sequenceBlock(seq, w) {
    const paras = [{ t: `Attack sequence${seq.id ? ` ${seq.id}` : ''}${seq.title ? `: ${seq.title}` : ''}`, pt: 12.5, bold: true,
      color: COLOR.accent, before: 0 }];
    if (seq.entry) paras.push({ t: `Point of entry: ${seq.entry}`, pt: 9.5, bold: true, color: COLOR.text, before: 8 });
    const parts = [];
    if (seq.steps.length) parts.push(`Sequence of attack (DFD threat events): ${seq.steps.join(' → ')}`);
    if (seq.actor) parts.push(`Threat actor: ${seq.actor}`);
    if (seq.ai && seq.layers) parts.push(`MAESTRO: ${seq.layers}`);
    if (parts.length) paras.push({ t: parts.join('     '), pt: 9.5, bold: false, color: COLOR.text, before: 5 });
    if (seq.narrative) paras.push({ t: seq.narrative, pt: 9, bold: false, color: COLOR.text, before: 6, narrative: true });
    const lineH = p => (p.pt * 1.2) / 72;
    const count = p => wrap(p.t, w - 0.05, p.pt, p.bold).length;
    const measure = () => paras.reduce((h, p) => h + p.before / 72 + count(p) * lineH(p), 0);
    // A very long narrative is cut so the block stays a block.
    const maxH = 2.6;
    const nar = paras.find(p => p.narrative);
    if (nar && measure() > maxH) {
      const keep = Math.max(1, Math.floor((maxH - (measure() - count(nar) * lineH(nar))) / lineH(nar)));
      const words = nar.t.split(' ');
      let lo = 1;
      let hi = words.length;
      while (lo < hi) {                                 // the most words that, with "…", fill `keep` lines
        const mid = Math.ceil((lo + hi) / 2);
        if (wrap(words.slice(0, mid).join(' ') + '…', w - 0.05, nar.pt, false).length <= keep) lo = mid;
        else hi = mid - 1;
      }
      nar.t = words.slice(0, lo).join(' ') + '…';
    }
    return { paras, h: measure() + 0.06 };
  }

  /** Bottom left as in the reference, or wherever else it covers none of the attack path. */
  function drawSequenceBlock(slide, seq, avoid) {
    const bottom = h => SLIDE_H - 0.12 - h;
    const cands = [];
    for (const w of [7.25, 6.4, 5.6, 4.8]) cands.push({ w, at: h => ({ x: 0.3, y: bottom(h) }) });
    cands.push({ w: LEGEND.w, at: () => ({ x: LEGEND.x, y: LEGEND.y }) });
    for (const w of [7.25, 6.4, 5.6, 4.8]) cands.push({ w, at: h => ({ x: SLIDE_W - 0.3 - w, y: bottom(h) }) });
    cands.push({ w: 7.25, at: h => ({ x: (SLIDE_W - 7.25) / 2, y: bottom(h) }) });
    let best = null;
    for (const c of cands) {
      const block = sequenceBlock(seq, c.w);
      const p = c.at(block.h);
      const box = { x: p.x, y: Math.max(AREA.t, p.y), w: c.w, h: block.h };
      const hits = avoid.filter(s => collide(boxShape(box), s, 0.05)).length;
      if (!best || hits < best.hits) best = { hits, box, block };
      if (!hits) break;
    }
    const { box, block } = best;
    slide.addText(block.paras.map((p, i) => ({
      text: p.t,
      options: { fontSize: p.pt, bold: p.bold, color: p.color, paraSpaceBefore: p.before || undefined,
        breakLine: i < block.paras.length - 1, align: 'left' },
    })), Object.assign({}, TEXT, { x: box.x, y: box.y, w: box.w, h: box.h, objectName: 'Attack sequence text' }));
  }

  /* ------------------------------------------------------------------------------------- slides */

  function severityText(h, m, l) {
    const parts = [[h, 'High'], [m, 'Medium'], [l, 'Low']].filter(([v]) => v > 0).map(([v, s]) => `${v} ${s}`);
    return parts.length ? ` (${parts.join(', ')})` : '';
  }

  /** A short note on a figure with nothing to show, where the diagram leaves room. */
  function addNote(slide, P, text) {
    const w = 7.25;
    const h = 0.3;
    const avoid = [...P.L.boxes.values()].map(b => b.shape).concat(P.L.zones.map(z => boxShape(z.rect)));
    const cands = [{ x: 0.3, y: SLIDE_H - 0.12 - h }, { x: SLIDE_W - 0.3 - w, y: SLIDE_H - 0.12 - h },
      { x: 0.3, y: AREA.t + 0.1 }, { x: LEGEND.x, y: LEGEND_BOTTOM + 0.1 }];
    const at = cands.find(c => !avoid.some(s => collide(boxShape({ x: c.x, y: c.y, w, h }), s, 0.05))) || cands[0];
    slide.addText(text, Object.assign({}, TEXT, { x: at.x, y: at.y, w, h, fontSize: 10, italic: true,
      color: COLOR.subtitle, objectName: 'Note' }));
  }

  async function build(result) {
    if (typeof PptxGenJS !== 'function') throw new Error('PptxGenJS is not loaded.');
    const P = await plan(result);
    const { D } = P;
    const pptx = new PptxGenJS();
    pptx.defineLayout({ name: 'CSA_DFD', width: SLIDE_W, height: SLIDE_H });
    pptx.layout = 'CSA_DFD';
    pptx.author = 'ThreatSim';
    pptx.subject = 'Data flow diagram with threats (CSA Guide to Cyber Threat Modelling)';
    pptx.title = `Data Flow Diagram with Threats${D.system ? ` — ${D.system}` : ''}`;

    const system = D.system || 'system';
    const theSystem = /^the\s/i.test(system) ? system : `the ${system}`;   // a page that names no system passes 'the system'
    const s = D.stats;
    let figure = 0;

    // Figure 1: the DFD with every ATT&CK threat-event location.
    {
      const slide = pptx.addSlide();
      const head = `Figure ${++figure}: Data Flow Diagram of ${theSystem} enumerated with `;
      addTitle(slide, D.profile.short ? fitTitle(head, D.profile.short, ' threat events') : `${head}threat events`);
      addSubtitle(slide, ['CSA Guide to Cyber Threat Modelling §3.2–3.3', 'STRIDE-LM + MITRE ATT&CK',
        plural(s.elements, 'element', 'elements'), plural(s.flows, 'data flow', 'data flows'),
        plural(s.zones, 'trust zone', 'trust zones'),
        plural(s.events, 'threat event', 'threat events') + severityText(s.high, s.medium, s.low)].join('  ·  '));
      drawDiagram(slide, P, { ai: false, faded: false });
      drawLegend(slide, P, false);
      if (!D.elements.length) addNote(slide, P, 'The decomposition has no elements to draw.');
      else if (D.locations.some(l => l.ai) && !D.locations.some(l => !l.ai)) {
        const aiFigure = 2 + D.sequences.filter(q => !q.ai).length;
        addNote(slide, P, `No ATT&CK threat events were raised; the AI threat events are shown in Figure ${aiFigure}.`);
      } else if (!D.locations.length) {
        addNote(slide, P, 'No threat events were raised, so the diagram carries no threat-event locations.');
      }
    }

    // One attack-modelling slide per sequence: the path over the faded DFD.
    const sequenceSlide = seq => {
      const slide = pptx.addSlide();
      const id = seq.id ? ` ${seq.id}` : '';
      if (seq.ai) {
        addTitle(slide, `Figure ${++figure}: AI attack modelling — MAESTRO/ATLAS attack sequence${id} over the DFD`);
      } else {
        // The sequence's threat actors as the register names them (the caption's "Threat actor"); their
        // short form, or the first of them, when that is long. A generic attacker is no profile to name.
        const head = `Figure ${++figure}: Attack modelling — `;
        const tail = ` attack sequence${id} over the DFD`;
        const actors = sequenceActors(D, seq);
        let who = actors ? actors.label : '';
        if (who && textWidth(head + who + tail, TITLE_MIN, true) > TITLE_W && actors.short) who = actors.short;
        addTitle(slide, who ? fitTitle(head, who, tail) : `${head}${tail.slice(1)}`);
      }
      const path = pathOf(P, seq);
      const steps = new Set(seq.steps);
      const drawn = drawDiagram(slide, P, { ai: seq.ai, faded: true, path: new Set(path), steps });
      const avoid = drawPath(slide, P, path, drawn);
      drawSequenceBlock(slide, seq, avoid);
    };
    D.sequences.filter(q => !q.ai).forEach(sequenceSlide);

    // The AI figure and its attack sequences, when there are AI locations.
    if (D.locations.some(l => l.ai)) {
      const slide = pptx.addSlide();
      const v = knowledgeVersions(D);
      addTitle(slide, `Figure ${++figure}: AI threat actors — MAESTRO/ATLAS threats on ${theSystem} DFD`);
      addSubtitle(slide, ['CSA Guide to Cyber Threat Modelling §3 (AI extension)', 'MAESTRO 7-layer framework',
        `MITRE ATLAS${v.atlas ? ` v${v.atlas}` : ''}`,
        plural(s.aiEvents, 'AI threat event', 'AI threat events') + severityText(s.aiHigh, s.aiMedium, s.aiLow)
          + ` at ${plural(s.aiLocations, 'AI-pipeline element', 'AI-pipeline elements')}`,
      ].join('  ·  '));
      drawDiagram(slide, P, { ai: true, faded: false });
      drawLegend(slide, P, true);
      D.sequences.filter(q => q.ai).forEach(sequenceSlide);
    }

    // PptxGenJS stores the package uncompressed whenever an output type is named; deflate it with
    // the JSZip the vendored bundle carries (a stored package is still a valid file).
    let data = await pptx.write({ outputType: 'arraybuffer' });
    if (typeof global.JSZip === 'function') {
      try {
        const zip = await global.JSZip.loadAsync(data);
        data = await zip.generateAsync({ type: 'arraybuffer', compression: 'DEFLATE', compressionOptions: { level: 6 } });
      } catch (e) {
        // keep the stored package
      }
    }
    return new Blob([data], { type: PPTX_MIME });
  }

  global.TMDfd = { build, FILE_NAME };
})(window);
