/*
 * tm-parse.js — read an architecture or network diagram into the system decomposition the threat
 * model works on (CSA Guide to Cyber Threat Modelling §3.2): elements, data flows and trust zones.
 *
 * Global `TMParse`. Reads draw.io files (.drawio / .xml, compressed or not, every page, and draw.io's
 * .svg and .png exports, which carry the diagram), PowerPoint slides drawn with shapes, icons and
 * connectors, and the model's own JSON. A picture (or a slide that is only a picture) has no geometry to
 * read: it comes back as { image } for Claude to read, or for decomposing by hand. No network access here.
 *
 * Model: {
 *   version, name, source: { kind, file, method },
 *   page: { w, h } | null,                         coordinate space of the geometry below (from 0, 0)
 *   zones:    [{ id, label, parent, geometry }],   trust zones (CSA trust boundaries), nested by parent
 *   elements: [{ id, label, type, zone, geometry, context: { purpose, sensitivity, auth, trust },
 *                crownJewel, ai }],                 crownJewel / ai: true, false or null (work it out)
 *   flows:    [{ id, source, target, label, bidirectional }],
 *   notes:    [string],                            what reading the file found that can't be worked out again
 *   warnings: [string],                            the notes plus the CSA §3.2 checks, recomputed by finish()
 * }
 * geometry is { x, y, w, h } or null; type is entity | process | cluster | datastore.
 */
(function (global) {
  'use strict';

  const TYPES = ['entity', 'process', 'cluster', 'datastore'];
  const TYPE_LABELS = { entity: 'External entity', process: 'Process', cluster: 'Cluster of processes', datastore: 'Data store' };

  // Words that say what a shape is when its style doesn't (from the cyber-threat-modelling skill).
  const DATASTORE_WORDS = ['database', 'db', 'data store', 'datastore', 'storage', 'bucket', 'repository', 'repo',
    'archive', 'data lake', 'warehouse', 'historian', 'file share', 'fileshare', 's3', 'blob', 'queue', 'cache', 'backup'];
  const ENTITY_WORDS = ['user', 'customer', 'client', 'actor', 'admin', 'operator', 'employee', 'third party',
    'third-party', 'vendor', 'supplier', 'partner', 'internet', 'external', 'public', 'citizen', 'staff',
    'contractor', 'browser', 'mobile'];
  const BOUNDARY_WORDS = ['dmz', 'trust', 'boundary', 'zone', 'network', 'vlan', 'segment', 'internal', 'external',
    'corporate', 'cloud', 'on-prem', 'enclave', 'perimeter', 'vpc', 'subnet', 'tier', 'level', 'environment',
    'layer', 'plane', 'domain'];
  // Icon libraries (draw.io's AWS, Azure, Cisco… shapes) name what they draw. Short names count only as whole
  // words, so 'aws3' isn't S3 and 'cards' isn't RDS.
  const ICON_DATASTORE = /database|datastore|dynamodb|aurora|storage|bucket|blob|cosmos|sql|disk|vault|backup|archive|file_?share|cache|redis|glacier|(^|[^a-z0-9])(db|rds|s3|nas|san|efs|ebs|tables?)([^a-z0-9]|$)/;
  const ICON_ENTITY = /user|client|actor|person|people|mobile|laptop|workstation|internet|customer|employee/;
  // draw.io's storage symbols: cylinders, the flowchart data, internal, direct-access and sequential stores, tape,
  // and a table (an ER entity) that a connector is glued to.
  const STORE_SHAPE = /cylinder|data_?stor|database|disk|internal_?storage|stored_data|direct_data|sequential_data|^tape$|^table$/;

  const CONTEXT_KEYS = {
    purpose: ['purpose', 'description', 'role', 'function'],
    sensitivity: ['sensitivity', 'data', 'classification', 'data_classification', 'dataclassification'],
    auth: ['auth', 'authentication', 'authn', 'access'],
    trust: ['trust', 'trust_level', 'trustlevel'],
  };
  const YES = /^(yes|y|true|1|x)$/i;
  const NO = /^(no|n|false|0)$/i;

  // How much one file may make the reader do, so a crafted file can't freeze or crash the tab.
  const LIMITS = { label: 500, context: 4000, name: 200, id: 200, note: 1000, notes: 100, items: 2000, raw: 20000 };
  const MB = 1024 * 1024;
  const MAX_INFLATED = 50 * MB;   // a draw.io page or PNG text chunk, unpacked
  const MAX_PART = 30 * MB, MAX_PICTURE = 40 * MB, MAX_PPTX = 300 * MB, MAX_SLIDES = 300, MAX_SHAPES = 5000;
  // Parsing XML is what takes the time: a deck's slides are read until DECK_XML of their XML, or DECK_SHAPES shapes
  // (the reference DFD deck is 2 MB and 2,500 shapes); a draw.io file or page over MAX_TAGS tags isn't parsed, and
  // a page's first MAX_CELLS cells are read.
  const DECK_XML = 16 * MB, DECK_SHAPES = 20000, MAX_TAGS = 400000, MAX_CELLS = 50000;
  const MAX_FILE = 100 * MB, MAX_DECK = 500 * MB;   // an upload: a deck may carry media; nothing else needs this much
  const MAX_PAGES = 50, PAGE_CELLS = 10000;   // draw.io pages looked at, and the cells read across them
  const GEO_LIMIT = 3000;         // beyond this many shapes, containment isn't tested pair by pair
  const MAX_POINTS = 64;          // points kept of a freeform's path

  const NUMBER = /^\s*[(#]?\d{1,4}[.)]?\s*$/;   // a step or threat marker, not a name
  // Words with a connector attached that are a note on the diagram, not the name of a part of it: a marker's
  // number, more than a name's 80 characters, 'Note:', 'Risk 2:' and the like, or a sentence.
  const NOTE = /^\s*(notes?|nb|risks?|threats?|issues?|assumptions?|warnings?|cautions?|caveats?|comments?|remarks?|todo|to do|questions?|mitigations?|findings?|gaps?|vulnerabilit(y|ies)|weakness(es)?|important)(\s*[#(]?\d{1,3}\)?)?\s*:/i;
  const remarkText = t => NUMBER.test(t) || t.length > 80 || NOTE.test(t) || (/[.!?]$/.test(t) && t.split(/\s+/).length >= 4);
  const LEGEND = /^(legend|key|diagram key|notation)\s*:?$/i;
  // What a legend calls the notation: a shape so named and joined to nothing is a legend sample.
  const NOTATION = /^(external entit(y|ies)|entit(y|ies)|process(es)?|cluster of processes|process clusters?|multiple processes|complex process(es)?|data ?stores?|trust boundar(y|ies)|trust zones?|boundar(y|ies)|data ?flows?|threats?|threat events?|interactors?|actors?)\s*:?$/i;
  const NOTATION_FLOW = /^(data ?flows?|dataflows?)\b/i;
  const DEFAULT_PAGE = /^((page|seite|página|pagina|pàgina|strona|sida|side|sivu|stránka|oldal|страница|сторінка|ページ|页面?|頁|페이지)[\s-]*\d+|第\s*\d+\s*页)$/i;

  // Text and numbers from a file or a saved model: an object (crafted JSON) is no text and no number.
  const scalar = v => v != null && typeof v !== 'object' && typeof v !== 'function';
  const words = s => (s && scalar(s) ? String(s) : '').toLowerCase();
  const str = v => (scalar(v) ? String(v).trim() : '');
  const num = v => (typeof v === 'number' ? v : typeof v === 'string' && v.trim() ? +v : NaN);
  /** Whole-word match, so 'db' doesn't fire on 'feedback' and 'user' does on 'Users'. One pattern per word list. */
  const wordPatterns = new WeakMap();
  const hasWord = (text, list) => {
    let re = wordPatterns.get(list);
    if (!re) {
      re = new RegExp('(^|[^a-z0-9])(' + list.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')s?([^a-z0-9]|$)');
      wordPatterns.set(list, re);
    }
    return re.test(text);
  };
  /** Cut text to n characters, marking the cut. */
  function clip(text, n) {
    const s = String(text);
    if (s.length <= n) return s;
    let t = s.slice(0, n - 1);
    if (/[\ud800-\udbff]$/.test(t)) t = t.slice(0, -1);
    return t + '…';
  }

  /** Plain text of an HTML label as draw.io shows it: tags dropped, entities decoded, line breaks as spaces. */
  function stripHtml(value) {
    const html = String(value == null ? '' : value).slice(0, LIMITS.raw);
    if (!/[<&]/.test(html)) return html.replace(/\s+/g, ' ').trim();
    // the browser's own HTML parser: every entity, out-of-range references as U+FFFD, nothing run or fetched
    const body = new DOMParser().parseFromString(html, 'text/html').body;
    if (!body) return '';
    for (const n of body.querySelectorAll('script, style, template, noscript')) n.remove();
    for (const n of body.querySelectorAll('br, div, p, li, tr, td, th, h1, h2, h3, h4, h5, h6, ul, ol, table, hr')) { n.before(' '); n.after(' '); }
    return (body.textContent || '').replace(/\s+/g, ' ').trim();
  }
  const plainText = value => String(value == null ? '' : value).slice(0, LIMITS.raw).replace(/\s+/g, ' ').trim();
  /** A draw.io label is HTML only when its style says html=1; otherwise '<' and '&' are just text. */
  const labelText = (value, style) => (style.html === '1' ? stripHtml(value) : plainText(value));

  function styleDict(style) {
    const out = {};
    for (const part of String(style || '').split(';')) {
      if (!part) continue;
      const i = part.indexOf('=');
      if (i < 0) out[part.trim().toLowerCase()] = '1';
      else out[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
    }
    return out;
  }

  function normaliseType(value) {
    const v = words(value).replace(/[^a-z]/g, '');
    if (!v) return null;
    if (/^(entity|externalentity|external|actor|interactor)$/.test(v)) return 'entity';
    if (/^(cluster|processcluster|clusterofprocesses|multipleprocess|multiprocess|complexprocess)$/.test(v)) return 'cluster';
    if (/^(datastore|store|database|data)$/.test(v)) return 'datastore';
    if (/^(process|service|application|app|system)$/.test(v)) return 'process';
    return null;
  }

  const flag = v => (!str(v) ? null : YES.test(str(v)) ? true : NO.test(str(v)) ? false : null);

  /** Context and flags from a draw.io object's own properties (Edit Data), or a context JSON entry: plain text. */
  function contextFrom(attrs) {
    const lower = {};
    for (const [k, v] of Object.entries(attrs || {})) lower[k.toLowerCase().replace(/[\s-]/g, '_')] = v;
    const context = {};
    for (const [key, names] of Object.entries(CONTEXT_KEYS)) {
      const name = names.find(n => str(lower[n]));
      context[key] = name ? plainText(lower[name]) : '';
    }
    return {
      context,
      type: normaliseType(lower.type || lower.csa_type || lower.element_type),
      crownJewel: flag(lower.crown_jewel ?? lower.crownjewel ?? lower.crown),
      ai: flag(lower.ai ?? lower.ai_element),
    };
  }

  // ---------------------------------------------------------------- draw.io

  function bytesFromBase64(text) {
    const bin = atob(String(text).replace(/\s+/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function tooLarge() {
    const e = new Error('The file is too large to read.');
    e.tooLarge = true;
    return e;
  }
  function concat(chunks, total) {
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
    return out;
  }
  /** Unpack deflate data ('deflate' or 'deflate-raw') as text, giving up past `limit` bytes. */
  async function inflateText(bytes, format, limit = MAX_INFLATED) {
    const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format)).getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) { reader.cancel().catch(() => {}); throw tooLarge(); }
      chunks.push(value);
    }
    return new TextDecoder().decode(concat(chunks, total));
  }

  /** draw.io stores a diagram deflated, base64'd and URL-encoded inside <diagram>. */
  async function decompressDiagram(text, limit) {
    let inflated;
    try {
      inflated = await inflateText(bytesFromBase64(text), 'deflate-raw', limit);
    } catch (e) {
      if (e.tooLarge) throw e;
      return null;
    }
    try { return decodeURIComponent(inflated); } catch (_) { return inflated; }
  }

  /** Whether XML text has more than MAX_TAGS tags, counted without parsing it (parsing millions takes many seconds). */
  function tooManyTags(text) {
    let n = 0;
    for (let i = text.indexOf('<'); i >= 0; i = text.indexOf('<', i + 1)) if (++n > MAX_TAGS) return true;
    return false;
  }

  function parseXml(text) {
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    if (doc.getElementsByTagName('parsererror').length) throw new Error("The file isn't well-formed XML.");
    return doc;
  }

  /**
   * Visit each page of a draw.io file as visit(<mxGraphModel>, name, index), one at a time: a compressed page is
   * unpacked and read before the next, so only one page's XML is held. A file can't make this endless: past
   * MAX_PAGES pages, PAGE_CELLS cells or MAX_INFLATED unpacked bytes in all, the rest are left with a note.
   * Returns { count: the file's pages, looked: how many were looked at, notes on pages too large or broken to read }.
   */
  async function eachPage(text, visit) {
    const NONE_FOUND = 'No draw.io diagram found in the file. In draw.io, use File > Export as > XML.';
    const CROWDED = 'This draw.io file is too large to read: it has more shapes than the browser can read in one go. '
      + 'Copy the page you want into a draw.io file of its own and upload that.';
    if (tooManyTags(text)) throw new Error(CROWDED);
    const root = parseXml(text).documentElement;
    if (root.nodeName === 'mxGraphModel') { visit(root, '', 0); return { count: 1, looked: 1, notes: [] }; }
    const notes = [];
    const diagrams = [...root.getElementsByTagName('diagram')];
    if (!diagrams.length) {
      const inner = root.getElementsByTagName('mxGraphModel')[0];
      if (!inner) throw new Error(NONE_FOUND);
      visit(inner, '', 0);
      return { count: 1, looked: 1, notes };
    }
    let read = 0, cells = 0, unpacked = 0, big = false, crowded = false, looked = diagrams.length;
    for (const [i, d] of diagrams.entries()) {
      if (read && (read >= MAX_PAGES || cells >= PAGE_CELLS || unpacked >= MAX_INFLATED)) { looked = i; break; }
      const name = d.getAttribute('name') || '';
      const title = name ? `The page "${name}"` : `Page ${i + 1}`;
      let model = [...d.children].find(c => c.nodeName === 'mxGraphModel') || null;
      if (!model) {
        const body = (d.textContent || '').trim();
        if (!body) continue;
        let decoded = null;
        try {
          decoded = await decompressDiagram(body, MAX_INFLATED - unpacked);
        } catch (e) {
          if (unpacked) { looked = i; break; }   // over what is left of the file's allowance
          big = true;
          notes.push(`${title} is too large to read (over ${MAX_INFLATED / MB} MB unpacked), so it was skipped.`);
          continue;
        }
        if (decoded) {
          unpacked += decoded.length;
          if (tooManyTags(decoded)) {
            crowded = true;
            notes.push(`${title} is too large to read (it has more shapes than the browser can read in one go), so it was skipped.`);
            continue;
          }
          try {
            const m = parseXml(decoded).documentElement;
            model = m.nodeName === 'mxGraphModel' ? m : m.getElementsByTagName('mxGraphModel')[0] || null;
          } catch (_) { /* noted below */ }
        }
        if (!model) { notes.push(`${title} couldn't be read, so it was skipped.`); continue; }
      }
      cells += model.getElementsByTagName('mxCell').length;
      visit(model, name, i);
      read++;
    }
    if (!read) throw new Error(big ? `This draw.io file is too large to read (a page is over ${MAX_INFLATED / MB} MB unpacked).` : crowded ? CROWDED : NONE_FOUND);
    return { count: diagrams.length, looked, notes };
  }

  /** The style's own shape wins over a bare 'ellipse' key (draw.io's Cloud is 'ellipse;shape=cloud'). */
  const isEllipse = style => (style.shape ? words(style.shape).includes('ellipse') : style.ellipse === '1');
  /** The open-ended DFD store: a partial rectangle with its top and bottom lines and no right side. */
  const isOpenStore = style => words(style.shape) === 'partialrectangle' && style.right === '0' && style.top !== '0' && style.bottom !== '0';
  const isContainer = style => style.container === '1' || 'swimlane' in style || words(style.shape) === 'swimlane';
  /** What an icon is called: its stencil name and its picture's file name, never a picture's inline data. */
  function iconName(style) {
    const image = String(style.image || '');
    const file = /^data:/i.test(image) ? '' : words(image).split(/[?#]/)[0].split('/').pop();
    return [words(style.shape), words(style.resicon), file].join(' ');
  }

  /**
   * A trust zone: a shape that holds connected elements (as their parent, or drawn round them), a dashed
   * outline that is large or holds anything, a container, or a large box with no fill named like a zone.
   */
  function isTrustBoundary(style, label, g, holds) {
    const dashed = style.dashed === '1';
    const fill = words(style.fillcolor);
    const unfilled = fill === 'none' || fill === 'transparent';   // no fillColor is draw.io's default white fill
    const large = g.w * g.h >= 20000;   // roughly 200 x 100 or bigger
    const namedZone = hasWord(words(label), BOUNDARY_WORDS);
    const holdsAny = holds.child || holds.any > 0;
    if (holds.childConnected || holds.connected) return true;
    if (dashed && (large || holdsAny)) return true;
    if (isContainer(style) && (holdsAny || (large && namedZone))) return true;
    if (large && unfilled && namedZone) return true;
    return false;
  }

  /**
   * Shape style first, then the label. A plain rectangle is an external entity in a diagram drawn to the
   * CSA conventions (processes as circles); in a diagram of boxes it is more likely a system, so the label decides.
   */
  function classify(style, label, csaStyle) {
    const shape = words(style.shape);
    const low = words(label);
    if (STORE_SHAPE.test(shape) || isOpenStore(style)) return 'datastore';
    if (shape.includes('doubleellipse') || style.double === '1') return 'cluster';
    if (isEllipse(style)) return 'process';
    if (/actor|umlactor|stickman|person|externalentity/.test(shape)) return 'entity';
    if (shape.startsWith('mxgraph.') || 'image' in style) {
      const icon = iconName(style);
      if (ICON_DATASTORE.test(icon)) return 'datastore';
      if (ICON_ENTITY.test(icon)) return 'entity';
    }
    if (hasWord(low, DATASTORE_WORDS)) return 'datastore';
    if (hasWord(low, ENTITY_WORDS)) return 'entity';
    const rectangle = !shape || shape === 'rectangle' || shape === 'rect';
    if (rectangle && csaStyle && style.rounded !== '1' && !('image' in style)) return 'entity';
    return 'process';
  }

  const centre = g => ({ x: g.x + g.w / 2, y: g.y + g.h / 2 });
  const containsPoint = (g, p, pad = 0) => p.x >= g.x - pad && p.x <= g.x + g.w + pad && p.y >= g.y - pad && p.y <= g.y + g.h + pad;
  const area = g => (g ? g.w * g.h : Infinity);
  const distance = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
  /** How far a point is from a box (0 inside it). */
  const boxDistance = (g, p) => Math.hypot(Math.max(g.x - p.x, 0, p.x - g.x - g.w), Math.max(g.y - p.y, 0, p.y - g.y - g.h));
  /** Notes on connectors that aren't data flows: one per distinct note, with a count when it is about several. */
  function tally() {
    const seen = new Map();   // the note for one connector -> { n, many: the note for n }
    return {
      add: (one, many) => { const x = seen.get(one); if (x) x.n++; else seen.set(one, { n: 1, many }); },
      notes: () => [...seen].map(([one, x]) => (x.n === 1 ? one : x.many(x.n))),
    };
  }
  function segmentDistance(p, a, b) {
    const dx = b.x - a.x, dy = b.y - a.y;
    const len = dx * dx + dy * dy;
    const t = len ? Math.max(0, Math.min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / len)) : 0;
    return Math.hypot(p.x - a.x - t * dx, p.y - a.y - t * dy);
  }

  /** One draw.io page as zones, elements, flows and notes, before finish(). */
  function readPage(model) {
    const cells = new Map();
    const all = model.getElementsByTagName('mxCell');
    for (let k = 0; k < Math.min(all.length, MAX_CELLS); k++) {   // no diagram has more: a crafted page's others aren't read
      const cell = all[k];
      // <object label="…" purpose="…"><mxCell/></object> keeps the label and custom properties on the wrapper.
      const wrapper = cell.parentNode && ['object', 'UserObject'].includes(cell.parentNode.nodeName) ? cell.parentNode : null;
      const id = (wrapper && wrapper.getAttribute('id')) || cell.getAttribute('id');
      if (!id) continue;
      const attrs = {};
      if (wrapper) for (const a of wrapper.attributes) if (!['id', 'label', 'placeholders'].includes(a.name)) attrs[a.name] = a.value;
      const geo = [...cell.children].find(c => c.nodeName === 'mxGeometry');
      const finite = v => (Number.isFinite(v) ? v : 0);
      const num = n => (geo ? finite(parseFloat(geo.getAttribute(n))) : 0);
      const point = as => {
        if (!geo) return null;
        const p = [...geo.children].find(c => c.nodeName === 'mxPoint' && c.getAttribute('as') === as);
        return p ? { x: finite(parseFloat(p.getAttribute('x'))), y: finite(parseFloat(p.getAttribute('y'))) } : null;
      };
      const style = cell.getAttribute('style') || '';
      cells.set(id, {
        id, attrs,
        raw: wrapper ? wrapper.getAttribute('label') ?? cell.getAttribute('value') : cell.getAttribute('value'),
        placeholders: !!wrapper && wrapper.getAttribute('placeholders') === '1',
        style: styleDict(style),
        picture: style.includes('image=data:image/') ? style : null,   // a picture pasted in: its data, in case the page is only that
        parent: cell.getAttribute('parent'),
        visible: cell.getAttribute('visible') !== '0',
        isEdge: cell.getAttribute('edge') === '1',
        isVertex: cell.getAttribute('vertex') === '1',
        source: cell.getAttribute('source'),
        target: cell.getAttribute('target'),
        x: num('x'), y: num('y'), w: num('width'), h: num('height'),
        sourcePoint: point('sourcePoint'), targetPoint: point('targetPoint'),
      });
    }
    // Parent chains can be long (a crafted file can nest cells thousands deep), so a walk up one is done once
    // per cell and remembered.
    const up = c => cells.get(c.parent);
    /** For a test, the function giving a cell's nearest ancestor that passes it, or null. */
    const above = test => {
      const memo = new Map();   // cell id -> the nearest cell at or above it that passes
      return c => {
        const path = [];
        let hit = null;
        for (let n = up(c), seen = new Set([c.id]); n && !seen.has(n.id); n = up(n)) {
          if (memo.has(n.id)) { hit = memo.get(n.id); break; }
          seen.add(n.id);
          path.push(n);
          if (test(n)) { hit = n; break; }
        }
        for (const n of path) memo.set(n.id, hit);
        return hit;
      };
    };
    // draw.io's placeholders="1": %name% shows the property of that name on the cell or the nearest ancestor
    // that has one (looked for a few dozen levels up: no diagram nests deeper)
    const fill = cell => {
      let n = 0;
      return String(cell.raw == null ? '' : cell.raw).slice(0, LIMITS.raw).replace(/%([^%\s]+)%/g, (whole, key) => {
        if (key === 'id') return cell.id;
        if (key === 'label' || key === 'tooltip' || ++n > 50) return whole;
        for (let c = cell, depth = 0, seen = new Set(); c && depth < 50 && !seen.has(c.id); c = up(c), depth++) {
          seen.add(c.id);
          if (Object.prototype.hasOwnProperty.call(c.attrs, key)) return String(c.attrs[key]).slice(0, LIMITS.raw);
        }
        return whole;
      });
    };
    for (const c of cells.values()) c.label = labelText(c.placeholders ? fill(c) : c.raw, c.style);

    const notes = [];
    if (all.length > MAX_CELLS) notes.push(`This page has ${all.length.toLocaleString('en')} cells; only the first ${MAX_CELLS.toLocaleString('en')} were read.`);
    // Hidden layers and cells aren't part of what the diagram shows.
    const hidden = new Map();
    const isHidden = c => {
      const path = [];
      let h = false;
      for (let n = c, seen = new Set(); n && !seen.has(n.id); n = cells.get(n.parent)) {
        if (hidden.has(n.id)) { h = hidden.get(n.id); break; }
        seen.add(n.id);
        path.push(n);
        if (!n.visible) { h = true; break; }
      }
      for (const n of path) hidden.set(n.id, h);
      return h;
    };
    const drawn = [...cells.values()].filter(c => c.isVertex || c.isEdge);
    const drawnIn = new Set(drawn.map(c => c.parent));
    const hiddenLayers = [...cells.values()].filter(l => !l.visible && !l.isVertex && !l.isEdge && drawnIn.has(l.id));
    if (hiddenLayers.length) {
      const names = hiddenLayers.map(l => `"${l.label || 'unnamed'}"`).join(', ');
      notes.push(`The hidden layer${hiddenLayers.length === 1 ? '' : 's'} ${names} ${hiddenLayers.length === 1 ? "wasn't" : "weren't"} read.`);
    }

    // Where a cell sits on the page: draw.io keeps a child's coordinates relative to its container.
    const origins = new Map();
    const origin = cell => {
      const path = [];
      let o = { x: 0, y: 0 };
      for (let n = cell, seen = new Set(); n && !n.isEdge && !seen.has(n.id); n = up(n)) {
        if (origins.has(n.id)) { o = origins.get(n.id); break; }
        seen.add(n.id);
        path.push(n);
      }
      for (let i = path.length - 1; i >= 0; i--) {
        o = { x: o.x + path[i].x, y: o.y + path[i].y };
        origins.set(path[i].id, o);
      }
      return o;
    };
    const absolute = c => { const o = origin(c); return { x: o.x, y: o.y, w: c.w, h: c.h }; };

    const isText = c => 'text' in c.style || 'edgelabel' in c.style;
    const isGroup = c => !!c && (c.style.group === '1' || 'group' in c.style);
    const isTable = c => words(c.style.shape) === 'table';
    const tableAbove = above(isTable);
    const edges = [], texts = [];
    let shapes = [];
    const edgeLabels = new Map();   // edge id -> text of label cells attached to it
    for (const c of drawn) {
      if (isHidden(c)) continue;
      if (c.isEdge) {   // draw.io doesn't draw a connector whose end is hidden
        if (![c.source, c.target].some(id => id && cells.has(id) && isHidden(cells.get(id)))) edges.push(c);
        continue;
      }
      const parent = up(c);
      if (parent && parent.isEdge) {   // a label placed on a connector
        if (c.label) edgeLabels.set(parent.id, [edgeLabels.get(parent.id), c.label].filter(Boolean).join(' '));
        continue;
      }
      if (tableAbove(c)) continue;   // a table's rows and cells are its text, not shapes of their own
      c.g = absolute(c);
      if (isText(c)) { if (c.label) texts.push(c); continue; }
      if (isGroup(c)) continue;
      shapes.push(c);
    }
    // A table is a data store (an ER entity) when a connector is glued to it or to one of its rows; otherwise
    // it annotates the diagram (a key, a list of notes).
    const gluedTables = new Set();
    for (const e of edges) {
      for (const id of [e.source, e.target]) {
        const c = id ? cells.get(id) : null;
        for (let t = c && (isTable(c) ? c : tableAbove(c)), seen = new Set(); t && !seen.has(t.id); t = tableAbove(t)) {
          seen.add(t.id);
          gluedTables.add(t.id);
        }
      }
    }
    shapes = shapes.filter(s => !isTable(s) || gluedTables.has(s.id));
    const shapeIds = new Set(shapes.map(s => s.id));
    const textIds = new Set(texts.map(t => t.id));
    /** The nearest shape a cell sits in, looking through groups. */
    const shapeParent = above(a => shapeIds.has(a.id));

    // A legend (a container, group or box titled Legend or Key) explains the notation: nothing in it is the system.
    const extent = shapes.reduce((m, s) => ({ x0: Math.min(m.x0, s.g.x), y0: Math.min(m.y0, s.g.y), x1: Math.max(m.x1, s.g.x + s.g.w), y1: Math.max(m.y1, s.g.y + s.g.h) }),
      { x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity });
    const pageArea = Math.max(0, extent.x1 - extent.x0) * Math.max(0, extent.y1 - extent.y0);
    const legends = [];   // { box, inside(cell) }
    let titled = 0;
    for (const t of [...shapes, ...texts]) {
      if (!LEGEND.test(t.label)) continue;
      if (++titled > 20) break;   // a diagram has a legend or two: a crafted file's thousands aren't each tried
      let box = shapeIds.has(t.id) ? t : null;
      if (!box) {
        const p = up(t);
        if (p && p.isVertex && !p.isEdge) { if (!p.g) p.g = absolute(p); box = p; }
        else box = shapes.filter(s => containsPoint(s.g, centre(t.g))).sort((a, b) => area(a.g) - area(b.g))[0] || null;
      }
      if (!box || !box.g || area(box.g) > pageArea / 4 || legends.some(l => l.box === box)) continue;
      const under = above(a => a === box);
      const inside = c => !!under(c) || (!!c.g && containsPoint(box.g, centre(c.g)));
      const members = [...shapes, ...texts].filter(c => c !== box && c !== t && inside(c));
      const crosses = edges.some(e => {
        const a = cells.get(e.source), b = cells.get(e.target);
        return a && b && inside(a) !== inside(b);
      });
      if (members.length && !crosses) legends.push({ box, inside });
    }
    const legendCell = c => legends.some(l => c === l.box || l.inside(c));
    const legendEdge = e => {
      const par = up(e);
      if (par && legendCell(par)) return true;
      const ends = [cells.get(e.source), cells.get(e.target)].filter(Boolean);
      return ends.length > 0 && ends.every(legendCell);
    };
    const live = shapes.filter(s => !legendCell(s));
    const liveTexts = texts.filter(t => !legendCell(t));
    const liveEdges = edges.filter(e => !legendEdge(e));
    const liveIds = new Set(live.map(s => s.id));

    // Which way a connector runs: draw.io draws an end arrow by default, a start arrow only when the style names
    // one. `along`: its data goes from its source end to its target end (and both ways when it has both arrows).
    const noArrow = v => v === 'none' || v === '';
    const runs = cell => {
      const forward = !noArrow(words(cell.style.endarrow)) || !('endarrow' in cell.style);
      const backward = 'startarrow' in cell.style && !noArrow(words(cell.style.startarrow));
      return { forward, backward, along: forward || !backward };
    };
    // Text a connector is glued to that stands on its own (on the page, or in a container or dashed zone, not
    // inside a shape) is a node of its own ('Internet'), unless it turns out to name a shape it sits on.
    const liveTextIds = new Set(liveTexts.map(t => t.id));
    const stuck = new Set();   // ids of such texts
    // of those, the ones a connector drawn like a flow is glued to: a leader line has no arrowhead, or is dashed,
    // where the diagram's other connectors have arrowheads, or are solid
    const arrowed = new Set();
    const headed = e => { const w = runs(e); return w.forward || w.backward; };
    const arrowsUsed = liveEdges.some(headed), solidUsed = liveEdges.some(e => e.style.dashed !== '1');
    const gluedEnds = new Map();   // such a text's id -> the cells at the other ends of its connectors
    for (const e of liveEdges) {
      const arrow = !(arrowsUsed && !headed(e)) && !(solidUsed && e.style.dashed === '1');
      for (const [id, other] of [[e.source, e.target], [e.target, e.source]]) {
        if (!id || !liveTextIds.has(id)) continue;
        if (!stuck.has(id)) {
          const holder = shapeParent(cells.get(id));
          if (holder && !isContainer(holder.style) && holder.style.dashed !== '1') continue;
          stuck.add(id);
          gluedEnds.set(id, []);
        }
        if (arrow) arrowed.add(id);
        gluedEnds.get(id).push(other ? cells.get(other) : null);
      }
    }
    // Shapes a connector is glued to, directly or through a text cell inside them.
    const direct = new Set();
    for (const e of liveEdges) {
      for (const id of [e.source, e.target]) {
        let c = id && !stuck.has(id) ? cells.get(id) : null;
        if (c && textIds.has(c.id)) c = cells.get(c.parent);
        if (c) direct.add(c.id);
      }
    }

    // Labels drawn as separate text cells: a shape's child text, its caption in the same group, or, for an
    // icon or a shape a connector is glued to, the text on or just below it (so a title banner, a box with
    // a heading on it, doesn't become an element). Decorations inside a labelled shape belong to that shape.
    // A number is a step or threat marker, unless a connector is glued to it: then it is a numbered process
    // (a DFD bubble), named by its caption when it has one.
    const usedText = new Set();
    const captionOf = new Map();   // glued text id -> the shape it names
    const stuckTexts = liveTexts.filter(t => stuck.has(t.id));
    const freeText = pred => liveTexts.filter(t => !usedText.has(t) && pred(t));
    const textsOf = new Map();   // cell id -> the text cells that are its children
    for (const t of liveTexts) { if (!textsOf.has(t.parent)) textsOf.set(t.parent, []); textsOf.get(t.parent).push(t); }
    const freeIn = (id, pred) => (textsOf.get(id) || []).filter(t => !usedText.has(t) && pred(t));
    /** The cell of the list nearest p (the first of equals), in one pass: no sort for each shape that looks. */
    const nearestTo = (list, p) => {
      let best = null, bestD = Infinity;
      for (const t of list) { const d = distance(centre(t.g), p); if (d < bestD) { best = t; bestD = d; } }
      return best;
    };
    const decoration = s => { const p = shapeParent(s); return !!p && !!p.label && !isContainer(p.style); };
    // Searching text by text for each unnamed shape is for pages of a size people draw: a crafted file of
    // thousands of each would make it endless.
    const bare = live.filter(c => (!c.label || NUMBER.test(c.label)) && c.style.dashed !== '1' && !isContainer(c.style)).length;
    const pairwise = bare * liveTexts.length <= GEO_LIMIT * GEO_LIMIT;
    const holding = new Set();   // shapes that hold shapes, by the file's parent links
    for (const s of live) { const p = shapeParent(s); if (p) holding.add(p.id); }
    const holdsShapes = c => holding.has(c.id) || live.some(s => s !== c && area(s.g) < area(c.g) && containsPoint(c.g, centre(s.g)));
    const iconLike = c => 'image' in c.style || words(c.style.shape).startsWith('mxgraph.');
    const numberedEnd = s => !!s.label && NUMBER.test(s.label) && direct.has(s.id) && !decoration(s);
    for (const c of live) {
      if ((c.label && !numberedEnd(c)) || c.style.dashed === '1' || isContainer(c.style) || decoration(c)) continue;
      if (live.length <= GEO_LIMIT && holdsShapes(c)) continue;   // a panel with shapes on it is named below, if it's a zone
      const cg = centre(c.g);
      const reach = 2 * Math.max(c.g.w, c.g.h) + 40;
      const below = t => {
        const tc = centre(t.g);
        return tc.x >= c.g.x - 10 && tc.x <= c.g.x + c.g.w + 10 && tc.y >= c.g.y + c.g.h && tc.y <= c.g.y + c.g.h + Math.max(40, c.g.h * 0.75);
      };
      // a shape with several glued words on it is a panel they stand on: none of them is its name
      let n = 0;
      if (pairwise && stuckTexts.length > 1) for (const x of stuckTexts) if (containsPoint(c.g, centre(x.g)) && ++n > 1) break;
      const name = x => n < 2 || !stuck.has(x.id);
      const t = nearestTo(freeIn(c.id, () => true), cg)
        || (pairwise && isGroup(up(c)) ? nearestTo(freeIn(c.parent, x => name(x) && distance(centre(x.g), cg) <= reach), cg) : null)
        || (pairwise && (iconLike(c) || direct.has(c.id))
          ? nearestTo(freeText(x => x.label.length <= 80 && name(x) && (containsPoint(c.g, centre(x.g)) || below(x))), cg) : null)
        || (pairwise && stuck.size && n < 2 ? nearestTo(stuckTexts.filter(x => !usedText.has(x) && containsPoint(c.g, centre(x.g))), cg) : null);
      if (!t) continue;
      c.label = t.label;
      usedText.add(t);
      if (stuck.has(t.id)) { captionOf.set(t.id, c); direct.add(c.id); }   // a connector glued to its name is the shape's
    }
    // The other glued texts are elements, read with the shapes from here on (in the file's order), unless they are
    // a note on the diagram (remarkText) or only leader lines are glued to them: those stay text (a zone's title,
    // say). A note drawn on a labelled shape with an arrow glued to it is that shape's, as a badge is (below).
    const drawIndex = new Map(drawn.map((c, i) => [c.id, i]));
    const remarks = [];
    for (const t of stuckTexts) {
      if (usedText.has(t)) continue;
      if (!arrowed.has(t.id) || remarkText(t.label)) { if (arrowed.has(t.id)) remarks.push(t); continue; }
      t.textElement = true;
      usedText.add(t);
      direct.add(t.id);
      live.push(t);
      liveIds.add(t.id);
    }
    if (live.some(c => c.textElement)) live.sort((a, b) => drawIndex.get(a.id) - drawIndex.get(b.id));

    // A number (or a word) drawn on a labelled shape (draw.io leaves it beside the shape, not in it) with a
    // connector glued to it is a step or threat badge (a note on the shape): the connector is the shape's, and
    // the badge doesn't make the shape a trust zone. Numbers joined to something else on the same shape are
    // numbered processes in a zone.
    const badgeOf = new Map();   // badge id -> the shape it is drawn on
    if (live.length <= GEO_LIMIT) {
      const boxes = live.filter(b => b.label && !NUMBER.test(b.label) && b.style.dashed !== '1' && !isContainer(b.style) && area(b.g) > 0);
      const notesToo = remarks.length * boxes.length <= GEO_LIMIT * GEO_LIMIT ? remarks : [];
      for (const s of notesToo.length ? live.concat(notesToo) : live) {
        if (!numberedEnd(s) && !s.textElement && !stuck.has(s.id)) continue;
        const c = centre(s.g);
        let box = null;
        for (const b of boxes) if (b !== s && area(b.g) > area(s.g) && containsPoint(b.g, c) && (!box || area(b.g) < area(box.g))) box = b;
        if (box) badgeOf.set(s.id, box);
      }
      const shapeOf = c => (!c ? c : captionOf.get(c.id) || (textIds.has(c.id) && !c.textElement ? cells.get(c.parent) : c));
      for (const e of badgeOf.size ? liveEdges : []) {
        const ends = [shapeOf(cells.get(e.source)), shapeOf(cells.get(e.target))];
        ends.forEach((x, i) => {
          const box = x && badgeOf.get(x.id), other = ends[1 - i];
          if (box && other && other.g && containsPoint(box.g, centre(other.g))) badgeOf.delete(x.id);
        });
      }
    }

    const named = s => !badgeOf.has(s.id) && !!s.label && (!NUMBER.test(s.label) || numberedEnd(s));
    const unnamedEnd = s => !s.label && direct.has(s.id) && !decoration(s);
    const elementish = live.filter(s => named(s) || unnamedEnd(s));
    const elementishIds = new Set(elementish.map(s => s.id));
    // What each shape holds: elements as its children, or elements whose centre it is drawn round.
    const holds = new Map();
    const holdOf = s => {
      if (!holds.has(s.id)) holds.set(s.id, { child: false, childConnected: false, any: 0, connected: 0 });
      return holds.get(s.id);
    };
    for (const s of elementish) {
      const p = shapeParent(s);
      if (p && liveIds.has(p.id)) { const h = holdOf(p); h.child = true; if (direct.has(s.id)) h.childConnected = true; }
    }
    if (live.length <= GEO_LIMIT) {
      for (const outer of live) {
        const og = outer.g;
        if (!(area(og) > 0)) continue;
        for (const s of elementish) {
          if (s === outer || !(area(s.g) < area(og)) || !containsPoint(og, centre(s.g))) continue;
          const h = holdOf(outer);
          h.any++;
          if (direct.has(s.id)) h.connected++;
        }
      }
    }
    const NONE = { child: false, childConnected: false, any: 0, connected: 0 };

    // Trust zones. A shape a connector is glued to is an element, unless it holds connected elements.
    const zones = [];
    const zoneCells = new Map();
    const fromEdge = (z, t) => { const y = centre(t.g).y; return Math.min(Math.abs(y - z.g.y), Math.abs(z.g.y + z.g.h - y)); };
    /** The free text in a zone nearest its top or bottom edge (for a plain panel, only along an edge): its title. */
    const zoneTitle = (z, edgeOnly) => {
      const band = Math.max(40, z.g.h * 0.2);
      let best = null, bestD = Infinity;
      for (const t of liveTexts) {
        if (usedText.has(t) || badgeOf.has(t.id) || !containsPoint(z.g, centre(t.g))) continue;
        const d = fromEdge(z, t);
        if ((!edgeOnly || d <= band) && d < bestD) { best = t; bestD = d; }
      }
      return best;
    };
    // A word with a connector dropped on it, where an unnamed zone's title goes (the word nearest its top or bottom
    // edge, along it, in a zone that holds other elements, with nothing in the zone at the connectors' other ends),
    // names the zone: the connector ends on the zone.
    const titleOf = new Map();   // a glued title's id -> the zone cell it names
    const textElements = live.filter(c => c.textElement);
    const gluedTitle = z => {
      if (!((holds.get(z.id) || NONE).any >= 2)) return null;
      let best = null, bestD = Infinity;
      for (const t of textElements) {
        if (titleOf.has(t.id) || badgeOf.has(t.id) || !containsPoint(z.g, centre(t.g))) continue;
        const d = fromEdge(z, t);
        if (d < bestD) { best = t; bestD = d; }
      }
      const inside = o => !!o && !!o.g && containsPoint(z.g, centre(o.g));
      return best && bestD <= Math.max(40, z.g.h * 0.2) && !gluedEnds.get(best.id).some(inside) ? best : null;
    };
    const zoneCandidates = live.filter(c => {
      if (contextFrom(c.attrs).type || isTable(c) || c.textElement) return false;
      const h = holds.get(c.id) || NONE;
      if (direct.has(c.id) && !(h.childConnected || h.connected)) return false;
      return isTrustBoundary(c.style, c.label, c.g, h);
    }).sort((a, b) => area(a.g) - area(b.g));   // inner zones take their titles first
    const frames = new Set();
    const titling = zoneCandidates.filter(c => !c.label).length * liveTexts.length <= GEO_LIMIT * GEO_LIMIT;
    for (const c of zoneCandidates) {
      const plain = c.style.dashed !== '1' && !isContainer(c.style);
      let label = c.label, title = null;
      if (!label) {
        // an unlabelled outline is named by the text inside it nearest its top or bottom edge; a plain
        // panel with no such title is a background, not a zone
        title = titling ? zoneTitle(c, plain) || gluedTitle(c) : null;
        if (title) label = title.label; else if (plain) continue;
      }
      // A plain panel drawn round every element is the diagram's frame (and the text on it the diagram's
      // title), not a trust boundary, unless its name says it is one.
      const h = holds.get(c.id) || NONE;
      const others = elementish.length - (elementishIds.has(c.id) ? 1 : 0);
      if (plain && !direct.has(c.id) && others > 0 && h.any >= others && !hasWord(words(label), BOUNDARY_WORDS)) { frames.add(c.id); continue; }
      if (title) { usedText.add(title); if (stuck.has(title.id)) titleOf.set(title.id, c); }
      const z = { id: c.id, label: label || 'Unnamed trust zone', parent: null, geometry: c.g };
      zones.push(z);
      zoneCells.set(c.id, z);
    }
    // the file's own order, which numbering falls back on when shapes have no position
    const drawOrder = new Map(live.map((c, i) => [c.id, i]));
    zones.sort((a, b) => drawOrder.get(a.id) - drawOrder.get(b.id));
    // a badge on a shape that is a zone anyway (it holds elements of its own) is a numbered element in it
    for (const [id, box] of badgeOf) if (zoneCells.has(box.id) || frames.has(box.id)) badgeOf.delete(id);

    const elements = [];
    for (const c of live) {
      if (zoneCells.has(c.id) || frames.has(c.id) || titleOf.has(c.id) || !(named(c) || unnamedEnd(c))) continue;
      const info = contextFrom(c.attrs);
      elements.push({ id: c.id, label: c.label, type: info.type, zone: null, geometry: c.g,
        context: info.context, crownJewel: info.crownJewel, ai: info.ai, cell: c });
    }

    // Nesting from the file's own parent links: a zone inside a container zone, an element in its container.
    const zoneAbove = above(x => zoneCells.has(x.id));
    for (const z of zones) { const a = zoneAbove(cells.get(z.id)); z.parent = a ? a.id : null; }
    const zoneById = new Map(zones.map(z => [z.id, z]));
    // each zone's span in the tree those links make, so whether one zone is inside another is one comparison
    const kids = new Map(zones.map(z => [z.id, []]));
    for (const z of zones) if (z.parent && kids.has(z.parent)) kids.get(z.parent).push(z.id);
    const span = new Map();
    let tick = 0;
    for (const z of zones) {
      if (z.parent && kids.has(z.parent)) continue;
      span.set(z.id, [tick++, 0]);
      for (const stack = [[z.id, 0]]; stack.length;) {
        const top = stack[stack.length - 1], list = kids.get(top[0]);
        if (top[1] < list.length) { const k = list[top[1]++]; span.set(k, [tick++, 0]); stack.push([k, 0]); } else { span.get(top[0])[1] = tick++; stack.pop(); }
      }
    }
    const linkedIn = (id, outerId) => { const a = span.get(id), b = span.get(outerId); return !!a && !!b && b[0] < a[0] && a[1] < b[1]; };
    const nestedIn = (z, outerId) => {
      if (linkedIn(z.id, outerId)) return true;
      const og = zoneById.get(outerId).geometry;
      return area(z.geometry) < area(og) && containsPoint(og, centre(z.geometry));
    };
    const bySize = zones.slice().sort((a, b) => area(a.geometry) - area(b.geometry));
    for (const e of elements) {
      const zp = zoneAbove(e.cell);
      if (!zp) continue;   // geometry decides, in finish()
      // a zone drawn inside the container (and round the element) is more specific than the container
      const c = centre(e.geometry);
      const inner = zones.length * elements.length <= GEO_LIMIT * GEO_LIMIT
        ? bySize.find(z => containsPoint(z.geometry, c) && (z.id === zp.id || nestedIn(z, zp.id))) : null;
      e.zone = inner ? inner.id : zp.id;
    }

    const byId = new Map(elements.map(e => [e.id, e]));
    const near = p => {
      const hits = elements.filter(e => area(e.geometry) > 0 && containsPoint(e.geometry, p, 12)).sort((a, b) => area(a.geometry) - area(b.geometry));
      return hits.length ? hits[0].id : null;
    };
    const liveEdgeIds = new Set(liveEdges.map(e => e.id));
    // A connector drawn to a shape's child (its label, an icon inside it) or to its name belongs to the shape, and
    // one drawn to a zone's title to the zone. One drawn to another connector joins that connector's flow: where
    // its data goes (`into`), it goes on to where that flow goes; where it comes from, from where that flow does.
    const holderAbove = above(x => byId.has(x.id) || zoneCells.has(x.id));
    const end = (id, p, o, into, seen) => {
      if (!id) return { el: p ? near({ x: p.x + o.x, y: p.y + o.y }) : null };
      let c = cells.get(id);
      if (!c) return {};
      if (c.isEdge) {
        if (!liveEdgeIds.has(c.id) || seen.has(c.id) || seen.size > 50) return {};
        seen.add(c.id);
        const side = runs(c).along === into ? 'target' : 'source';
        const par = up(c);
        return end(c[side], c[side + 'Point'], par && par.isVertex ? origin(par) : { x: 0, y: 0 }, into, seen);
      }
      c = captionOf.get(c.id) || titleOf.get(c.id) || c;
      const badge = badgeOf.get(c.id) || (textIds.has(c.id) && badgeOf.get(c.parent));   // a badge, or the text in one
      if (badge) c = badge;
      const a = byId.has(c.id) || zoneCells.has(c.id) ? c : holderAbove(c);
      if (!a) return {};
      if (byId.has(a.id)) return { el: a.id };
      return a === c || (textIds.has(c.id) && c.parent === a.id) ? { zone: zoneCells.get(a.id).label } : {};
    };
    const flows = [];
    const lost = tally();
    for (const cell of liveEdges) {
      const label = [cell.label, edgeLabels.get(cell.id)].filter(Boolean).join(' ');
      // points of a connector with a loose end are relative to the container or group it was drawn in
      const par = up(cell);
      const o = par && par.isVertex ? origin(par) : { x: 0, y: 0 };
      const way = runs(cell);
      const a = end(cell.source, cell.sourcePoint, o, !way.along, new Set([cell.id]));
      const b = end(cell.target, cell.targetPoint, o, way.along, new Set([cell.id]));
      const src = a.el, tgt = b.el;
      const name = `Connector "${label || cell.id}"`, several = n => `${n} connectors labelled "${label}"`;
      if (src && tgt && src !== tgt) {
        flows.push({
          id: cell.id, label,
          source: way.along ? src : tgt,
          target: way.along ? tgt : src,
          bidirectional: way.forward && way.backward,
        });
      } else if (src && src === tgt) {
        const who = byId.get(src).label, whom = who ? `"${who}"` : 'an unnamed shape';
        lost.add(`${name} joins ${whom} to itself, so it isn't a data flow.`, n => `${several(n)} join ${whom} to itself, so they aren't data flows.`);
      } else if (a.zone || b.zone) {
        const zone = a.zone || b.zone;
        lost.add(`${name} ends on the trust zone "${zone}" rather than on an element in it, so it isn't a data flow.`,
          n => `${several(n)} end on the trust zone "${zone}" rather than on an element in it, so they aren't data flows.`);
      } else if ((src || tgt || cell.source || cell.target || cell.sourcePoint || cell.targetPoint) && !NOTATION_FLOW.test(label)) {
        lost.add(`${name} isn't joined to two elements, so it isn't a data flow.`, n => `${several(n)} aren't joined to two elements, so they aren't data flows.`);
      }
    }
    notes.push(...lost.notes());

    // Circles for processes (CSA Figure 3) make a plain rectangle an external entity: count only circles
    // that are joined into the data flows, so a cloud or a numbered marker doesn't switch the convention.
    const ends = new Set(flows.flatMap(f => [f.source, f.target]));
    const csaStyle = elements.some(e => isEllipse(e.cell.style) && ends.has(e.id));
    for (const e of elements) e.type = e.type || (e.cell.textElement ? classify({}, e.label, false) : classify(e.cell.style, e.label, csaStyle));   // a word: by its words
    // legend samples drawn without a legend box (notation names joined to nothing), and a lone legend title
    const kept = elements.filter(e => ends.has(e.id) || !(NOTATION.test(e.label) || LEGEND.test(e.label)));
    const keptZones = zones.filter(z => !NOTATION.test(z.label) || (holds.get(z.id) || NONE).any > 0 || (holds.get(z.id) || NONE).child);
    for (const e of kept) delete e.cell;
    // A page with no elements that holds a large picture pasted into draw.io is a picture of the diagram.
    let picture = null;
    for (const c of kept.length ? [] : live) if (c.picture && area(c.g) > 0 && (!picture || area(c.g) > area(picture.g))) picture = c;
    if (picture && area(picture.g) < pageArea / 10) picture = null;
    return { zones: keptZones, elements: kept, flows, notes, content: live.length + liveTexts.length + liveEdges.length,
      picture: picture ? picture.picture : null };
  }

  /**
   * A draw.io file as { model, picture }: the model of its diagram, and, from the first page that is only a
   * picture pasted into draw.io, that picture's cell style (or null).
   */
  async function readDrawio(text, file) {
    // the page with the most data flows (then elements) is the diagram: only its reading is kept
    const seen = [];
    let best = null, picture = null;
    const { count, looked, notes } = await eachPage(text, (model, name, index) => {
      const r = Object.assign(readPage(model), { name, index });
      seen.push({ name, index, flows: r.flows.length, elements: r.elements.length, content: r.content });
      if (!picture && r.picture) picture = { style: r.picture, page: name && !DEFAULT_PAGE.test(name.trim()) ? `page "${name}"` : `page ${index + 1}` };
      if (!best || r.flows.length > best.flows.length || (r.flows.length === best.flows.length && r.elements.length > best.elements.length)) best = r;
    });
    // say which pages were left
    const title = r => (r.name ? `"${r.name}"` : `page ${r.index + 1}`);
    const others = seen.filter(r => r.index !== best.index && r.content > 0);
    const cut = looked < count ? `, and the first ${looked} were looked at (reading them all would take too long)` : '';
    if (others.length) {
      const tie = others.some(r => r.flows === best.flows.length && r.elements === best.elements.length);
      const most = best.flows.length ? 'data flows' : 'elements';
      const why = !best.flows.length && !best.elements.length ? 'the first page'
        : tie ? `the first of the pages with the most ${most}` : `the page with the most ${most}`;
      const left = others.length > 5 ? `${others.slice(0, 5).map(title).join(', ')} and ${others.length - 5} more` : others.map(title).join(', ');
      notes.unshift(`This file has ${count} pages${cut}: ${title(best)} was read, as ${why}; ${left} ${others.length === 1 ? 'was' : 'were'} not. `
        + 'To model another page, copy it into a draw.io file of its own and upload that.');
    } else if (cut) {
      notes.unshift(`This file has ${count} pages${cut}: ${title(best)} was read. To model a later page, copy it into a draw.io file of its own and upload that.`);
    }
    const model = finish({
      name: DEFAULT_PAGE.test(best.name.trim()) ? '' : best.name,   // draw.io's default 'Page-1' names nothing
      source: { kind: 'drawio', file: file || '', method: 'parsed' },
      zones: best.zones, elements: best.elements, flows: best.flows, notes: notes.concat(best.notes),
    });
    return { model, picture: picture && Object.assign(picture, { pages: count }) };
  }
  async function parseDrawio(text, file) {
    return (await readDrawio(text, file)).model;
  }

  /** What a picture's first bytes say it is: PNG, JPEG, GIF or WebP (null for anything else). */
  const pictureType = b => (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 ? 'image/png'
    : b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff ? 'image/jpeg'
      : b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38 ? 'image/gif'
        : b.length >= 12 && String.fromCharCode(...b.subarray(0, 4)) === 'RIFF' && String.fromCharCode(...b.subarray(8, 12)) === 'WEBP' ? 'image/webp' : null);
  /** The picture a draw.io image cell carries: image=data:image/png,<base64> (draw.io leaves out ';base64'). */
  function pictureOf(style, name) {
    const m = /(?:^|;)\s*image\s*=\s*data:image\/[\w.+-]+(?:;base64)?,([A-Za-z0-9+/=\s]+)(?:;|$)/.exec(style);
    if (!m || m[1].length > MAX_PICTURE / 3 * 4 + 1024) return null;
    let bytes;
    try { bytes = bytesFromBase64(m[1]); } catch (_) { return null; }
    const type = pictureType(bytes);
    return type ? { blob: new Blob([bytes], { type }), mediaType: type, name } : null;
  }
  /** A draw.io diagram as { model }, or as { image } when its page is only a picture pasted into draw.io. */
  async function drawioResult(text, name, kind) {
    const { model, picture } = await readDrawio(text, name);
    const image = !model.elements.length && picture ? pictureOf(picture.style, picture.pages > 1 ? `${name} (${picture.page})` : name) : null;
    return image ? { image } : { model: kind ? withFile(model, kind) : model };
  }

  // ---------------------------------------------------------------- PowerPoint

  const EMU = 9144;   // EMU per 1/100 inch: geometry is kept in hundredths of an inch

  function nodes(parent, name) {
    return parent ? [...parent.getElementsByTagNameNS('*', name)] : [];
  }
  const first = (parent, name) => nodes(parent, name)[0] || null;
  const children = (parent, name) => (parent ? [...parent.children].filter(c => c.localName === name) : []);
  const child = (parent, name) => children(parent, name)[0] || null;

  function xfrm(el) {
    const x = child(el, 'xfrm');
    if (!x) return null;
    const off = child(x, 'off'), ext = child(x, 'ext');
    const out = {
      x: +(off && off.getAttribute('x')) || 0, y: +(off && off.getAttribute('y')) || 0,
      w: +(ext && ext.getAttribute('cx')) || 0, h: +(ext && ext.getAttribute('cy')) || 0,
      flipH: x.getAttribute('flipH') === '1', flipV: x.getAttribute('flipV') === '1',
      rot: (+x.getAttribute('rot') || 0) / 60000,   // degrees, clockwise
    };
    const chOff = child(x, 'chOff'), chExt = child(x, 'chExt');
    if (chOff && chExt) {
      out.chX = +chOff.getAttribute('x') || 0; out.chY = +chOff.getAttribute('y') || 0;
      out.chW = +chExt.getAttribute('cx') || 1; out.chH = +chExt.getAttribute('cy') || 1;
    }
    return out;
  }

  // 2-D affine transforms [a, b, c, d, e, f]: (x, y) -> (a x + c y + e, b x + d y + f).
  const IDENTITY = [1, 0, 0, 1, 0, 0];
  const apply = (m, p) => ({ x: m[0] * p.x + m[2] * p.y + m[4], y: m[1] * p.x + m[3] * p.y + m[5] });
  const compose = (m, n) => [m[0] * n[0] + m[2] * n[1], m[1] * n[0] + m[3] * n[1], m[0] * n[2] + m[2] * n[3],
    m[1] * n[2] + m[3] * n[3], m[0] * n[4] + m[2] * n[5] + m[4], m[1] * n[4] + m[3] * n[5] + m[5]];
  /** A box's flips, then its rotation, both about its centre (the order DrawingML applies them in). */
  function flipRotate(t) {
    const cx = t.x + t.w / 2, cy = t.y + t.h / 2;
    const sx = t.flipH ? -1 : 1, sy = t.flipV ? -1 : 1;
    const r = (t.rot || 0) * Math.PI / 180, cos = Math.cos(r), sin = Math.sin(r);
    const a = cos * sx, b = sin * sx, c = -sin * sy, d = cos * sy;
    return [a, b, c, d, cx - a * cx - c * cy, cy - b * cx - d * cy];
  }
  function bounds(points) {
    const xs = points.map(p => p.x), ys = points.map(p => p.y);
    const x = Math.min(...xs), y = Math.min(...ys);
    return { x, y, w: Math.max(...xs) - x, h: Math.max(...ys) - y };
  }

  /** Largest font size (points) and whether every run is bold, from a shape's text runs. */
  const fontOf = el => {
    const runs = nodes(first(el, 'txBody'), 'rPr').concat(nodes(first(el, 'txBody'), 'defRPr'));
    const sizes = runs.map(r => +r.getAttribute('sz')).filter(Boolean);
    const pPr = first(first(el, 'txBody'), 'pPr');
    return { size: sizes.length ? Math.max(...sizes) / 100 : null, bold: runs.length > 0 && runs.every(r => r.getAttribute('b') === '1'),
      align: (pPr && pPr.getAttribute('algn')) || 'l' };
  };
  const textOf = el => {
    const body = first(el, 'txBody');
    if (!body) return '';
    return nodes(body, 'p').map(p => nodes(p, 't').map(t => t.textContent).join('')).filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
  };
  // The presets that are connectors (flowChartConnector, the flowchart circle, is a shape).
  const LINE_PRST = /^(line|lineInv|straightConnector1|bentConnector[2-5]|curvedConnector[2-5])$/;

  /**
   * Shapes on one slide, flattened out of groups into slide coordinates (EMU), with every group's scale,
   * flips and rotation applied. Each: { id, kind: 'shape' | 'line' | 'picture', prst, text, box, dashed,
   * filled, textBox, font, groups, start, end, path, stCxn, endCxn, head, tail, rel }. Past `limit` shapes the
   * rest are only counted. Returns { shapes, total }.
   */
  function slideShapes(doc, placeholderBox, limit = Infinity) {
    const out = [];
    let extra = 0;
    const SHAPE = ['sp', 'cxnSp', 'pic'];
    const count = parent => { for (const el of parent.children) { if (el.localName === 'grpSp') count(el); else if (SHAPE.includes(el.localName)) extra++; } };
    const tree = first(doc, 'spTree');
    const walk = (parent, m, groups) => {
      for (const el of parent.children) {
        const name = el.localName;
        if (out.length >= limit) { if (name === 'grpSp') count(el); else if (SHAPE.includes(name)) extra++; continue; }
        if (name === 'grpSp') {
          // a group maps its children's coordinate space (chOff, chExt) onto its own box (off, ext), then flips and turns it
          const t = xfrm(child(el, 'grpSpPr'));
          let g = m;
          if (t) {
            const sx = t.chW ? t.w / t.chW : 1, sy = t.chH ? t.h / t.chH : 1;
            const scale = t.chW ? [sx, 0, 0, sy, t.x - t.chX * sx, t.y - t.chY * sy] : IDENTITY;
            g = compose(m, compose(flipRotate(t), scale));
          }
          const nv = first(child(el, 'nvGrpSpPr'), 'cNvPr');
          walk(el, g, groups.concat('g' + (nv ? nv.getAttribute('id') : out.length)));
          continue;
        }
        if (!SHAPE.includes(name)) continue;
        const spPr = child(el, 'spPr');
        let t = xfrm(spPr);
        if (!t) {
          // a picture in a layout's placeholder takes the placeholder's position
          const ph = name === 'pic' ? first(el, 'ph') : null;
          const box = ph && placeholderBox ? placeholderBox(ph) : null;
          if (!box) continue;
          t = { x: box.x, y: box.y, w: box.w, h: box.h, flipH: false, flipV: false, rot: 0 };
        }
        const shapeMap = compose(m, flipRotate(t));
        // a point in the shape's own box (0..1) on the slide
        const at = (u, v) => apply(shapeMap, { x: t.x + u * t.w, y: t.y + v * t.h });
        const box = bounds([at(0, 0), at(1, 0), at(1, 1), at(0, 1)]);
        // the box's own size before it is turned (a line of text is as tall as the frame, however it stands),
        // and whether it is turned on end
        const o = at(0, 0), across = at(1, 0), down = at(0, 1);
        const frame = { w: Math.hypot(across.x - o.x, across.y - o.y), h: Math.hypot(down.x - o.x, down.y - o.y),
          upright: Math.abs(across.y - o.y) > Math.abs(across.x - o.x) };
        const nv = first(el, 'cNvPr');
        const geom = child(spPr, 'prstGeom');
        const prst = geom ? geom.getAttribute('prst') || '' : child(spPr, 'custGeom') ? 'custGeom' : '';
        const ln = child(spPr, 'ln');
        const dash = ln && child(ln, 'prstDash');
        const solidFill = child(spPr, 'solidFill') || child(spPr, 'gradFill') || child(spPr, 'blipFill');
        // whether the shape is drawn at all: a fill or an outline of its own, or the theme's (p:style)
        const style = child(el, 'style');
        const themed = ref => { const r = child(style, ref); return !!r && +r.getAttribute('idx') > 0; };
        const has = (parent, kinds) => kinds.some(k => child(parent, k));
        const fillDrawn = child(spPr, 'noFill') ? false : has(spPr, ['solidFill', 'gradFill', 'blipFill', 'pattFill', 'grpFill']) || themed('fillRef');
        const lineDrawn = ln && child(ln, 'noFill') ? false : (!!ln && has(ln, ['solidFill', 'gradFill', 'pattFill'])) || themed('lnRef');
        const bodyPr = first(first(el, 'txBody'), 'bodyPr');
        const inset = side => (bodyPr && bodyPr.hasAttribute(side) ? +bodyPr.getAttribute(side) || 0 : 45720);   // 0.05 in by default
        const shape = {
          id: nv ? nv.getAttribute('id') : '', name: nv ? nv.getAttribute('name') || '' : '',
          kind: name === 'pic' ? 'picture' : name === 'cxnSp' || LINE_PRST.test(prst) ? 'line' : 'shape',
          prst, text: textOf(el), box, frame, groups,
          dashed: !!(dash && dash.getAttribute('val') !== 'solid'),
          filled: !!solidFill && !child(spPr, 'noFill'),
          visible: fillDrawn || lineDrawn,
          textBox: !!first(el, 'cNvSpPr') && first(el, 'cNvSpPr').getAttribute('txBox') === '1',
          placeholder: !!first(child(el, 'nvSpPr'), 'ph'),
          font: fontOf(el), insets: inset('tIns') + inset('bIns'),
        };
        const head = ln && child(ln, 'headEnd'), tail = ln && child(ln, 'tailEnd');
        const arrow = end => !!(end && end.getAttribute('type') && end.getAttribute('type') !== 'none');
        if (shape.kind === 'line') {
          shape.start = at(0, 0);
          shape.end = at(1, 1);
          shape.path = [shape.start, shape.end];
        } else if (prst === 'custGeom') {
          // a freeform: its first path, as points on the slide (a long one thinned to MAX_POINTS, ends kept)
          const path = first(child(spPr, 'custGeom'), 'path');
          let pts = path ? nodes(path, 'pt') : [];
          const pw = path && +path.getAttribute('w'), ph = path && +path.getAttribute('h');
          if (pts.length > MAX_POINTS) {
            const n = pts.length;
            pts = Array.from({ length: MAX_POINTS }, (_, k) => pts[Math.round(k * (n - 1) / (MAX_POINTS - 1))]);
          }
          if (pts.length >= 2) {
            const rel = (p, size) => (size ? +p / size : 0);
            shape.path = pts.map(p => at(rel(p.getAttribute('x'), pw), rel(p.getAttribute('y'), ph)));
            if (!shape.filled && (arrow(head) || arrow(tail))) {   // a freeform connector (an elbow or curve)
              shape.kind = 'line';
              shape.start = shape.path[0];
              shape.end = shape.path[shape.path.length - 1];
            }
          }
        }
        if (shape.kind === 'line') {
          const st = first(el, 'stCxn'), en = first(el, 'endCxn');
          shape.stCxn = st ? st.getAttribute('id') : null;
          shape.endCxn = en ? en.getAttribute('id') : null;
        }
        shape.head = arrow(head);
        shape.tail = arrow(tail);
        if (name === 'pic') {
          const blip = first(el, 'blip');
          shape.rel = blip ? blip.getAttributeNS('http://schemas.openxmlformats.org/officeDocument/2006/relationships', 'embed') : null;
        }
        out.push(shape);
      }
    };
    if (tree) walk(tree, IDENTITY, []);
    return { shapes: out, total: out.length + extra };
  }

  // Element presets. A fixed type is an unambiguous DFD symbol; otherwise the label's words decide first. A
  // shape of another preset is an element only when a connector is glued to it, unless it marks or points
  // rather than stands for a part of the system: callouts, block arrows, brackets, bursts, and octagons or
  // stars that carry a number or nothing (the CSA figures' threat markers).
  const ANNOTATION = /callout|Arrow$|Bracket|Brace|^irregularSeal[12]$/i;
  const MARKER = /^(octagon|star\d+)$/;
  const PRST = {
    ellipse: { type: 'process', fixed: true }, flowChartConnector: { type: 'process', fixed: true },
    can: { type: 'datastore', fixed: true }, flowChartMagneticDisk: { type: 'datastore', fixed: true },
    flowChartMagneticDrum: { type: 'datastore', fixed: true }, flowChartOnlineStorage: { type: 'datastore', fixed: true },
    flowChartOfflineStorage: { type: 'datastore', fixed: true }, flowChartMagneticTape: { type: 'datastore', fixed: true },
    flowChartInternalStorage: { type: 'datastore', fixed: true },
    roundRect: { type: 'process' }, flowChartAlternateProcess: { type: 'process' }, flowChartProcess: { type: 'process' },
    flowChartPredefinedProcess: { type: 'process' }, hexagon: { type: 'process' }, cube: { type: 'datastore' },
    rect: { type: 'entity' }, snip1Rect: { type: 'entity' }, flowChartTerminator: { type: 'entity' }, cloud: { type: 'entity' },
  };
  function slideType(e, csaStyle) {
    if (e.cluster) return 'cluster';
    const kind = e.picture || e.text ? { type: 'process' } : PRST[e.raw.prst] || { type: 'process' };
    if (kind.fixed) return kind.type;
    const low = words(e.label);
    if (hasWord(low, DATASTORE_WORDS)) return 'datastore';
    if (hasWord(low, ENTITY_WORDS)) return 'entity';
    return kind.type === 'entity' ? (csaStyle ? 'entity' : 'process') : kind.type;
  }

  /** The shapes of a legend on a slide: a small group or box with a Legend / Key title, and all in it. */
  function legendOf(shapes, slideArea) {
    const out = new Set();
    const ends = s => (s.kind === 'line' ? [s.a, s.b] : null);
    let titled = 0;
    for (const t of shapes) {
      if (!t.text || !LEGEND.test(t.text)) continue;
      if (++titled > 20) break;   // a slide has a legend or two: a crafted one's thousands aren't each tried
      const tc = centre(t.g);
      const regions = [];
      const group = t.groups[t.groups.length - 1];
      if (group) regions.push(shapes.filter(s => s.groups.includes(group)));
      const box = !t.textBox && t.kind === 'shape' && shapes.some(s => s !== t && containsPoint(t.g, centre(s.g))) ? t
        : shapes.filter(s => s !== t && s.kind === 'shape' && !s.textBox && containsPoint(s.g, tc)).sort((a, b) => area(a.g) - area(b.g))[0];
      if (box) regions.push([box, ...shapes.filter(s => s !== box && containsPoint(box.g, centre(s.g)))]);
      for (const members of regions) {
        if (members.length < 2) continue;
        const g = bounds(members.flatMap(s => [{ x: s.g.x, y: s.g.y }, { x: s.g.x + s.g.w, y: s.g.y + s.g.h }]));
        if (area(g) > slideArea / 4) continue;   // a whole-slide group or box is the diagram, not its legend
        const member = new Set(members);
        const crosses = shapes.some(s => ends(s) && !member.has(s) && ends(s).some(p => containsPoint(g, p)) && !ends(s).every(p => containsPoint(g, p)));
        if (crosses) continue;
        for (const s of members) out.add(s);
      }
    }
    return out;
  }

  /** Read the shapes of a PowerPoint slide as a DFD. Returns null when the slide carries no diagram. */
  function modelFromSlide(shapes, slideW, slideH, slideNo) {
    const geo = b => ({ x: b.x / EMU, y: b.y / EMU, w: b.w / EMU, h: b.h / EMU });
    const pt = p => ({ x: p.x / EMU, y: p.y / EMU });
    const slideArea = (slideW / EMU) * (slideH / EMU);
    for (const s of shapes) {
      s.g = geo(s.box);
      s.lineH = s.frame ? s.frame.h / EMU : s.g.h;   // how tall its text stands, even in a box turned on end
      s.inset = (s.insets || 0) / EMU;
      if (s.path) s.pts = s.path.map(pt);
      if (s.kind === 'line') { s.a = pt(s.start); s.b = pt(s.end); }
    }
    const notes = [];
    const legend = legendOf(shapes, slideArea);
    const live = shapes.filter(s => !legend.has(s));
    const glued = new Set();
    // shapes a connector drawn like a flow is glued to: a leader line has no arrowhead, or is dashed, where the
    // slide's other connectors have arrowheads, or are solid
    const arrowed = new Set();
    const connectors = live.filter(s => s.kind === 'line');
    const arrowsUsed = connectors.some(s => s.head || s.tail), solidUsed = connectors.some(s => !s.dashed);
    for (const s of connectors) {
      const flowLike = !(arrowsUsed && !s.head && !s.tail) && !(solidUsed && s.dashed);
      for (const id of [s.stCxn, s.endCxn]) if (id) { glued.add(id); if (flowLike) arrowed.add(id); }
    }
    // Words on the slide rather than boxes: text boxes, and shapes drawn with no fill and no outline.
    const unboxed = s => s.kind === 'shape' && !s.textBox && !s.visible && !!s.text && !s.placeholder;
    const textBoxes = live.filter(s => s.kind === 'shape' && (s.textBox || unboxed(s)) && s.text);
    // One line of text: the frame is under one and a half lines tall (a line is about 1.2 times the font size,
    // the theme's 18 pt unless the text says), plus its top and bottom insets; or 0.35 in, whichever is more.
    const oneLine = t => t.lineH <= Math.max(35, t.inset + 1.8 * (t.font.size || 18) * 100 / 72);
    const used = new Set();
    const zones = [];
    const elements = [];
    const ellipses = [];
    const element = (s, extra) => Object.assign({ id: 'e' + s.id, label: s.text || '', type: null, zone: null, geometry: s.g,
      context: { purpose: '', sensitivity: '', auth: '', trust: '' }, crownJewel: null, ai: null, raw: s }, extra);
    // a marker, a callout or a note: a shape of another preset carrying a number, a note or nothing but a mark
    const annotation = s => ANNOTATION.test(s.prst) || (MARKER.test(s.prst) && (!s.text || NUMBER.test(s.text))) || (!!s.text && remarkText(s.text));
    for (const s of live) {
      if (s.kind === 'picture') {
        // an icon is an element once it has a caption; a picture filling a good share of the slide is the diagram itself
        if (area(s.g) < slideArea / 4) elements.push(element(s, { picture: true }));
        continue;
      }
      if (s.kind !== 'shape') continue;
      // A connector glued to a shape says it is a node, whatever its preset: a word ('Internet'), an outlined
      // text box, a freeform. Other text is captions and labels, read below. Words with no box round them need a
      // connector drawn like a flow: a leader line glued to them marks what a note is about. A note (remarkText)
      // with one is kept for now, in case it is a labelled shape's badge (below).
      const stuck = glued.has(s.id);
      if ((s.textBox && !s.prst.match(/ellipse|can/)) || unboxed(s)) {
        if (stuck && (s.text || s.visible)) {
          const remark = (!s.visible && !arrowed.has(s.id)) || (!!s.text && remarkText(s.text));
          if (!remark || arrowed.has(s.id)) elements.push(element(s, { text: true, remark }));
        }
        continue;
      }
      if (s.prst === 'custGeom') { if (stuck && !annotation(s)) elements.push(element(s)); continue; }
      if (s.dashed && area(s.g) >= 20000) {
        zones.push({ id: 'z' + s.id, label: s.text || '', parent: null, geometry: s.g, raw: s });
        continue;
      }
      if (!(s.prst in PRST) && !(stuck && !annotation(s))) continue;   // octagons, stars, arrows and callouts are annotations
      if (s.prst === 'ellipse') ellipses.push(s);
      elements.push(element(s));
    }
    // Two concentric circles are one cluster of processes (CSA Figure 3).
    const byRaw = new Map(elements.map(e => [e.raw, e]));
    const merged = new Set();
    for (const outer of ellipses) {
      for (const inner of ellipses) {
        if (outer === inner) continue;
        const o = outer.box, i = inner.box;
        const inside = i.x >= o.x && i.y >= o.y && i.x + i.w <= o.x + o.w && i.y + i.h <= o.y + o.h;
        if (!inside) continue;
        const keep = byRaw.get(inner) || byRaw.get(outer);
        const drop = byRaw.get(keep && keep.raw === inner ? outer : inner);
        if (keep) {
          keep.cluster = true;
          keep.label = keep.label || (drop && drop.label) || '';
          keep.geometry = geo(outer.box);
          keep.alias = [outer.id, inner.id];
        }
        if (drop && drop !== keep) { merged.add(drop); byRaw.delete(drop.raw); }
      }
    }
    if (merged.size) { const left = elements.filter(e => !merged.has(e)); elements.length = 0; elements.push(...left); }
    // A shape's text sometimes sits in a text box on top of it: use the box that covers its centre, unless that is
    // a glued word and other elements stand on the shape too (it is the panel they are drawn on).
    const labelOf = new Map();   // text box -> the element it names
    for (const e of elements) {
      if (e.label) continue;
      const c = centre(e.geometry);
      let on = null;   // the named or glued elements drawn on it (pair by pair: not for a crafted slide of thousands)
      const panel = t => {
        if (!on) on = elements.length > GEO_LIMIT ? [] : elements.filter(o => o !== e && !o.remark && (o.label || glued.has(o.raw.id))
          && area(o.geometry) < area(e.geometry) && containsPoint(e.geometry, centre(o.geometry)));
        return on.some(o => o.raw !== t);
      };
      const tb = textBoxes.find(t => !used.has(t) && t !== e.raw && containsPoint(t.g, c) && !(glued.has(t.id) && panel(t)));
      if (tb) { e.label = tb.text; used.add(tb); labelOf.set(tb, e); }
    }
    const isGlued = e => glued.has(e.raw.id) || (e.alias || []).some(a => glued.has(a));
    // An icon's caption is the text box just under or over it; so is a numbered process's, a DFD bubble with
    // a connector glued to it (a number with nothing glued to it is a step or threat marker).
    for (const e of elements) {
      const numbered = !!e.label && NUMBER.test(e.label) && isGlued(e) && !e.remark;
      if (!(e.picture && !e.label) && !numbered) continue;
      const g = e.geometry, cx = g.x + g.w / 2;
      let best = null, bestScore = Infinity;
      for (const t of textBoxes) {
        if (used.has(t) || t === e.raw || t.lineH > 70 || t.text.length > 80) continue;
        const tc = centre(t.g);
        if (tc.x < g.x - 30 || tc.x > g.x + g.w + 30) continue;
        const below = t.g.y - (g.y + g.h), above = g.y - (t.g.y + t.g.h);
        const gap = Math.min(below >= -t.g.h ? Math.max(below, 0) : Infinity, above >= -t.g.h ? Math.max(above, 0) : Infinity);
        if (gap > 50) continue;   // within 0.5 in
        const score = gap + Math.abs(tc.x - cx) / 4;
        if (score < bestScore) { best = t; bestScore = score; }
      }
      if (best) { e.label = best.text; used.add(best); labelOf.set(best, e); }
    }
    // A glued text box that names a shape or an icon is part of it, connector and all; the others are nodes
    // of their own, so they aren't read as captions or titles.
    const named = elements.filter(e => !(e.text && labelOf.has(e.raw)));
    for (const e of elements) {
      if (!e.text) continue;
      const owner = labelOf.get(e.raw);
      if (owner) owner.alias = (owner.alias || [owner.raw.id]).concat(e.raw.id); else used.add(e.raw);
    }
    if (named.length < elements.length) { elements.length = 0; elements.push(...named); }
    // A picture is part of the system when a connector is glued to it or ends at it, or when it has a caption
    // in the body of the slide: a logo over a footer, in the slide's top or bottom eighth, isn't.
    const lineEnds = live.filter(s => s.kind === 'line').flatMap(s => [s.a, s.b]);
    const touched = e => lineEnds.some(p => boxDistance(e.geometry, p) <= 30);
    const band = slideH / EMU / 8;
    const inBody = g => g.y >= band && g.y + g.h <= slideH / EMU - band;
    const loose = e => e.picture && !isGlued(e) && !inBody(e.geometry) && !touched(e);
    // An element counts when it has a name that isn't a number, or a connector is glued to it. Labels are
    // settled by now, so each answer is worked out once: the tests below ask it shape by shape.
    const counts = new Map();
    const real = e => {
      if (!counts.has(e)) counts.set(e, !e.remark && !loose(e) && ((!!e.label && !NUMBER.test(e.label)) || isGlued(e)));
      return counts.get(e);
    };
    // A number (or a word) drawn on a labelled shape with a connector glued to it is a step or threat badge (a
    // note on the shape): the connector is the shape's, and the badge doesn't make the shape a trust zone.
    // Numbers joined to something else on the same shape are numbered processes in a zone.
    const badgeOf = new Map();   // badge element -> the element it is drawn on
    if (elements.length <= GEO_LIMIT) {
      const boxes = elements.filter(b => b.label && !NUMBER.test(b.label) && !b.cluster && !b.raw.dashed && real(b));
      for (const n of elements) {
        if (!n.label || !(NUMBER.test(n.label) || n.text) || !isGlued(n)) continue;
        const c = centre(n.geometry);
        let box = null;
        for (const b of boxes) if (b !== n && area(b.geometry) > area(n.geometry) && containsPoint(b.geometry, c) && (!box || area(b.geometry) < area(box.geometry))) box = b;
        if (box) badgeOf.set(n, box);
      }
      if (badgeOf.size) {
        const byShape = new Map();
        for (const e of elements) for (const sid of e.alias || [e.raw.id]) byShape.set(sid, e);
        for (const s of live) {
          if (s.kind !== 'line') continue;
          const a = byShape.get(s.stCxn), b = byShape.get(s.endCxn);
          const pa = a ? centre(a.geometry) : s.a, pb = b ? centre(b.geometry) : s.b;
          if (a && badgeOf.has(a) && containsPoint(badgeOf.get(a).geometry, pb)) badgeOf.delete(a);
          if (b && badgeOf.has(b) && containsPoint(badgeOf.get(b).geometry, pa)) badgeOf.delete(b);
        }
      }
    }
    const inBox = (outer, inner) => inner.x >= outer.x - 1 && inner.y >= outer.y - 1 && inner.x + inner.w <= outer.x + outer.w + 1 && inner.y + inner.h <= outer.y + outer.h + 1;
    const titleIn = (g, band) => textBoxes.filter(t => !used.has(t) && oneLine(t) && containsPoint(g, centre(t.g)))
      .map(t => ({ t, d: Math.min(Math.abs(t.g.y - g.y), Math.abs(t.g.y + t.g.h - g.y - g.h)) }))
      .filter(x => x.d <= band).sort((a, b) => a.d - b.d).map(x => x.t)[0] || null;
    // A glued word where an unnamed zone's title goes (a line along its top or bottom edge, in a zone that holds
    // other elements, with nothing in the zone at its connectors' other ends) is the zone's name, and a connector
    // dropped on it ends on the zone.
    const titleOf = new Map();   // such a word's element -> the zone it names
    const titledBy = new Map();   // a glued text box a zone takes as its title (a leader glued to it) -> the zone
    const shapeById = new Map(), farEnds = new Map();   // a glued shape's id -> where its connectors' other ends are
    for (const s of live) if (!shapeById.has(s.id)) shapeById.set(s.id, s);
    for (const s of live) {
      if (s.kind !== 'line') continue;
      for (const [id, other, p] of [[s.stCxn, s.endCxn, s.b], [s.endCxn, s.stCxn, s.a]]) {
        if (!id) continue;
        if (!farEnds.has(id)) farEnds.set(id, []);
        farEnds.get(id).push(other && shapeById.has(other) ? centre(shapeById.get(other).g) : p);
      }
    }
    const gluedTitle = (g, band) => {
      let best = null, bestD = Infinity;
      for (const t of elements) {
        if (!t.text || !t.label || titleOf.has(t) || badgeOf.has(t) || !real(t) || !oneLine(t.raw) || !containsPoint(g, centre(t.geometry))) continue;
        const d = Math.min(Math.abs(t.geometry.y - g.y), Math.abs(t.geometry.y + t.geometry.h - g.y - g.h));
        if (d < bestD) { best = t; bestD = d; }
      }
      if (!best || bestD > band || (farEnds.get(best.raw.id) || []).some(p => containsPoint(g, p))) return null;
      const others = elements.some(o => o !== best && !titleOf.has(o) && !badgeOf.has(o) && real(o) && area(o.geometry) < area(g) && containsPoint(g, centre(o.geometry)));
      return others ? best : null;
    };
    // A box drawn round other elements is a trust zone (a solid outline too), unless a connector is glued
    // to it and to nothing in it. An unlabelled box needs a title along its top or bottom edge. A solid box
    // round every element is the slide's frame (and the text on it the diagram's title), not a trust
    // boundary, unless its name says it is one.
    const containers = new Set(), frames = new Set(), boxZones = new Set();
    const everything = elements.filter(e => real(e) && !badgeOf.has(e)).length;
    for (const e of elements.length <= GEO_LIMIT ? elements : []) {   // pair by pair: not for a crafted slide of thousands
      if (e.picture || e.cluster || (PRST[e.raw.prst] || {}).fixed) continue;
      if (e.label && NUMBER.test(e.label)) continue;
      const inside = elements.filter(o => o !== e && !badgeOf.has(o) && area(o.geometry) < area(e.geometry) && inBox(e.geometry, o.geometry) && real(o));
      if (!inside.length) continue;
      if (isGlued(e) && !inside.some(isGlued)) continue;
      let label = e.label, title = null, word = null;
      if (!label) {
        title = titleIn(e.geometry, 50);
        word = title ? null : gluedTitle(e.geometry, 50);
        if (!title && !word) continue;
        label = title ? title.text : word.label;
      }
      if (!e.raw.dashed && !isGlued(e) && inside.length >= everything - (real(e) ? 1 : 0) && !hasWord(words(label), BOUNDARY_WORDS)) {
        frames.add(e);
        continue;
      }
      if (title) used.add(title);
      containers.add(e);
      const z = { id: 'z' + e.raw.id, label, parent: null, geometry: e.geometry, raw: e.raw };
      if (word) titleOf.set(word, z);
      if (title && glued.has(title.id)) titledBy.set(title.id, z);
      boxZones.add(z);
      zones.push(z);
    }
    // A dashed outline a connector is glued to, round nothing, is a dashed element (an external or planned system).
    for (const z of zones.slice()) {
      if (boxZones.has(z) || !glued.has(z.raw.id)) continue;
      if (elements.some(o => containsPoint(z.geometry, centre(o.geometry)) && real(o))) continue;
      zones.splice(zones.indexOf(z), 1);
      if (z.raw.prst in PRST || !annotation(z.raw)) elements.push(element(z.raw));
    }
    for (const z of zones) {
      if (z.label) continue;
      const g = z.geometry;
      const tb = textBoxes.filter(t => !used.has(t) && containsPoint(g, centre(t.g)))
        .sort((a, b) => Math.min(Math.abs(a.g.y - g.y), Math.abs(a.g.y + a.g.h - g.y - g.h))
          - Math.min(Math.abs(b.g.y - g.y), Math.abs(b.g.y + b.g.h - g.y - g.h)))[0];
      if (tb) { z.label = tb.text; used.add(tb); if (glued.has(tb.id)) titledBy.set(tb.id, z); continue; }
      const word = zones.length * elements.length <= GEO_LIMIT * GEO_LIMIT ? gluedTitle(g, 50) : null;
      if (word) { z.label = word.label; titleOf.set(word, z); }
    }
    // a badge on a shape that is a zone anyway (it holds elements of its own) is a numbered element in it
    for (const [n, box] of badgeOf) if (containers.has(box) || frames.has(box)) badgeOf.delete(n);
    const kept = elements.filter(e => !containers.has(e) && !frames.has(e) && !badgeOf.has(e) && !titleOf.has(e) && real(e));
    if (!kept.some(e => e.label)) return null;
    // a connector glued to a zone, or to its title, ends on the zone
    const zoneEnd = new Map();   // shape id -> the zone's name
    for (const z of zones) zoneEnd.set(z.raw.id, z.label || 'Unnamed trust zone');
    for (const [word, z] of titleOf) zoneEnd.set(word.raw.id, z.label);
    for (const [id, z] of titledBy) zoneEnd.set(id, z.label);

    const idOf = new Map();
    for (const e of kept) for (const sid of e.alias || [e.raw.id]) idOf.set(sid, e.id);
    for (const [n, box] of badgeOf) if (idOf.has(box.raw.id)) for (const sid of n.alias || [n.raw.id]) idOf.set(sid, box.id);   // a badge's connector is its shape's
    const nearest = p => {
      let best = null, bestD = 30, bestArea = Infinity;   // within 0.3 in of the shape's edge
      for (const e of kept) {
        const g = e.geometry;
        const d = boxDistance(g, p);
        // inside two shapes at once (an icon on a box): the smaller one
        if (d < bestD - 1e-9 || (best && Math.abs(d - bestD) <= 1e-9 && area(g) < bestArea)) { best = e; bestD = d; bestArea = area(g); }
      }
      return best ? best.id : null;
    };
    const flows = [];
    // captions: one-line text boxes that aren't a number (threat markers), bold or large (headings) or over an element
    const marks = kept.map(e => e.geometry);
    const labelBoxes = textBoxes.filter(t => !used.has(t) && oneLine(t) && !NUMBER.test(t.text)
      && !t.font.bold && !(t.font.size > 20) && !marks.some(g => containsPoint(g, centre(t.g))));
    // a dashed line with no arrows is a trust boundary drawn as a line
    const boundary = s => s.dashed && !s.head && !s.tail && (s.kind === 'line' || (s.prst === 'custGeom' && !s.filled))
      && Math.max(s.g.w, s.g.h) >= 100 && (s.pts || []).length >= 2;
    const lines = live.filter(x => x.kind === 'line' && !(x.dashed && !x.head && !x.tail));
    // Captions go to connectors closest pair first, so a caption isn't taken by a connector that merely passes it
    // (pair by pair: not for a crafted slide of thousands of each). Small captions close to their line (up to
    // 14 pt and 0.35 in tall, within 0.45 in) are paired first; larger or further ones then label only the
    // connectors left without one, so a nearby heading or zone name doesn't take a connector's own caption.
    const caption = new Map();
    const close = [], wider = [];
    const small = t => t.lineH <= 35 && !(t.font.size > 14);
    const segments = lines.reduce((n, s) => n + (s.text ? 0 : s.pts.length - 1), 0);
    const affordable = list => segments * list.length <= GEO_LIMIT * GEO_LIMIT;
    const candidates = affordable(labelBoxes) ? labelBoxes : labelBoxes.filter(small);   // the small ones at least
    if (affordable(candidates)) lines.forEach((s, i) => {
      if (s.text) return;
      const pts = s.pts;
      for (const t of candidates) {
        // measure from where the caption is anchored: its left end when left-aligned, and so on (its centre
        // when it is turned on end)
        const g = t.g;
        const c = { x: t.font.align === 'ctr' || t.frame.upright ? g.x + g.w / 2 : t.font.align === 'r' ? g.x + g.w : g.x, y: g.y + g.h / 2 };
        let d = Infinity;
        for (let k = 1; k < pts.length; k++) d = Math.min(d, segmentDistance(c, pts[k - 1], pts[k]));
        if (small(t) && d < 45) close.push({ i, t, d });
        // or within 0.45 in of the nearer edge of its line of text (half a line, 0.6 times the font size, from its middle)
        else if (d - 0.6 * (t.font.size || 18) * 100 / 72 < 45) wider.push({ i, t, d });
      }
    });
    for (const pairs of [close, wider]) {
      pairs.sort((a, b) => a.d - b.d);
      for (const { i, t } of pairs) {
        if (caption.has(i) || used.has(t)) continue;
        caption.set(i, t.text);
        used.add(t);
      }
    }
    const lost = tally();
    lines.forEach((s, i) => {
      const src = idOf.get(s.stCxn) || nearest(s.a);
      const tgt = idOf.get(s.endCxn) || nearest(s.b);
      const label = s.text || caption.get(i) || '';
      const called = label ? ` ("${label}")` : '';
      if (src && tgt && src !== tgt) {
        const forward = s.tail || !s.head;
        flows.push({ id: 'f' + s.id, label, source: forward ? src : tgt, target: forward ? tgt : src,
          bidirectional: s.head && s.tail });
      } else if (src && src === tgt) {
        const who = kept.find(e => e.id === src).label;
        const whom = who ? `"${who}"` : 'an unnamed shape';
        lost.add(`A connector${called} joins ${whom} to itself, so it isn't a data flow.`,
          n => `${n} connectors${called} join ${whom} to itself, so they aren't data flows.`);
      } else if (!NOTATION_FLOW.test(label)) {   // a legend's sample arrow isn't worth a note
        const zone = (!src && zoneEnd.get(s.stCxn)) || (!tgt && zoneEnd.get(s.endCxn));
        if (zone) {
          lost.add(`A connector${called} ends on the trust zone "${zone}" rather than on an element in it, so it isn't a data flow.`,
            n => `${n} connectors${called} end on the trust zone "${zone}" rather than on an element in it, so they aren't data flows.`);
        } else {
          lost.add(`A connector${called} isn't joined to two elements, so it isn't a data flow.`,
            n => `${n} connectors${called} aren't joined to two elements, so they aren't data flows.`);
        }
      }
    });
    notes.push(...lost.notes());
    // Circles joined into the data flows mean the CSA conventions: a plain rectangle is an external entity.
    const ends = new Set(flows.flatMap(f => [f.source, f.target]));
    const csaStyle = kept.some(e => e.raw.prst === 'ellipse' && ends.has(e.id));
    for (const e of kept) e.type = slideType(e, csaStyle);
    const final = kept.filter(e => ends.has(e.id) || !(NOTATION.test(e.label) || LEGEND.test(e.label)));   // legend samples and titles
    if (!zones.length) {
      // Trust boundaries drawn as dashed lines (as in the CSA figures) enclose nothing that can be read as a zone.
      const lines2 = live.filter(boundary);
      if (lines2.length) {
        const near = textBoxes.length * lines2.reduce((n, l) => n + l.pts.length, 0) <= GEO_LIMIT * GEO_LIMIT;
        const names = textBoxes.filter(t => near && !used.has(t) && t.font.bold && oneLine(t) && t.text.length <= 80 && !NUMBER.test(t.text) && !LEGEND.test(t.text)
          && lines2.some(l => l.pts.some((p, k) => k > 0 && segmentDistance(centre(t.g), l.pts[k - 1], p) <= 300)))
          .sort((a, b) => a.g.y - b.g.y || a.g.x - b.g.x).map(t => t.text).filter((v, i, a) => a.indexOf(v) === i);
        const n = lines2.length;
        notes.push(`Slide ${slideNo} draws its trust boundaries as ${n} dashed line${n === 1 ? '' : 's'}, not as closed shapes, `
          + `so no trust zones were read from ${n === 1 ? 'it' : 'them'}. Add the zones in the decomposition editor, or redraw each boundary as a closed dashed shape`
          + (names.length ? `. Names on the slide that look like zones: ${names.slice(0, 12).map(x => `"${x}"`).join(', ')}${names.length > 12 ? ' …' : ''}.` : '.'));
      }
    }
    for (const e of final) { delete e.raw; delete e.picture; delete e.cluster; delete e.alias; delete e.text; }
    for (const z of zones) delete z.raw;
    return { zones, elements: final, flows, notes, page: { w: slideW / EMU, h: slideH / EMU } };
  }

  /** Unzip with the JSZip that the PowerPoint writer (js/vendor/pptxgen.bundle.js) brings along. */
  async function unzip(buffer) {
    if (!global.JSZip) throw new Error('The PowerPoint reader is not loaded (js/vendor/pptxgen.bundle.js).');
    try {
      return await global.JSZip.loadAsync(buffer);
    } catch (_) {
      throw new Error('This file can’t be opened as a PowerPoint file: it may be damaged, or not be a .pptx file.');
    }
  }

  /**
   * Read parts of a zip with a byte budget: each part is streamed and abandoned past its limit, so a part
   * that unpacks to gigabytes (whatever its header claims) can't exhaust the tab's memory.
   */
  function zipReader(zip) {
    let budget = MAX_PPTX;
    const read = (path, limit, asText) => {
      const f = zip.file(path);
      if (!f) return Promise.resolve(null);
      const cap = Math.min(limit, budget);
      const declared = f._data && typeof f._data.uncompressedSize === 'number' ? f._data.uncompressedSize : 0;
      if (declared > cap) return Promise.reject(tooLarge());
      if (typeof f.internalStream !== 'function') return f.async(asText ? 'string' : 'uint8array');
      return new Promise((resolve, reject) => {
        const chunks = [];
        let total = 0, settled = false;
        const stream = f.internalStream('uint8array');
        stream.on('data', chunk => {
          if (settled) return;
          total += chunk.length;
          // what was unpacked before giving up counts too, so a deck of parts that lie about their size can't
          // make the reader unpack without end
          if (total > cap) { settled = true; budget -= total; stream.pause(); reject(tooLarge()); return; }
          chunks.push(chunk);
        }).on('error', e => {
          if (!settled) { settled = true; reject(e); }
        }).on('end', () => {
          if (settled) return;
          settled = true;
          budget -= total;
          const bytes = concat(chunks, total);
          resolve(asText ? new TextDecoder().decode(bytes) : bytes);
        }).resume();
      });
    };
    return { has: p => !!zip.file(p), text: (p, limit = MAX_PART) => read(p, limit, true), bytes: (p, limit = MAX_PART) => read(p, limit, false) };
  }

  /** A part's relationships; read(path, limit) gives a part's text (or null when there is none). */
  const relsOf = async (read, path) => {
    const dir = path.slice(0, path.lastIndexOf('/'));
    const relPath = dir + '/_rels/' + path.slice(path.lastIndexOf('/') + 1) + '.rels';
    const out = new Map();
    const text = await read(relPath, 5 * MB);
    if (!text) return out;
    for (const r of parseXml(text).getElementsByTagName('Relationship')) {
      const target = r.getAttribute('Target') || '';
      const resolved = target.startsWith('/') ? target.slice(1) : resolvePath(dir, target);
      out.set(r.getAttribute('Id'), { type: r.getAttribute('Type') || '', target: resolved });
    }
    return out;
  };
  function resolvePath(dir, rel) {
    const parts = dir.split('/');
    for (const p of rel.split('/')) {
      if (p === '..') parts.pop();
      else if (p && p !== '.') parts.push(p);
    }
    return parts.join('/');
  }

  /**
   * Where the slide's layout (or its master) puts each placeholder: the position a bare picture inherits.
   * Each layout and master is read once a deck (cache: path -> its placeholders and relationships).
   */
  async function placeholderBoxes(read, rels, cache) {
    const scan = path => {
      if (!cache.has(path)) {
        cache.set(path, (async () => {
          const found = [];
          const text = await read(path, 10 * MB);
          if (!text) return { boxes: found, rels: new Map() };
          const doc = parseXml(text);
          for (const el of nodes(doc, 'sp').concat(nodes(doc, 'pic'))) {
            const ph = first(el, 'ph');
            const t = ph && xfrm(child(el, 'spPr'));
            if (t) found.push({ type: ph.getAttribute('type') || 'obj', idx: ph.getAttribute('idx'), box: { x: t.x, y: t.y, w: t.w, h: t.h } });
          }
          return { boxes: found, rels: await relsOf(read, path) };
        })());
      }
      return cache.get(path);
    };
    const boxes = [];
    const layout = [...rels.values()].find(r => /\/slideLayout$/.test(r.type));
    if (layout) {
      const l = await scan(layout.target);
      boxes.push(...l.boxes);
      const master = [...l.rels.values()].find(r => /\/slideMaster$/.test(r.type));
      if (master) boxes.push(...(await scan(master.target)).boxes);
    }
    return ph => {
      const idx = ph.getAttribute('idx'), type = ph.getAttribute('type') || 'obj';
      const hit = (idx != null && boxes.find(b => b.idx === idx)) || boxes.find(b => b.type === type);
      return hit ? hit.box : null;
    };
  }

  const IMAGE_TYPES = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' };

  async function parsePptx(buffer, file) {
    const zip = await unzip(buffer);
    const reader = zipReader(zip);
    const big = () => new Error('This PowerPoint file is too large to read: its slides unpack to more than the browser can safely hold.');
    const pres = zip.file('ppt/presentation.xml');
    if (!pres) throw new Error("This isn't a PowerPoint file (no ppt/presentation.xml).");
    let presXml;
    try { presXml = await reader.text('ppt/presentation.xml', 5 * MB); } catch (e) { throw e.tooLarge ? big() : e; }
    const presDoc = parseXml(presXml);
    const size = first(presDoc, 'sldSz');
    const slideW = (size && +size.getAttribute('cx')) || 12192000, slideH = (size && +size.getAttribute('cy')) || 6858000;
    const presRels = await relsOf(reader.text, 'ppt/presentation.xml');
    const RNS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
    let slides = nodes(presDoc, 'sldId').map(s => presRels.get(s.getAttributeNS(RNS, 'id'))).filter(Boolean).map(r => r.target);
    const notes = [];
    const deckSlides = slides.length;
    if (slides.length > MAX_SLIDES) slides = slides.slice(0, MAX_SLIDES);

    const read = [];
    const skipped = [];   // slides too large to read
    const pictures = [];
    const slideArea = slideW * slideH;
    // The slides are read until their XML (and the parts that go with it) reaches DECK_XML, or their shapes
    // DECK_SHAPES: a crafted deck of thousands of shapes on every slide can't freeze the tab.
    let xmlLeft = DECK_XML, shapesRead = 0, looked = slides.length, looseText = false;
    const xmlOf = async (path, limit) => {
      const text = await reader.text(path, Math.max(0, Math.min(limit, xmlLeft)));
      if (text) xmlLeft -= text.length;
      return text;
    };
    const layouts = new Map();   // each layout and master, read once
    for (const [index, path] of slides.entries()) {
      if (!reader.has(path)) continue;
      if (xmlLeft <= 0 || shapesRead >= DECK_SHAPES) { looked = index; break; }
      const fresh = xmlLeft === DECK_XML;   // with nothing read yet, a slide over the allowance is too large by itself
      let doc, rels, shapes, all;
      try {
        doc = parseXml(await xmlOf(path, MAX_PART));
        rels = await relsOf(xmlOf, path);
        // a picture dropped into a layout placeholder has no position of its own
        const bare = nodes(doc, 'pic').some(p => first(p, 'ph') && !child(child(p, 'spPr'), 'xfrm'));
        const boxOf = bare ? await placeholderBoxes(xmlOf, rels, layouts) : null;
        // no diagram has more than MAX_SHAPES shapes: a crafted slide's others are only counted
        ({ shapes, total: all } = slideShapes(doc, ph => (boxOf && boxOf(ph)) || { x: 0, y: 0, w: slideW, h: slideH }, MAX_SHAPES));
      } catch (e) {
        if (!e.tooLarge) throw e;
        if (!fresh) { looked = index; break; }   // over what is left of the deck's allowance
        skipped.push(index + 1);
        notes.push(`Slide ${index + 1} is too large to read, so it was skipped.`);
        continue;
      }
      shapesRead += shapes.length;
      // Hide Slide: not part of the show (show is an xsd:boolean, written "0" or "false")
      const hidden = /^\s*(0|false)\s*$/.test(doc.documentElement.getAttribute('show') || '');
      const model = modelFromSlide(shapes, slideW, slideH, index + 1);
      if (model && all > MAX_SHAPES) {
        model.notes.unshift(`Slide ${index + 1} has ${all.toLocaleString('en')} shapes; only the first ${MAX_SHAPES.toLocaleString('en')} were read.`);
      }
      if (model) read.push({ model, index, hidden });
      // text boxes and connectors with nothing read from them: the connectors aren't attached to the boxes
      else if (shapes.some(s => s.kind === 'line') && shapes.some(s => s.kind === 'shape' && s.textBox && s.text)) looseText = true;
      // Pictures, in case no slide has a diagram drawn in shapes: never an icon or a logo (it covers a tenth of
      // the slide or more).
      const title = nodes(doc, 'ph').some(ph => ph.getAttribute('type') === 'ctrTitle');
      for (const p of shapes.filter(s => s.kind === 'picture' && s.rel)) {
        const target = rels.get(p.rel);
        const ext = target ? target.target.split('.').pop().toLowerCase() : '';
        if (!IMAGE_TYPES[ext]) continue;
        const areaEmu = p.box.w * p.box.h;
        if (areaEmu < slideArea / 10) continue;
        pictures.push({ area: areaEmu, path: target.target, ext, slide: index + 1, title, hidden });
      }
    }
    if (looked < slides.length) {
      notes.unshift(`This deck has ${deckSlides} slides, and only ${looked === 1 ? 'the first was' : `the first ${looked} were`} read (reading them all would take too long). `
        + 'To model a later slide, copy it into a deck of its own and upload that.');
    } else if (deckSlides > MAX_SLIDES) {
      notes.unshift(`Only the first ${MAX_SLIDES} of the deck's ${deckSlides} slides were read.`);
    }
    // The first slide with a diagram on it; failing that, the most elements joined by flows; then the biggest
    // picture of the diagram. A slide of shapes with no flows (text boxes on a title slide) comes after those,
    // and a photo on a title slide last. A hidden slide is read only when no visible slide has a diagram.
    const most = list => (list.length ? list.reduce((a, b) => (b.model.elements.length > a.model.elements.length ? b : a)) : null);
    const isDiagram = s => s.model.elements.length >= 3 && s.model.flows.length >= 1;
    const flowing = list => list.find(isDiagram) || most(list.filter(s => s.model.elements.length >= 2 && s.model.flows.length >= 1));
    const drawn = list => most(list.filter(s => s.model.elements.length >= 2));
    const picture = (hidden, title) => pictures.filter(p => p.hidden === hidden && p.title === title).reduce((a, b) => (!a || b.area > a.area ? b : a), null);
    const shown = read.filter(s => !s.hidden), hid = read.filter(s => s.hidden);
    const choice = [() => flowing(shown), () => picture(false, false), () => flowing(hid), () => picture(true, false),
      () => drawn(shown), () => drawn(hid), () => picture(false, true), () => picture(true, true)].reduce((found, next) => found || next(), null);
    if (choice && choice.model) {
      const best = choice, { model } = best;
      const others = read.filter(s => s !== best && isDiagram(s));
      if (others.length) {
        const which = !best.hidden && others.some(s => s.hidden && s.index < best.index) ? 'the first visible one' : 'the first';
        const names = others.map(s => `${s.index + 1}${s.hidden ? ' (hidden)' : ''}`);
        notes.unshift(`This deck has diagrams on ${others.length + 1} slides: slide ${best.index + 1}, ${which}, was read, and slide${others.length === 1 ? '' : 's'} `
          + `${names.length > 3 ? `${names.slice(0, 3).join(', ')} and ${names.length - 3} more` : names.join(', ')} ${others.length === 1 ? 'was' : 'were'} not. `
          + 'To model another slide, copy it into a deck of its own and upload that.');
      }
      if (best.hidden) notes.unshift(`Slide ${best.index + 1} is hidden in the deck. It was read because no visible slide has a diagram.`);
      return finish({
        name: '', source: { kind: 'pptx', file: file || '', method: 'parsed', slide: best.index + 1 },
        page: model.page, zones: model.zones, elements: model.elements, flows: model.flows, notes: notes.concat(model.notes),
      });
    }
    if (choice) {
      let bytes;
      try { bytes = await reader.bytes(choice.path, MAX_PICTURE); } catch (e) { throw e.tooLarge ? big() : e; }
      return { image: { blob: new Blob([bytes], { type: IMAGE_TYPES[choice.ext] }), mediaType: IMAGE_TYPES[choice.ext],
        name: `${file || 'slide'} (${choice.hidden ? 'hidden ' : ''}slide ${choice.slide})`, slide: choice.slide } };
    }
    if (skipped.length) {
      throw new Error(`No diagram could be read from the PowerPoint file: slide${skipped.length === 1 ? '' : 's'} ${skipped.slice(0, 5).join(', ')}${skipped.length > 5 ? ' …' : ''} `
        + `${skipped.length === 1 ? 'is' : 'are'} too large to read (over ${Math.min(MAX_PART, DECK_XML) / MB} MB unpacked), and no other slide has a diagram.`);
    }
    throw new Error('No diagram found in the PowerPoint file: no slide has shapes and connectors, or a picture of one.'
      + (looseText ? ' Text boxes count as elements only when a connector is attached to them: drag each connector’s ends onto the boxes they join.' : ''));
  }

  // ---------------------------------------------------------------- draw.io exports (.svg, .png)

  /** Decode the five XML entities and character references in one pass. */
  const decodeXml = text => text.replace(/&(#x[0-9a-f]+|#\d+|quot|lt|gt|amp|apos);/gi, (whole, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return n <= 0x10ffff ? String.fromCodePoint(n) : '�';
    }
    return { quot: '"', lt: '<', gt: '>', amp: '&', apos: "'" }[e.toLowerCase()];
  });

  /** Where a '<!' declaration (a DOCTYPE, with any internal subset) that starts at i ends, or -1. */
  function declarationEnd(text, i) {
    let quote = '', depth = 0;
    for (let k = i + 2; k < text.length; k++) {
      const ch = text[k];
      if (quote) { if (ch === quote) quote = ''; } else if (ch === '"' || ch === "'") quote = ch;
      else if (ch === '[') depth++;
      else if (ch === ']') depth = Math.max(0, depth - 1);
      else if (ch === '>' && !depth) return k + 1;
    }
    return -1;
  }

  /**
   * draw.io's SVG export keeps the diagram in the <svg content="…"> attribute. Found in one forward pass over
   * the markup: the XML declaration, comments, a DOCTYPE and CDATA are stepped over, and each attribute's
   * quoted value is read where it stands, so a '>' inside one is just text. Any prefix (<svg:svg>) will do.
   */
  function drawioFromSvg(text) {
    const tagName = /<([^\s/>!?<]+)/y;
    const attr = /\s+([^\s=/>"'<]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'))?/y;
    const past = (end, from) => { const k = text.indexOf(end, from); return k < 0 ? -1 : k + end.length; };
    for (let i = text.indexOf('<'); i >= 0; i = text.indexOf('<', i)) {
      if (text.startsWith('<!--', i)) i = past('-->', i + 4);
      else if (text.startsWith('<![CDATA[', i)) i = past(']]>', i + 9);
      else if (text.startsWith('<?', i)) i = past('?>', i + 2);
      else if (text.startsWith('<!', i)) i = declarationEnd(text, i);
      else if (text[i + 1] === '/') i += 2;
      else {
        tagName.lastIndex = i;
        const tag = tagName.exec(text);
        if (!tag) { i++; continue; }
        const svg = /^([\w.-]+:)?svg$/i.test(tag[1]);
        let k = tagName.lastIndex;
        for (;;) {
          attr.lastIndex = k;
          const a = attr.exec(text);
          if (!a) break;
          k = attr.lastIndex;
          if (svg && a[1].toLowerCase() === 'content' && (a[2] != null || a[3] != null)) {
            const content = decodeXml(a[2] ?? a[3]);
            if (content.includes('<mxfile') || content.includes('<mxGraphModel')) return content;
          }
        }
        i = k;
      }
      if (i < 0) return null;
    }
    return null;
  }

  /** draw.io's PNG export keeps the diagram in a tEXt chunk named mxfile (older ones: zTXt mxGraphModel). */
  async function drawioFromPng(bytes) {
    if (bytes.length < 8 || bytes[0] !== 0x89 || bytes[1] !== 0x50) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const latin1 = arr => new TextDecoder('latin1').decode(arr);
    for (let p = 8; p + 8 <= bytes.length;) {
      const len = view.getUint32(p);
      const type = latin1(bytes.subarray(p + 4, p + 8));
      const data = bytes.subarray(p + 8, p + 8 + len);
      if (type === 'tEXt' || type === 'zTXt') {
        const nul = data.subarray(0, 80).indexOf(0);   // a keyword is 1 to 79 bytes
        const key = nul > 0 ? latin1(data.subarray(0, nul)) : '';
        if (key === 'mxfile' || key === 'mxGraphModel') {
          let value = null;
          if (type === 'tEXt') {
            value = latin1(data.subarray(nul + 1));
          } else {
            // the PNG standard says zlib; draw.io's older Java export wrote raw deflate, with '+' for spaces
            for (const format of ['deflate', 'deflate-raw']) {
              try { value = await inflateText(data.subarray(nul + 2), format); break; } catch (e) { if (e.tooLarge) throw e; }
            }
            if (value !== null && key === 'mxGraphModel') value = value.replace(/\+/g, ' ');
          }
          if (value !== null) {
            for (let i = 0; i < 2 && value.charAt(0) === '%'; i++) {
              try { value = decodeURIComponent(value); } catch (_) { break; }
            }
            return value;
          }
        }
      }
      if (type === 'IEND') break;
      p += 12 + len;
    }
    return null;
  }

  // ---------------------------------------------------------------- the model

  let seq = 0;
  const newId = prefix => prefix + Date.now().toString(36) + (++seq).toString(36);

  // The CSA §3.2 checks finish() writes. The wording is fixed, so a legacy model's copies can be told from its notes.
  const NO_ELEMENTS = 'No elements found. Check that the diagram has labelled shapes.';
  const NO_FLOWS = 'No data flows found. CSA §3.2 needs the connections between elements: draw them as connectors.';
  const NO_ZONES = 'No trust boundaries found. Draw a dashed container round each trust zone (CSA §3.2): without them, '
    + 'the threats that matter most — those that cross zones — cannot be told apart.';
  const GENERATED = [/^No elements found\. /, /^No data flows found\. /, /^No trust boundaries found\. /, /^\d+ data flows? (has|have) no label\. /,
    /^\d+ elements? (is|are) outside every trust zone/, /^\d+ elements? (has|have) no name/, /^\d+ trust zones? (has|have) no name/];
  const BOUNDARY_LINES = /draws its trust boundaries as \d+ dashed lines?, not as closed shapes/;
  const UNNAMED = /^Unnamed element( \d+)?$/;
  const MORE_NOTES = /^… and ([\d,]+) more notes?\.$/;
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  /** Give each element with no label a name the user can see and change: 'Unnamed element', numbered if several. */
  function nameUnnamed(elements) {
    const blank = elements.filter(e => !e.label);
    if (!blank.length) return;
    const taken = new Set(elements.map(e => e.label));
    if (blank.length === 1 && !taken.has('Unnamed element')) { blank[0].label = 'Unnamed element'; return; }
    let k = taken.has('Unnamed element') ? 2 : 1;
    for (const e of blank) {
      while (taken.has(`Unnamed element ${k}`)) k++;
      e.label = `Unnamed element ${k++}`;
      taken.add(e.label);
    }
  }

  /**
   * Check a model and fill in what follows from it: zone nesting and element membership from geometry,
   * unique ids, valid types, flows that join two different elements. Carries the model's notes and
   * recomputes its warnings (the notes plus the CSA §3.2 checks) from scratch.
   */
  function finish(model) {
    const m = model && typeof model === 'object' ? model : {};
    const list = v => (Array.isArray(v) ? v.filter(x => x && typeof x === 'object') : []);
    const key = v => (scalar(v) ? String(v) : '');
    const notes = [];
    let moreNotes = 0;
    const note = text => {
      const t = clip(String(text).trim(), LIMITS.note);
      if (!t || notes.includes(t)) return;
      if (notes.length < LIMITS.notes) notes.push(t); else moreNotes++;
    };
    // A model saved before notes existed keeps what its warnings learnt from the file, minus finish()'s own checks.
    const legacy = !Array.isArray(m.notes) && Array.isArray(m.warnings);
    for (const n of legacy ? m.warnings.filter(w => typeof w === 'string' && !GENERATED.some(re => re.test(w))) : Array.isArray(m.notes) ? m.notes : []) {
      if (typeof n !== 'string') continue;
      const more = MORE_NOTES.exec(n.trim());   // the count of notes an earlier pass left out, kept as a count
      if (more) moreNotes += +more[1].replace(/,/g, ''); else note(n);
    }

    // At most LIMITS.items of each; flows to the elements left out go with them, counted in one note.
    const rawZones = list(m.zones), rawElements = list(m.elements), rawFlows = list(m.flows);
    const keptIds = new Set(rawElements.slice(0, LIMITS.items).map(e => key(e.id)));
    const cutIds = new Set(rawElements.slice(LIMITS.items).map(e => key(e.id)).filter(id => id && !keptIds.has(id)));
    const toCut = f => cutIds.has(key(f.source)) || cutIds.has(key(f.target));
    const count = n => n.toLocaleString('en');
    const capped = (items, what, more = '') => {
      if (items.length <= LIMITS.items) return items;
      note(`The model has ${count(items.length)} ${what}; only the first ${count(LIMITS.items)} were kept${more}.`);
      return items.slice(0, LIMITS.items);
    };

    // Ids: unique across zones, elements and flows. A repeated id gets a count (a, a_2, a_3…); references
    // to a repeated id mean its first holder.
    const used = new Set(), counts = new Map();
    const unique = (id, prefix) => {
      const base = clip(key(id).trim(), LIMITS.id) || newId(prefix);
      const n = (counts.get(base) || 0) + 1;
      counts.set(base, n);
      let v = n > 1 ? `${base}_${n}` : base;
      while (used.has(v)) v = newId(prefix);
      used.add(v);
      return v;
    };
    const zoneIds = new Map();
    const zones = capped(rawZones, 'trust zones').map(z => {
      const id = unique(z.id, 'z');
      if (key(z.id) && !zoneIds.has(key(z.id))) zoneIds.set(key(z.id), id);
      return { id, label: clip(str(z.label), LIMITS.label) || 'Unnamed trust zone', parent: z.parent, geometry: validGeometry(z.geometry) };
    });
    for (const z of zones) z.parent = zoneIds.get(key(z.parent)) || null;
    const elementIds = new Map();
    const cutFlows = rawFlows.slice(0, LIMITS.items).filter(toCut).length;
    const elements = capped(rawElements, 'elements', cutFlows
      ? `, so ${plural(cutFlows, 'data flow', 'data flows')} to the others ${cutFlows === 1 ? 'was' : 'were'} left out too` : '').map(e => {
      const id = unique(e.id, 'e');
      if (key(e.id) && !elementIds.has(key(e.id))) elementIds.set(key(e.id), id);
      const ctx = e.context && typeof e.context === 'object' ? e.context : {};
      const text = v => clip(str(v), LIMITS.context);
      return {
        id, label: clip(str(e.label), LIMITS.label),
        type: TYPES.includes(e.type) ? e.type : normaliseType(e.type) || 'process',
        zone: zoneIds.get(key(e.zone)) || null,
        geometry: validGeometry(e.geometry),
        context: { purpose: text(ctx.purpose), sensitivity: text(ctx.sensitivity), auth: text(ctx.auth), trust: text(ctx.trust) },
        crownJewel: typeof e.crownJewel === 'boolean' ? e.crownJewel : null,
        ai: typeof e.ai === 'boolean' ? e.ai : null,
      };
    });
    nameUnnamed(elements);

    // Zones inside zones, and each element in its innermost zone (centre-point test, smallest first).
    const sized = zones.filter(z => z.geometry).sort((a, b) => area(a.geometry) - area(b.geometry));
    for (const z of sized) {
      if (z.parent) continue;
      const c = centre(z.geometry);
      const outer = sized.find(o => o !== z && area(o.geometry) > area(z.geometry) && containsPoint(o.geometry, c));
      if (outer) z.parent = outer.id;
    }
    // A zone that is its own ancestor (a file's parents, or theirs and geometry's together) is a top-level zone.
    const zoneById = new Map(zones.map(z => [z.id, z]));
    for (const z of zones) {
      const seen = new Set();
      for (let p = zoneById.get(z.parent); p && !seen.has(p.id); p = zoneById.get(p.parent)) {
        if (p.id === z.id) { z.parent = null; break; }
        seen.add(p.id);
      }
    }
    for (const e of elements) {
      if (e.zone || !e.geometry) continue;
      const c = centre(e.geometry);
      const z = sized.find(o => containsPoint(o.geometry, c));
      if (z) e.zone = z.id;
    }

    // Flows join two different elements; say which were left out, and why.
    const elementById = new Map(elements.map(e => [e.id, e]));
    const flows = [];
    const dropped = [];
    for (const f of capped(rawFlows, 'data flows')) {
      const source = elementIds.get(key(f.source)), target = elementIds.get(key(f.target));
      if ((!source || !target) && toCut(f)) continue;   // counted in the note on the elements left out
      const label = clip(str(f.label), LIMITS.label);
      if (source && target && source !== target) {
        flows.push({ id: unique(f.id, 'f'), source, target, label, bidirectional: !!f.bidirectional });
        continue;
      }
      const name = (raw, id) => (id ? elementById.get(id).label : zoneIds.has(key(raw)) ? zoneById.get(zoneIds.get(key(raw))).label : clip(key(raw), 60) || 'nothing');
      const bad = [[f.source, source, 'source'], [f.target, target, 'target']].filter(([, id]) => !id);
      const zone = bad.find(([raw]) => zoneIds.has(key(raw)));
      const why = !bad.length ? `it joins "${name(f.source, source)}" to itself`
        : zone ? `"${name(zone[0])}" is a trust zone, not an element`
          : bad.map(([raw, , end]) => (key(raw) ? `no element is called "${clip(key(raw), 60)}"` : `it has no ${end}`)).join(' and ');
      dropped.push(`${label ? `The data flow "${label}"` : 'A data flow'} (${name(f.source, source)} to ${name(f.target, target)}) was left out: ${why}.`);
    }
    dropped.slice(0, 10).forEach(note);
    if (dropped.length > 10) note(`${plural(dropped.length - 10, 'more data flow was', 'more data flows were')} left out for the same reasons.`);
    // A slide's trust boundaries drawn as dashed lines were noted with a request to add the zones by hand: once
    // the model has zones, that note has done its work (and would ask for what is already there).
    if (zones.length) for (let i = notes.length - 1; i >= 0; i--) if (BOUNDARY_LINES.test(notes[i])) notes.splice(i, 1);
    if (moreNotes) notes.push(`… and ${count(moreNotes)} more note${moreNotes === 1 ? '' : 's'}.`);

    // The page is the geometry's coordinate space from 0, 0: a diagram drawn at negative coordinates moves onto it.
    const pw = m.page && typeof m.page === 'object' ? num(m.page.w) : NaN, ph = m.page && typeof m.page === 'object' ? num(m.page.h) : NaN;
    let page = Number.isFinite(pw) && Number.isFinite(ph) && pw > 0 && ph > 0 ? { w: pw, h: ph } : null;
    const boxes = [...zones, ...elements].map(x => x.geometry).filter(Boolean);
    if (boxes.length) {
      const minX = boxes.reduce((v, g) => Math.min(v, g.x), Infinity), minY = boxes.reduce((v, g) => Math.min(v, g.y), Infinity);
      const dx = minX < 0 ? -minX : 0, dy = minY < 0 ? -minY : 0;
      if (dx || dy) {
        for (const g of boxes) { g.x += dx; g.y += dy; }
        if (page) page = { w: page.w + dx, h: page.h + dy };
      }
      const maxX = boxes.reduce((v, g) => Math.max(v, g.x + g.w), 0), maxY = boxes.reduce((v, g) => Math.max(v, g.y + g.h), 0);
      if (!page || page.w < maxX || page.h < maxY) page = { w: Math.max(maxX, page ? page.w : 0), h: Math.max(maxY, page ? page.h : 0) };
    }

    const warnings = notes.slice();
    if (!elements.length) warnings.push(NO_ELEMENTS);
    if (elements.length && !flows.length) warnings.push(NO_FLOWS);
    if (elements.length && !zones.length && !notes.some(n => BOUNDARY_LINES.test(n))) warnings.push(NO_ZONES);
    // external entities are outside the system's zones by nature (the skill's sample draws its Customer so)
    const outside = zones.length ? elements.filter(e => !e.zone && e.type !== 'entity') : [];
    if (outside.length) {
      const names = outside.slice(0, 5).map(e => `"${e.label}"`).join(', ') + (outside.length > 5 ? ` and ${outside.length - 5} more` : '');
      warnings.push(`${plural(outside.length, 'element is', 'elements are')} outside every trust zone: ${names}. `
        + 'Put each in the zone it runs in, so the threats that cross zones are found.');
    }
    const unnamed = elements.filter(e => UNNAMED.test(e.label)).map(e => `"${e.label}"`);
    if (unnamed.length) {
      const n = unnamed.length, called = n <= 3 ? unnamed.join(n === 2 ? ' and ' : ', ') : `${unnamed.slice(0, 2).join(', ')} and so on`;
      warnings.push(`${plural(n, 'element has', 'elements have')} no name in the diagram, so ${n === 1 ? 'it is' : 'they are'} `
        + `called ${called}: name ${n === 1 ? 'it' : 'them'} so the register says what is at risk.`);
    }
    const unnamedZones = zones.filter(z => z.label === 'Unnamed trust zone').length;
    if (unnamedZones) {
      warnings.push(`${plural(unnamedZones, 'trust zone has', 'trust zones have')} no name, so ${unnamedZones === 1 ? 'it is' : 'they are'} `
        + `called "Unnamed trust zone": name ${unnamedZones === 1 ? 'it' : 'them'} so the register says where each element sits.`);
    }
    const unlabelled = flows.filter(f => !f.label).length;
    if (unlabelled) {
      warnings.push(`${unlabelled} data flow${unlabelled === 1 ? ' has' : 's have'} no label. A protocol or data type (HTTPS, SQL, SMB) sharpens the threats.`);
    }
    // Where the model came from: text only (a saved file could hold anything here), and the slide it was read from.
    const from = m.source && typeof m.source === 'object' ? m.source : {};
    const source = { kind: clip(str(from.kind), 40) || 'manual', file: clip(str(from.file), LIMITS.label), method: clip(str(from.method), 40) || 'manual' };
    const slide = num(from.slide);
    if (Number.isInteger(slide) && slide > 0) source.slide = slide;
    return {
      version: 1,
      name: clip(str(m.name), LIMITS.name),
      source,
      page, zones, elements, flows, notes,
      warnings: [...new Set(warnings)],
    };
  }

  function validGeometry(g) {
    if (!g || typeof g !== 'object') return null;
    const out = { x: num(g.x), y: num(g.y), w: num(g.w), h: num(g.h) };
    return Object.values(out).every(Number.isFinite) && out.w > 0 && out.h > 0 ? out : null;
  }

  /**
   * Apply a component-context JSON (the skill's format: { "<label or id>": { purpose, sensitivity, auth,
   * trust, type?, crown_jewel?, ai? } }) to a model. Returns the labels that matched nothing.
   */
  function applyContext(model, json) {
    const unmatched = [];
    for (const [key, value] of Object.entries(json || {})) {
      if (!value || typeof value !== 'object') continue;
      const k = String(key).trim().toLowerCase();
      const e = model.elements.find(x => x.id === key) || model.elements.find(x => x.label.toLowerCase() === k)
        || model.elements.find(x => str(value.label) && x.label.toLowerCase() === str(value.label).toLowerCase());
      if (!e) { unmatched.push(key); continue; }
      const info = contextFrom(value);
      for (const [f, v] of Object.entries(info.context)) if (v) e.context[f] = v;
      if (info.type) e.type = info.type;
      if (info.crownJewel !== null) e.crownJewel = info.crownJewel;
      if (info.ai !== null) e.ai = info.ai;
    }
    return unmatched;
  }

  /** A model saved by this page (Save decomposition). */
  function fromJson(text, file) {
    let data;
    try { data = JSON.parse(text); } catch (_) { throw new Error("The JSON file can't be read."); }
    const m = data && data.threatsimModel ? data.threatsimModel : data;
    if (!m || !Array.isArray(m.elements)) throw new Error("This JSON isn't a saved ThreatSim decomposition (no elements list).");
    const method = str(m.source && typeof m.source === 'object' ? m.source.method : '');
    return finish(Object.assign({}, m, { source: { kind: 'json', file: file || '', method: method || 'manual' } }));
  }

  function toJson(model) {
    return JSON.stringify({ threatsimModel: model }, null, 2);
  }

  /**
   * Read an uploaded file. Resolves to { model } or { image: { blob, mediaType, name } }; rejects with a
   * message for the user when the file can't be used.
   */
  async function parseFile(file) {
    const name = file.name || 'diagram';
    const ext = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
    const most = ext === 'pptx' || ext === 'potx' ? MAX_DECK : MAX_FILE;
    if (file.size > most) throw new Error(`This file is too large to read (over ${most / MB} MB).`);
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    if (ext === 'pptx' || ext === 'potx') return asResult(await parsePptx(buffer, name));
    if (ext === 'ppt') throw new Error('Old PowerPoint files (.ppt) can’t be read. Save the deck as .pptx and upload that.');
    if (ext === 'vsdx' || ext === 'vsd') {
      throw new Error('Visio files can’t be read directly. Open the file in draw.io (app.diagrams.net), then use File > Export as > XML and upload that.');
    }
    if (ext === 'json') return { model: fromJson(new TextDecoder().decode(bytes), name) };
    if (ext === 'png') {
      // a draw.io PNG carries its diagram; if that can't be read, or holds no shapes (a pasted screenshot),
      // the PNG is still a picture of the diagram
      try {
        const xml = await drawioFromPng(bytes);
        if (xml) {
          const model = withFile(await parseDrawio(xml, name), 'drawio');
          if (model.elements.length) return { model };
        }
      } catch (_) { /* read it as a picture */ }
    }
    if (ext === 'svg') {
      const xml = drawioFromSvg(new TextDecoder().decode(bytes));
      if (xml) return drawioResult(xml, name, 'drawio');
      throw new Error('This SVG has no draw.io diagram inside it. Upload the draw.io file, or a PNG or JPEG picture of the diagram.');
    }
    if (IMAGE_TYPES[ext]) return { image: { blob: new Blob([bytes], { type: IMAGE_TYPES[ext] }), mediaType: IMAGE_TYPES[ext], name } };
    const text = new TextDecoder().decode(bytes);
    if (/<mxfile|<mxGraphModel/.test(text.slice(0, 4096)) || ext === 'drawio' || ext === 'xml') return drawioResult(text, name);
    throw new Error('This file type can’t be read. Upload a draw.io diagram (.drawio, .xml, or a draw.io .png / .svg), '
      + 'a PowerPoint slide (.pptx), a picture (.png, .jpg, .gif, .webp) or a saved decomposition (.json).');
  }
  const asResult = r => (r.image ? r : { model: r });
  const withFile = (model, kind) => Object.assign(model, { source: Object.assign({}, model.source, { kind }) });

  global.TMParse = {
    TYPES, TYPE_LABELS, parseFile, parseDrawio, parsePptx, fromJson, toJson, finish, applyContext,
    stripHtml, classify, styleDict, hasWord, DATASTORE_WORDS, ENTITY_WORDS, BOUNDARY_WORDS, newId,
  };
})(window);
