/*
 * workpaper.js — exports the simulator dashboard as an Excel workpaper.
 *
 * Global `Workpaper`. Builds an .xlsx with ExcelJS (vendored in js/vendor and
 * loaded on first use) with these sheets: Executive Summary, one Matrix sheet
 * per domain, Techniques, Mitigations, Detections, ICS Assets, Telemetry,
 * Analytics, Control Map and NIST 800-53. The last comes from CTID's Mappings
 * Explorer (r.nist, set by SimEngine.mapExternal).
 *
 * The status cells on Mitigations and Detections are drop-down inputs. Every
 * figure that depends on them — technique coverage, the readiness bars, matrix
 * status, the "live" columns — is a formula, so the workbook recalculates when a
 * status changes. Each formula also carries its value for the posture at export,
 * so previews that never recalculate still show the right numbers.
 */
(function (global) {
  'use strict';

  const EXCELJS_SRC = 'js/vendor/exceljs.min.js';
  const XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

  const MIT = { on: 'In Place', off: 'Not In Place' };
  const DET = { on: 'Deployed', off: 'Not Deployed' };
  const COVERAGE = { covered: 'Mitigated + detected', mitigated: 'Mitigated only', detected: 'Detected only', gap: 'No coverage' };
  const GLYPH = { covered: '✓', mitigated: 'M', detected: 'D', gap: '✕' };
  const SHEET = {
    summary: 'Executive Summary', techniques: 'Techniques', mitigations: 'Mitigations', detections: 'Detections',
    assets: 'ICS Assets', telemetry: 'Telemetry', analytics: 'Analytics', map: 'Control Map',
    nist: 'NIST 800-53',
  };
  // CTID Mappings Explorer source (MappingsDB id)
  const NIST_SOURCE = 'nist-800-53-r5';
  // Why an Enterprise profile technique has no 800-53 control (Techniques sheet): CTID judged it, or CTID's mapping
  // has no row for it at all (some of those were added to ATT&CK after the release CTID mapped)
  const NO_CONTROL = {
    judged: 'CTID: not mappable',
    absent: v => 'Not in CTID\'s mapping' + (v ? ` (ATT&CK ${v})` : ''),
    late: v => `Not in CTID's mapping: added to ATT&CK after ${v}`,
  };
  const matrixSheetName = label => 'Matrix (' + label + ')';

  // Readiness bars on the summary: BAR.cells narrow columns from column BAR.first, each worth 1/BAR.cells.
  const BAR = { first: 10, cells: 40 };
  const TOP_ACTIONS = 10;
  const CHANNELS_PER_SOURCE = 8;   // Telemetry 'What to collect'; the Analytics sheet lists every one

  // Light palette only: spreadsheet cells have no dark mode.
  const C = {
    ink: 'FF111827', muted: 'FF6B7280', white: 'FFFFFFFF',
    header: 'FF1F2937', band: 'FF334155', subband: 'FFE2E8F0', border: 'FFD1D5DB',
    input: 'FFFFF4CC', inputSoft: 'FFFFFBEB', inputBorder: 'FFD4A600', inputHeader: 'FF8A6D00', inputTab: 'FFFAB219',
    live: 'FFF1F5F9', link: 'FF1D4ED8', track: 'FFE5E7EB', idle: 'FFF3F4F6',
    good: 'FF0CA30C', warning: 'FFFAB219', critical: 'FFD03B3B',
    goodTint: 'FFD9F2D9', goodInk: 'FF0B5D0B', warnTint: 'FFFFF0C7', warnInk: 'FF7A5200', critTint: 'FFF9D6D6', critInk: 'FF8B1D1D',
  };
  // Sequential blue (usage), light steps 1-6 with the ink that stays legible on each.
  const SEQ = [
    ['FFCDE2FB', 'FF0B0B0B'], ['FF9EC5F4', 'FF0B0B0B'], ['FF6DA7EC', 'FF0B0B0B'],
    ['FF2A78D6', 'FFFFFFFF'], ['FF1C5CAB', 'FFFFFFFF'], ['FF104281', 'FFFFFFFF'],
  ];

  // ---------- column layouts (fixed, so formulas can address columns by key) ----------
  // wrap: the cell wraps and its row grows to fit. Everything else stays on one line.

  const TECH_COLS = [
    { key: 'domain', header: 'Domain', width: 11 },
    { key: 'id', header: 'Technique ID', width: 12, link: true },
    { key: 'name', header: 'Technique', width: 32, wrap: true },
    { key: 'parent', header: 'Sub-technique of', width: 26, wrap: true },
    { key: 'tactics', header: 'Tactics', width: 22, wrap: true },
    { key: 'platforms', header: 'Platforms', width: 24, wrap: true },
    { key: 'usedN', header: 'Used by (#)', width: 9, fmt: '0', center: true },
    { key: 'usedBy', header: 'Used by', width: 32 },
    { key: 'mitN', header: 'Mitigations (#)', width: 11, fmt: '0', center: true },
    { key: 'mits', header: 'Mitigations', width: 42 },
    { key: 'detN', header: 'Detection strategies (#)', width: 11, fmt: '0', center: true },
    { key: 'dets', header: 'Detection strategies', width: 42 },
    { key: 'assets', header: 'ICS assets targeted', width: 30 },
    { key: 'nistN', header: 'NIST 800-53 controls (#)', width: 10, fmt: '0', center: true },
    { key: 'mitigated', header: 'Mitigation in place? (live)', width: 13, live: true, center: true },
    { key: 'detected', header: 'Detection deployed? (live)', width: 13, live: true, center: true },
    { key: 'coverage', header: 'Coverage (live)', width: 21, live: true },
    { key: 'procedures', header: 'How the profile uses it (procedure examples)', width: 80, noPrint: true },
    { key: 'description', header: 'Description', width: 80, noPrint: true },
    { key: 'nistWhy', header: 'Why no NIST 800-53 control', width: 36, noPrint: true },   // NO_CONTROL; blank when it has one
    { key: 'nistNote', header: 'CTID\'s comment (not mappable)', width: 60, noPrint: true },
    { key: 'key', header: 'Key', helper: true },
    { key: 'tacticKeys', header: 'Tactic keys', helper: true },
    { key: 'assetKeys', header: 'Asset keys', helper: true },
    { key: 'code', header: 'Coverage code (live)', helper: true },
    { key: 'nistKeys', header: 'NIST control keys', helper: true },   // ';Enterprise:AC-2;…;'
  ];

  // Shared by Mitigations and Detections: the inputs sit right after the name so they stay in view.
  const controlCols = (noun, statusHeader, verb) => [
    { key: 'priority', header: 'Priority (at export)', width: 9, fmt: '0', center: true },
    { key: 'domain', header: 'Domain', width: 11 },
    { key: 'id', header: noun + ' ID', width: 12, link: true },
    { key: 'name', header: noun, width: noun === 'Mitigation' ? 32 : 44, wrap: true },
    { key: 'status', header: statusHeader, width: 17, input: true },
    { key: 'owner', header: 'Owner', width: 16, inputSoft: true, wrap: true },
    { key: 'targetDate', header: 'Target date', width: 12, inputSoft: true, fmt: 'yyyy-mm-dd' },
    { key: 'notes', header: 'Notes / evidence', width: 36, inputSoft: true, wrap: true },
    { key: 'statusAtExport', header: 'Status at export', width: 13 },
    { key: 'changed', header: 'Changed since export (live)', width: 12, live: true, center: true },
    { key: 'techN', header: `Profile techniques ${verb} (#)`, width: 12, fmt: '0', center: true },
    { key: 'share', header: "Share of its domain's profile techniques", width: 13, fmt: '0.0%', center: true },
    { key: 'adds', header: 'Adds (at export)', width: 10, fmt: '0', center: true },
    { key: 'score', header: 'Weighted score (at export)', width: 10, fmt: '0', center: true },
    { key: 'cumulative', header: `Cumulative share ${noun === 'Mitigation' ? 'mitigated' : 'detected'} (at export)`, width: 13, fmt: '0%', center: true },
    { key: 'open', header: noun === 'Mitigation' ? 'Unmitigated techniques it addresses (live)' : 'Undetected techniques it covers (live)', width: 15, fmt: '0', live: true, center: true },
  ];

  const MIT_COLS = [
    ...controlCols('Mitigation', 'Implementation status ▼', 'addressed'),
    { key: 'techs', header: 'Profile techniques addressed (IDs)', width: 40 },
    { key: 'description', header: 'Description', width: 80, noPrint: true },
    { key: 'key', header: 'Key', helper: true },
    { key: 'nistKeys', header: 'NIST control keys', helper: true },   // the NIST controls sharing a profile technique with it
  ];

  const DET_COLS = [
    ...controlCols('Detection strategy', 'Deployment status ▼', 'covered'),
    { key: 'techs', header: 'Profile techniques covered (IDs)', width: 30 },
    { key: 'anN', header: 'Analytics (#)', width: 10, fmt: '0', center: true },
    { key: 'platforms', header: 'Analytic platforms', width: 22, wrap: true },
    { key: 'dcs', header: 'Data components', width: 36, noPrint: true },   // the Analytics sheet prints these in full
    { key: 'logSources', header: 'Log sources', width: 36, noPrint: true },
    { key: 'key', header: 'Key', helper: true },
    { key: 'dcKeys', header: 'Data component keys', helper: true },
  ];

  const ASSET_COLS = [
    { key: 'id', header: 'Asset ID', width: 10, link: true },
    { key: 'name', header: 'ICS asset', width: 32, wrap: true },
    { key: 'techN', header: 'Profile techniques targeting it (#)', width: 13, fmt: '0', center: true },
    { key: 'share', header: 'Share of ICS profile techniques', width: 13, fmt: '0.0%', center: true },
    { key: 'exposed', header: 'Targeting techniques with no coverage (live)', width: 16, fmt: '0', live: true, center: true },
    { key: 'covered', header: 'Targeting techniques fully covered (live)', width: 16, fmt: '0', live: true, center: true },
    { key: 'platforms', header: 'Platforms', width: 24, wrap: true },
    { key: 'sectors', header: 'Sectors', width: 16 },
    { key: 'techs', header: 'Profile techniques targeting it (IDs)', width: 50 },
    { key: 'description', header: 'Description', width: 80, noPrint: true },
    { key: 'key', header: 'Key', helper: true },
  ];

  const TEL_COLS = [
    { key: 'domain', header: 'Domain', width: 11 },
    { key: 'id', header: 'Data component ID', width: 13, link: true },
    { key: 'name', header: 'Data component', width: 30, wrap: true },
    { key: 'techN', header: 'Profile techniques it helps detect (#)', width: 14, fmt: '0', center: true },
    { key: 'share', header: "Share of its domain's profile techniques", width: 13, fmt: '0.0%', center: true },
    { key: 'dsN', header: 'Detection strategies relying on it (#)', width: 14, fmt: '0', center: true },
    { key: 'deployed', header: 'Deployed strategies using it (live)', width: 14, fmt: '0', live: true, center: true },
    { key: 'logSources', header: 'Log sources', width: 40 },
    { key: 'details', header: 'What to collect (log source: what to look for; the Analytics sheet lists every entry)', width: 90 },
    { key: 'description', header: 'Description', width: 60, noPrint: true },
    { key: 'key', header: 'Key', helper: true },
  ];

  const ANALYTIC_COLS = [
    { key: 'domain', header: 'Domain', width: 11 },
    { key: 'detId', header: 'Detection ID', width: 12, link: true },
    { key: 'anId', header: 'Analytic ID', width: 11, link: true },
    { key: 'det', header: 'Detection strategy', width: 40, wrap: true },
    { key: 'status', header: 'Deployment status (live)', width: 15, live: true },
    { key: 'platforms', header: 'Platforms', width: 18, wrap: true },
    { key: 'dc', header: 'Data component', width: 28 },
    { key: 'logSource', header: 'Log source', width: 30 },
    { key: 'lookFor', header: 'What to look for', width: 80 },
    { key: 'techs', header: 'Profile techniques the strategy covers', width: 24 },
    { key: 'description', header: 'Analytic description', width: 80, noPrint: true },
    { key: 'detKey', header: 'Detection key', helper: true },
  ];

  const MAP_COLS = [
    { key: 'domain', header: 'Domain', width: 11 },
    { key: 'techId', header: 'Technique ID', width: 12 },
    { key: 'ctlId', header: 'Control ID', width: 11, link: true },
    { key: 'tech', header: 'Technique', width: 32, wrap: true },
    { key: 'type', header: 'Control type', width: 17 },
    { key: 'ctl', header: 'Control', width: 40, wrap: true },
    { key: 'status', header: 'Control status (live)', width: 15, live: true },
    { key: 'guidance', header: 'How it applies to this technique', width: 90 },
    { key: 'techKey', header: 'Technique key', helper: true },
    { key: 'ctlKey', header: 'Control key', helper: true },
    { key: 'techCovered', header: 'Technique covered by this control type (live)', helper: true },
  ];
  const MAP_TYPE = { mit: 'Mitigation', det: 'Detection strategy' };

  // One row per control mitigating at least one profile technique (NIST maps Enterprise ATT&CK only).
  const NIST_COLS = [
    { key: 'domain', header: 'Domain', width: 11 },
    { key: 'id', header: 'Control ID', width: 9 },
    { key: 'name', header: 'Control', width: 28, wrap: true },
    { key: 'family', header: 'Control family', width: 24, wrap: true },
    { key: 'techN', header: 'Profile techniques it mitigates (#)', width: 11, fmt: '0', center: true },
    { key: 'viaParentN', header: 'Of which through the parent technique (#)', width: 11, fmt: '0', center: true },
    { key: 'gaps', header: 'Gaps it addresses: no coverage (live)', width: 12, fmt: '0', live: true, center: true },
    { key: 'open', header: 'Techniques it mitigates not fully covered (live)', width: 12, fmt: '0', live: true, center: true },
    { key: 'mitN', header: 'Related ATT&CK mitigations (#)', width: 11, fmt: '0', center: true },
    { key: 'mitOn', header: 'Related mitigations in place (live)', width: 11, fmt: '0', live: true, center: true },
    // ThreatSim's link, not CTID's: the profile's ATT&CK mitigations addressing the same techniques. The printed
    // column shows the top few (a control can share techniques with 40 mitigations); the full list is not printed.
    { key: 'mitsTop', header: 'Top related ATT&CK mitigations (shared profile techniques)', width: 32, wrap: true },
    { key: 'techs', header: 'Profile techniques it mitigates (IDs)', width: 60, noPrint: true },
    { key: 'mits', header: 'Related ATT&CK mitigations (shared profile techniques, most first)', width: 60, noPrint: true },
    { key: 'comments', header: 'CTID comments', width: 80, noPrint: true },
    { key: 'key', header: 'Key', helper: true },
  ];

  // ---------- small helpers ----------

  function colLetter(n) {
    let s = '';
    while (n > 0) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - 1) / 26); }
    return s;
  }
  const quoteSheet = name => "'" + name.replace(/'/g, "''") + "'";
  const lit = s => '"' + String(s).replace(/"/g, '""') + '"';       // string literal inside a formula
  const F = (formula, result) => ({ formula, result });
  const uniq = a => [...new Set(a)];
  const byAttackId = (a, b) => String(a.attackId).localeCompare(String(b.attackId), undefined, { numeric: true });
  const byName = (a, b) => String(a.name || '').localeCompare(String(b.name || ''));
  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);
  /** A key part without the characters COUNTIFS treats as wildcards or that the key lists use as separators. */
  const safeKey = s => String(s).replace(/[*?~;]/g, '_');
  /** First n items, then '+N more'. */
  const listCapped = (items, n, sep = ', ') => items.slice(0, n).join(sep) + (items.length > n ? `${sep}+${items.length - n} more` : '');
  /**
   * Lines a long cell wraps to, breaking after spaces and hyphens as the apps do (a token longer than a line is
   * split); for long texts, where a plain length / perLine over-counts by a few lines.
   */
  const wrapLines = (s, perLine) => {
    let n = 1, len = 0;
    for (const w of String(s).split(/(?<=[\s-])/)) {
      if (len && len + w.trimEnd().length > perLine) { n++; len = 0; }
      len += w.length;
      while (len > perLine) { n++; len -= perLine; }
    }
    return n;
  };

  const KB_NAMES = { attack: 'ATT&CK', atlas: 'ATLAS' };
  /** How a procedure path names the campaign or case study it passes through (as the dashboard does). */
  const VIA_PREFIX = { campaign: 'campaign ', 'case-study': 'case study ' };
  /** The knowledge bases a workbook covers: 'ATT&CK', 'ATLAS' or 'ATT&CK and ATLAS'. */
  const kbList = P => [...new Set(P.domains.map(D => D.kb))].join(' and ') || 'ATT&CK';
  const workbookTitle = P => kbList(P) + ' threat readiness workpaper';
  /** A release date; ATLAS gives plain days ('2026-10-28'), shown as written rather than shifted to local time. */
  const fmtDay = s => new Date(s).toLocaleDateString(undefined,
    /^\d{4}-\d{2}-\d{2}$/.test(String(s)) ? { dateStyle: 'medium', timeZone: 'UTC' } : { dateStyle: 'medium' });

  const MAX_CELL = 32000;   // Excel's limit is 32,767 characters per cell

  /** Text that is valid XML 1.0 and fits in a cell. */
  function clean(s) {
    if (s == null) return '';
    // control characters, and the bidirectional overrides and isolates that could make text display
    // reversed or spoofed (U+202A-U+202E, U+2066-U+2069)
    let t = String(s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u202A-\u202E\u2066-\u2069￾￿]/g, '');
    t = typeof t.toWellFormed === 'function'
      ? t.toWellFormed()
      : t.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]|[\uD800-\uDFFF]/g, m => (m.length === 2 ? m : '�'));
    if (t.length > MAX_CELL) {
      let cut = MAX_CELL - 1;
      if (/[\uD800-\uDBFF]/.test(t[cut - 1])) cut--;
      t = t.slice(0, cut) + '…';
    }
    return t;
  }

  const ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ' };
  function decodeEntities(t) {
    return t.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
      if (e[0] === '#') {
        const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1));
        return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : m;
      }
      const k = e.toLowerCase();
      return Object.prototype.hasOwnProperty.call(ENTITIES, k) ? ENTITIES[k] : m;
    });
  }

  /**
   * ATT&CK and ATLAS description markdown flattened to one line of plain text: citations (ATT&CK
   * "(Citation: …)", ATLAS "[[ref]]"), links (incl. ATLAS site-relative ones), emphasis, headings,
   * <br> and entities removed; list items become "• "; code spans kept as written.
   */
  function plain(md) {
    if (!md) return '';
    const spans = [];
    const keep = c => '\u0001' + (spans.push(c) - 1) + '\u0002';   // code is kept as written
    const t = decodeEntities(String(md)
      .replace(/```[^\n`]*\n?([\s\S]*?)```/g, (_, c) => keep(c.trim().replace(/\s*\n\s*/g, ' ')))   // ATLAS code fences
      .replace(/\s*\(Citation:[^)]*\)/g, '')
      .replace(/\[\[[^\]]*\]\](\(\s*[^)\s]*\s*\))?/g, '')
      // links (also ATLAS's with spaces, empty targets, or site-relative paths) become their text
      .replace(/\[([^\]]+)\]\(\s*(?:(?:https?:\/\/|\/)[^)\s]*|(?:tactics|techniques|mitigations|studies|entities|software)\/[^)\s]*)?\s*\)/g, '$1')
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/?code>/gi, '')
      .replace(/`([^`]+)`/g, (_, c) => keep(c))
      // ATLAS presentational wrappers: the tags go, their text stays (placeholders like <profile_name> stay too)
      .replace(/<\/?(?:atlas-[a-z-]+|div|span|sup)(?:\s[^>]*)?>/gi, '')
      // ATLAS markdown tables: rule rows go, each row's cells are joined
      .replace(/^[ \t]*\|?(?:[ \t]*:?-+:?[ \t]*\|)+[ \t]*(?::?-+:?)?[ \t]*$/gm, '')
      .replace(/^[ \t]*\|(.*)\|[ \t]*$/gm, (_, r) => r.split('|').map(c => c.trim()).filter(Boolean).join(', ') + ';')
      .replace(/^[ \t]*>[ \t]?/gm, '')
      .replace(/^#{1,6}[ \t]+/gm, '')
      .replace(/\*\*([^*]+)\*\*/g, '$1')
      .replace(/(^|[\s(])\*(?=[^\s*])([^*\n]*?[^\s*\\])\*(?=$|[\s.,;:!?)])/gm, '$1$2')
      .replace(/\\([*_])/g, '$1')
      .replace(/\u0001(\d+)\u0002/g, (_, i) => spans[Number(i)]))
      .replace(/^[ \t]*[*-][ \t]+/gm, '• ')
      .replace(/\s*\n\s*/g, ' ')
      .replace(/[ \t]{2,}/g, ' ')
      .trim();
    return clean(t);
  }

  /** CTID's mapping comments: plain text, minus emphasis markers CTID left unclosed. */
  const ctidText = s => plain(s).replace(/\*\*/g, '');
  /** Log-source channel text is query and log syntax, not markdown: keep it verbatim on one line. */
  const channelText = s => clean(String(s).replace(/\s+/g, ' ').trim());
  /** Log-source names, trimmed: a few ATT&CK references carry a trailing space. */
  const sourceName = l => String(l.name || '').trim();

  const link = (text, url) => (url ? { text: clean(text), hyperlink: url } : clean(text));
  const solid = argb => ({ type: 'pattern', pattern: 'solid', fgColor: { argb }, bgColor: { argb } });
  const thin = argb => ({ style: 'thin', color: { argb } });
  const box = argb => ({ top: thin(argb), left: thin(argb), bottom: thin(argb), right: thin(argb) });
  const font = (o = {}) => Object.assign({ name: 'Calibri', size: 10, color: { argb: C.ink } }, o);

  function put(ws, row, col, value, style) {
    const cell = ws.getCell(row, col);
    cell.value = value;
    if (style) Object.assign(cell, style);
    return cell;
  }

  /** Column addressing for one table sheet (header in row 1, data from row 2). */
  function layout(sheet, cols, count) {
    const idx = new Map(cols.map((c, i) => [c.key, i + 1]));
    const last = Math.max(2, count + 1);   // never an inverted range, even for an empty table
    const letter = key => {
      if (!idx.has(key)) throw new Error(`Unknown column ${key} on ${sheet}`);
      return colLetter(idx.get(key));
    };
    return {
      sheet, cols, count, last, letter,
      range: key => `${quoteSheet(sheet)}!$${letter(key)}$2:$${letter(key)}$${last}`,
    };
  }

  /** Per-sheet conditional-format priority counter. */
  function priorities() { let p = 0; return () => ++p; }

  /**
   * Page footer: sheet name, profile and date, page numbers. '&' starts a footer code, so it is
   * doubled; no font-size codes, since '&8' followed by a name like '2015 …' would read as size 82015.
   */
  function footer(ws, centre) {
    const short = centre.length > 150 ? centre.slice(0, 149) + '…' : centre;
    ws.headerFooter = { oddFooter: `&L&A&C${short.replace(/&/g, '&&')}&RPage &P of &N` };
  }

  // ---------- data preparation (no ExcelJS) ----------

  function prepare(ctx) {
    const P = { domains: [], techniques: [], mitigations: [], detections: [], assets: [], telemetry: [], analytics: [], map: [], profile: [],
      nist: [], unresolved: new Set() };
    const generated = ctx.generatedAt || new Date();
    // CTID mappings pulled when the workbook was exported (provenance from the simulator's ctx.mappings)
    const pulled = id => (Array.isArray(ctx.mappings) ? ctx.mappings : []).find(x => x && x.source === id) || null;
    P.mappings = { nist: pulled(NIST_SOURCE) };
    // the ATT&CK release CTID's NIST mapping targets, and whether a technique was added to ATT&CK after it
    const nistVersion = P.mappings.nist && P.mappings.nist.attackVersion ? String(P.mappings.nist.attackVersion) : '';
    const addedAfter = tech => global.SimEngine.addedAfterRelease(tech, nistVersion);

    for (const r of ctx.results) {
      const m = r.model;
      const label = ctx.domainLabel(r.domain);
      const keyOf = o => label + ':' + (o.attackId || o.id);
      const tacticName = new Map(m.tactics.map(t => [t.shortname, t.name]));
      const mitOn = id => ctx.inPlace.mitigations.has(r.domain + '|' + id);
      const detOn = id => ctx.inPlace.detections.has(r.domain + '|' + id);
      // Data components can be defined only in another domain's bundle (see SimEngine.analyzeDomain).
      const lookup = id => m.byId.get(id) || (ctx.entity ? ctx.entity(id) : null);
      const name = id => { const o = lookup(id); return o ? o.name : id; };
      const idName = id => { const o = lookup(id); return o ? [o.attackId, o.name].filter(Boolean).join(' ') : id; };
      const total = r.techniques.size;
      const techList = [...r.techniques.values()];

      const info = ctx.domainInfo ? ctx.domainInfo(r.domain) : { title: label + ' ATT&CK', family: 'attack' };
      const D = {
        domain: r.domain, label, result: r, total, keyOf,
        title: info.title, family: info.family, kb: KB_NAMES[info.family] || 'ATT&CK',   // 'Enterprise ATT&CK' / 'ATLAS'; kb 'ATT&CK' / 'ATLAS'
        platforms: ctx.platformsByDomain ? ctx.platformsByDomain[r.domain] || [] : null,
        version: m.meta.version, released: m.meta.modified,
        counts: { covered: 0, mitigated: 0, detected: 0, gap: 0 },
        subs: 0, tacticsHit: 0, tacticsAll: m.tactics.length, noMitigation: 0,
        tactics: [], mitTotal: r.mitigations.size, detTotal: r.detections.size, mitOn: 0, detOn: 0,
        dcTotal: r.dataComponents.size, assetTotal: r.assets.size,
        topMitigations: [], topDetections: [], tierCounts: { mit: new Map(), det: new Map() },
        // CTID mappings joined by SimEngine.mapExternal (null when not pulled or not this domain)
        nist: r.nist || null, mappingStatus: r.mappingStatus || {},
        noControl: { judged: 0, absent: 0, late: 0 },   // profile techniques with no 800-53 control, by NO_CONTROL reason
      };
      for (const t of techList) {
        D.counts[t.status]++;
        if (t.tech.isSubtechnique) D.subs++;
        if (!t.mitigations.length) D.noMitigation++;
      }
      for (const tactic of m.tactics) {
        const ts = techList.filter(t => (t.tech.tactics || []).includes(tactic.shortname));
        const c = { covered: 0, mitigated: 0, detected: 0, gap: 0 };
        for (const t of ts) c[t.status]++;
        D.tactics.push({ tactic, total: ts.length, counts: c });
        if (ts.length) D.tacticsHit++;
      }
      for (const id of r.mitigations.keys()) if (mitOn(id)) D.mitOn++;
      for (const id of r.detections.keys()) if (detOn(id)) D.detOn++;
      P.domains.push(D);

      const viaText = via => via.map(id => { const o = lookup(id); return ((o && VIA_PREFIX[o.kind]) || '') + name(id); }).join(' → ');
      const nistKey = capId => label + ':' + safeKey(capId);
      // NIST controls sharing at least one profile technique with each ATT&CK mitigation (Mitigations helper)
      const nistByMit = new Map();
      if (D.nist) {
        for (const [capId, c] of D.nist.controls) {
          for (const mid of c.mitigations.keys()) {
            if (!r.mitigations.has(mid)) continue;
            if (!nistByMit.has(mid)) nistByMit.set(mid, []);
            nistByMit.get(mid).push(nistKey(capId));
          }
        }
      }

      // Techniques: most-used first, then by ID.
      techList.sort((a, b) => b.roots.size - a.roots.size || byAttackId(a.tech, b.tech));
      // No 800-53 control: CTID judged the technique not mappable, or no CTID row (mapped or not mappable) resolves to it
      const noControl = t => {
        if (!D.nist || (t.nist || []).length) return '';
        const why = D.nist.nonMappable.has(t.tech.id) ? 'judged' : addedAfter(t.tech) ? 'late' : 'absent';
        D.noControl[why]++;
        if (why === 'late') D.noControl.absent++;
        return why === 'judged' ? NO_CONTROL.judged : NO_CONTROL[why](nistVersion);
      };
      for (const t of techList) {
        const mitIds = uniq(t.mitigations), detIds = uniq(t.detections), assetIds = uniq(t.assets);
        const parent = t.tech.parent ? m.byId.get(t.tech.parent) : null;
        const roots = [...t.roots].map(id => m.byId.get(id)).filter(Boolean).sort(byName);
        const procs = SimEngine.procedures(t).map(g => {
          const via = g.paths.filter(p => p.length).map(viaText);
          const how = via.length ? ' (' + (g.paths.some(p => !p.length) ? 'directly; ' : '') + 'via ' + via.join('; via ') + ')' : '';
          return name(g.root) + how + ': ' + plain(g.description);
        });
        P.techniques.push({
          D, t,
          domain: label,
          id: link(t.tech.attackId || t.tech.id, t.tech.url),
          name: clean(t.tech.name),
          parent: parent ? clean(idName(parent.id)) : '',
          tactics: clean((t.tech.tactics || []).map(s => tacticName.get(s) || s).join('; ')),
          platforms: clean((t.tech.platforms || []).join(', ')),
          usedN: t.roots.size,
          usedBy: clean(roots.map(o => o.name).join('; ')),
          mitN: mitIds.length,
          mits: clean(mitIds.map(idName).join('; ')),
          detN: detIds.length,
          dets: clean(detIds.map(idName).join('; ')),
          assets: clean(assetIds.map(name).sort().join('; ')),
          procedures: clean(procs.length > 1 ? procs.map((p, i) => `[${i + 1}] ${p}`).join('  ') : procs.join('')),
          description: plain(t.tech.description),
          key: keyOf(t.tech),
          tacticKeys: ';' + (t.tech.tactics || []).join(';') + ';',
          assetKeys: clean(';' + assetIds.map(id => keyOf(m.byId.get(id))).join(';') + ';'),
          nistN: D.nist ? (t.nist || []).length : null,
          nistKeys: D.nist && (t.nist || []).length ? clean(';' + t.nist.map(nistKey).join(';') + ';') : '',
          nistWhy: noControl(t),
          // CTID's reason for judging a technique not mappable (it then has no control), where CTID gave one
          nistNote: D.nist && D.nist.nonMappable.has(t.tech.id) && !(t.nist || []).length ? ctidText(D.nist.index.nonMappable.get(t.tech.id)) : '',
          isMitigated: t.isMitigated, isDetected: t.isDetected, status: t.status,
        });

        for (const id of mitIds) {
          const ctl = m.byId.get(id);
          P.map.push({
            domain: label, techId: t.tech.attackId, tech: clean(t.tech.name), type: MAP_TYPE.mit,
            ctlId: link(ctl.attackId || ctl.id, ctl.url), ctl: clean(ctl.name),
            guidance: plain(r.mitigations.get(id).guidance.get(t.tech.id)),
            techKey: keyOf(t.tech), ctlKey: keyOf(ctl), kind: 'mit',
            statusNow: mitOn(id) ? MIT.on : MIT.off, coveredNow: t.isMitigated,
            sort: [label, t.tech, 0, ctl],
          });
        }
        for (const id of detIds) {
          const ctl = m.byId.get(id);
          const e = r.detections.get(id);
          P.map.push({
            domain: label, techId: t.tech.attackId, tech: clean(t.tech.name), type: MAP_TYPE.det,
            ctlId: link(ctl.attackId || ctl.id, ctl.url), ctl: clean(ctl.name),
            guidance: clean('Analytics: ' + (e.analytics.map(a => a.attackId + ' (' + (a.platforms || []).join(', ') + ')').join('; ') || 'none for the selected platforms')
              + '. The Analytics sheet lists what to collect for each.'),
            techKey: keyOf(t.tech), ctlKey: keyOf(ctl), kind: 'det',
            statusNow: detOn(id) ? DET.on : DET.off, coveredNow: t.isDetected,
            sort: [label, t.tech, 1, ctl],
          });
        }
      }

      // Controls: in place at export first, then by priority (sequential rank), then by reach.
      const order = (pri, on) => (a, b) => {
        const pa = pri.get(a[0]), pb = pri.get(b[0]);
        const ka = on(a[0]) ? -1 : pa.rank == null ? 1e6 : pa.rank;
        const kb = on(b[0]) ? -1 : pb.rank == null ? 1e6 : pb.rank;
        return ka - kb || b[1].techniques.size - a[1].techniques.size || byAttackId(a[1].obj, b[1].obj);
      };
      const controlRow = (e, p, on, V) => ({
        D, e,
        rank: on ? null : p.rank,
        priority: on || p.rank == null ? null : p.tier,
        domain: label,
        id: link(e.obj.attackId || e.obj.id, e.obj.url),
        name: clean(e.obj.name),
        status: on ? V.on : V.off,
        statusAtExport: on ? V.on : V.off,
        techN: e.techniques.size,
        share: total ? e.techniques.size / total : 0,
        adds: on ? null : p.adds,
        score: on ? null : p.score,
        cumulative: p.cumulative,
        key: keyOf(e.obj),
      });

      for (const [id, e] of [...r.mitigations].sort(order(r.mitPriority, mitOn))) {
        const techs = [...e.techniques].map(tid => m.byId.get(tid)).sort(byAttackId);
        const row = Object.assign(controlRow(e, r.mitPriority.get(id), mitOn(id), MIT), {
          openNow: techs.filter(tech => !r.techniques.get(tech.id).isMitigated).length,
          techs: clean(techs.map(tech => tech.attackId).join(', ')),
          description: plain(e.obj.description),
          nistKeys: nistByMit.has(id) ? clean(';' + nistByMit.get(id).join(';') + ';') : '',
        });
        P.mitigations.push(row);
        if (row.priority != null) D.tierCounts.mit.set(row.priority, (D.tierCounts.mit.get(row.priority) || 0) + 1);
        if (row.rank != null && row.rank <= TOP_ACTIONS) D.topMitigations.push(row);
      }

      for (const [id, e] of [...r.detections].sort(order(r.detPriority, detOn))) {
        const techs = [...e.techniques].map(tid => m.byId.get(tid)).sort(byAttackId);
        const dcs = [...e.dataComponents].map(lookup).filter(Boolean).sort(byName);
        const missing = e.dataComponents.size - dcs.length;   // referenced but not in the loaded ATT&CK data
        const logSources = uniq(e.analytics.flatMap(a => (a.logSources || []).map(sourceName).filter(Boolean))).sort();
        const row = Object.assign(controlRow(e, r.detPriority.get(id), detOn(id), DET), {
          openNow: techs.filter(tech => !r.techniques.get(tech.id).isDetected).length,
          anN: e.analytics.length,
          platforms: clean(uniq(e.analytics.flatMap(a => a.platforms || [])).sort().join(', ')),
          dcs: clean(dcs.map(dc => dc.name).join('; ') + (missing ? `${dcs.length ? '; ' : ''}+${missing} not in the loaded ATT&CK data` : '')),
          logSources: clean(logSources.join('; ')),
          techs: clean(techs.map(tech => tech.attackId).join(', ')),
          dcKeys: clean(';' + dcs.map(keyOf).join(';') + ';'),
        });
        P.detections.push(row);
        if (row.priority != null) D.tierCounts.det.set(row.priority, (D.tierCounts.det.get(row.priority) || 0) + 1);
        if (row.rank != null && row.rank <= TOP_ACTIONS) D.topDetections.push(row);

        // Analytics sheet: one row per log-source reference (or one per analytic without any)
        for (const a of e.analytics) {
          const refs = (a.logSources || []).length ? a.logSources : [{}];
          for (const l of refs) {
            const dc = l.dataComponent ? lookup(l.dataComponent) : null;
            if (l.dataComponent && !dc) P.unresolved.add(l.dataComponent);
            P.analytics.push({
              domain: label,
              detId: link(e.obj.attackId || e.obj.id, e.obj.url),
              det: clean(e.obj.name),
              statusNow: detOn(id) ? DET.on : DET.off,
              anId: link(a.attackId || a.id, a.url),
              platforms: clean((a.platforms || []).join(', ')),
              dc: dc ? clean([dc.attackId, dc.name].filter(Boolean).join(' ')) : l.dataComponent ? 'Not in the loaded ATT&CK data' : '',
              logSource: clean(sourceName(l)),
              lookFor: l.channel && l.channel !== 'None' ? channelText(l.channel) : '',
              techs: clean(techs.map(tech => tech.attackId).join(', ')),
              description: plain(a.description),
              detKey: keyOf(e.obj),
            });
          }
        }
      }

      for (const [, e] of [...r.assets].sort((a, b) => b[1].techniques.size - a[1].techniques.size || byAttackId(a[1].obj, b[1].obj))) {
        const techs = [...e.techniques].map(tid => r.techniques.get(tid));
        P.assets.push({
          D, e,
          id: link(e.obj.attackId || e.obj.id, e.obj.url),
          name: clean(e.obj.name),
          techN: e.techniques.size,
          share: total ? e.techniques.size / total : 0,
          exposedNow: techs.filter(t => t.status === 'gap').length,
          coveredNow: techs.filter(t => t.status === 'covered').length,
          platforms: clean((e.obj.platforms || []).join(', ')),
          sectors: clean((e.obj.sectors || []).join(', ')),
          techs: clean(techs.map(t => t.tech).sort(byAttackId).map(tech => tech.attackId).join(', ')),
          description: plain(e.obj.description),
          key: keyOf(e.obj),
        });
      }

      // NIST 800-53: in the simulator's order (most profile techniques first, then by control ID)
      if (D.nist) {
        for (const [capId, c] of D.nist.controls) {
          const techs = [...c.techniques].map(id => m.byId.get(id)).filter(Boolean).sort(byAttackId);
          const status = tech => r.techniques.get(tech.id).status;
          // only mitigations with a row on the Mitigations sheet, so the live count can find each one
          const related = [...c.mitigations].map(([id, n]) => [m.byId.get(id), n, id]).filter(([o, , id]) => o && r.mitigations.has(id));
          // CTID's comments, once per technique CTID mapped the control to: a sub-technique counted through its
          // parent shares the parent's mapping, so its comment is listed under the parent's ID
          const notes = new Map();   // CTID technique ID -> { text, subs: [IDs counted through it] }
          for (const tech of techs) {
            const parent = c.viaParent.has(tech.id) ? m.byId.get(tech.parent) : null;
            const from = parent ? parent.attackId : tech.attackId;
            if (!notes.has(from)) notes.set(from, { text: '', subs: [] });
            const n = notes.get(from);
            if (parent) n.subs.push(tech.attackId);
            const text = c.notes.get(tech.id) ? ctidText(c.notes.get(tech.id)) : '';
            if (text && !n.text) n.text = text;
          }
          P.nist.push({
            D, domain: label,
            id: clean(capId),
            name: clean(c.obj.name),
            family: clean(c.obj.familyName || c.obj.family),
            techN: techs.length,
            viaParentN: c.viaParent.size,
            gapsNow: techs.filter(tech => status(tech) === 'gap').length,
            openNow: techs.filter(tech => status(tech) !== 'covered').length,
            mitN: related.length,
            mitOnNow: related.filter(([, , id]) => mitOn(id)).length,
            mits: clean(related.map(([o, n]) => `${o.attackId} (${n})`).join('; ')),
            mitsTop: clean(listCapped(related.map(([o, n]) => `${o.attackId} (${n})`), 3, '; ')),
            techs: clean(techs.map(tech => tech.attackId + (c.viaParent.has(tech.id) && m.byId.get(tech.parent) ? ' via ' + m.byId.get(tech.parent).attackId : '')).join(', ')),
            comments: clean([...notes].filter(([, n]) => n.text)
              .map(([from, n]) => from + (n.subs.length ? ` (parent of ${n.subs.join(', ')})` : '') + ': ' + n.text).join('  ')),
            key: nistKey(capId),
          });
        }
      }

      for (const [, e] of [...r.dataComponents].sort((a, b) => b[1].techniques.size - a[1].techniques.size || byAttackId(a[1].obj, b[1].obj))) {
        const names = [...e.logSources.keys()].sort();
        const details = names.map(n => {
          const ch = uniq([...e.logSources.get(n)].map(channelText)).sort((a, b) => a.localeCompare(b));
          return n + (ch.length ? ': ' + ch.slice(0, CHANNELS_PER_SOURCE).join(' | ')
            + (ch.length > CHANNELS_PER_SOURCE ? ` | +${ch.length - CHANNELS_PER_SOURCE} more` : '') : '');
        });
        P.telemetry.push({
          D, e,
          domain: label,
          id: link(e.obj.attackId || e.obj.id, e.obj.url),
          name: clean(e.obj.name),
          techN: e.techniques.size,
          share: total ? e.techniques.size / total : 0,
          dsN: e.strategies.size,
          deployedNow: [...e.strategies].filter(detOn).length,
          logSources: clean(names.join('; ')),
          details: clean(details.join('  •  ')),
          description: plain(e.obj.description),
          key: keyOf(e.obj),
        });
      }
    }

    P.map.sort((a, b) => {
      const [da, ta, ka, ca] = a.sort, [db, tb, kb, cb] = b.sort;
      return P.domains.findIndex(d => d.label === da) - P.domains.findIndex(d => d.label === db)
        || byAttackId(ta, tb) || ka - kb || byAttackId(ca, cb);
    });

    // Threat profile: every selected adversary, with the techniques it contributes.
    // Type: Malware / Tool for software; ATLAS case studies add Incident or Exercise; ATLAS case studies and entities
    // add the activity purpose ATLAS records (identity does not imply intent: many entities are security evaluators)
    const kindLabel = (kind, o) => {
      if (o.softwareType === 'malware') return 'Malware';
      if (o.softwareType === 'tool') return 'Tool';
      const purposes = ctx.activityPurposes ? ctx.activityPurposes(o) : [];
      const detail = [o.kind === 'case-study' ? o.caseType : null, ...purposes].filter(Boolean);
      return kind.one + (detail.length ? ` (${detail.join(', ')})` : '');
    };
    for (const kind of ctx.kinds) {
      for (const id of ctx.selection[kind.key]) {
        const o = ctx.entity(id);
        if (!o) continue;
        const inDomains = P.domains.filter(D => D.result.roots.some(x => x.id === id));
        let n = 0;
        for (const D of inDomains) for (const t of D.result.techniques.values()) if (t.roots.has(id)) n++;
        P.profile.push({
          obj: o, kind: kindLabel(kind, o),
          domains: inDomains.map(D => D.label).join(', ') || 'Not in scope',
          techniques: n,
          aliases: (o.aliases || []).filter(a => a !== o.name).join(', '),
        });
      }
    }

    const dcDomains = new Map();   // data component -> number of domains using it
    for (const D of P.domains) for (const e of D.result.dataComponents.values()) {
      const k = e.obj.attackId || e.obj.id;
      dcDomains.set(k, (dcDomains.get(k) || 0) + 1);
    }
    P.dataComponents = dcDomains.size;
    P.dcShared = [...dcDomains.values()].filter(n => n > 1).length;
    P.generated = generated;
    P.mappingNotes = mappingNotes(P);
    return P;
  }

  // ---------- CTID mappings: scope and empty-sheet notes ----------

  // ATT&CK domains the CTID mapping covers (as SimEngine.MAPPING_SOURCES)
  const MAPPED_DOMAINS = { nist: ['enterprise-attack'] };
  const MAPPING_NAME = { nist: 'NIST SP 800-53 Rev 5' };
  /** Profile domains with techniques that a mapping covers. */
  const mappedDomains = (P, key) => P.domains.filter(D => MAPPED_DOMAINS[key].includes(D.domain) && D.total);
  const notPulledNote = key => `The ${MAPPING_NAME[key]} mappings were not pulled when this workpaper was exported. `
    + 'Pull the control mappings (CTID) on ThreatSim\'s Data page, then export again.';
  /** A pulled mapping's version label without the dataset's name ('ATT&CK 16.1'). */
  const versionLabel = (P, key) => {
    const label = String((P.mappings[key] || {}).label || '');
    return label.replace(/^Rev 5 · /i, '') || label;
  };
  /** -1, 0 or 1: ATT&CK release numbers compared part by part ('16.1' < '20.0'; '20' == '20.0'). */
  const cmpVersion = (a, b) => {
    const x = String(a || '').split('.').map(Number), y = String(b || '').split('.').map(Number);
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const d = (x[i] || 0) - (y[i] || 0);
      if (d) return d < 0 ? -1 : 1;
    }
    return 0;
  };
  /** The mapping keys ('nist') with rows for at least one of the profile's domains. */
  const usedMappings = P => ['nist'].filter(k => P.domains.some(D => D[k]));

  /**
   * Why the profile techniques with no 800-53 control have none, in sentences: CTID judged them not mappable, or they
   * are not in CTID's mapping at all (neither mapped nor judged; some added to ATT&CK after the release CTID mapped).
   * c = { none, judged, absent, late } summed over the domains shown.
   */
  function noControlText(P, c) {
    const v = P.mappings.nist && P.mappings.nist.attackVersion;
    const { none, judged, absent, late } = c;
    const out = [];
    if (judged === none) out.push(`CTID judged ${none === 1 ? 'it' : 'all of them'} not mappable to 800-53.`);
    else if (!judged) out.push(`${none === 1 ? 'It is not' : 'None of them is'} in CTID's mapping at all (neither mapped nor judged).`);
    else out.push(`CTID judged ${judged} of them not mappable to 800-53; the other ${absent === 1 ? 'one is' : absent + ' are'} not in CTID's mapping at all (neither mapped nor judged).`);
    if (late) {
      out.push((absent === 1 ? 'It was' : late === absent ? `All ${absent} were` : `${late} of these ${absent} ${late === 1 ? 'was' : 'were'}`)
        + ` added to ATT&CK after ${v}, the release CTID mapped.`);
    }
    return out.join(' ');
  }

  /** Why the NIST 800-53 sheet has no rows (null when it has some). */
  function mappingNotes(P) {
    const note = key => {
      if (P.nist.length) return null;
      const inScope = mappedDomains(P, key);
      const meta = P.mappings[key];
      if (!inScope.length) return 'CTID maps NIST SP 800-53 Rev 5 controls to Enterprise ATT&CK only, and this threat profile has no Enterprise ATT&CK techniques.';
      const shown = inScope.filter(D => D[key]);
      if (!meta || (!shown.length && !inScope.some(D => D.mappingStatus[key] === 'no-attack-data'))) return notPulledNote(key);
      if (!shown.length) return `The pulled ${MAPPING_NAME[key]} mappings (${versionLabel(P, key)}) have no entries for ${inScope.map(D => D.title).join(' or ')}.`;
      const total = shown.reduce((n, D) => n + D.total, 0);
      const c = { none: total, judged: 0, absent: 0, late: 0 };
      for (const D of shown) for (const k of ['judged', 'absent', 'late']) c[k] += D.noControl[k];
      return `No NIST SP 800-53 Rev 5 control in CTID's mapping (${versionLabel(P, key)}) mitigates any of this threat profile's `
        + `${plural(total, 'Enterprise technique', 'Enterprise techniques')}. ` + noControlText(P, c);
    };
    return { nist: note('nist') };
  }

  // ---------- generic table writer ----------

  /**
   * Header row + data rows. Row values may be functions of the row number
   * (used for formulas that reference their own row).
   */
  function writeTable(ws, L, rows, { freezeCols = 0, emptyNote, fitToWidth = 2 } = {}) {
    L.cols.forEach((c, i) => {
      const col = ws.getColumn(i + 1);
      col.width = c.helper ? 14 : (c.width || 12);
      if (c.helper) col.hidden = true;
      put(ws, 1, i + 1, c.header, {
        font: font({ bold: true, color: { argb: C.white } }),
        fill: solid(c.input || c.inputSoft ? C.inputHeader : C.header),
        alignment: { vertical: 'middle', wrapText: true },
        border: box(C.border),
      });
    });
    ws.getRow(1).height = 58;

    rows.forEach((row, ri) => {
      const rn = ri + 2;
      L.cols.forEach((c, ci) => {
        let v = row[c.key];
        if (typeof v === 'function') v = v(rn);
        const cell = ws.getCell(rn, ci + 1);
        cell.value = v === undefined || v === '' ? null : v;
        const isLink = v && typeof v === 'object' && v.hyperlink;
        cell.font = font(isLink ? { color: { argb: C.link }, underline: true } : {});
        if (c.fmt) cell.numFmt = c.fmt;
        if (c.live) cell.fill = solid(C.live);
        if (c.input) {
          cell.fill = solid(C.input);
          cell.border = box(C.inputBorder);
          cell.font = font({ bold: true });
        }
        if (c.inputSoft) {
          cell.fill = solid(C.inputSoft);
          cell.border = box(C.inputBorder);
        }
        cell.alignment = { vertical: 'top', horizontal: c.center ? 'center' : undefined, wrapText: c.wrap || undefined };
      });
    });

    // Long single-line columns (narratives and lists) show only their start on paper, so they stay out of the print area.
    const stop = L.cols.findIndex(c => c.noPrint || c.helper);
    const lastPrinted = stop < 0 ? L.cols.length : stop;
    const note = !rows.length && emptyNote ? clean(emptyNote) : '';
    if (note) {
      // An empty sheet says why in one wrapped cell across the printed columns, sized to its text, so a long note is
      // neither cut off at the print area's right edge nor split across pages: on a sheet printed two pages wide it
      // spans only the columns that fit on the first page at full size (A4 landscape holds about 1,000 pixels of
      // columns; a column of width w takes 7w + 5).
      const widths = L.cols.slice(0, lastPrinted).map(c => (c.helper ? 14 : c.width || 12));
      let last = widths.length;
      if (fitToWidth > 1) {
        let px = 7 * widths[0] + 5;
        for (last = 1; last < widths.length && px + 7 * widths[last] + 5 <= 1000; last++) px += 7 * widths[last] + 5;
      }
      const units = widths.slice(0, last).reduce((a, b) => a + b, 0);
      if (last > 1) ws.mergeCells(2, 1, 2, last);
      put(ws, 2, 1, note, { font: font({ italic: true, color: { argb: C.muted } }), alignment: { wrapText: true, vertical: 'top' } });
      // about 1.15 characters of 10pt Calibri a width unit (the summary's 112 a line for 91 units, less a margin for
      // Excel), 13pt a line
      ws.getRow(2).height = 13 * wrapLines(note, Math.max(20, Math.floor(units * 1.15))) + 4;
    }
    // The filter spans the data rows, including the hidden helper columns, so sorting keeps each
    // row's keys with it. build() adds the _xlnm._FilterDatabase name LibreOffice needs to import it.
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: L.last, column: L.cols.length } };
    // with no rows there are no IDs to keep in view, and a frozen column split would cut through the note
    ws.views = [{ state: 'frozen', xSplit: note ? 0 : freezeCols, ySplit: 1, activeCell: 'A2' }];
    ws.pageSetup = {
      orientation: 'landscape', paperSize: 9, fitToPage: true, fitToWidth, fitToHeight: 0, pageOrder: 'overThenDown',
      printArea: `A$1:${colLetter(lastPrinted)}$${L.last}`,   // absolute rows: LibreOffice ignores a relative print area
      printTitlesRow: '1:1', printTitlesColumn: freezeCols && !note ? `A:${colLetter(freezeCols)}` : undefined,
      margins: { left: 0.4, right: 0.4, top: 0.5, bottom: 0.6, header: 0.3, footer: 0.3 },
    };
  }

  function coverageRules(ws, ref, prio) {
    const rule = (text, fill, ink) => ({
      type: 'cellIs', operator: 'equal', formulae: [lit(text)], priority: prio(),
      style: { fill: solid(fill), font: { color: { argb: ink }, bold: true } },
    });
    ws.addConditionalFormatting({
      ref,
      rules: [
        rule(COVERAGE.covered, C.goodTint, C.goodInk),
        rule(COVERAGE.mitigated, C.warnTint, C.warnInk),
        rule(COVERAGE.detected, C.warnTint, C.warnInk),
        rule(COVERAGE.gap, C.critTint, C.critInk),
      ],
    });
  }

  function equalsRule(ws, ref, value, fill, ink, prio) {
    ws.addConditionalFormatting({
      ref,
      rules: [{ type: 'cellIs', operator: 'equal', formulae: [lit(value)], priority: prio(),
        style: { fill: solid(fill), font: { color: { argb: ink }, bold: true } } }],
    });
  }

  function dropdown(ws, L, onValue, offValue, what) {
    if (!L.count) return;
    const col = L.letter('status');
    ws.dataValidations.add(`${col}2:${col}${L.count + 1}`, {
      type: 'list',
      allowBlank: true,
      formulae: [lit(onValue + ',' + offValue)],
      showInputMessage: true,
      promptTitle: what,
      prompt: `Choose ${onValue} or ${offValue}. Readiness on the Executive Summary updates automatically.`,
      showErrorMessage: true,
      errorStyle: 'stop',
      errorTitle: 'Choose from the list',
      error: `Use ${onValue} or ${offValue}.`,
    });
  }

  // ---------- sheets ----------

  function writeTechniques(ws, P, L, LMap) {
    const flags = rn => ({
      mitigated: `IF(COUNTIFS(${LMap.range('techKey')},$${L.letter('key')}${rn},${LMap.range('type')},${lit(MAP_TYPE.mit)},${LMap.range('status')},${lit(MIT.on)})>0,"Yes","No")`,
      detected: `IF(COUNTIFS(${LMap.range('techKey')},$${L.letter('key')}${rn},${LMap.range('type')},${lit(MAP_TYPE.det)},${LMap.range('status')},${lit(DET.on)})>0,"Yes","No")`,
    });
    const pick = (rn, out) => {
      const m = `$${L.letter('mitigated')}${rn}="Yes"`, d = `$${L.letter('detected')}${rn}="Yes"`;
      return `IF(AND(${m},${d}),${lit(out.covered)},IF(${m},${lit(out.mitigated)},IF(${d},${lit(out.detected)},${lit(out.gap)})))`;
    };
    const rows = P.techniques.map(row => Object.assign({}, row, {
      mitigated: rn => F(flags(rn).mitigated, row.isMitigated ? 'Yes' : 'No'),
      detected: rn => F(flags(rn).detected, row.isDetected ? 'Yes' : 'No'),
      coverage: rn => F(pick(rn, COVERAGE), COVERAGE[row.status]),
      code: rn => F(pick(rn, GLYPH), GLYPH[row.status]),
    }));
    writeTable(ws, L, rows, { freezeCols: 3, emptyNote: 'No techniques in this threat profile.' });
    const prio = priorities();
    const cov = L.letter('coverage');
    coverageRules(ws, `${cov}2:${cov}${L.last}`, prio);
    for (const key of ['mitigated', 'detected']) {
      const col = L.letter(key);
      ws.addConditionalFormatting({
        ref: `${col}2:${col}${L.last}`,
        rules: [{ type: 'cellIs', operator: 'equal', formulae: ['"Yes"'], priority: prio(),
          style: { font: { color: { argb: C.goodInk }, bold: true } } }],
      });
    }
  }

  function writeControls(ws, rows, L, LMap, kind, P) {
    const isMit = kind === 'mit';
    const V = isMit ? MIT : DET;
    const k = key => '$' + L.letter(key);
    const out = rows.map(row => Object.assign({}, row, {
      changed: rn => F(`IF(${k('status')}${rn}<>${k('statusAtExport')}${rn},"Changed","")`, ''),
      // Techniques this control maps to that no in-place control of the same type covers yet
      open: rn => F(`COUNTIFS(${LMap.range('ctlKey')},${k('key')}${rn},${LMap.range('techCovered')},"No")`, row.openNow),
    }));
    writeTable(ws, L, out, { freezeCols: 5, emptyNote: isMit ? 'No mitigations map to this threat profile.'
      : 'No detection strategies map to this threat profile.' + (P.domains.some(D => D.family === 'atlas') ? ' ATLAS defines no detection strategies.' : '') });
    const prio = priorities();
    const st = L.letter('status');
    equalsRule(ws, `${st}2:${st}${L.last}`, V.on, C.goodTint, C.goodInk, prio);
    const ch = L.letter('changed');
    equalsRule(ws, `${ch}2:${ch}${L.last}`, 'Changed', C.warnTint, C.warnInk, prio);
    dropdown(ws, L, V.on, V.off, isMit ? 'Implementation status' : 'Deployment status');
  }

  function writeAssets(ws, P, L, LT) {
    const listed = rn => `${LT.range('assetKeys')},"*;"&$${L.letter('key')}${rn}&";*"`;
    const rows = P.assets.map(row => Object.assign({}, row, {
      exposed: rn => F(`COUNTIFS(${LT.range('coverage')},${lit(COVERAGE.gap)},${listed(rn)})`, row.exposedNow),
      covered: rn => F(`COUNTIFS(${LT.range('coverage')},${lit(COVERAGE.covered)},${listed(rn)})`, row.coveredNow),
    }));
    writeTable(ws, L, rows, { freezeCols: 2, emptyNote: 'This threat profile has no ICS techniques, so no ICS assets are targeted. Add ICS groups, software or campaigns in ThreatSim to populate this sheet.' });
    const prio = priorities();
    const ex = L.letter('exposed');
    ws.addConditionalFormatting({
      ref: `${ex}2:${ex}${L.last}`,
      rules: [{ type: 'cellIs', operator: 'greaterThan', formulae: ['0'], priority: prio(),
        style: { fill: solid(C.critTint), font: { color: { argb: C.critInk }, bold: true } } }],
    });
  }

  function writeTelemetry(ws, P, L, LD) {
    const rows = P.telemetry.map(row => Object.assign({}, row, {
      deployed: rn => F(`COUNTIFS(${LD.range('status')},${lit(DET.on)},${LD.range('dcKeys')},"*;"&$${L.letter('key')}${rn}&";*")`, row.deployedNow),
    }));
    writeTable(ws, L, rows, { freezeCols: 3, emptyNote: 'No detection strategies, and so no telemetry, map to this threat profile.' });
  }

  function writeAnalytics(ws, P, L, LD) {
    const rows = P.analytics.map(row => Object.assign({}, row, {
      status: rn => F(`IFERROR(INDEX(${LD.range('status')},MATCH($${L.letter('detKey')}${rn},${LD.range('key')},0))&"","")`, row.statusNow),
    }));
    writeTable(ws, L, rows, { freezeCols: 3, emptyNote: 'No detection analytics map to this threat profile.' });
    const st = L.letter('status');
    equalsRule(ws, `${st}2:${st}${L.last}`, DET.on, C.goodTint, C.goodInk, priorities());
  }

  function writeMap(ws, P, L, LMit, LDet, LT) {
    const rows = P.map.map(row => Object.assign({}, row, {
      status: rn => {
        const T = row.kind === 'mit' ? LMit : LDet;
        return F(`IFERROR(INDEX(${T.range('status')},MATCH($${L.letter('ctlKey')}${rn},${T.range('key')},0))&"","")`, row.statusNow);
      },
      techCovered: rn => F(`IFERROR(INDEX(${LT.range(row.kind === 'mit' ? 'mitigated' : 'detected')},MATCH($${L.letter('techKey')}${rn},${LT.range('key')},0)),"")`,
        row.coveredNow ? 'Yes' : 'No'),
    }));
    writeTable(ws, L, rows, { freezeCols: 3, emptyNote: 'No mitigations or detection strategies map to this threat profile.' });
    const prio = priorities();
    const st = L.letter('status');
    for (const v of [MIT.on, DET.on]) equalsRule(ws, `${st}2:${st}${L.last}`, v, C.goodTint, C.goodInk, prio);
  }

  function writeNist(ws, P, L, LT, LM) {
    // the control's key in a ';…;' key list (Techniques for its techniques, Mitigations for its related mitigations)
    const listed = (T, rn) => `${T.range('nistKeys')},"*;"&$${L.letter('key')}${rn}&";*"`;
    const rows = P.nist.map(row => Object.assign({}, row, {
      gaps: rn => F(`COUNTIFS(${LT.range('coverage')},${lit(COVERAGE.gap)},${listed(LT, rn)})`, row.gapsNow),
      open: rn => F(`COUNTIFS(${LT.range('coverage')},${lit('<>' + COVERAGE.covered)},${listed(LT, rn)})`, row.openNow),
      mitOn: rn => F(`COUNTIFS(${LM.range('status')},${lit(MIT.on)},${listed(LM, rn)})`, row.mitOnNow),
    }));
    writeTable(ws, L, rows, { freezeCols: 3, emptyNote: P.mappingNotes.nist, fitToWidth: 1 });
    const prio = priorities();
    const g = L.letter('gaps');
    ws.addConditionalFormatting({
      ref: `${g}2:${g}${L.last}`,
      rules: [{ type: 'cellIs', operator: 'greaterThan', formulae: ['0'], priority: prio(),
        style: { fill: solid(C.critTint), font: { color: { argb: C.critInk }, bold: true } } }],
    });
  }

  // ---------- matrix ----------

  function usageStep(count, max) {
    if (max <= 1) return 4;
    return 1 + Math.round(((count - 1) / (max - 1)) * 5);
  }

  function writeMatrix(ws, D, ctx, LT) {
    const r = D.result;
    const cols = SimEngine.matrixColumns(r, { showAll: !!ctx.showAll });
    let max = 1;
    for (const t of r.techniques.values()) max = Math.max(max, t.roots.size);

    const TECH_W = 24, STATUS_W = 3.6;
    cols.forEach((c, i) => {
      ws.getColumn(2 * i + 1).width = STATUS_W;
      ws.getColumn(2 * i + 2).width = TECH_W;
    });

    // Title and legends
    put(ws, 1, 1, `${D.title} v${D.version} — threat profile matrix`, { font: font({ size: 14, bold: true }) });
    put(ws, 2, 1, clean(`Profile: ${profileNames(ctx)}. ${ctx.showAll ? 'All techniques are shown; grey ones are not used by the profile.' : 'Profile techniques only; grey parents give context for their sub-techniques.'}`),
      { font: font({ color: { argb: C.muted } }) });

    const groups = new Map();
    for (let c = 1; c <= max; c++) {
      const s = usageStep(c, max);
      if (!groups.has(s)) groups.set(s, []);
      groups.get(s).push(c);
    }
    const who = D.family === 'atlas' ? ['threat', 'threats'] : ['adversary', 'adversaries'];
    put(ws, 3, 2, `Shade = ${who[1]} using it:`, { font: font({ bold: true }) });
    let lc = 4;
    for (const [s, counts] of groups) {
      const lo = counts[0], hi = counts[counts.length - 1];
      put(ws, 3, lc, (lo === hi ? lo : lo + '–' + hi) + ' ' + (hi === 1 ? who[0] : who[1]), {
        font: font({ color: { argb: SEQ[s - 1][1] }, bold: true }), fill: solid(SEQ[s - 1][0]), alignment: { horizontal: 'center' },
        border: box(C.white),
      });
      lc += 2;
    }
    const legend = [['covered', C.good, C.white], ['mitigated', C.warning, C.ink], ['detected', C.warning, C.ink], ['gap', C.critical, C.white]];
    legend.forEach(([k, fill, ink], i) => {
      put(ws, 4, 2 * i + 1, GLYPH[k], { font: font({ bold: true, color: { argb: ink } }), fill: solid(fill), alignment: { horizontal: 'center' } });
      put(ws, 4, 2 * i + 2, COVERAGE[k], { font: font() });
    });
    put(ws, 4, 2 * legend.length + 2, 'Status column is live: it follows the Mitigations and Detections sheets.', { font: font({ italic: true, color: { argb: C.muted } }) });

    const HEAD = 6, COUNTS = 7, FIRST = 8;
    const lists = cols.map(c => {
      const out = [];
      for (const row of c.rows) {
        out.push({ tech: row.tech, used: row.used, sub: false });
        for (const s of row.subs) out.push({ tech: s.tech, used: s.used, sub: true });
      }
      return out;
    });
    const height = Math.max(1, ...lists.map(l => l.length));
    const last = FIRST + height - 1;
    const lines = new Array(height).fill(1);

    cols.forEach((c, i) => {
      const sc = 2 * i + 1, tc = 2 * i + 2;
      const S = colLetter(sc);
      ws.mergeCells(HEAD, sc, HEAD, tc);
      put(ws, HEAD, sc, c.tactic.name, {
        font: font({ bold: true, color: { argb: C.white } }), fill: solid(C.header),
        alignment: { vertical: 'middle', wrapText: true },
      });
      ws.mergeCells(COUNTS, sc, COUNTS, tc);
      const n = c.usedCount;
      const gaps = lists[i].filter(x => x.used && x.used.status === 'gap').length;
      const lead = plural(n, 'technique', 'techniques');
      put(ws, COUNTS, sc, n ? F(`${lit(lead + ' · ')}&COUNTIF(${S}${FIRST}:${S}${last},"✕")&" uncovered"`, `${lead} · ${gaps} uncovered`) : lead, {
        font: font({ color: { argb: C.muted } }), fill: solid(C.subband), alignment: { vertical: 'middle' },
      });

      lists[i].forEach((x, j) => {
        const rowN = FIRST + j;
        const text = [x.tech.attackId, x.tech.name].filter(Boolean).join(' ');
        const step = x.used ? usageStep(x.used.roots.size, max) : 0;
        const fill = x.used ? SEQ[step - 1][0] : C.idle;
        const ink = x.used ? SEQ[step - 1][1] : C.muted;
        put(ws, rowN, tc, clean(text), {
          font: font({ size: 9, color: { argb: ink }, italic: !x.used }),
          fill: solid(fill),
          alignment: x.sub ? { vertical: 'top', horizontal: 'left', wrapText: true, indent: 1 } : { vertical: 'top', wrapText: true },
          border: box(C.white),
        });
        if (x.used) {
          put(ws, rowN, sc, F(`IFERROR(INDEX(${LT.range('code')},MATCH(${lit(D.keyOf(x.tech))},${LT.range('key')},0)),"")`, GLYPH[x.used.status]), {
            font: font({ size: 9, bold: true }), alignment: { horizontal: 'center', vertical: 'top' }, border: box(C.white),
          });
        } else {
          put(ws, rowN, sc, null, { fill: solid(C.idle), border: box(C.white) });
        }
        const perLine = x.sub ? 27 : 30;   // ~characters per line at 9pt in a 24-wide column
        lines[j] = Math.max(lines[j], Math.ceil(text.length / perLine));
      });
    });

    // Live status colours (one rule set per status column)
    const prio = priorities();
    cols.forEach((c, i) => {
      const S = colLetter(2 * i + 1);
      const rule = (glyph, fill, ink) => ({ type: 'cellIs', operator: 'equal', formulae: [lit(glyph)], priority: prio(),
        style: { fill: solid(fill), font: { color: { argb: ink }, bold: true } } });
      ws.addConditionalFormatting({
        ref: `${S}${FIRST}:${S}${last}`,
        rules: [rule(GLYPH.covered, C.good, C.white), rule(GLYPH.mitigated, C.warning, C.ink),
          rule(GLYPH.detected, C.warning, C.ink), rule(GLYPH.gap, C.critical, C.white)],
      });
    });

    ws.getRow(HEAD).height = 30;
    ws.getRow(COUNTS).height = 16;
    lines.forEach((l, j) => { ws.getRow(FIRST + j).height = Math.max(15, 12 * l + 3); });
    ws.views = [{ state: 'frozen', xSplit: 0, ySplit: COUNTS, activeCell: 'A' + FIRST, showGridLines: false }];
    // A3 landscape. A tactic is a status + technique column pair (about 161pt printed); when the matrix is
    // wider than a page it prints as two halves with a manual break between tactics (written by build()),
    // scaled so each half fits. Fit-to-page is off because it can override manual breaks.
    const PAGE_W = 1133, TACTIC_W = 161;
    const per = cols.length * TACTIC_W > PAGE_W ? Math.ceil(cols.length / 2) : cols.length;
    D.matrixColumnBreak = per < cols.length ? 2 * per : null;
    ws.pageSetup = {
      orientation: 'landscape', paperSize: 8, scale: Math.min(100, Math.floor((100 * PAGE_W) / (per * TACTIC_W))),
      pageOrder: 'overThenDown', printTitlesRow: `${HEAD}:${COUNTS}`,
      margins: { left: 0.4, right: 0.4, top: 0.5, bottom: 0.6, header: 0.3, footer: 0.3 },
    };
  }

  function profileNames(ctx) {
    const names = [];
    for (const kind of ctx.kinds) for (const id of ctx.selection[kind.key]) { const o = ctx.entity(id); if (o) names.push(o.name); }
    return names.length > 8 ? names.slice(0, 8).join(', ') + ' +' + (names.length - 8) + ' more' : names.join(', ');
  }

  // ---------- executive summary ----------

  /** "Profile at a glance" rows for the CTID mappings that apply to the profile's domains. */
  function mappingGlance(P) {
    const out = [];
    const ids = (D, set) => [...set].map(id => D.result.model.byId.get(id)).filter(Boolean).sort(byAttackId).map(t => t.attackId);
    const nistIn = mappedDomains(P, 'nist');
    if (nistIn.length) {
      const shown = nistIn.filter(D => D.nist);
      if (!shown.length) {
        out.push(['NIST 800-53 Rev 5 controls mapped', null, P.mappings.nist ? P.mappingNotes.nist : notPulledNote('nist')]);
      } else {
        const total = shown.reduce((n, D) => n + D.total, 0);
        const covered = shown.reduce((n, D) => n + D.nist.covered.size, 0);
        // covered only through ThreatSim's parent roll-up: CTID maps no control to the sub-technique itself
        const viaOnly = shown.reduce((n, D) => n + (D.nist.viaParentOnly ? D.nist.viaParentOnly.size : 0), 0);
        const c = { judged: 0, absent: 0, late: 0 };
        for (const D of shown) for (const k of Object.keys(c)) c[k] += D.noControl[k];
        const none = shown.flatMap(D => ids(D, D.nist.uncovered).map(id => (shown.length > 1 ? D.label + ' ' : '') + id));
        const shownN = 15;
        out.push(['NIST 800-53 Rev 5 controls mapped', new Set(P.nist.map(x => x.id)).size,
          `Controls CTID maps to at least one profile technique or its parent technique (${versionLabel(P, 'nist')}); `
          + `${covered} of the ${plural(total, 'Enterprise profile technique has', 'Enterprise profile techniques have')} at least one`
          + (viaOnly ? ` (${viaOnly === covered ? (covered === 1 ? 'it' : 'all of them') : viaOnly + ' of them'} only through ThreatSim's parent roll-up: `
            + `CTID maps no control to ${viaOnly === 1 ? 'that sub-technique' : 'those sub-techniques'} directly)` : '')
          + '. See the NIST 800-53 sheet.']);
        out.push(['Profile techniques with no 800-53 control', none.length, none.length
          ? noControlText(P, Object.assign({ none: none.length }, c))
            + ` The Techniques sheet's "Why no NIST 800-53 control" column gives the reason for each${c.judged ? ' (and the next column CTID\'s comment, where it gave one)' : ''}: `
            + listCapped(none, shownN)
            + (none.length > shownN ? '. Filter its "NIST 800-53 controls (#)" column for 0 to see them all.' : '.')
          : 'Every Enterprise profile technique has at least one mapped control.']);
      }
    }
    return out;
  }

  /** Why CTID's technique ID did not match a current technique of D, in the workbook's terms. */
  const unmatchedReason = (D, reason) => {
    const release = `${D.title} v${D.version}`;
    if (/^not in\b/i.test(reason || '')) return `not ${/^[aeiou]/i.test(release) ? 'an' : 'a'} ${release} technique`;
    if (reason === 'deprecated') return `deprecated in ${release}`;
    return clean(reason || 'not matched');
  };

  /** Scope and method: the CTID mapping the workbook uses and how it was matched to the stored ATT&CK release. */
  function mappingMethod(P) {
    const meta = P.mappings.nist;
    const out = [];
    if (meta) {
      out.push('From the Center for Threat-Informed Defense\'s Mappings Explorer: '
        + `${MAPPING_NAME.nist} (${versionLabel(P, 'nist')}, pulled ${fmtDay(meta.pulledAt)}).`);
    } else {
      out.push(`${MAPPING_NAME.nist}: not pulled when this workpaper was exported`
        + (mappedDomains(P, 'nist').length ? ', so the NIST 800-53 sheet is empty (pull it on ThreatSim\'s Data page and export again).' : '.'));
    }
    const shown = meta ? P.domains.filter(D => D.nist) : [];
    if (meta && !shown.length) {
      out.push('Not used: this threat profile has no Enterprise ATT&CK techniques.');
    }
    for (const D of shown) {
      const ix = D.nist.index;
      const ids = ix.replaced.map(x => [x.from, x.to]).sort((a, b) => byAttackId({ attackId: a[0] }, { attackId: b[0] })).map(([from, to]) => from + ' → ' + to);
      const lost = ix.unresolved.map(x => `${x.techniqueId} (NIST 800-53: ${unmatchedReason(D, x.reason)}, ${plural(x.rows, 'mapping', 'mappings')})`);
      out.push(`${MAPPING_NAME.nist} targets ATT&CK ${meta.attackVersion}; ThreatSim matched it to ${D.title} v${D.version} by technique ID`
        + (ids.length ? `, carrying the IDs revoked since forward to their replacements (NIST 800-53 ${ix.replaced.length}): ${listCapped(ids, 25)}` : '')
        + (lost.length ? `. Not matched, so left out: ${listCapped(lost, 10, '; ')}` : '') + '.');
    }
    if (usedMappings(P).includes('nist')) {
      out.push('ThreatSim, not CTID, counts a NIST control for a sub-technique when CTID maps the control to its parent technique ("via" on the NIST 800-53 sheet). '
        + 'NIST 800-53 covers Enterprise ATT&CK only.');
    }
    return out.join(' ');
  }

  /** Licence and source rows for the CTID mappings in the workbook. */
  function mappingLicences(P) {
    // only for the mappings this workbook uses
    const nist = P.domains.some(D => D.nist);
    return [
      nist ? ['Mappings Explorer licence', 'Control mappings from the Center for Threat-Informed Defense\'s Mappings Explorer (https://ctid.mitre.org/mappings/). '
        + '© 2024 MITRE. Licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0); distributed on an "AS IS" basis, without warranties or conditions of any kind. '
        + 'Source: https://github.com/center-for-threat-informed-defense/mappings-explorer'] : null,
      nist ? ['NIST SP 800-53', 'NIST Special Publication 800-53 Revision 5, Security and Privacy Controls for Information Systems and Organizations, is a publication of the '
        + 'National Institute of Standards and Technology (NIST). Control names and families are as CTID\'s mapping gives them.'] : null,
    ];
  }

  /** The 'Sheets' row's text for the NIST 800-53 sheet. */
  function mappingSheets(P) {
    if (!usedMappings(P).includes('nist')) return `${SHEET.nist}: empty for this profile; the sheet says why.`;
    return 'NIST 800-53: the NIST SP 800-53 Rev 5 controls CTID maps to the profile\'s Enterprise techniques (or to their parent techniques), '
      + 'with live counts of the gaps each addresses and of its related ATT&CK mitigations in place. '
      + 'Related ATT&CK mitigations are ThreatSim\'s link, not CTID\'s: the profile\'s ATT&CK mitigations that address the same techniques as the control. CTID maps controls to techniques only.';
  }

  /** The 'Limits' row's sentences on the CTID mapping (none when the workbook doesn't use it). */
  function mappingLimits(P) {
    if (!usedMappings(P).includes('nist')) return '';
    const version = (P.mappings.nist && P.mappings.nist.attackVersion) || '?';
    // the ATT&CK release the mapping targets, against the release of each domain it is matched to
    const pairs = P.domains.filter(D => D.nist).map(D => cmpVersion(P.mappings.nist && P.mappings.nist.attackVersion, D.version));
    const matched = pairs.every(d => d === 0) ? 'matched by technique ID'
      : pairs.every(d => d < 0) ? 'an earlier release than this workbook\'s, matched to it by technique ID'
        : 'matched to this workbook\'s release by technique ID';
    return ` The controls on the ${SHEET.nist} sheet come from CTID's mappings to ATT&CK ${version}, ${matched}; `
      + 'they inform but do not change readiness.';
  }

  function writeSummary(ws, ctx, P, Ls) {
    const { T: LT, M: LM, D: LD } = Ls;
    const prio = priorities();
    const LAST_COL = BAR.first + BAR.cells - 1;
    const barA = colLetter(BAR.first), barZ = colLetter(LAST_COL);

    ws.getColumn(1).width = 34;
    for (let c = 2; c <= 8; c++) ws.getColumn(c).width = 13;
    ws.getColumn(9).width = 2;
    for (let c = BAR.first; c <= LAST_COL; c++) ws.getColumn(c).width = 1.4;

    let row = 1;
    const blockStarts = [];   // [row, level]: sections (0) and the blocks inside them (1), kept together on paper
    const text = (r, c, v, f = {}) => put(ws, r, c, v, { font: font(f) });
    const band = title => {
      blockStarts.push([row, 0]);
      for (let c = 1; c <= LAST_COL; c++) {
        put(ws, row, c, c === 1 ? title : null, { fill: solid(C.band), font: font({ bold: true, size: 12, color: { argb: C.white } }), alignment: { vertical: 'middle' } });
      }
      ws.getRow(row).height = 22;
      row++;
    };
    const legendRuns = (title, items) => ({
      richText: [{ text: title + '   ', font: font({ bold: true }) }]
        .concat(...items.map(([fill, label, glyph = '■']) => [
          { text: glyph + ' ', font: font({ size: 12, color: { argb: fill } }) },
          { text: label + '   ', font: font() },
        ])),
    });
    const headerRow = (labels, barLegend) => {
      labels.forEach((l, i) => put(ws, row, i + 1, l, {
        font: font({ bold: true }), fill: solid(C.subband),
        alignment: { vertical: 'middle', wrapText: true, horizontal: i ? 'center' : undefined }, border: { bottom: thin(C.border) },
      }));
      if (barLegend) {
        ws.mergeCells(row, BAR.first, row, LAST_COL);
        put(ws, row, BAR.first, barLegend, { fill: solid(C.subband), alignment: { vertical: 'middle', wrapText: true } });
      }
      ws.getRow(row).height = 46;
      row++;
    };
    const merged = (r, c1, c2, value, style, height) => {
      ws.mergeCells(r, c1, r, c2);
      put(ws, r, c1, value, style);
      if (height) ws.getRow(r).height = height;
    };
    const lines = (s, perLine) => Math.max(1, Math.ceil(String(s).length / perLine));
    // Bar cells hold hidden position values that the conditional formats compare against; white
    // top and bottom borders keep the bars of adjacent rows apart.
    const barCells = r => {
      for (let k = 0; k < BAR.cells; k++) {
        put(ws, r, BAR.first + k, (k + 0.5) / BAR.cells, {
          numFmt: ';;;', fill: solid(C.track),
          border: { top: { style: 'medium', color: { argb: C.white } }, bottom: { style: 'medium', color: { argb: C.white } } },
        });
      }
      if (!ws.getRow(r).height) ws.getRow(r).height = 18;
    };
    // Stacked bars for rows r1..r2. Columns B..E hold Techniques, Mitigated + detected, Mitigated only
    // and Detected only, read from each bar's own row, or from row `src` when given.
    const stackedBarRules = (r1, r2, src) => {
      if (r2 < r1) return;
      const a = `${barA}${r1}`;
      const ref = c => (src ? `$${c}$${src}` : `$${c}${r1}`);
      ws.addConditionalFormatting({
        ref: `${barA}${r1}:${barZ}${r2}`,
        rules: [
          { type: 'expression', priority: prio(), formulae: [`AND(${ref('B')}>0,${a}<${ref('C')}/${ref('B')})`], style: { fill: solid(C.good) } },
          { type: 'expression', priority: prio(), formulae: [`AND(${ref('B')}>0,${a}<(${ref('C')}+${ref('D')}+${ref('E')})/${ref('B')})`], style: { fill: solid(C.warning) } },
          { type: 'expression', priority: prio(), formulae: [`${ref('B')}>0`], style: { fill: solid(C.critical) } },
        ],
      });
    };
    const progressBarRules = (r1, r2) => {
      if (r2 < r1) return;
      ws.addConditionalFormatting({
        ref: `${barA}${r1}:${barZ}${r2}`,
        rules: [{ type: 'expression', priority: prio(), formulae: [`AND($B${r1}>0,${barA}${r1}<$C${r1}/$B${r1})`], style: { fill: solid(C.good) } }],
      });
    };
    const pct = (num, den) => (den ? num / den : '');
    const READINESS_LEGEND = legendRuns('Readiness bar (live)', [[C.good, COVERAGE.covered], [C.warning, 'Partial'], [C.critical, COVERAGE.gap]]);
    const center = { horizontal: 'center', vertical: 'top' };
    const sum = k => P.domains.reduce((n, D) => n + D[k], 0);
    const totalTech = sum('total');
    const all = { covered: 0, mitigated: 0, detected: 0, gap: 0 };
    for (const D of P.domains) for (const k of Object.keys(all)) all[k] += D.counts[k];

    // Title block
    text(row, 1, workbookTitle(P), { size: 18, bold: true });
    ws.getRow(row).height = 28;
    row++;
    const profileLine = clean('Threat profile: ' + profileNames(ctx));
    merged(row, 1, LAST_COL, profileLine, { font: font({ size: 12, bold: true }), alignment: { wrapText: true, vertical: 'top' } }, 17 * lines(profileLine, 150) + 2);
    row++;
    const when = P.generated.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    text(row, 1, clean(`Generated ${when} with ThreatSim · ` + P.domains.map(D => `${D.title} v${D.version}`).join(' · ')), { color: { argb: C.muted } });
    row += 2;
    // name only the sheets that have statuses to set (an ATLAS-only profile has no detection strategies)
    const hasDet = P.detections.length > 0;
    const howTo = 'How to use this workpaper: set each mitigation\'s Implementation status (In Place / Not In Place) on the Mitigations sheet'
      + (hasDet ? ', and each detection strategy\'s Deployment status (Deployed / Not Deployed) on the Detections sheet,' : ',')
      + ' using the yellow drop-down cells (they turn green when ' + (hasDet ? 'In Place or Deployed' : 'In Place') + '). '
      + (P.domains.some(D => D.family === 'atlas') ? 'ATLAS has no detection strategies; its detection controls are ATLAS mitigations. ' : '')
      + 'Figures marked (live) and every readiness bar recalculate from those choices; '
      + 'figures marked (at export) were fixed when the workpaper was exported.';
    merged(row, 1, 8, howTo, { font: font({ bold: true, color: { argb: C.warnInk } }), fill: solid(C.input), alignment: { wrapText: true, vertical: 'middle' },
      border: box(C.inputBorder) }, Math.max(62, 15 * lines(howTo, 118) + 6));
    row += 2;

    // ---- Readiness (live) ----
    band('Readiness');
    const headline = row;
    const tableFirst = headline + 3;   // first data row of the readiness table (asserted below)
    put(ws, row, 1, 'Overall readiness', { font: font({ bold: true, size: 12 }), alignment: { vertical: 'middle' } });
    const readyNow = pct(all.covered + all.mitigated + all.detected, totalTech);
    put(ws, row, 2, F(`$G$${tableFirst}`, readyNow), { font: font({ size: 22, bold: true }), numFmt: '0%', alignment: { horizontal: 'center', vertical: 'middle' } });
    const t = c => `$${c}$${tableFirst}`;
    const partial = all.mitigated + all.detected;
    merged(row, 3, 8, F(`${t('C')}&" of "&${t('B')}&IF(${t('B')}=1," technique"," techniques")&IF(${t('C')}=1," is"," are")&" mitigated and detected, "`
      + `&(${t('D')}+${t('E')})&IF(${t('D')}+${t('E')}=1," is"," are")&" partly covered and "&${t('F')}&IF(${t('F')}=1," has"," have")&" no coverage."`,
    `${all.covered} of ${totalTech} ${totalTech === 1 ? 'technique' : 'techniques'} ${all.covered === 1 ? 'is' : 'are'} mitigated and detected, `
      + `${partial} ${partial === 1 ? 'is' : 'are'} partly covered and ${all.gap} ${all.gap === 1 ? 'has' : 'have'} no coverage.`),
    { font: font({ size: 11 }), alignment: { wrapText: true, vertical: 'middle' } });
    ws.getRow(row).height = 36;
    barCells(row);
    stackedBarRules(row, row, tableFirst);
    row++;
    merged(row, 1, 8, 'Readiness = share of profile techniques with at least one mitigation In Place or detection strategy Deployed. Fully covered = both.',
      { font: font({ italic: true, color: { argb: C.muted } }) });
    row++;

    headerRow(['Scope', 'Techniques', COVERAGE.covered, COVERAGE.mitigated, COVERAGE.detected, COVERAGE.gap, 'Readiness', 'Fully covered'], READINESS_LEGEND);
    if (row !== tableFirst) throw new Error('Summary layout drifted');
    const T = key => LT.range(key);
    const scopeRows = [];
    if (P.domains.length > 1) scopeRows.push({ label: 'All domains', domain: null, counts: all, total: totalTech });
    for (const D of P.domains) scopeRows.push({ label: D.title, domain: D.label, counts: D.counts, total: D.total });
    const firstScope = row;
    for (const s of scopeRows) {
      const count = status => (s.domain
        ? `COUNTIFS(${T('domain')},${lit(s.domain)},${T('coverage')},${lit(COVERAGE[status])})`
        : `COUNTIF(${T('coverage')},${lit(COVERAGE[status])})`);
      text(row, 1, s.label, { bold: true });
      put(ws, row, 2, F(s.domain ? `COUNTIF(${T('domain')},${lit(s.domain)})` : `COUNTA(${T('key')})`, s.total), { font: font(), numFmt: '#,##0', alignment: { horizontal: 'center' } });
      ['covered', 'mitigated', 'detected', 'gap'].forEach((k, i) => {
        put(ws, row, 3 + i, F(count(k), s.counts[k]), { font: font(), numFmt: '#,##0', alignment: { horizontal: 'center' } });
      });
      put(ws, row, 7, F(`IF($B${row}=0,"",($C${row}+$D${row}+$E${row})/$B${row})`, pct(s.counts.covered + s.counts.mitigated + s.counts.detected, s.total)),
        { font: font({ bold: true }), numFmt: '0%', alignment: { horizontal: 'center' } });
      put(ws, row, 8, F(`IF($B${row}=0,"",$C${row}/$B${row})`, pct(s.counts.covered, s.total)), { font: font(), numFmt: '0%', alignment: { horizontal: 'center' } });
      barCells(row);
      row++;
    }
    stackedBarRules(firstScope, row - 1);
    row++;

    // Controls (live)
    blockStarts.push([row, 1]);
    headerRow(['Controls', 'Mapped', 'In place / deployed', 'Not yet', 'Share in place'], legendRuns('Progress (live)', [[C.good, 'In place / deployed'], [C.muted, 'Not yet', '□']]));
    const ctlRows = [];
    const addCtl = (label, perDomain, L, on, totalKey, onKey, domains = P.domains) => {
      ctlRows.push({ label, L, on, total: sum(totalKey), now: sum(onKey) });
      if (P.domains.length > 1) {
        for (const D of domains) ctlRows.push({ label: `  ${D.label} ${perDomain}`, L, on, domain: D.label, total: D[totalKey], now: D[onKey] });
      }
    };
    addCtl('Mitigations in place', 'mitigations', LM, MIT.on, 'mitTotal', 'mitOn');
    // ATLAS defines no detection strategies, so it gets no per-domain row here
    addCtl('Detection strategies deployed', 'detection strategies', LD, DET.on, 'detTotal', 'detOn', P.domains.filter(D => D.family !== 'atlas'));
    const firstCtl = row;
    for (const c of ctlRows) {
      const R = key => c.L.range(key);
      text(row, 1, c.label, { bold: !c.domain });
      put(ws, row, 2, F(c.domain ? `COUNTIF(${R('domain')},${lit(c.domain)})` : `COUNTA(${R('key')})`, c.total), { font: font(), numFmt: '#,##0', alignment: { horizontal: 'center' } });
      put(ws, row, 3, F(c.domain ? `COUNTIFS(${R('domain')},${lit(c.domain)},${R('status')},${lit(c.on)})` : `COUNTIF(${R('status')},${lit(c.on)})`, c.now),
        { font: font({ bold: true }), numFmt: '#,##0', alignment: { horizontal: 'center' } });
      put(ws, row, 4, F(`$B${row}-$C${row}`, c.total - c.now), { font: font(), numFmt: '#,##0', alignment: { horizontal: 'center' } });
      put(ws, row, 5, F(`IF($B${row}=0,"",$C${row}/$B${row})`, pct(c.now, c.total)), { font: font(), numFmt: '0%', alignment: { horizontal: 'center' } });
      barCells(row);
      row++;
    }
    progressBarRules(firstCtl, row - 1);
    const changedRow = row;
    const changedNote = `IF($B${changedRow}=0,"None: every status still matches the export.",$B${changedRow}&IF($B${changedRow}=1," status differs"," statuses differ")`
      + `&" from the export. Priorities and Adds are still the export values; set the same statuses in ThreatSim and export again to re-rank.")`;
    text(row, 1, 'Statuses changed since export (live)', { bold: true });
    put(ws, row, 2, F(`COUNTIF(${LM.range('changed')},"Changed")+COUNTIF(${LD.range('changed')},"Changed")`, 0),
      { font: font({ bold: true }), numFmt: '#,##0', alignment: { horizontal: 'center' }, fill: solid(C.live) });
    merged(row, 3, 8, F(changedNote, 'None: every status still matches the export.'), { font: font({ color: { argb: C.muted } }), alignment: { wrapText: true, vertical: 'top' } }, 28);
    row += 2;

    // ---- Recommended next actions (ranked at export, live status) ----
    band(`Recommended next actions (top ${TOP_ACTIONS} per domain, ranked at export)`);
    merged(row, 1, 8, F(`IF($B$${changedRow}>0,"Ranked at export; "&$B$${changedRow}&IF($B$${changedRow}=1," status has"," statuses have")&" changed since, so export again from ThreatSim to re-rank.","")`, ''),
      { font: font({ italic: true, color: { argb: C.warnInk } }) });
    row++;
    const actions = (kind, L, V) => {
      const isMit = kind === 'mit';
      blockStarts.push([row, 1]);
      text(row, 1, isMit ? 'Mitigations to put in place' : 'Detection strategies to deploy', { bold: true, size: 11 });
      row++;
      headerRow([isMit ? 'Mitigation' : 'Detection strategy', 'ID', 'Domain', 'Priority (at export)', 'Profile techniques', 'Adds (at export)',
        isMit ? 'Still unmitigated (live)' : 'Still undetected (live)', 'Status (live)']);
      const first = row;
      const note = msg => merged(row++, 1, 8, msg, { font: font({ italic: true, color: { argb: C.muted } }), alignment: { wrapText: true, vertical: 'top' } }, 15 * lines(msg, 125) + 3);
      for (const D of P.domains) {
        const list = isMit ? D.topMitigations : D.topDetections;
        const total = isMit ? D.mitTotal : D.detTotal, on = isMit ? D.mitOn : D.detOn;
        const noun = isMit ? 'mitigation' : 'detection strategy', nouns = isMit ? 'mitigations' : 'detection strategies';
        if (!list.length) {
          const off = total - on;
          note(!total ? (!isMit && D.family === 'atlas' ? `${D.label}: ATLAS has no detection strategies; its detection controls are ATLAS mitigations, listed above.`
            : `${D.label}: no ${D.kb} ${nouns} map to this profile's techniques.`)
            : on === total ? (total === 1 ? `${D.label}: the only ${noun} was already ${V.on} at export.` : `${D.label}: all ${total} ${nouns} were already ${V.on} at export.`)
            : isMit ? `${D.label}: the ${plural(off, noun, nouns)} not ${V.on} at export ${off === 1 ? 'addresses' : 'address'} no technique that is still unmitigated.`
            : `${D.label}: the ${plural(off, noun, nouns)} not ${V.on} at export ${off === 1 ? 'covers' : 'cover'} no technique that is still undetected.`);
          continue;
        }
        for (const a of list) {
          put(ws, row, 1, a.name, { font: font(), alignment: { wrapText: true, vertical: 'top' } });
          put(ws, row, 2, a.id, { font: font({ color: { argb: C.link }, underline: true }), alignment: { vertical: 'top' } });
          put(ws, row, 3, a.domain, { font: font(), alignment: { vertical: 'top' } });
          put(ws, row, 4, a.priority, { font: font({ bold: true }), alignment: center });
          put(ws, row, 5, a.techN, { font: font(), alignment: center });
          put(ws, row, 6, a.adds, { font: font(), alignment: center });
          put(ws, row, 7, F(`IFERROR(INDEX(${L.range('open')},MATCH(${lit(a.key)},${L.range('key')},0)),"")`, a.openNow), { font: font(), alignment: center, fill: solid(C.live) });
          put(ws, row, 8, F(`IFERROR(INDEX(${L.range('status')},MATCH(${lit(a.key)},${L.range('key')},0))&"","")`, a.status), { font: font({ bold: true }), alignment: center });
          ws.getRow(row).height = 13 * lines(a.name, 42) + 3;   // column A holds ~42 characters per line
          row++;
        }
        // Equal scores share a priority number; say so when the tie runs past the list.
        const lastTier = list[list.length - 1].priority;
        const inTier = (isMit ? D.tierCounts.mit : D.tierCounts.det).get(lastTier) || 0;
        const shown = list.filter(a => a.priority === lastTier).length;
        if (inTier > shown) {
          note(`${D.label}: ${inTier} ${nouns} share priority ${lastTier}; `
            + (shown === 1 ? `the one shown was picked by reach, documented procedure examples, then ${D.kb} ID.`
              : `the ${shown} shown are ordered by reach, documented procedure examples, then ${D.kb} ID.`));
        }
      }
      if (row > first) equalsRule(ws, `H${first}:H${row - 1}`, V.on, C.goodTint, C.goodInk, prio);
      row++;
    };
    actions('mit', LM, MIT);
    actions('det', LD, DET);

    // ---- Coverage by tactic (live) ----
    band('Coverage by tactic');
    headerRow(['Tactic', 'Techniques', COVERAGE.covered, COVERAGE.mitigated, COVERAGE.detected, COVERAGE.gap, 'Readiness', 'Fully covered'], READINESS_LEGEND);
    for (const D of P.domains) {
      if (P.domains.length > 1) {
        blockStarts.push([row, 1]);
        for (let c = 1; c <= 8; c++) put(ws, row, c, c === 1 ? D.title : null, { font: font({ bold: true }), fill: solid(C.idle) });
        row++;
      }
      const first = row;
      for (const tr of D.tactics) {
        const scope = `${T('domain')},${lit(D.label)},${T('tacticKeys')},${lit('*;' + tr.tactic.shortname + ';*')}`;
        const count = status => `COUNTIFS(${scope},${T('coverage')},${lit(COVERAGE[status])})`;
        text(row, 1, clean(tr.tactic.name), { color: { argb: tr.total ? C.ink : C.muted } });
        put(ws, row, 2, F(`COUNTIFS(${scope})`, tr.total), { font: font(), numFmt: '#,##0', alignment: { horizontal: 'center' } });
        ['covered', 'mitigated', 'detected', 'gap'].forEach((k, i) => {
          put(ws, row, 3 + i, F(count(k), tr.counts[k]), { font: font(), numFmt: '#,##0', alignment: { horizontal: 'center' } });
        });
        put(ws, row, 7, F(`IF($B${row}=0,"",($C${row}+$D${row}+$E${row})/$B${row})`, pct(tr.counts.covered + tr.counts.mitigated + tr.counts.detected, tr.total)),
          { font: font({ bold: true }), numFmt: '0%', alignment: { horizontal: 'center' } });
        put(ws, row, 8, F(`IF($B${row}=0,"",$C${row}/$B${row})`, pct(tr.counts.covered, tr.total)), { font: font(), numFmt: '0%', alignment: { horizontal: 'center' } });
        barCells(row);
        row++;
      }
      stackedBarRules(first, row - 1);
    }
    row++;

    // ---- Profile at a glance (at export) ----
    band('Profile at a glance');
    const hasAttack = P.domains.some(D => D.family === 'attack'), hasAtlas = P.domains.some(D => D.family === 'atlas');
    const glance = [
      ['Threats in profile', P.profile.length, profileNames(ctx)],
      ['Techniques in scope', totalTech, `${plural(sum('subs'), 'sub-technique', 'sub-techniques')} · ${sum('tacticsHit')} of ${sum('tacticsAll')} tactics`],
      ['Techniques with no mitigation', sum('noMitigation'),
        (P.domains.length > 1 ? P.domains.map(D => `${D.noMitigation} ${D.label}`).join(', ') + '. ' : '')
        + (!hasAttack ? 'ATLAS has no detection strategies either, so these stay uncovered here.'
          : hasAtlas ? 'Detection is the only lever for the ATT&CK ones; ATLAS has no detection strategies.' : 'Detection is the only lever for these.')],
      ['Mitigations mapped', sum('mitTotal'), `${kbList(P)} mitigations that address at least one profile technique`],
      ['Detection strategies mapped', sum('detTotal'), hasAttack ? 'ATT&CK detection strategies for the profile techniques' + (hasAtlas ? ' (ATLAS has none: its detection controls are mitigations)' : '')
        : 'ATLAS has no detection strategies; its detection controls are mitigations'],
      ['Data components (telemetry)', P.dataComponents, 'Distinct log data types the detection strategies rely on'
        + (P.dcShared > 0 ? ` (${P.dcShared} ${P.dcShared === 1 ? 'is' : 'are'} used by more than one domain and get a Telemetry row in each: ${sum('dcTotal')} rows)` : '')],
    ];
    if (P.unresolved.size) {
      glance.push(['Data components not loaded', P.unresolved.size, 'Referenced by these analytics but not in the loaded ATT&CK data (ICS ATT&CK uses some Enterprise data components). '
        + 'Pull Enterprise ATT&CK on the Data page for the complete telemetry list.']);
    }
    if (P.domains.some(D => D.assetTotal)) glance.push(['ICS assets targeted', sum('assetTotal'), 'Assets targeted by the profile\'s ICS techniques']);
    glance.push(...mappingGlance(P));
    for (const [label, value, note] of glance) {
      text(row, 1, label, { bold: true });
      put(ws, row, 2, value, { font: font({ size: 12, bold: true }), numFmt: '#,##0', alignment: { horizontal: 'center', vertical: 'top' } });
      const n = clean(note);
      // column A holds ~36 bold characters a line
      merged(row, 3, 8, n, { font: font({ color: { argb: C.muted } }), alignment: { wrapText: true, vertical: 'top' } }, Math.max(17, 13 * Math.max(lines(n, 100), lines(label, 36)) + 4));
      ws.getCell(row, 1).alignment = { vertical: 'top', wrapText: true };
      row++;
    }
    row++;

    // ---- Threat profile ----
    band('Threat profile');
    headerRow(['Threat', 'Type', 'ID', 'Domains', 'Techniques contributed', 'Aliases']);
    for (const p of P.profile) {
      const top = { vertical: 'top' };
      put(ws, row, 1, link(p.obj.name, p.obj.url), { font: font({ color: { argb: C.link }, underline: true }), alignment: { vertical: 'top', wrapText: true } });
      put(ws, row, 2, p.kind, { font: font(), alignment: { vertical: 'top', wrapText: true } });
      put(ws, row, 3, p.obj.attackId || '', { font: font(), alignment: top });
      put(ws, row, 4, p.domains, { font: font(), alignment: { vertical: 'top', wrapText: true } });
      put(ws, row, 5, p.techniques, { font: font(), alignment: center });
      const aliases = clean(p.aliases);
      // column A holds ~42 characters a line, B and D ~13 ('Enterprise, Mobile' wraps); ATLAS case-study names are long
      merged(row, 6, 8, aliases || null, { font: font({ color: { argb: C.muted } }), alignment: { wrapText: true, vertical: 'top' } },
        13 * Math.max(lines(aliases, 40), lines(p.obj.name, 42), lines(p.kind, 13), wrapLines(p.domains, 15)) + 3);
      row++;
    }
    row++;

    // ---- Scope and method ----
    band('Scope and method');
    const opts = ctx.opts;
    const hasAttackKb = P.domains.some(D => D.family === 'attack'), hasAtlasKb = P.domains.some(D => D.family === 'atlas');
    // the platform filter applies per knowledge base (ThreatSim narrows each domain by its own platforms only)
    const platforms = P.domains.some(D => D.platforms)
      ? (P.domains.every(D => !(D.platforms || []).length) ? 'All platforms'
        : P.domains.map(D => `${D.label}: ${(D.platforms || []).length ? D.platforms.join(', ') : 'all platforms'}`).join('; '))
      : (opts.platforms && opts.platforms.size ? [...opts.platforms].join(', ') : 'All platforms');
    const yearOf = D => (D.released ? new Date(D.released).getUTCFullYear() : 0);
    const year = P.domains.filter(D => D.family === 'attack').reduce((y, D) => Math.max(y, yearOf(D)), 0) || P.generated.getFullYear();
    const atlasYear = P.domains.filter(D => D.family === 'atlas').reduce((y, D) => Math.max(y, yearOf(D)), 0) || P.generated.getFullYear();
    const attributed = [hasAttackKb ? 'campaigns attributed to selected groups' : null, hasAtlasKb ? 'case studies attributed to selected entities' : null].filter(Boolean).join(' and ');
    const who = hasAtlasKb ? 'threats' : 'adversaries';
    const method = [
      ['Data', P.domains.map(D => `${D.title} v${D.version}` + (D.released ? ` (released ${fmtDay(D.released)})` : '')).join('; ')],
      ['Mappings (CTID)', mappingMethod(P)],
      ['Scope', `Techniques used by the selected threats. Software they use: ${opts.viaSoftware ? 'included' : 'not included'}. `
        + `${attributed.charAt(0).toUpperCase() + attributed.slice(1)}: ${opts.viaCampaigns ? 'included' : 'not included'}. Platforms: ${platforms}.`],
      ['Readiness', 'Share of profile techniques with at least one mitigation In Place or detection strategy Deployed. Fully covered means both. Partial means one of the two.'],
      ['Coverage', 'A technique is mitigated when any mitigation mapped to it on the Control Map sheet is In Place, and detected when any detection strategy mapped to it is Deployed.'],
      ['(live) and (at export)', 'Figures marked (live) are formulas that recalculate when you change a status. Figures marked (at export), including priorities, were fixed when ThreatSim exported this workbook. "Status at export" keeps the original statuses, and "Changed since export" flags the rows you have edited.'],
      ['Priority', `Ranked by ThreatSim at export: each step picks the control covering the most still-uncovered techniques, weighting techniques used by more selected ${who} higher. The weighted score is the sum, over the techniques a pick newly covers, of the number of selected ${who} using each.`
        + ' Controls with equal scores share a priority number and are listed by reach, documented procedure examples, then ID. Adds is how many techniques a pick newly covers; Cumulative is the share covered once it is added. To re-rank after editing statuses here, set the same statuses in ThreatSim and export again (owners, dates and notes are not carried over).'],
      ['Sheets', 'Matrix: techniques by tactic, shaded by usage, with a live status column. Techniques: every profile technique with live coverage. '
        + 'Mitigations and Detections: set statuses here (yellow drop-downs), with owner, target date and notes. ICS Assets: assets targeted by ICS techniques and how exposed they are. '
        + 'Telemetry: data components and log sources the detection strategies rely on. Analytics: every analytic and what to look for in each log source. '
        + 'Control Map: each technique-to-control link the coverage formulas use. ' + mappingSheets(P)],
      ['Limits', `${kbList(P)} ${hasAttackKb && hasAtlasKb ? 'do' : 'does'} not enumerate every adversary behaviour, and some techniques have no mitigation. `
        + (hasAtlasKb ? 'ATLAS has no detection strategies: its detection controls (for example AML.M0024 AI Telemetry Logging and Monitoring) are ATLAS mitigations, so ATLAS techniques count as mitigated or not, never as detected. ' : '')
        + `Readiness here measures coverage of ${kbList(P)} mappings, not overall security.` + mappingLimits(P)],
      hasAttackKb ? ['ATT&CK licence', `© ${year} The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. `
        + 'License: The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. '
        + 'Any copy you make for such purposes is authorized provided that you reproduce MITRE\'s copyright designation and this license in any such copy. '
        + 'MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation. Source: https://github.com/mitre-attack/attack-stix-data'] : null,
      hasAtlasKb ? ['ATLAS licence', `© ${atlasYear > 2021 ? '2021–' + atlasYear : '2021'} The MITRE Corporation. MITRE ATLAS data is licensed under the Apache License, Version 2.0 `
        + '(https://www.apache.org/licenses/LICENSE-2.0); it is distributed on an "AS IS" basis, without warranties or conditions of any kind. '
        + 'MITRE ATLAS and ATLAS are trademarks of The MITRE Corporation. Source: https://github.com/mitre-atlas/atlas-data'] : null,
      ...mappingLicences(P),
    ].filter(Boolean);
    for (const [label, value] of method) {
      put(ws, row, 1, label, { font: font({ bold: true }), alignment: { vertical: 'top' } });
      // columns B..H hold about 118 characters a line in LibreOffice (112 leaves room for Excel's wrapping); a 10pt
      // line takes about 12.2pt in LibreOffice and 12.75pt in Excel
      merged(row, 2, 8, clean(value), { font: font(), alignment: { wrapText: true, vertical: 'top' } }, 13 * wrapLines(clean(value), 112) + 4);
      row++;
    }

    // Paginate the summary here so Excel and LibreOffice break it in the same places: a manual break goes
    // before any row that would not fit, so neither app adds breaks of its own (Excel keeps manual row
    // breaks when only the width is fitted). A4 landscape leaves 516pt of rows and the summary prints at
    // about 81% to fit the width; the 5% headroom covers differences in how the apps scale. A heading
    // stays with its first rows, and a block shorter than half a page stays whole.
    const CAPACITY = 0.95 * 516 / 0.81;
    const heightOf = r => ws.getRow(r).height || 15;
    const span = (a, b) => { let h = 0; for (let k = a; k < b; k++) h += heightOf(k); return h; };
    const blockEnds = new Map();   // first row -> end rows (exclusive) of the blocks that start there
    blockStarts.forEach(([r, level], i) => {
      const next = blockStarts.slice(i + 1).find(([, l]) => l <= level);
      blockEnds.set(r, [...(blockEnds.get(r) || []), next ? next[0] : row]);
    });
    const needAt = r => {   // height that must share a page with row r
      if (!blockEnds.has(r)) return heightOf(r);
      let need = 0, h = 0;
      for (let k = r; k < Math.min(r + 4, row); k++) {   // the heading and three rows...
        if (k > r && blockEnds.has(k)) { need = Math.max(need, h + needAt(k)); break; }   // ...or what a heading below needs
        h += heightOf(k);
        need = Math.max(need, h);
      }
      for (const e of blockEnds.get(r)) if (span(r, e) <= CAPACITY / 2) need = Math.max(need, span(r, e));
      return need;
    };
    let used = 0;
    for (let r = 1; r < row; r++) {
      if (used > 0 && used + needAt(r) > CAPACITY) { ws.getRow(r - 1).addPageBreak(1, 16384); used = 0; }
      used += heightOf(r);
    }

    ws.views = [{ showGridLines: false, activeCell: 'A1' }];
    ws.pageSetup = {
      orientation: 'landscape', paperSize: 9, fitToPage: true, fitToWidth: 1, fitToHeight: 0,
      printArea: `A$1:${barZ}$${row - 1}`,   // absolute rows: LibreOffice ignores a relative print area
      margins: { left: 0.4, right: 0.4, top: 0.5, bottom: 0.6, header: 0.3, footer: 0.3 },
    };
  }

  // ---------- workbook ----------

  function build(ExcelJS, ctx) {
    const P = prepare(ctx);
    const wb = new ExcelJS.Workbook();
    wb.creator = 'ThreatSim';
    wb.lastModifiedBy = 'ThreatSim';
    wb.created = P.generated;
    wb.modified = P.generated;
    wb.title = workbookTitle(P);
    wb.subject = clean('Threat profile: ' + profileNames(ctx));
    wb.calcProperties.fullCalcOnLoad = true;

    // Sheets in tab order; filled once every table's size (and so every range) is known.
    const summary = wb.addWorksheet(SHEET.summary, { properties: { tabColor: { argb: C.header } } });
    const matrices = P.domains.map(D => wb.addWorksheet(matrixSheetName(D.label)));
    const techniques = wb.addWorksheet(SHEET.techniques);
    const mitigations = wb.addWorksheet(SHEET.mitigations, { properties: { tabColor: { argb: C.inputTab } } });
    const detections = wb.addWorksheet(SHEET.detections, { properties: { tabColor: { argb: C.inputTab } } });
    const assets = wb.addWorksheet(SHEET.assets);
    const telemetry = wb.addWorksheet(SHEET.telemetry);
    const analytics = wb.addWorksheet(SHEET.analytics);
    const map = wb.addWorksheet(SHEET.map);
    const nist = wb.addWorksheet(SHEET.nist);

    const LT = layout(SHEET.techniques, TECH_COLS, P.techniques.length);
    const LM = layout(SHEET.mitigations, MIT_COLS, P.mitigations.length);
    const LD = layout(SHEET.detections, DET_COLS, P.detections.length);
    const LA = layout(SHEET.assets, ASSET_COLS, P.assets.length);
    const LTel = layout(SHEET.telemetry, TEL_COLS, P.telemetry.length);
    const LAn = layout(SHEET.analytics, ANALYTIC_COLS, P.analytics.length);
    const LMap = layout(SHEET.map, MAP_COLS, P.map.length);
    const LN = layout(SHEET.nist, NIST_COLS, P.nist.length);

    writeSummary(summary, ctx, P, { T: LT, M: LM, D: LD });
    P.domains.forEach((D, i) => writeMatrix(matrices[i], D, ctx, LT));
    writeTechniques(techniques, P, LT, LMap);
    writeControls(mitigations, P.mitigations, LM, LMap, 'mit', P);
    writeControls(detections, P.detections, LD, LMap, 'det', P);
    writeAssets(assets, P, LA, LT);
    writeTelemetry(telemetry, P, LTel, LD);
    writeAnalytics(analytics, P, LAn, LD);
    writeMap(map, P, LMap, LM, LD, LT);
    writeNist(nist, P, LN, LT, LM);

    const stamp = profileNames(ctx) + ' · generated ' + P.generated.toLocaleDateString(undefined, { dateStyle: 'medium' });
    for (const ws of wb.worksheets) footer(ws, stamp);

    // LibreOffice imports an autoFilter only when the sheet also has the sheet-local, hidden
    // _xlnm._FilterDatabase name that Excel writes. ExcelJS cannot write hidden names, so add
    // them to workbook.xml as it is written.
    const xmlText = t => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const filterNames = [[techniques, LT], [mitigations, LM], [detections, LD], [assets, LA], [telemetry, LTel], [analytics, LAn], [map, LMap], [nist, LN]]
      .map(([ws, L]) => `<definedName name="_xlnm._FilterDatabase" localSheetId="${wb.worksheets.indexOf(ws)}" hidden="1">`
        + xmlText(`${quoteSheet(ws.name)}!$A$1:$${colLetter(L.cols.length)}$${L.last}`) + '</definedName>')
      .join('');
    const patches = new Map([['xl/workbook.xml', xml => (xml.includes('</definedNames>')
      ? xml.replace('</definedNames>', () => filterNames + '</definedNames>')
      : xml.replace('<calcPr', () => '<definedNames>' + filterNames + '</definedNames><calcPr'))]]);

    // ExcelJS writes row breaks but not column breaks: add the matrix halves' break after the
    // page-setup elements, where CT_Worksheet expects colBreaks (after headerFooter and rowBreaks).
    P.domains.forEach((D, i) => {
      if (!D.matrixColumnBreak) return;
      const breaks = `<colBreaks count="1" manualBreakCount="1"><brk id="${D.matrixColumnBreak}" max="1048575" man="1"/></colBreaks>`;
      patches.set(`xl/worksheets/sheet${matrices[i].id}.xml`, xml => {
        for (const end of ['</rowBreaks>', '</headerFooter>']) {
          if (xml.includes(end)) return xml.replace(end, () => end + breaks);
        }
        return xml.replace('</worksheet>', () => breaks + '</worksheet>');
      });
    });
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
    return wb;
  }

  // ---------- loading and download ----------

  let loading = null;
  function loadExcelJS() {
    if (global.ExcelJS) return Promise.resolve(global.ExcelJS);
    if (!loading) {
      loading = new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = EXCELJS_SRC;
        s.onload = () => (global.ExcelJS ? resolve(global.ExcelJS) : reject(new Error('ExcelJS loaded but did not register')));
        s.onerror = () => { s.remove(); reject(new Error('Could not load ' + EXCELJS_SRC)); };
        document.head.append(s);
      }).catch(e => { loading = null; throw e; });
    }
    return loading;
  }

  function fileName(ctx, when) {
    const names = [];
    for (const kind of ctx.kinds) for (const id of ctx.selection[kind.key]) { const o = ctx.entity(id); if (o) names.push(o.name); }
    const part = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24).replace(/-$/, '');
    const slug = names.slice(0, 3).map(part).filter(Boolean).join('-') + (names.length > 3 ? `-and-${names.length - 3}-more` : '');
    const pad = n => String(n).padStart(2, '0');
    const stamp = `${when.getFullYear()}${pad(when.getMonth() + 1)}${pad(when.getDate())}-${pad(when.getHours())}${pad(when.getMinutes())}`;
    return `threatsim-workpaper-${slug || 'profile'}-${stamp}.xlsx`;
  }

  /** Builds the workbook and returns { blob, name }. */
  async function create(ctx) {
    if (!ctx.results || !ctx.results.length) throw new Error('Build a threat profile first.');
    const ExcelJS = await loadExcelJS();
    const c = Object.assign({}, ctx, { generatedAt: ctx.generatedAt || new Date() });
    const wb = build(ExcelJS, c);
    const buf = await wb.xlsx.writeBuffer();
    return { blob: new Blob([buf], { type: XLSX_MIME }), name: fileName(c, c.generatedAt) };
  }

  async function download(ctx) {
    const { blob, name } = await create(ctx);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    return name;
  }

  global.Workpaper = { create, download, build, prepare, loadExcelJS, MIT, DET, COVERAGE, SHEET };
})(window);
