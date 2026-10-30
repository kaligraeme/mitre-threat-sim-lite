# ThreatSim · MITRE ATT&CK and ATLAS data instance

A browser-based cyber threat simulator. It keeps a local copy of the MITRE ATT&CK **Enterprise** and
**ICS** datasets (Mobile is available but off by default) and of **MITRE ATLAS**, the knowledge base of
threats to AI systems. It maps ATT&CK Groups, Software and Campaigns, and ATLAS Case Studies, Entities and
Software, to the techniques they use, then to the relevant mitigations and detections.

## Pages

- **Data** (`index.html`): pull MITRE ATT&CK and ATLAS releases into the local database.
- **Simulator** (`simulator.html`): build a threat profile and map it to mitigations and detections.

## Simulator

1. **Profile:** pick threats in each knowledge base's own categories, by search or with filters:
   - **ATT&CK:** Groups, Software and Campaigns (filters: description keywords, software type and
     platform, campaign activity window).
   - **ATLAS:** Case Studies, Entities and Software, as on the ATLAS site (filters: incident or exercise,
     date, entity type, activity purpose, software type and category). ATLAS records why each case
     study and entity is there (*Adversarial Operation*, *Security Evaluation* or *Unintended
     Consequence*): many ATLAS entities are red teams and researchers, so the picker, the details and the
     workpaper show that purpose, and the filter can keep a profile to real adversary activity.

   An **ATT&CK | ATLAS** switch appears when both are on. **Select all shown** adds everything the
   current filter matches.
2. **Scope:** optionally pull in techniques from software that selected threats use, and from campaigns
   and case studies attributed to selected groups and entities. You can also limit results to chosen
   platforms; each knowledge base is filtered by its own platforms (ATT&CK: Windows, Linux…; ATLAS:
   Predictive, Generative and Agentic AI, Enterprise), so filtering one never empties the other.
3. **Results**, per domain (Enterprise / ICS / ATLAS):
   - **Matrix:** ATT&CK matrix of the profile's techniques. *Usage* shades each technique by how many
     selected adversaries use it; *Coverage* shows simulated posture.
   - **Techniques:** sortable table: who uses each technique, its mitigation and detection counts, and coverage.
   - **Mitigations / Detections:** ranked by priority. Tick *In place* / *Deployed*, or press
     **Mark top 5**, to see how much exposure is left.
   - **Telemetry:** the data components and log sources the detections rely on.
   - **ICS assets:** assets targeted by the profile's ICS techniques.
   - Click any row or matrix cell for details: procedure examples, mitigation guidance, and analytics
     with their log sources. ATLAS details add technique maturity, mitigation categories and AI
     lifecycle phases, attribution with its activity purpose, the matching ATT&CK object where ATLAS
     names one, and sources.
4. **Export:** an Excel workpaper (below), a CSV of the technique mapping, or Navigator layers (one
   JSON per domain; the ATLAS layer opens in the ATLAS Navigator).

ATLAS has no detection strategies: its detection controls (for example *AML.M0024 AI Telemetry Logging
and Monitoring*) are ATLAS mitigations, so ATLAS techniques count as mitigated or not, never as detected.
The Detections and Telemetry views say so instead of showing empty tables.

Priority uses a weighted greedy method: each step picks the control that covers the most uncovered
techniques, with a technique counting once per selected threat that uses it. Controls with equal
scores share a priority number and are ordered by reach, documented procedure examples, then ID,
so the result doesn't depend on the order you picked threats in. Your selections and
posture are saved in the browser's localStorage.

## Excel workpaper

**Export workpaper**, in the toolbar beside the threat profile on the Simulator tab, writes the current
profile and posture to an `.xlsx` workbook:

| Sheet | Contents |
|---|---|
| Executive Summary | Overall readiness with the **readiness bar**, readiness per domain, controls in place, how many statuses have changed since export, the top 10 recommended mitigations and detection strategies per domain, coverage by tactic, the profile at a glance, the threat profile, and scope and method notes |
| Matrix (Enterprise) / Matrix (ICS) / Matrix (ATLAS) | Matrix of the profile in that domain's tactic order, shaded by how many selected threats use each technique, with a live coverage column (✓ mitigated + detected, M mitigated only, D detected only, ✕ no coverage) |
| Techniques | Every profile technique: tactics, platforms, who uses it, its mitigations and detection strategies, live coverage, procedure examples |
| Mitigations | **Implementation status** drop-down (*In Place* / *Not In Place*), owner, target date and notes; status at export and a live *Changed* flag; priority, adds, weighted score and cumulative coverage at export; live count of unmitigated techniques it addresses |
| Detections | **Deployment status** drop-down (*Deployed* / *Not Deployed*), the same tracking and priority columns, analytics, data components and log sources |
| ICS Assets | Assets targeted by the profile's ICS techniques, with live counts of exposed and fully covered techniques |
| Telemetry | Data components and log sources the detection strategies rely on, with a live count of deployed strategies using each |
| Analytics | One row per analytic log source: what to collect and what to look for, with the strategy's live deployment status |
| Control Map | Each technique-to-control link, with the control's live status and how the mitigation applies |

The drop-downs start at the posture you set in ThreatSim. Everything that depends on them is a formula:
technique coverage, the readiness figures and bars, the matrix status column and the columns marked
*(live)*. Changing a status recalculates the workbook; no macros are involved. Columns marked
*(at export)*, including priorities, keep their values from export time; to re-rank, set the same
statuses in ThreatSim and export again. Controls with equal priority scores share a priority number and
are listed by reach, documented procedure examples, then ID.

Workbooks that include ATLAS name each domain by its own title (for example *ATLAS v2026.10*), show
each ATLAS threat's case type and activity purpose, note that ATLAS's detection controls are
mitigations, and carry the ATLAS licence (Apache 2.0) beside the ATT&CK terms of use.

The bars are conditional formatting on cells, so they work in Excel, LibreOffice Calc and Google Sheets.
Every formula also stores its value at export, so file previews that don't recalculate still show the
right figures. Sheets print landscape with page footers. The summary sets its own page breaks so
headings stay with their rows; tables repeat their header row and key columns on every page and leave
long description columns out of the print area; the matrices print on A3, split between tactics when
they are too wide for one page.

The workbook is built in the browser with [ExcelJS](https://github.com/exceljs/exceljs) 4.4.0 (MIT,
`js/vendor/exceljs.min.js`, licence in `js/vendor/exceljs.LICENSE.txt`). It loads only when you first
export. ATLAS YAML is parsed with [js-yaml](https://github.com/nodeca/js-yaml) 4.3.2 (MIT,
`js/vendor/js-yaml.min.js`, licence in `js/vendor/js-yaml.LICENSE.txt`) on the Data page.

## Run

```bash
cd mitre-threat-sim-plus
python3 -m http.server 8000
```

Open http://localhost:8000 and press **Pull**. Opening `index.html` directly from disk also works,
but serving it keeps the database on one origin for every page you add later.

## How it works

- **Checking for updates:** reads MITRE's release lists every time the page loads, and again when you
  press **Check for updates**, and compares the latest version of each domain with what's stored:
  - ATT&CK: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json`.
  - ATLAS: `https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml`. Every
    ATLAS release since 2021.05 is listed in format v6, which is what ThreatSim reads.

  If one list can't be reached, the other still works.
- **Pull:** downloads each selected domain that's out of date: the STIX 2.1 bundle for ATT&CK, the
  release's YAML file (`dist/v6/ATLAS-<release>.yaml`) for ATLAS. It checks that the file's version is
  the one requested, normalizes it, then replaces that domain's data in a single IndexedDB transaction.
  If a pull fails, the data already stored is left as it was.
- The **Pull** dropdown on each card can pin an older release. The **Re-pull** checkbox downloads
  again even when the stored data is current. ATLAS added entities and software in release 2026.10;
  older ATLAS releases have case studies only. ATLAS releases before 2026.05 don't link sub-techniques
  to their parents or tactics, so ThreatSim takes the parent from the ID (`AML.T0043.000` →
  `AML.T0043`) and its tactics, as later releases state explicitly.

## Database (`mitre-attack-db`, IndexedDB)

| Store | Key | Contents |
|---|---|---|
| `meta` | domain | stored version, release date, source URL, pulled-at, counts |
| `objects` | `<domain>\|<id>` | slim normalized records: `kind`, `attackId`, `name`, `description`, `platforms`, `tactics`, `parent` (sub-techniques), `aliases`, `analyticRefs`, `logSources`, `active` … |
| `relationships` | `<domain>\|<id>` | `relType` (uses, mitigates, detects, attributed-to, subtechnique-of, targets, revoked-by), `source`, `target`, endpoint kinds, `active` |
| `raw` | `<domain>\|<id>` | original object: `{stix}` for ATT&CK (citations, external references), `{atlas}` for ATLAS |
| `history` | auto | log of pulls |

`active` is false for revoked or deprecated objects, and for relationships that touch one.

ATLAS (domain `atlas`) is stored in the same records, keyed by ATLAS ID (`atlas|AML.T0051`):

| ATLAS | `kind` | Extra fields |
|---|---|---|
| Tactic | `tactic` | `shortname` (lower-cased name, as in ATLAS's own STIX) |
| Technique, sub-technique | `technique` | `tactics`, `parent`, `isSubtechnique`, `maturity`, `platforms` |
| Mitigation | `mitigation` | `categories`, `lifecyclePhases` |
| Case study | `case-study` | `caseType` (Incident / Exercise), `actor`, `target`, `reporter`, `firstSeen` / `lastSeen` |
| Entity | `entity` | `entityType`, `aliases` (associated entities) |
| Software | `software` | `softwareType` (tool / malware), `softwareCategories`, `aliases` |

Every ATLAS record also keeps `references` and, where ATLAS gives one, `attackRef` (the matching ATT&CK
object). ATLAS relationships keep their own type in `atlasType` and map to the `relType` the simulator
walks: `employs` (case study → technique), `implements` (software → technique) and `uses` become `uses`;
`specializes` becomes `subtechnique-of`; `mitigates` and `attributed-to` keep their names. `reported-by` is
reporting provenance, never attribution, so the simulator doesn't follow it. Case-study steps keep their
`tactic`, `stepId` and `leadsTo`.

Mapping paths the simulator will use:

```
Group / Software / Campaign --uses--> Technique
Campaign --attributed-to--> Group,   Group --uses--> Software
Case Study / Entity --uses--> Technique (ATLAS employs) ,   Software --uses--> Technique (ATLAS implements)
Case Study --attributed-to--> Entity,   Case Study / Entity --uses--> Software
Mitigation --mitigates--> Technique
Detection Strategy --detects--> Technique
Detection Strategy .analyticRefs -> Analytic .logSources[].dataComponent -> Data Component
Technique (ICS) --targets--> Asset
```

## API for other pages (`js/attack-db.js`, global `AttackDB`)

`getObjects(domain, kind)`, `getObject(domain, id)`, `getRaw(domain, id)`, `findByAttackId(id, domain?)`,
`relationshipsFrom(domain, id, relType?)`, `relationshipsTo(domain, id, relType?)`,
`relationshipsByType(domain, relType)`, `search(text, {domain, kinds, limit})`, `getAllMeta()`.
