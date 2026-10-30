# ThreatSim · MITRE ATT&CK and ATLAS data instance

A browser-based cyber threat simulator. It keeps a local copy of the MITRE ATT&CK **Enterprise** and
**ICS** datasets (Mobile is available but off by default) and of **MITRE ATLAS**, the knowledge base of
threats to AI systems. It maps ATT&CK Groups, Software and Campaigns, and ATLAS Case Studies, Entities and
Software, to the techniques they use, then to the relevant mitigations and detections.

## Pages

- **Sign in** (`login.html`): the only page anyone can open without signing in.
- **Data** (`index.html`): pull MITRE ATT&CK and ATLAS releases into the local database.
- **Simulator** (`simulator.html`): build a threat profile and map it to mitigations and detections.

## Sign-in

ThreatSim runs behind its own small server, `server.py`, which checks the session on every request.
Until you sign in it serves only the sign-in page and the stylesheet and script that page needs. The
Data page, the Simulator and all their scripts are refused: pages redirect to sign-in, anything else
gets 401. Run it as described under [Run](#run). Serving the folder with any other web server would
leave the app open to anyone, so the pages then refuse to start and the sign-in page says why.

- **First sign-in:** username `admin`, password `admin`. Until that password is changed, the server
  warns when it starts and every page shows a banner. **Change password** is in the page header. The
  new password needs at least 8 characters and can't be the current one, the username or `admin`.
  Changing it ends that account's sessions in other browsers.
- **Sessions** are a random token in an HttpOnly cookie (SameSite=Lax, and Secure over HTTPS), kept in
  the server's memory. A session ends after 12 hours without use, or when you sign out, which also
  takes this browser's other ThreatSim tabs to the sign-in page. It also ends when the password is
  changed elsewhere, or when the server restarts.
- **Failed sign-ins:** after five wrong passwords from one address, sign-in from it pauses for 30
  seconds. Each further pause within the hour doubles, up to 15 minutes.
- **Passwords** are stored only as PBKDF2-HMAC-SHA-256 hashes (310,000 iterations, random salt) in
  `.threatsim/users.json` (mode 600). The server never serves that file, `server.py` or anything else
  outside the app's pages, `css/` and `js/`.
- **Forgotten password, or another account:** `python3 server.py --set-password admin` (or a new
  username) asks for a new password. You can run it while the server is running; that account's
  sessions end.

Your browser downloads the MITRE data straight from GitHub and keeps it in its own database
(IndexedDB), as before. The server only serves the app.

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
cd mitre-threat-sim-pro
python3 server.py
```

Open http://localhost:8000, sign in (`admin` / `admin` the first time) and change the password. Then
press **Pull** on the Data page. Needs Python 3.8 or later; nothing to install.

To host it for others:

- **Directly, over HTTPS:** `python3 server.py --host 0.0.0.0 --port 8443 --cert cert.pem --key key.pem`.
  Without `--cert` the server warns you, because plain HTTP on a network sends passwords unencrypted.
- **Behind a reverse proxy** (nginx, Apache, Caddy) that serves HTTPS: keep the default `--host
  127.0.0.1` and add `--behind-proxy`, so the server takes the visitor's address and the scheme from
  the proxy. The proxy must pass on the Host header the browser sent, port included: the server
  refuses sign-ins whose origin doesn't match it. For nginx:

  ```nginx
  location / {
      proxy_pass http://127.0.0.1:8000;
      proxy_set_header Host $http_host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
  }
  ```

Other options: `--port` (default 8000) and `--data-dir` (where `users.json` lives; default `.threatsim`
beside `server.py`). The server is a single process using only the Python standard library.

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
