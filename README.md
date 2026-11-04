# ThreatSim · MITRE ATT&CK and ATLAS data instance

A browser-based cyber threat simulator. It keeps a local copy of the MITRE ATT&CK **Enterprise** and
**ICS** datasets (Mobile is available but off by default) and of **MITRE ATLAS**, the knowledge base of
threats to AI systems. It maps ATT&CK Groups, Software and Campaigns, and ATLAS Case Studies, Entities and
Software, to the techniques they use, then to the relevant mitigations and detections. It also maps the
profile's techniques to **NIST SP 800-53 Rev 5** controls and to CVEs in **CISA's Known Exploited
Vulnerabilities** catalog, using the Center for Threat-Informed Defense's (CTID) published mappings.

## Pages

- **Sign in** (`login.html`): the only page anyone can open without signing in.
- **Data** (`index.html`): pull MITRE ATT&CK and ATLAS releases, and CTID's NIST 800-53 and KEV
  mappings, into the local database.
- **Threat Profile** (`simulator.html`): build a threat profile and map it to mitigations and detections.
- **Threat Modelling** (`threatmodel.html`): threat-model an architecture or network diagram with that
  profile, to the CSA Guide to Cyber Threat Modelling, and download the threat register and the
  data-flow diagram with threats.

## Sign-in

ThreatSim runs behind its own small server, `server.py`, which checks the session on every request.
Until you sign in it serves only the sign-in page and the stylesheet and script that page needs. The
Data page, the Threat Profile and Threat Modelling pages and all their scripts are refused: pages redirect to sign-in, anything else
gets 401. Run it as described under [Run](#run). Don't serve the folder with any other web server:
anyone could then download the app's files without signing in. (The pages notice and refuse to start,
and the sign-in page says why, but the files are out.)

- **First sign-in:** username `admin`, password `admin`. Until that password is changed, the server
  warns when it starts and every page shows a banner. **Change password** is in the page header. The
  new password needs at least 8 characters and can't be the current one, the username or `admin`.
  Changing it ends that account's sessions in other browsers, and any Claude job they had running, and
  gives this browser a new session.
- **Sessions** are a random token in an HttpOnly cookie (SameSite=Lax, and Secure over HTTPS), kept in
  the server's memory. A session ends after 12 hours without use, or when you sign out, which also
  takes this browser's other ThreatSim tabs to the sign-in page. It also ends when the password is
  changed elsewhere, or when the server restarts.
- **Failed sign-ins:** five wrong passwords for one username from one address within 15 minutes pause
  signing in to that username from there for 30 seconds. Twenty wrong passwords from one address
  within 15 minutes, for any usernames, pause the whole address. Each further pause doubles, up to 15
  minutes, until an hour passes without a wrong password. Right passwords don't count. Five wrong
  current passwords in **Change password** pause changes to that account in the same way.
- **Passwords** are stored only as PBKDF2-HMAC-SHA-256 hashes (310,000 iterations, random salt) in
  `users.json` (mode 600). By default it lives outside the app folder, in `~/.local/share/threatsim`
  (`$XDG_DATA_HOME/threatsim` if that is set, `%LOCALAPPDATA%\threatsim` on Windows); `--data-dir` puts
  it elsewhere. The server never serves anything but the app's pages, `css/`, `js/` and `examples/`.
- **Forgotten password, or another account:** `python3 server.py --set-password admin` (or a new
  username) asks for a new password. You can run it while the server is running; that account's
  sessions end.

Your browser downloads the MITRE data straight from GitHub and keeps it in its own database
(IndexedDB), as before. The server only serves the app. That data, and the threat profile built on the Threat Profile tab
and posture, belong to the browser and the exact address you open, not to the account. Every account
that signs in from that browser shares them, and they stay after sign-out, so people who share a
computer should use separate browser profiles. `localhost` and `127.0.0.1` count as different
addresses, so keep to one.

## Threat Profile

The **Threat Profile** tab (`simulator.html`; it was called *Simulator* before) builds the threat profile and
maps it to mitigations and detections.

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
   - **800-53** and **KEV:** the NIST SP 800-53 Rev 5 controls that mitigate the profile's techniques,
     and the known exploited CVEs mapped to them (see [Control and vulnerability mappings](#control-and-vulnerability-mappings-ctid)).
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

## Control and vulnerability mappings (CTID)

The Data page pulls two datasets from CTID's
[Mappings Explorer](https://github.com/center-for-threat-informed-defense/mappings-explorer)
(Apache 2.0), in a second group of cards, *Control and vulnerability mappings (CTID)*:

- **NIST SP 800-53 Rev 5:** which security controls mitigate the Enterprise ATT&CK techniques CTID
  mapped (with CTID's comment where it gave one, which is rare, and a list of techniques it judged not
  mappable), and (when available) NIST's description of each control. Techniques added to ATT&CK after
  the release CTID mapped have no controls.
- **CISA Known Exploited Vulnerabilities:** for a selection of the CVEs in CISA's catalog, the ATT&CK
  techniques used to exploit each one and its primary and secondary impacts. CTID has mapped only part of
  the catalog (419 Enterprise and 14 Mobile CVEs, 424 in all, in its 28 Jul 2025 files): a CVE that isn't
  listed hasn't been mapped by CTID, which doesn't mean it isn't exploited.

They take part in the same Pull, version pickers, *Re-pull*, history and *Clear local database* as the
MITRE data, and are stored in a browser database of their own (`threatsim-mappings`). CTID publishes no
index of its files, so the page reads GitHub's file listing (api.github.com allows 60 unauthenticated
calls an hour; the page reuses a listing it read in the last hour, and **Check for updates** reads it
again). If the listing can't be read, the page uses the files known when ThreatSim was written and says
so: newer files may exist.

**Matching to ATT&CK.** CTID mapped these to ATT&CK 16.1 (older versions to older releases); ThreatSim
matches them to the stored ATT&CK release by technique ID. A technique ATT&CK has since revoked is
carried forward to its replacement (for example T1562.001 is now T1685); an ID with no current technique
is listed as not current and left out. Each tab, and the workpaper's summary, list those IDs.

On the Threat Profile tab:

- **800-53** (Enterprise only): how many profile techniques have at least one control, which have none
  and which CTID judged not mappable, then one row per control with its family, the profile techniques
  it mitigates, the coverage gaps it addresses and related ATT&CK mitigations. A profile sub-technique
  also counts for a control CTID mapped to its parent technique, marked *via parent* (ThreatSim's rule,
  not CTID's), unless CTID judged that sub-technique not mappable; a control mapped only to a
  sub-technique never counts for the parent.
- **KEV** (Enterprise and Mobile, exact technique matches only): the CVEs mapped to profile techniques,
  with each technique's role (exploitation technique, primary impact, secondary impact). CTID links CVEs
  to techniques, not to threat groups: a CVE is listed because the profile uses one of its techniques,
  not because the selected threats are known to exploit it, nor because it is in your systems. CVEs whose
  exploitation technique is in the profile come first, and **Only CVEs exploited through a profile
  technique** hides the rest. Mobile CVEs need Mobile ATT&CK pulled and switched on.
- **Related ATT&CK mitigations** are ThreatSim's own link, not part of CTID's mapping: the profile's
  ATT&CK mitigations that address the same techniques as a control or CVE.
- Drawers: a control shows NIST's description, the profile techniques it mitigates with CTID's notes and
  the related mitigations; a CVE shows its techniques by role, references, and links to the NVD and the
  CISA catalog; technique details list their controls and CVEs, and mitigation details list the controls
  for the same techniques.
- ICS ATT&CK and ATLAS have no such mappings, and their results say so.

NIST SP 800-53 is a NIST publication; the KEV catalog is CISA's.

## Excel workpaper

**Export workpaper**, in the toolbar beside the threat profile on the Threat Profile tab, writes the current
profile and posture to an `.xlsx` workbook:

| Sheet | Contents |
|---|---|
| Executive Summary | Overall readiness with the **readiness bar**, readiness per domain, controls in place, how many statuses have changed since export, the top 10 recommended mitigations and detection strategies per domain, coverage by tactic, the profile at a glance, the threat profile, and scope and method notes |
| Matrix (Enterprise) / Matrix (ICS) / Matrix (ATLAS) | Matrix of the profile in that domain's tactic order, shaded by how many selected threats use each technique, with a live coverage column (✓ mitigated + detected, M mitigated only, D detected only, ✕ no coverage) |
| Techniques | Every profile technique: tactics, platforms, who uses it, its mitigations and detection strategies, its NIST 800-53 controls (#), live coverage, procedure examples, and CTID's note where it judged a technique not mappable to 800-53 |
| Mitigations | **Implementation status** drop-down (*In Place* / *Not In Place*), owner, target date and notes; status at export and a live *Changed* flag; priority, adds, weighted score and cumulative coverage at export; live count of unmitigated techniques it addresses |
| Detections | **Deployment status** drop-down (*Deployed* / *Not Deployed*), the same tracking and priority columns, analytics, data components and log sources |
| ICS Assets | Assets targeted by the profile's ICS techniques, with live counts of exposed and fully covered techniques |
| Telemetry | Data components and log sources the detection strategies rely on, with a live count of deployed strategies using each |
| Analytics | One row per analytic log source: what to collect and what to look for, with the strategy's live deployment status |
| Control Map | Each technique-to-control link, with the control's live status and how the mitigation applies |
| NIST 800-53 | One row per NIST SP 800-53 Rev 5 control that CTID maps to a profile technique or to its parent technique (ThreatSim's roll-up, marked *via*): the techniques it mitigates (and how many through a parent technique), live counts of the gaps it addresses and of the techniques not fully covered, related ATT&CK mitigations and how many are in place (live), and CTID's comment where it gave one (rare) |
| Known Exploited CVEs | One row per CVE, role and profile technique: the CVE (linked to the NVD), the vulnerability and its type, the technique's role, the technique's live coverage, CTID's note and references |

The drop-downs start at the posture you set in ThreatSim. Everything that depends on them is a formula:
technique coverage, the readiness figures and bars, the matrix status column and the columns marked
*(live)*. Changing a status recalculates the workbook; no macros are involved. Columns marked
*(at export)*, including priorities, keep their values from export time; to re-rank, set the same
statuses in ThreatSim and export again. Controls with equal priority scores share a priority number and
are listed by reach, documented procedure examples, then ID.

The NIST 800-53 and Known Exploited CVEs sheets inform but don't change readiness; the summary's
*Mappings (CTID)* row names the datasets and versions, and lists technique IDs carried forward or not
current. *Profile at a glance* counts the controls and CVEs and the profile techniques with no 800-53
control. When a mapping is used, the summary also carries source and licence rows for CTID's Mappings
Explorer (Apache 2.0), NIST SP 800-53 and CISA's KEV catalog. Each sheet is always present and says why
when it has no rows (not pulled, no Enterprise or Mobile techniques, nothing mapped).

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

## Threat Modelling

The **Threat Modelling** tab carries out cyber threat modelling to the *Guide to Cyber Threat Modelling*
of the Cyber Security Agency of Singapore (CSA), Section 3, over an architecture or network diagram. It
uses the threat profile built on the Threat Profile tab as the Sectorial Threat Profile, and produces the two
deliverables a CSA threat model is judged on. It is a port of the `cyber-threat-modelling` skill's
method (STRIDE-LM gates, severity scoring, ATT&CK attack modelling), driven by ThreatSim's own MITRE data.

1. **Threat profile.** The groups, software and campaigns (ATT&CK) and case studies, entities and
   software (ATLAS) picked on the Threat Profile tab. With no profile, a generic external attacker is assumed.
   The Threat Profile tab's platform filter and knowledge-base switches don't apply here: techniques are matched
   to each element's own platforms, and the profile card says so.
2. **Architecture diagram.** Choose a file or drop it on the page:

   | File | How it is read |
   |---|---|
   | draw.io: `.drawio` or `.xml` (compressed or not), or a draw.io `.png` / `.svg` export, which carries the diagram | Shapes are elements (CSA Figure 3: rectangle = external entity, ellipse = process, double ellipse = cluster of processes, cylinder = data store; for icons and plain boxes the style and the label decide), connectors are data flows, large dashed containers are trust zones. An element's draw.io properties (*Edit Data*) `purpose`, `sensitivity`, `auth`, `trust`, `crown_jewel`, `ai` and `type` are read as its context. A word with a connector attached is an element too, unless it reads as a note (a number, a sentence, 'Note:'); a connector that ends on another connector joins its flow, and one dropped on a zone's title ends on the zone. In a file with several pages, the page with the most data flows is read and the page says which; copy another page into a file of its own to model it. A page that is only a pasted picture is read as a picture. |
   | PowerPoint `.pptx` | The first visible slide drawn with shapes and connectors (a hidden slide only when no visible one has a diagram), read the same way: any shape, freeform or text box with a connector attached is an element, except callouts, block arrows and numbered markers; two concentric circles are a cluster; text next to a connector, in a text box or a shape with no fill or outline, is its label. A slide that is only a picture is read as a picture. |
   | Picture: `.png`, `.jpg`, `.gif`, `.webp` | A picture has no shapes to read. Decompose it by hand on the page, or have Claude read it when the server allows (see below). |
   | `.json` | A decomposition saved from this page. |

   **Load the example** opens `examples/sovereign-ai-architecture.drawio`: the Sovereign AI reference
   architecture (a single picture in its source deck) re-modelled as a CSA data-flow diagram, with each
   element's context filled in. Visio files: open them in draw.io and export as XML.
3. **System decomposition** (CSA §3.2). Check the elements, data flows and trust zones that were read,
   and edit them. Fill in each element's context: what it does, the data it holds, how it authenticates,
   how far it is trusted. This drives the threats and their severity more than anything else. Elements
   are crown jewels and AI elements when their context says so, unless you set them. **Load component
   context** takes a JSON object keyed by element name or id, as the skill's `component_context.json`;
   its values replace what the elements had, and the page says how many it filled in and whose it
   replaced. The decomposition stays in this browser between visits, for the signed-in user only
   (pictures don't), and tabs open on the page share it; **Save the decomposition** downloads it.
   Replacing or clearing it asks first. The last ten removals, and a loaded context file, can be undone,
   latest first, with **Undo** at the foot of the editor or Ctrl+Z (⌘Z on a Mac) outside a text field.
4. **Threat model** (CSA §3.3), built in the browser in well under a second:
   - **Sectorial Threat Profile.** The profile's ATT&CK techniques are grouped into themes (edge
     exploitation, network-device compromise, virtualisation, credential abuse, cloud, implants,
     anti-forensics, host compromise, lateral movement, data theft, disruption, supply chain, covert
     C2). Each theme the profile uses is an item, STP-1, STP-2…, with MITRE's procedure examples as
     its evidence. Crown-jewel theft is added, marked *extrapolated*, when the profile records none.
   - **STRIDE-LM walk.** Every element is walked against all seven categories through the skill's two
     gates: the structural one (STRIDE-per-element: an external entity can only be spoofed or fail to
     be held to account; a data store can't be spoofed or elevate privilege) and the contextual one
     (its context, its place in the flow graph, the lens). A threat event is raised where a profile
     theme bears on the element: at most one per category, two to five per element (more for exposed
     crown jewels). Every other applicable cell is listed as an omission for the analyst to review.
   - **ATT&CK.** Each event cites the profile's own techniques first (◆), suited to the element (network
     devices, ESXi, containers, cloud…), then generic STRIDE-LM ones. Mitigations (M-IDs) and detection
     strategies with their data sources come from the same local MITRE data, so every ID is one MITRE
     publishes.
   - **Severity** is the skill's score: what the category costs if it lands, what is at stake (crown
     jewel +3, sensitive data +1), exposure, and the profile agreeing. High from 6, Medium from 4. It
     is a triage aid, not a risk rating.
   - **Attack sequences** (the CSA Table of Attack) follow the data-flow graph, in either direction,
     from the elements an attacker can reach (the DMZ, Internet-facing systems, supplier links) through
     threat-event locations to the crown jewels; every crown jewel with such a route ends one, up to
     seven. A sequence, step or threat event whose technique MITRE doesn't record for the profile's
     actors is marked *extrapolated*, and so is a row raised with generic techniques where a profile
     theme bears on an element but none of the actor's techniques fits it.
   - **AI elements** (models, training, inference, feature and vector stores, agents, MLOps) also get the
     AI pass: MAESTRO layers L1–L7 and AI threat events with MITRE ATLAS techniques, mitigations and case
     studies, numbered after the ATT&CK locations, with AI attack sequences. It needs ATLAS pulled on the
     Data page.
5. **Deliverables**, both from the same run, so they can't disagree:
   - **Threat register**, `Cyber_Threat_Modelling_Register.xlsx`: *Threat Register* (one row per threat
     event: S/n coloured by severity, threat (STP), techniques, STRIDE-LM category, threat actor,
     sequence of attack, threat event, component with its DFD number and zone, mitigations, detections;
     the AI rows after a separator), *Table of Attack (CSA)*, *AI Table of Attack (MAESTRO)*, *STRIDE-LM
     Coverage*, *Threat Profile*, *AI Threat Profile (MAESTRO)*, *MAESTRO Coverage* and *About*
     (method, scope, verification, how to read severity, assumptions and limits, sources). No merged
     cells, so it filters and sorts.
   - **Data-flow diagram with threats**, `Dataflow_Diagram_with_Threats.pptx`, in the CSA design: external
     entities as rectangles, processes as circles, clusters as double circles, data stores as cylinders,
     data flows as arrows with their labels, trust boundaries as red dashed lines, crown jewels with a
     yellow star, and each threat-event location as a red octagon with its DFD number. Figure 1 is the
     whole DFD; then one slide per attack sequence, with the path highlighted and the rest faded; then
     the AI threats and the AI attack sequences. When the diagram had positions (draw.io, PowerPoint, or
     a picture read by Claude), the DFD keeps its layout; otherwise it is laid out in rows of zones.

   The workbook is built with ExcelJS (above) and the deck with
   [PptxGenJS](https://github.com/gitbrent/PptxGenJS) 4.0.1 (MIT, `js/vendor/pptxgen.bundle.js`, which
   includes JSZip; licences in `js/vendor/pptxgen.LICENSE.txt`). Both load only when first needed.

   The last run's results, Claude's text included, are kept in this browser for the signed-in user
   (IndexedDB) and come back on the next visit, marked out of date if the decomposition, the profile or
   the MITRE data has changed since. Replacing or clearing the decomposition drops them.

The register and diagram are a rigorous first pass for an analyst, not a finished assessment: scope
(CSA §3.1), existing controls and full attack scenarios remain the analyst's.

### Claude (optional)

If the server's operator sets `ANTHROPIC_API_KEY` and installs the Anthropic Python SDK
(`pip install -U "anthropic>=0.108"`, Python 3.10 or later), the tab can also:

- **Read the picture with Claude:** read a picture of a diagram into a decomposition, with positions
  taken from the picture, for you to check.
- **Have Claude write the threat events in more detail:** rewrite each event's title, sequence of
  attack and description, and each attack sequence's narrative, for this system and this threat actor.

Technique IDs, mitigations, detections and severities never come from Claude. A rewritten field is
dropped, and the engine's own text kept, if it names an ATT&CK or ATLAS ID (technique, mitigation, group,
software, campaign, case study) or a CVE that its event doesn't carry, or holds a link or an e-mail
address.

The detail box starts unticked; the browser remembers each user's own choice. Events and attack
sequences Claude rewrote are marked *by Claude*, or *partly by Claude* where some of its text was refused,
and the register's *About* sheet lists the rows holding Claude's text: review its wording before relying
on it. An answer that isn't the shape asked for (a field of the wrong kind, a coordinate out of range)
isn't used, and the page says so.

**What is sent:** only when a signed-in user presses **Read the picture with Claude**, or runs the
threat model with the detail box ticked: the picture, or the decomposition (element names and context)
and the draft register text, go to Anthropic's API. Diagram text is sent as data, not instructions, and
only answers for the events that were sent are kept. Characters a reader can't see (zero-width and bidi
controls, tag characters, variation selectors) are left out of what is sent, and the log says how many.
A picture is redrawn before it is sent (PNG, or JPEG if large; at most 2576 px on the long edge and 3.75
megapixels), so the file's own metadata isn't sent. Without the key or the SDK nothing is sent anywhere
and the controls don't appear; an SDK that fails to load, or is older than 0.108, leaves Claude off,
and the server says why when it starts.

The server uses `claude-opus-5-5` (set `THREATSIM_CLAUDE_MODEL` for another), with adaptive thinking and
structured JSON output, and opts into Anthropic's server-side fallback, so a request a safety classifier
declines is retried on the model Anthropic recommends for it (`THREATSIM_CLAUDE_FALLBACK=off` stops this,
for an account or API gateway that refuses it; the start-up line says whether it is on). Calls run as
background jobs that the page checks every few seconds, so a proxy's read timeout doesn't cut them off:
one at a time per user (a second request waits for the first and offers to cancel it), three started at
a time per server (at most 8 more may be uploading), and at most 100 started per user in 24 hours (set
`THREATSIM_CLAUDE_JOBS_PER_DAY`; `0` for no limit). A picture may take as long as it needs to upload on
a slow line while it keeps coming: after 15 seconds it must average 8 KB/s, and 30 seconds without data
ends it. While a job runs the page shows its progress and a **Cancel** button. A job stops after 15
minutes and keeps what it has done. Leaving the page (closing it, reloading, or going to another tab of
the app) stops it too, and so does signing out, or a password change that ends the session that started
it; coming back in the same browser tab, the page picks up what the job did and says what stopped it. A
result waits on the server for 15 minutes, or until the page has used it. One enrichment holds at most
400 threat events and 50 attack sequences: the page sends the first ones and the rest keep the engine's
text. Each call costs money on the operator's Anthropic account; the server logs one line per job with
how many requests were sent, answered or broken off and the tokens Anthropic reported. With systemd, put the key in an environment file that
only root can read (`EnvironmentFile=/etc/threatsim/claude.env` holding `ANTHROPIC_API_KEY=…`). Behind
nginx, raise `client_max_body_size` (see [Hosting](#hosting)) or larger pictures are refused.

## Run

```bash
cd mitre-threat-sim-pro
python3 server.py
```

Open http://localhost:8000, sign in (`admin` / `admin` the first time) and change the password. Then
press **Pull** on the Data page. Needs Python 3.8 or later; nothing to install. (Only the Threat
Modelling tab's optional Claude features need more: see [Claude (optional)](#claude-optional).)

Options:

| Option | Default | |
|---|---|---|
| `--host` | `127.0.0.1` | address to listen on; `0.0.0.0` for every interface |
| `--port` | `8000` | |
| `--data-dir` | `~/.local/share/threatsim` | where `users.json` (the accounts) is kept; keep it outside the app folder |
| `--cert`, `--key` | | serve HTTPS with this certificate and private key (PEM) |
| `--behind-proxy` | off | take the visitor's address and the scheme from a reverse proxy on the same machine |
| `--set-password USER` | | set USER's password (creating the account if new), then exit |

The server is a single process using only the Python standard library. It keeps sessions in memory,
so restarting it signs everyone out.

## Hosting

These steps put ThreatSim on a Linux server at `https://threatsim.example.com`. systemd runs it, and
nginx sits in front of it to handle HTTPS. Use your own names and paths. Any system with Python 3.8
or later can run `server.py`; only the service and proxy set-up differ.

1. **Install the code, and an account for the service to run as.** The accounts file goes in
   `/var/lib/threatsim`, away from the code, so updating the code never touches it.

   ```bash
   sudo git clone https://github.com/kaligraeme/mitre-threat-sim-pro.git /opt/threatsim
   ```

   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin threatsim
   ```

   ```bash
   sudo install -d -o threatsim -g threatsim -m 700 /var/lib/threatsim
   ```

2. **Set the admin password before the server can be reached**, so `admin` / `admin` never works on
   the network. Check that it ends with `Saved in /var/lib/threatsim/users.json`. Add other accounts
   the same way, for example `--set-password alice`.

   ```bash
   sudo -u threatsim python3 /opt/threatsim/server.py --data-dir /var/lib/threatsim --set-password admin
   ```

3. **Run it as a service.** Create `/etc/systemd/system/threatsim.service`:

   ```ini
   [Unit]
   Description=ThreatSim
   After=network.target

   [Service]
   User=threatsim
   ExecStart=/usr/bin/python3 /opt/threatsim/server.py --host 127.0.0.1 --port 8000 --data-dir /var/lib/threatsim --behind-proxy
   Restart=on-failure
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   PrivateTmp=true
   ReadWritePaths=/var/lib/threatsim

   [Install]
   WantedBy=multi-user.target
   ```

   Then start it, now and at every boot:

   ```bash
   sudo systemctl daemon-reload
   ```

   ```bash
   sudo systemctl enable --now threatsim
   ```

   `sudo journalctl -u threatsim` shows its start-up messages and a line for each request.
   `ProtectHome=true` hides `/home` and `/root` from the service, so keep the code and the data
   directory elsewhere, as here.

4. **Put nginx in front for HTTPS.** Get a certificate for the name with certbot's nginx plugin, which
   also renews it through nginx (`sudo certbot certonly --nginx -d threatsim.example.com`). Then add a
   site like this and reload nginx (`sudo nginx -t && sudo systemctl reload nginx`):

   ```nginx
   server {
       listen 443 ssl;
       server_name threatsim.example.com;
       ssl_certificate     /etc/letsencrypt/live/threatsim.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/threatsim.example.com/privkey.pem;

       client_max_body_size 10m;   # pictures sent to Claude from the Threat Modelling tab

       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $http_host;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }

   server {
       listen 80;
       server_name threatsim.example.com;
       return 301 https://$host$request_uri;
   }
   ```

   The proxy must pass on the Host header that the browser sent, port included. The server refuses
   any sign-in whose origin doesn't match it. The redirect block assumes HTTPS on port 443. The server
   adds a Strict-Transport-Security header to its HTTPS answers itself.

   With Apache, enable the modules (`sudo a2enmod proxy proxy_http headers ssl`), then put
   `ProxyPreserveHost On`, `ProxyPass / http://127.0.0.1:8000/` and
   `RequestHeader set X-Forwarded-Proto "https"` in the `*:443` virtual host that holds the SSL
   settings. With Caddy, `reverse_proxy 127.0.0.1:8000` is enough.

5. **Open the firewall for the web ports**, 443, and 80 for the redirect and certbot, and keep your way
   in, such as SSH, open. With ufw:

   ```bash
   sudo ufw allow OpenSSH
   ```

   ```bash
   sudo ufw allow 80,443/tcp
   ```

   ```bash
   sudo ufw enable
   ```

   The service listens on 127.0.0.1, so port 8000 can't be reached from outside anyway.

6. **Sign in** at `https://threatsim.example.com` with the password from step 2, then pull the data on
   the Data page. Each person's browser downloads the MITRE data and CTID's mappings itself, from
   `raw.githubusercontent.com`, so their network must allow that. It also reads CTID's file listing from
   `api.github.com`; without it the page falls back to the files known when ThreatSim was written and
   says newer files may exist.

**Without a reverse proxy**, ThreatSim can serve HTTPS itself. certbot keeps its keys readable only by
root, so have it copy them where the service can read them, at issue and at every renewal:

```bash
sudo certbot certonly --standalone -d threatsim.example.com --deploy-hook 'install -D -m 640 -g threatsim -t /etc/threatsim "$RENEWED_LINEAGE"/fullchain.pem "$RENEWED_LINEAGE"/privkey.pem && systemctl restart threatsim'
```

certbot's standalone mode answers on port 80 itself, so keep port 80 open and free of other servers, at
issue and at every renewal. In the service, use this `ExecStart` and add
`AmbientCapabilities=CAP_NET_BIND_SERVICE` so it can use port 443:

```ini
ExecStart=/usr/bin/python3 /opt/threatsim/server.py --host 0.0.0.0 --port 443 --data-dir /var/lib/threatsim --cert /etc/threatsim/fullchain.pem --key /etc/threatsim/privkey.pem
```

The hook restarts the service after each renewal, because the server reads the certificate only when it
starts. Prefer the reverse proxy for anything facing the internet: it shields the server from slow or
flooding clients. The server's own defence is a cap of 128 open connections.

**Looking after it:**

- **Updating:** `sudo git -C /opt/threatsim pull`, then `sudo systemctl restart threatsim`. Restarting
  signs everyone out.
- **Back up** `/var/lib/threatsim/users.json`, which holds the accounts.
- **Run commands as the service account** (`sudo -u threatsim ...`), as in step 2. If you run
  `--set-password` as root, it keeps the file owned by the account that owns the data directory.
- **Forgotten password:** run the step 2 command again. It works while the service is running and ends
  that account's sessions.
- **Don't serve the folder any other way.** Don't point a web server's document root (nginx `root`,
  Apache `DocumentRoot`) or a static file host at it. Anyone could then download the app's files
  without signing in.

## How it works

- **Checking for updates:** reads MITRE's release lists every time the page loads, and again when you
  press **Check for updates**, and compares the latest version of each domain with what's stored:
  - ATT&CK: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json`.
  - ATLAS: `https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml`. Every
    ATLAS release since 2021.05 is listed in format v6, which is what ThreatSim reads.

  - CTID's mappings: GitHub's file listing of the Mappings Explorer repository
    (`https://api.github.com/repos/center-for-threat-informed-defense/mappings-explorer/git/trees/main?recursive=1`),
    reused for an hour, with a built-in list of known files as the fallback.

  If one list can't be reached, the others still work.
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
object). ATLAS relationships keep their own type in `atlasType` and map to the `relType` the Threat Profile tab
walks: `employs` (case study → technique), `implements` (software → technique) and `uses` become `uses`;
`specializes` becomes `subtechnique-of`; `mitigates` and `attributed-to` keep their names. `reported-by` is
reporting provenance, never attribution, so the Threat Profile tab doesn't follow it. Case-study steps keep their
`tactic`, `stepId` and `leadsTo`.

Mapping paths the Threat Profile tab follows:

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

### CTID mappings (`threatsim-mappings`, IndexedDB; `js/mappings-db.js`, global `MappingsDB`)

| Store | Key | Contents |
|---|---|---|
| `meta` | source (`nist-800-53-r5`, `kev`) | stored version, ATT&CK version it maps to, files with their URLs, pulled-at, counts |
| `rows` | `<source>\|<domain>\|<n>` | one CTID mapping: `capabilityId` (NIST form, `AC-2`; or the CVE), name, group (control family or vulnerability type), `mappingType`, `techniqueId` and name as CTID wrote them, `comments`, `references`, `status` |
| `details` | `<source>\|<id>` | NIST control descriptions, as plain text |
| `history` | auto | log of mapping pulls (shown with the MITRE pulls on the Data page) |

Technique IDs stay as CTID wrote them (ATT&CK 16.1); the Threat Profile tab matches them to the stored ATT&CK
release when it loads, following `revoked-by` relationships to replacements.

## API for other pages (`js/attack-db.js`, global `AttackDB`)

`getObjects(domain, kind)`, `getObject(domain, id)`, `getRaw(domain, id)`, `findByAttackId(id, domain?)`,
`relationshipsFrom(domain, id, relType?)`, `relationshipsTo(domain, id, relType?)`,
`relationshipsByType(domain, relType)`, `search(text, {domain, kinds, limit})`, `getAllMeta()`.

A new page must load `js/auth.js` in its `<head>`, like `index.html` and `simulator.html`. The server only
serves files it knows, so also add the page to `ROOT_FILES` in `server.py`. To let sign-in return to it,
add it to `PAGES` in `server.py`, `js/auth.js` and `js/login.js`. Files outside `css/` and `js/` need
their folder added to `SERVED_DIRS`, and a file type not listed in `TYPES` needs adding there.
