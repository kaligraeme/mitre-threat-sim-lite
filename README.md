# ThreatSim · MITRE ATT&CK and ATLAS data instance

This is the lite edition of ThreatSim: it has no Threat Modelling tab and no CISA KEV mappings.

A browser-based cyber threat simulator. It keeps a local copy of the MITRE ATT&CK **Enterprise** and
**ICS** datasets (Mobile is available but off by default) and of **MITRE ATLAS**, the knowledge base of
threats to AI systems. It maps ATT&CK Groups, Software and Campaigns, and ATLAS Case Studies, Entities and
Software, to the techniques they use, then to the relevant mitigations and detections. It also maps the
profile's techniques to **NIST SP 800-53 Rev 5** controls, using the Center for Threat-Informed Defense's
(CTID) published mappings.

## Pages

- **Sign in** (`login.html`): the only page anyone can open without signing in.
- **Data** (`index.html`): pull MITRE ATT&CK and ATLAS releases, and CTID's NIST 800-53 mappings, into
  the local database.
- **Threat Profile** (`simulator.html`): build a threat profile and map it to mitigations and detections.

## Sign-in

ThreatSim runs behind its own small server, `server.py`, which checks the session on every request.
Until you sign in it serves only the sign-in page and the stylesheet and script that page needs. The
Data and Threat Profile pages and all their scripts are refused: pages redirect to sign-in, anything else
gets 401. Run it as described under [Run](#run). Don't serve the folder with any other web server:
anyone could then download the app's files without signing in. (The pages notice and refuse to start,
and the sign-in page says why, but the files are out.)

- **First sign-in:** username `admin`, password `admin`. Until that password is changed, the server
  warns when it starts and every page shows a banner. **Change password** is in the page header. The
  new password needs at least 8 characters and can't be the current one, the username or `admin`.
  Changing it ends that account's sessions in other browsers and gives this browser a new session.
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
  it elsewhere. The server never serves anything but the app's pages, `css/` and `js/`.
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
   - **800-53:** the NIST SP 800-53 Rev 5 controls that mitigate the profile's techniques (see
     [Control mappings](#control-mappings-ctid)).
   - Click any row or matrix cell for details: procedure examples, mitigation guidance, and analytics
     with their log sources. ATLAS details add technique maturity, mitigation categories and AI
     lifecycle phases, attribution with its activity purpose, the matching ATT&CK object where ATLAS
     names one, and sources.
4. **Export:** an Excel workpaper (below), a CSV of the technique mapping, or Navigator layers (one
   JSON per domain; the ATLAS layer opens in the ATLAS Navigator).

**Coverage at a glance.** Above the result tabs, four tiles count the profile's techniques, mitigations,
detection strategies and data components. A fifth gives the number of techniques with no mitigation or
detection in place, with a spider chart of **average coverage by tactic**: one axis per tactic the profile's
techniques fall under, in matrix order, and three rings as levels:

- **1** no coverage (red);
- **2** partial: mitigated or detected only (amber);
- **3** mitigated + detected (green).

A tactic's point sits at the average level of its techniques (a technique under several tactics counts in
each), so it moves outward as you mark mitigations in place and detections deployed; its dot takes the
colour of the highest level that average reaches. Averages are rounded down to one decimal, so 3.0 means
every technique of the tactic is mitigated and detected. There is one chart per domain, with a switch when
the profile spans several; it opens on the domain you last picked with that switch (remembered from one
profile to the next), otherwise on Enterprise unless Enterprise has nothing to chart. ATLAS has no
detection strategies, so ATLAS tactics top out at 2. With fewer than three tactics, or too many to label
around a spider on a narrow screen, each tactic's average is shown as a dot on a line from 1 to 3 instead.
Hover or tap an axis, or focus the chart and use the arrow keys, to see a tactic's numbers (Escape closes
them); **Show as table** lists them all, under the KPI tiles (on a narrow screen such as a phone's, under
the chart), and **How to read this chart** explains the scale.

ATLAS has no detection strategies: its detection controls (for example *AML.M0024 AI Telemetry Logging
and Monitoring*) are ATLAS mitigations, so ATLAS techniques count as mitigated or not, never as detected.
The Detections and Telemetry views say so instead of showing empty tables.

Priority uses a weighted greedy method: each step picks the control that covers the most uncovered
techniques, with a technique counting once per selected threat that uses it. Controls with equal
scores share a priority number and are ordered by reach, documented procedure examples, then ID,
so the result doesn't depend on the order you picked threats in. Your selections and
posture are saved in the browser's localStorage.

## Control mappings (CTID)

The Data page pulls one dataset from CTID's
[Mappings Explorer](https://github.com/center-for-threat-informed-defense/mappings-explorer)
(Apache 2.0), in a second group of cards, *Control mappings (CTID)*:

- **NIST SP 800-53 Rev 5:** which security controls mitigate the Enterprise ATT&CK techniques CTID
  mapped (with CTID's comment where it gave one, which is rare, and a list of techniques it judged not
  mappable), and (when available) NIST's description of each control. Techniques added to ATT&CK after
  the release CTID mapped have no controls.

It takes part in the same Pull, version picker, *Re-pull*, history and *Clear local database* as the
MITRE data, and is stored in a browser database of its own (`threatsim-mappings`). CTID publishes no
index of its files, so the page reads GitHub's file listing (api.github.com allows 60 unauthenticated
calls an hour; the page reuses a listing it read in the last hour, and **Check for updates** reads it
again). If the listing can't be read, the page uses the files known when ThreatSim was written and says
so: newer files may exist. Mappings of a dataset this edition doesn't offer, left in the browser by
another edition of ThreatSim, are ignored, and only *Clear local database* removes them.

**Matching to ATT&CK.** CTID mapped NIST 800-53 to ATT&CK 16.1 (older versions to older releases);
ThreatSim matches it to the stored ATT&CK release by technique ID. A technique ATT&CK has since revoked is
carried forward to its replacement (for example T1562.001 is now T1685); an ID with no current technique
is listed as not current and left out. The 800-53 tab, and the workpaper's summary, list those IDs.

On the Threat Profile tab:

- **800-53** (Enterprise only): how many profile techniques have at least one control, which have none
  and which CTID judged not mappable, then one row per control with its family, the profile techniques
  it mitigates, the coverage gaps it addresses and related ATT&CK mitigations. A profile sub-technique
  also counts for a control CTID mapped to its parent technique, marked *via parent* (ThreatSim's rule,
  not CTID's), unless CTID judged that sub-technique not mappable; a control mapped only to a
  sub-technique never counts for the parent.
- **Related ATT&CK mitigations** are ThreatSim's own link, not part of CTID's mapping: the profile's
  ATT&CK mitigations that address the same techniques as a control.
- Drawers: a control shows NIST's description, the profile techniques it mitigates with CTID's notes and
  the related mitigations; technique details list their controls, and mitigation details list the
  controls for the same techniques.
- Mobile ATT&CK, ICS ATT&CK and ATLAS have no such mappings, and their results say so.

NIST SP 800-53 is a NIST publication.

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

The drop-downs start at the posture you set in ThreatSim. Everything that depends on them is a formula:
technique coverage, the readiness figures and bars, the matrix status column and the columns marked
*(live)*. Changing a status recalculates the workbook; no macros are involved. Columns marked
*(at export)*, including priorities, keep their values from export time; to re-rank, set the same
statuses in ThreatSim and export again. Controls with equal priority scores share a priority number and
are listed by reach, documented procedure examples, then ID.

The NIST 800-53 sheet informs but doesn't change readiness; the summary's *Mappings (CTID)* row names
the dataset and version, and lists technique IDs carried forward or not current. *Profile at a glance*
counts the controls and the profile techniques with no 800-53 control. When the mapping is used, the
summary also carries source and licence rows for CTID's Mappings Explorer (Apache 2.0) and NIST SP 800-53.
The sheet is always present and says why when it has no rows (not pulled, no Enterprise techniques,
nothing mapped).

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
cd mitre-threat-sim-lite
python3 server.py
```

Open http://localhost:8000, sign in (`admin` / `admin` the first time) and change the password. Then
press **Pull** on the Data page. Needs Python 3.8 or later; nothing to install.

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
   sudo git clone https://github.com/kaligraeme/mitre-threat-sim-lite.git /opt/threatsim
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
| `meta` | source (`nist-800-53-r5`) | stored version, ATT&CK version it maps to, files with their URLs, pulled-at, counts |
| `rows` | `<source>\|<domain>\|<n>` | one CTID mapping: `capabilityId` (NIST form, `AC-2`), name, group (control family), `mappingType`, `techniqueId` and name as CTID wrote them, `comments`, `references`, `status` |
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
