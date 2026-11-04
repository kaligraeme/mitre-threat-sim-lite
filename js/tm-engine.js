/*
 * tm-engine.js — cyber threat modelling over a decomposed system, to the CSA Guide to Cyber Threat
 * Modelling §3.3 (STRIDE-LM threat identification) with MITRE ATT&CK attack modelling, and a second pass
 * for AI elements with the MAESTRO 7-layer framework and MITRE ATLAS.
 *
 * Global `TMEngine`. A port of the cyber-threat-modelling skill's STRIDE-LM engine (structural and
 * contextual gates, severity scoring, sequences and events), driven by the threat profile built on the Threat Profile tab:
 * the profile's techniques, grouped into themes, become the Sectorial Threat Profile lenses, and each
 * threat event cites the techniques MITRE attributes to the profile (◆) before generic ones. Every
 * technique, mitigation, detection strategy and case study comes from the local MITRE data (AttackDB),
 * so nothing printed is an ID MITRE doesn't publish. No DOM access here.
 *
 * run(model, ctx) -> result (the TMResult in the deliverable writers' contract)
 *   model: from TMParse; ctx: { models: { domain: SimEngine model }, selection, opts, system?,
 *   uncapped? (raise every cell that passes the gates: for comparing with the skill) }
 */
(function (global) {
  'use strict';

  const CATEGORIES = [
    { code: 'S', name: 'Spoofing', property: 'Authenticity' },
    { code: 'T', name: 'Tampering', property: 'Integrity' },
    { code: 'R', name: 'Repudiation', property: 'Non-repudiation' },
    { code: 'I', name: 'Information Disclosure', property: 'Confidentiality' },
    { code: 'D', name: 'Denial of Service', property: 'Availability' },
    { code: 'E', name: 'Elevation of Privilege', property: 'Authorisation' },
    { code: 'LM', name: 'Lateral Movement', property: 'Containment' },
  ];
  const CAT = Object.fromEntries(CATEGORIES.map(c => [c.code, c]));
  const CODES = CATEGORIES.map(c => c.code);

  // STRIDE-per-element (CSA Figure 12): an external entity can only be spoofed or fail to be held to
  // account; a data store can't be spoofed or escalate. This gate overrides every other signal.
  const APPLICABLE = {
    entity: new Set(['S', 'R']),
    process: new Set(CODES),
    cluster: new Set(CODES),
    datastore: new Set(['T', 'R', 'I', 'D', 'LM']),
  };

  // What a category costs if it lands, before the target is considered (skill: _IMPACT).
  const IMPACT = { I: 2, E: 2, D: 2, T: 1, LM: 1, S: 1, R: 0 };

  // Two tiers of sensitive data (skill): crown-jewel data turns a breach into a board-level event.
  const CROWN_WORDS = ['restricted', 'classified', 'pii', 'personal data', 'payment', 'card', 'financial', 'health',
    'medical', 'secret', 'credential', 'private key'];
  const SENSITIVE_WORDS = CROWN_WORDS.concat(['confidential', 'sensitive', 'internal only', 'proprietary']);
  const EXPOSED_WORDS = ['dmz', 'untrusted', 'external', 'public', 'internet', 'perimeter', 'edge'];
  // A zone outside the system (the Internet, a partner's or a supplier's network), and one that is the system's own
  // exposed tier even when it is named for what it faces ('DMZ (Untrusted)', 'Internet Edge', 'External-facing services').
  const OUTSIDE_ZONE = /\b(internet|external|outside|third[- ]part(y|ies)|partners?|vendors?|suppliers?)\b/;
  const SYSTEM_EDGE = /\b(dmz|perimeter|edge|facing|exposed|subnets?)\b/;

  // Generic candidates per category and element type (skill: _CANDIDATES), used when the profile has no
  // technique for a cell an observed theme covers, and for runs without a profile. Validated against the DB.
  const CANDIDATES = {
    // T1684.001 Impersonation (ATT&CK v18+); T1656 for older data
    S: { entity: ['T1566.001', 'T1566.002', 'T1078', 'T1684.001', 'T1656'], process: ['T1078', 'T1550.001', 'T1557', 'T1036'],
      cluster: ['T1078', 'T1557', 'T1036'], datastore: ['T1078', 'T1550.001'] },
    T: { entity: ['T1565.002', 'T1557'], process: ['T1565.001', 'T1505.003', 'T1554', 'T1195.002'],
      cluster: ['T1565.001', 'T1505.003'], datastore: ['T1565.001', 'T1485', 'T1491.001'] },
    R: { entity: ['T1070', 'T1685.005', 'T1562.008'], process: ['T1070', 'T1685.001', 'T1685.005', 'T1562.001', 'T1070.006'],
      cluster: ['T1070', 'T1685.001', 'T1562.001', 'T1070.006'], datastore: ['T1070.004', 'T1070.006', 'T1685.005', 'T1562.008'] },
    I: { entity: ['T1114.001', 'T1056.001'], process: ['T1005', 'T1552.001', 'T1040', 'T1041'],
      cluster: ['T1005', 'T1552.001'], datastore: ['T1005', 'T1213', 'T1530', 'T1119'] },
    D: { entity: ['T1498.001'], process: ['T1499.004', 'T1498.001', 'T1489', 'T1529'],
      cluster: ['T1499.004', 'T1498.001'], datastore: ['T1486', 'T1485', 'T1490'] },
    E: { entity: ['T1078.003'], process: ['T1068', 'T1190', 'T1548.002', 'T1134.001'],
      cluster: ['T1068', 'T1548.002'], datastore: ['T1078.003', 'T1068'] },
    LM: { entity: ['T1534'], process: ['T1021.001', 'T1021.002', 'T1570', 'T1210'],
      cluster: ['T1021.002', 'T1570'], datastore: ['T1021.002', 'T1550.002'] },
  };

  // The same for elements that live in a cloud or SaaS platform, where host techniques don't apply.
  const CLOUD_CANDIDATES = {
    S: ['T1078.004', 'T1550.001', 'T1606.002'], T: ['T1578', 'T1525', 'T1098.001'], R: ['T1685.002', 'T1562.008', 'T1070'],
    I: ['T1530', 'T1537', 'T1213'], D: ['T1485', 'T1496', 'T1490'], E: ['T1078.004', 'T1098.003', 'T1651'],
    LM: ['T1021.007', 'T1550.001'],
  };

  // Which ATT&CK tactics (kill-chain phase short names, Enterprise and ICS) serve each category. ICS v18+
  // shares Enterprise's names and files its evasion techniques under 'evasion'; older data used '-ics' names.
  const CATEGORY_TACTICS = {
    S: ['initial-access', 'credential-access', 'stealth', 'defense-evasion', 'evasion', 'initial-access-ics', 'evasion-ics'],
    T: ['persistence', 'stealth', 'defense-evasion', 'execution', 'persistence-ics', 'impair-process-control', 'execution-ics'],
    R: ['defense-impairment', 'defense-evasion', 'stealth', 'evasion', 'evasion-ics'],
    I: ['collection', 'exfiltration', 'credential-access', 'collection-ics'],
    D: ['impact', 'inhibit-response-function', 'impact-ics'],
    E: ['privilege-escalation', 'execution', 'initial-access', 'privilege-escalation-ics', 'execution-ics'],
    LM: ['lateral-movement', 'lateral-movement-ics'],
  };
  // Techniques that fit a category by what they do, whatever tactic MITRE files them under (Enterprise, then
  // ICS: T08xx and the v18+ T1691-T1695 / T1701 IDs, which only OT elements are offered).
  const CATEGORY_FIT = {
    S: /^T(1078|1550|1557|1036|1566|1598|1656|1684|1606|1556|1110|1539|1528|1621|1111|1134|1199|1553|1534|1585|1586|1564\.008|0849|0848|0856|0859|1692\.002|1694)\b/,
    T: /^T(1565|1505|1554|1195|1542|1601|1037|1543|1547|1574|1053|1098|1136|1546|1525|1612|1610|1578|1072|1014|1112|1222|1484|1556|1205|1647|0831|0832|0836|0806|0855|0821|0889|0835|0838|0858|0873|1692|1693)\b/,
    R: /^T(1070|1562|1685|0872)\b/,
    I: /^T(1005|1039|1213|1119|1560|1074|1114|1530|1041|1048|1567|1020|1029|1030|1537|1040|1552|1555|1003|1602|1056|1125|1113|1123|1185|1115|1212|1558|1539|0801|0802|0811|0830|0845|0852|0861|0868|0877|0882|0887|0893)\b/,
    D: /^T(1486|1485|1490|1489|1529|1499|1498|1561|1491|1565|1496|1657|1531|1495|0813|0814|0815|0816|0826|0827|0829|0837|0880|0881|0809|1691|1695)\b/,
    E: /^T(1068|1190|1548|1134|1611|1078|1055|1203|1059|1133|1212|1210|1574|1484|0890|0874|0819|0822|0866)\b/,
    LM: /^T(1021|1570|1210|1534|1550|1563|1072|1080|1090|1572|1599|0866|0867|0886|0859|1694)\b/,
  };

  // Within a category, the techniques that best express it rank first.
  const PREFER = {
    S: /^T(1078|1556|1550|1606|1557|1199|1566|1684|1036\.00[45]|0849|0848|0856|1692\.002)\b/,
    T: /^T(1554|1601|1542|1505|1565|1037|1525|1195|1014|1543|0831|0832|0836|0806|0855|0821|0889|1692|1693)\b/,
    R: /^T(1070|1685\.00[1-6]|1562\.00[238]|1562\.01[12]|0872)\b/,
    I: /^T(1005|1039|1213|1530|1602|1040|1552|1555|1003|1041|1048|1567|1114|0882|0801|0811|0893)\b/,
    D: /^T(1486|1485|1490|1489|1529|1499|1498|1561|0813|0814|0815|0816|0826|0827|0829|0837|0880|0881|0809)\b/,
    E: /^T(1068|1190|1611|1548|1078|1134|1133|1210|0890|0819)\b/,
    LM: /^T(1021|1570|1210|1550|1563|1599|1534|1072|0866|0867|0886|0859)\b/,
  };
  // What a data store's own Tampering looks like: its data changed, destroyed or encrypted, or the images and
  // software it holds implanted. Host implants, rootkits and boot persistence are threats to a server, not to
  // the data it stores.
  const DATASTORE_TAMPERING = /^T(1565|1485|1491|1486|1561|1525|1195|0809)\b/;
  // ...and for a store of keys, secrets or identities, the accounts, permissions and policies that guard them
  const GUARD_TAMPERING = /^T(1098|1484|1222)\b/;
  const GUARD_CANDIDATES = ['T1098', 'T1484'];
  // A data store's repudiation is about its records: logs, files and timestamps cleared or disabled, not a host's
  // network-connection history, share mappings or persistence.
  const DATASTORE_REPUDIATION = /^T(?:1070(?:\.00[1246])?|1685\.00[12456]|1562\.00[28]|1562\.012|0872)$/;
  // An external entity that is a device or a system (vendor and built-in default accounts are on those, not on the
  // people or partners an entity stands for).
  const DEVICE_WORDS = /\b(devices?|sensors?|iot|ot|systems?|appliances?|equipment|machines?|controllers?|plcs?|terminals?|printers?|cameras?|servers?)\b/;

  /*
   * Threat themes: how a threat profile's techniques group into Sectorial Threat Profile lenses. A theme
   * becomes a lens when the profile uses at least one of its techniques ('Observed'). Each names the STRIDE-LM
   * categories it emphasises, the elements it bears on, the generic techniques it adds per category, and how
   * the attack ends — so an espionage lens and a ransomware lens over the same database read differently.
   */
  const THEMES = [
    { key: 'edge', name: 'Exploitation of internet-facing services and edge devices', short: 'Edge exploitation',
      ids: /^T(1190|1133|1587\.004|1588\.00[56]|1595|1203)\b/, categories: ['E', 'T', 'S'],
      targets: { exposed: true, tags: ['network', 'web'] }, extra: { E: ['T1190', 'T1068'], T: ['T1505.003', 'T1554'] },
      ending: 'a perimeter foothold that every later step builds on' },
    { key: 'phishing', name: 'Phishing and user-targeted intrusion', short: 'Phishing',
      ids: /^T(1566|1598|1204|1189|1534|1656|1684|1585|1586|1608)\b/, categories: ['S'],
      targets: { types: ['entity'], tags: ['people', 'email', 'web'] }, extra: { S: ['T1566.002', 'T1598.003'] },
      ending: 'stolen access used to reach the systems the victim can reach' },
    { key: 'credentials', name: 'Credential theft and abuse of valid accounts', short: 'Credential abuse',
      ids: /^T(1078|1110|1003|1552|1555|1556|1558|1550|1539|1528|1606|1621|1111|1212|1187|1098)\b/, categories: ['S', 'E', 'I'],
      targets: { authExposed: true, tags: ['identity', 'admin', 'secrets', 'people'] }, extra: { S: ['T1078', 'T1550'], E: ['T1078.003'] },
      ending: 'trusted identities in the attacker’s hands, so later activity looks legitimate' },
    { key: 'network', name: 'Network device and network infrastructure compromise', short: 'Network-device compromise',
      ids: /^T(1040|1556\.004|1601|1599|1602|1205|1095|1090|1572|1557|1542\.005|1600|1037)\b/, platforms: ['Network Devices'],
      categories: ['T', 'I', 'LM', 'R'], targets: { tags: ['network'] },
      extra: { T: ['T1601.001', 'T1556.004'], I: ['T1040', 'T1602'], LM: ['T1599', 'T1090'] },
      ending: 'persistent, hard-to-detect control of the network path, with traffic and credentials intercepted' },
    { key: 'virtualisation', name: 'Hypervisor, container and virtualisation compromise', short: 'Virtualisation compromise',
      ids: /^T(1611|1610|1609|1612|1613|1525|1578|1564\.006|1059\.012)\b/, platforms: ['ESXi', 'Containers'],
      categories: ['E', 'T', 'LM', 'I'], targets: { tags: ['virtualisation'] },
      extra: { E: ['T1611', 'T1068'], T: ['T1525', 'T1543'], LM: ['T1021.004', 'T1570'], I: ['T1005', 'T1213'] },
      ending: 'control of the platform underneath every workload, invisible to the guests' },
    { key: 'cloud', name: 'Cloud, SaaS and identity-provider abuse', short: 'Cloud abuse',
      ids: /^T(1078\.004|1530|1537|1580|1538|1651|1098\.00[13]|1136\.003|1606\.002|1199|1648|1666)\b/,
      platforms: ['IaaS', 'SaaS', 'Identity Provider', 'Office Suite'], categories: ['I', 'E', 'S', 'R'],
      targets: { tags: ['cloud', 'identity'] }, extra: { I: ['T1530', 'T1537'], E: ['T1078.004'], S: ['T1550.001'], R: ['T1685.002'] },
      ending: 'cloud-hosted data and control-plane access taken through legitimate cloud interfaces' },
    { key: 'persistence', name: 'Persistent implants on servers and appliances', short: 'Implants',
      ids: /^T(1505|1543|1547|1053|1554|1542|1037|1136|1546|1574|1014|1098)\b/, tactics: ['persistence'],
      categories: ['T', 'E'], targets: { exposed: true, tags: ['network', 'virtualisation', 'web', 'cicd', 'identity'], nonEntity: true },
      extra: { T: ['T1505.003', 'T1554', 'T1543'] },
      ending: 'access that survives reboots, patching and password changes' },
    { key: 'evasion', name: 'Defence evasion and anti-forensics', short: 'Anti-forensics',
      ids: /^T(1070|1562|1685|1036|1027|1014|1564|1620|1218|1112|1222|1497|1480|1600)\b/,
      tactics: ['defense-evasion', 'defense-impairment', 'stealth', 'evasion'], categories: ['R', 'T'],
      targets: { tags: ['logging', 'network', 'virtualisation', 'identity', 'secrets'], exposed: true, nonEntity: true },
      extra: { R: ['T1070', 'T1685.001', 'T1685.005'], T: ['T1562.001'] },
      ending: 'activity that leaves no reliable record, so it cannot be scoped or attributed' },
    { key: 'lateral', name: 'Lateral movement through trusted connections', short: 'Lateral movement',
      ids: /^T(1021|1570|1210|1534|1550|1563|1072|1080)\b/, tactics: ['lateral-movement', 'lateral-movement-ics'],
      categories: ['LM'], targets: { pivot: true }, extra: { LM: ['T1021.004', 'T1570', 'T1021.001'] },
      ending: 'reach extended across trust zones toward the crown jewels' },
    { key: 'collection', name: 'Collection and exfiltration of sensitive data', short: 'Data theft',
      ids: /^T(1005|1039|1213|1119|1560|1074|1114|1530|1041|1048|1567|1020|1029|1030|1537|1602)\b/,
      tactics: ['collection', 'exfiltration', 'collection-ics'], categories: ['I'],
      targets: { sensitive: true, types: ['datastore'] }, extra: { I: ['T1005', 'T1213', 'T1041', 'T1560.001'] },
      ending: 'sensitive data exfiltrated, quietly and over time' },
    { key: 'impact', name: 'Disruption, destruction and extortion', short: 'Disruption',
      ids: /^T(1486|1485|1490|1489|1529|1499|1498|1561|1491|1565|1496|1657|1531|1495)\b/,
      tactics: ['impact', 'inhibit-response-function', 'impair-process-control'], categories: ['D', 'T'],
      targets: { crown: true, dependants: true },
      extra: { D: ['T1486', 'T1490', 'T1489'], T: ['T1565.001'] },
      ending: 'services stopped or data destroyed, with extortion likely to follow' },
    { key: 'execution', name: 'Privilege escalation and code execution on hosts', short: 'Host compromise',
      ids: /^T(1068|1548|1134|1055|1059|1203|1106|1569|1047|1611|1574)\b/, tactics: ['execution', 'privilege-escalation'],
      categories: ['E', 'T'], targets: { exposed: true, tags: ['virtualisation', 'web', 'cicd', 'identity'], nonEntity: true },
      extra: { E: ['T1068', 'T1548'], T: ['T1059'] },
      ending: 'administrative control of the host and everything it runs' },
    { key: 'supply', name: 'Supply-chain and trusted-relationship compromise', short: 'Supply-chain compromise',
      ids: /^T(1195|1199|1072|1554|1553)\b/, categories: ['T', 'S', 'E'],
      targets: { tags: ['thirdparty', 'cicd'] }, extra: { T: ['T1195.002', 'T1554'], S: ['T1199', 'T1553.002'], E: ['T1072'] },
      ending: 'trusted code or access abused to reach whatever the supplier could reach' },
    { key: 'c2', name: 'Covert command and control', short: 'Covert C2',
      ids: /^T(1071|1573|1105|1102|1219|1001|1008|1568|1132|1104|1665)\b/, tactics: ['command-and-control', 'command-and-control-ics'],
      categories: ['I', 'LM'], targets: { exposed: true, tags: ['network'], nonEntity: true }, extra: { I: ['T1041', 'T1048.003'] },
      ending: 'a covert channel that blends with legitimate traffic' },
  ];

  // Element tags from what an element is called and does (label, purpose, zone).
  const TAGS = [
    ['network', /\b(router|switch|firewall|vpn|gateway|waf|load ?balancer|proxy|dns|network|connectivity|edge|ddos|sd-?wan|wan|lan|vlan|segmentation)\b/],
    // the platform itself, not anything that computes or hosts (a Kafka cluster, a GPU farm)
    ['virtualisation', /\b(hypervisors?|virtuali[sz]ation|vmware|esxi|vcenter|vsphere|hyper-?v|vm|vms|virtual machines?|containers?|kubernetes|k8s|docker|pods?|openshift)\b/],
    ['cloud', /\b(cloud|saas|tenant|s3|blob|bucket|azure|aws|gcp|iaas|paas|m365|o365|office 365|workspace)\b/],
    ['identity', /\b(iam|identity|idp|sso|active directory|ad|directory|ldap|okta|entra|kerberos|pam|authentication|auth)\b/],
    ['secrets', /\b(key|keys|kms|hsm|secret|secrets|vault|certificate|pki|credential)\b/],
    ['logging', /\b(log|logs|logging|siem|audit|monitoring|observability|telemetry|soc|lineage|evidence)\b/],
    ['admin', /\b(admin|admins|administrator|administrators|privileged|operator|operators|root|jump ?host|bastion)\b/],
    ['people', /\b(user|users|customer|customers|citizen|citizens|staff|employee|employees|public|researcher|researchers|agency|agencies|partner|partners|admin|administrators)\b/],
    ['thirdparty', /\b(third[- ]party|vendor|vendors|supplier|suppliers|partner|partners|external|provider|providers|contractor|collaborators?)\b/],
    ['cicd', /\b(ci\/cd|cicd|pipeline|pipelines|devops|mlops|llmops|build|deploy|deployment|registry|repository|repo|artifact|artefact|package|update)\b/],
    ['web', /\b(web|portal|website|api|application|app|apps|frontend|front-end|https?)\b/],
    ['email', /\b(email|e-mail|mail|exchange|smtp)\b/],
    // not an IT 'domain controller' or 'IDS sensor'
    ['ot', /\b(ot|ics|scada|plcs?|hmis?|rtus?|historian|dcs|iot|field devices?|safety instrumented|(?:programmable logic|safety|field|process|automation|industrial) controllers?)\b|(?<!\b(?:ids|ips|edr|xdr|security|network|intrusion) )\bsensors?\b/],
  ];

  const PLATFORMS_BY_TAG = {
    network: ['Network Devices', 'Linux'],
    virtualisation: ['ESXi', 'Linux', 'Containers'],
    cloud: ['IaaS', 'SaaS', 'Identity Provider'],
    identity: ['Identity Provider', 'Windows', 'Linux'],
    email: ['Office Suite', 'Windows'],
    ot: ['Embedded'],
  };
  // Office Suite techniques (mailbox and document collection) only where the element is an office suite or mail.
  const OFFICE_WORDS = /\b(m365|o365|office ?365|microsoft 365|google workspace|workspace|sharepoint|onedrive|outlook)\b/;
  const ON_PREM = /\bon[- ]?prem(ise|ises)?\b/;
  const CLOUD_TAG = TAGS.find(([t]) => t === 'cloud')[1];
  const SERVER_PLATFORMS = ['Linux', 'Windows', 'macOS', 'Containers'];
  // Network devices by what they are called: a router, switch, firewall, WAF, load balancer or VPN, or a 'network' element
  // whose purpose lists network gear. Not a server ('Firewall Management Server'), nor a gateway, proxy or DNS service, a
  // payment or message 'switch' or an LLM 'router': those are software on a host that may well run Windows.
  const NETWORK_DEVICE = /\b(routers?|switch(es)?|firewalls?|wafs?|load ?balancers?|ddos|sd-?wan|vpn|network\s*(&|and|\/)?\s*(connectivity|segmentation|devices?|infrastructure|appliances?))\b/;
  const NETWORK_GEAR = /\b(routers?|switch(es)?|firewalls?|load ?balancers?|network (devices?|appliances?|infrastructure))\b/;
  const NOT_A_DEVICE = /\b(servers?|hosts?|workstations?|laptops?|desktops?|vms?)\b|\b(payment|card|transaction|eft|atm|pos|message|messaging|event|interbank|kvm|feature|llm|model|prompt|query|semantic|api|request|agent|ai)\s+(switch(es)?|routers?)\b/;
  // Techniques that need a person at a client (a browser, a mail reader): not for servers and devices.
  const USER_SIDE = /^T(1203|1204|1189|1566|1598|1534|1185)\b/;
  // Mailbox collection: only for mail systems (and the people who use them).
  const MAIL_SIDE = /^T1114\b/;
  // Techniques that are about this kind of element.
  const TAG_PREFER = {
    network: /^T(1040|1557|1602|1601|1556\.004|1599|1205|1095|1090|1600|1542\.005)\b/,
    virtualisation: /^T(1611|1610|1525|1578|1059\.012|1505\.006|1564\.006|1675|1068)\b/,
    cloud: /^T(1530|1537|1078\.004|1651|1538|1580|1098\.00[13]|1685\.002)\b/,
    identity: /^T(1556|1606|1558|1003|1098|1078|1621|1111)\b/,
    secrets: /^T(1552|1555|1649|1606|1003)\b/,
    logging: /^T(1070|1685|1562)\b/,
    web: /^T(1190|1505\.003|1133|1059\.007)\b/,
    cicd: /^T(1195|1072|1554|1608|1199)\b/,
    ot: /^T(0\d{3}|169[1-5]|1701)\b/,   // ICS (Enterprise owns T1686-T1690 and T1696-T1700)
  };

  // Short threat titles for the DFD octagons, by technique (most specific first).
  const TITLES = {
    T1190: 'Edge exploit', T1133: 'Remote-access abuse', 'T1587.004': 'Exploit development', T1203: 'Client exploit',
    T1566: 'Phishing', 'T1566.001': 'Spear-phishing attachment', 'T1566.002': 'Spear-phishing link', T1598: 'Credential phishing',
    T1204: 'User execution', T1189: 'Drive-by compromise', T1534: 'Internal phishing', T1656: 'Impersonation',
    T1684: 'Social engineering', 'T1684.001': 'Impersonation', 'T1684.002': 'Email spoofing',
    T1078: 'Valid-account abuse', 'T1078.004': 'Cloud account abuse', 'T1078.003': 'Local account abuse', T1110: 'Password guessing',
    T1003: 'Credential dumping', T1552: 'Unsecured credentials', 'T1552.001': 'Credentials in files', T1555: 'Password-store theft',
    T1556: 'Authentication tampering', 'T1556.004': 'Device auth bypass', T1558: 'Kerberos ticket theft', T1550: 'Token / hash reuse',
    'T1550.001': 'Token theft', T1539: 'Session-cookie theft', T1528: 'App token theft', T1606: 'Forged credentials',
    T1621: 'MFA fatigue', T1111: 'MFA interception', T1212: 'Credential-access exploit', T1187: 'Forced authentication',
    T1040: 'Traffic sniffing', T1557: 'Interception (MITM)', T1601: 'Device image tampering', 'T1601.001': 'Firmware implant',
    T1599: 'Segmentation bypass', T1602: 'Config theft', T1205: 'Port-knocking backdoor', T1095: 'Covert channel',
    T1090: 'Proxy relay', T1572: 'Protocol tunnelling', T1542: 'Boot implant', T1600: 'Crypto weakening',
    T1611: 'Escape to host', T1610: 'Rogue container', T1609: 'Container exec abuse', T1612: 'Image built on host',
    T1613: 'Container discovery', T1525: 'Implanted image', T1578: 'Snapshot abuse', 'T1564.006': 'Hidden VM',
    T1530: 'Cloud data theft', T1537: 'Exfil to cloud account', T1580: 'Cloud discovery', T1538: 'Cloud dashboard abuse',
    T1651: 'Cloud admin commands', T1098: 'Account manipulation', 'T1098.004': 'SSH key implant', T1136: 'Rogue account',
    T1505: 'Server implant', 'T1505.003': 'Web shell', T1543: 'Rogue service', T1547: 'Autostart implant',
    T1053: 'Scheduled-task abuse', T1554: 'Binary implant', T1037: 'Boot-script implant', T1546: 'Event-trigger implant',
    T1574: 'Hijacked execution', T1014: 'Rootkit', T1070: 'Log wiping', 'T1070.004': 'Evidence deletion', 'T1070.006': 'Timestomping',
    'T1070.002': 'Log clearing', 'T1070.003': 'History clearing', 'T1070.007': 'Connection-log wiping',
    T1562: 'Defences disabled', 'T1562.001': 'Security tools disabled', 'T1562.008': 'Cloud logs disabled',
    T1685: 'Security tools disabled', 'T1685.001': 'Event logging disabled', 'T1685.002': 'Cloud logs disabled',
    'T1685.003': 'Tool display spoofed', 'T1685.004': 'Audit logging disabled', 'T1685.005': 'Event logs cleared',
    'T1685.006': 'System logs cleared',
    T1036: 'Masquerading', T1027: 'Obfuscated payload', T1564: 'Hidden artefacts', T1620: 'In-memory loading',
    T1218: 'Proxy execution', T1112: 'Registry tampering', T1222: 'Permission tampering', T1497: 'Sandbox evasion',
    T1021: 'Remote-service pivot', 'T1021.001': 'RDP pivot', 'T1021.002': 'SMB pivot', 'T1021.004': 'SSH pivot',
    T1570: 'Tool transfer', T1210: 'Remote exploit pivot', T1563: 'Session hijack', T1072: 'Deploy-tool abuse',
    T1080: 'Tainted share', T1005: 'Data theft', T1039: 'Share data theft', T1213: 'Repository data theft',
    T1119: 'Automated collection', T1560: 'Data archived', T1074: 'Data staged', T1114: 'Email collection',
    T1041: 'Exfil over C2', T1048: 'Exfil (alt protocol)', T1567: 'Exfil to web service', T1020: 'Automated exfil',
    T1029: 'Scheduled exfil', T1030: 'Size-limited exfil', T1056: 'Input capture', T1113: 'Screen capture',
    T1486: 'Data encrypted', T1485: 'Data destruction', T1490: 'Recovery inhibited', T1489: 'Service stop',
    T1529: 'Shutdown / reboot', T1499: 'Endpoint DoS', T1498: 'Network DoS', T1561: 'Disk wipe', T1491: 'Defacement',
    T1565: 'Data manipulation', T1496: 'Resource hijacking', T1657: 'Financial theft', T1531: 'Access removal',
    T1195: 'Supply-chain compromise', 'T1195.002': 'Software supply chain', T1199: 'Trusted-party abuse', T1553: 'Trust controls subverted',
    T1068: 'Privilege escalation', T1548: 'Elevation abuse', T1134: 'Token manipulation', T1055: 'Process injection',
    T1059: 'Script execution', T1106: 'Native API abuse', T1569: 'Service execution', T1047: 'WMI execution',
    T1071: 'C2 over app protocol', T1573: 'Encrypted C2', T1105: 'Tool ingress', T1102: 'Web-service C2',
    T1219: 'Remote-access tool', T1001: 'Obfuscated C2', T1008: 'Fallback channel', T1568: 'Dynamic C2',
    T1046: 'Service scanning', T1018: 'Host discovery', T1082: 'System discovery', T1087: 'Account discovery',
    T1595: 'Active scanning',
    // ICS
    T0813: 'Denial of control', T0814: 'Device DoS', T0815: 'Denial of view', T0816: 'Device restart / shutdown',
    T0826: 'Loss of availability', T0827: 'Loss of control', T0829: 'Loss of view', T0837: 'Loss of protection',
    T0880: 'Loss of safety', T0881: 'Service stop', T0809: 'Data destruction', T0831: 'Control manipulated',
    T0832: 'View manipulated', T0836: 'Parameter tampering', T0806: 'I/O brute force', T0855: 'Unauthorised command',
    T1692: 'Unauthorised message', 'T1692.001': 'Unauthorised command', 'T1692.002': 'Spoofed reporting',
    T1693: 'Firmware tampering', T0821: 'Controller tasking changed', T0889: 'Program modified', T0872: 'Indicator removal',
    T0849: 'Masquerading', T0848: 'Rogue master', T0859: 'Valid-account abuse', T0866: 'Remote exploit pivot',
    T0867: 'Tool transfer', T0886: 'Remote-service pivot', T0882: 'Operational data theft', T0801: 'Process monitoring',
    T0811: 'Repository data theft', T0893: 'Data theft', T0890: 'Privilege escalation', T0819: 'Edge exploit',
    T0822: 'Remote-access abuse', T1694: 'Insecure credentials', 'T1694.001': 'Default credentials',
    'T1694.002': 'Hardcoded credentials', T1691: 'Messages blocked', T1695: 'Communications blocked',
  };
  // Technique roles in a sequence of attack: getting credentials, using them, holding on, the way in.
  const CREDENTIAL_THEFT = /^T(1566|1598|1534|1585|1586|1003|1552|1555|1557|1539|1528|1111|1056|1606|1558|1212|1187|0865)\b/;
  const AUTH_USE = /^T(1078|1550|1199|1556|1684|1656|1134|1110|1621|0859|1694)\b/;
  const HOLD_TACTICS = ['persistence', 'stealth', 'defense-impairment', 'defense-evasion', 'evasion', 'persistence-ics', 'evasion-ics'];
  const FOOTHOLD = /^T(1190|1133|0819|0822|0866)\b/;
  // Classification words that open a sensitivity ('Restricted — PII', 'Internal + Confidential (sessions)').
  const CLASSIFICATION_WORD = String.raw`(?:top[- ]secret|secret|restricted|confidential|internal(?: only)?|public|sensitive|classified|official(?:[- ]sensitive)?|private|proprietary|unclassified|licensed)`;
  const CLASSIFICATION_HEAD = new RegExp(String.raw`^${CLASSIFICATION_WORD}\b`, 'i');
  const MARKINGS = new Set(['top-secret', 'secret', 'restricted', 'confidential', 'internal', 'public', 'sensitive', 'classified',
    'official', 'official-sensitive', 'private', 'proprietary', 'unclassified', 'licensed']);
  /** Whether a text is classification markings only ('Internal + Confidential', 'OFFICIAL-SENSITIVE'), word by word. */
  const isClassification = text => {
    const words = String(text).toLowerCase().split(/[\s+/&,]+/).filter(Boolean);
    return words.length > 0 && words.every((w, i) => MARKINGS.has(w)
      || (w === 'top' && words[i + 1] === 'secret') || (w === 'only' && words[i - 1] === 'internal')
      || ((w === 'and' || w === 'or') && i > 0 && i < words.length - 1 && !/^(and|or)$/.test(words[i - 1])));
  };
  const DATA_NOUN = /\b(data|records?|keys?|secrets?|credentials?|weights|traffic|logs?|logins?|prompts?|outputs?|responses?|information|sessions?|tokens?|telemetry|files?|documents?|datasets?|models?|messages?|e-?mails?|backups?|images?|history|transactions?|pii|identit(y|ies)|certificates?|configurations?|config|metadata|evidence|decisions?|checkpoints?|code|ip|intellectual property|lineage|features?|embeddings?)\b/i;
  const CATEGORY_TITLES = { S: 'Spoofed identity', T: 'Tampering', R: 'Unattributed actions', I: 'Data theft',
    D: 'Service disruption', E: 'Privilege escalation', LM: 'Pivot' };

  // ---------------------------------------------------------------- MAESTRO / ATLAS

  const LAYERS = [
    { id: 'L1', name: 'Foundation Models', lens: 'Foundation-model attacks',
      summary: 'Prompt injection and jailbreak, model extraction, inversion and membership inference, and model poisoning or backdooring of the foundation and domain models',
      match: /\b(model training|training|fine-?tun\w*|foundation|llm|large language|inference|model serving|serving|neural)\b/ },
    { id: 'L2', name: 'Data Operations', lens: 'Data-operations attacks',
      summary: 'Training-data poisoning, retrieval (RAG) and knowledge-base poisoning, and dataset-integrity erosion across the data pipeline and feature store',
      match: /\b(data lake|feature store|dataset|datasets|data processing|ingestion|etl|label\w*|vector|embedding\w*|rag|retrieval|knowledge base|corpus|training data)\b/ },
    { id: 'L3', name: 'Agent Frameworks', lens: 'Agent-framework attacks',
      summary: 'Abuse of agent tool invocation, context and memory poisoning, agent-configuration tampering, credential harvesting from tools and configurations',
      match: /\b(agent|agents|agentic|ai application|ai applications|assistant|chatbot|copilot|orchestrat\w*|tool|tools|plugin|plugins|mcp)\b/ },
    { id: 'L4', name: 'Deployment & Infrastructure', lens: 'Deployment and infrastructure attacks',
      summary: 'Compromise of the compute, GPU, container and cloud platform the AI runs on — modelled by the ATT&CK pass',
      match: /\b(gpu|accelerator|accelerators|compute|kubernetes|container|containers|hypervisor|cloud)\b/ },
    { id: 'L5', name: 'Evaluation & Observability', lens: 'Evaluation and observability evasion',
      summary: 'Erosion of model integrity and evasion of evaluation and safety monitoring, degrading trust and masking manipulation over time',
      match: /\b(monitoring|observability|evaluation|eval|telemetry|drift)\b/ },
    { id: 'L6', name: 'Security & Compliance', lens: 'Security, compliance and guardrail bypass',
      summary: 'Bypass of guardrails, safety filters and output controls, and manipulation of trusted output components to defeat compliance controls',
      match: /\b(guardrail\w*|safety|content filter|policy|compliance|red team)\b/ },
    { id: 'L7', name: 'Agent Ecosystem', lens: 'Agent-ecosystem and supply-chain attacks',
      summary: 'Compromise of the model, dataset, package and tool supply chain, poisoned published models and agent tools, and abuse of external AI services for command and control',
      match: /\b(external ai|ai service|ai services|third[- ]party|vendor|vendors|marketplace|hub|model registry|registry|package|mlops|llmops|model development|notebook|notebooks)\b/ },
  ];
  // AI elements. One AI-specific term is enough. Ordinary IT words that AI also uses (agent, training, label,
  // model, vector, GPU, assistant, prompt) count in pairs, or alone in an element that exchanges data with a
  // plainly AI one (an 'Agent Memory Store' beside an LLM orchestrator), so an 'EDR Agent', a 'Staff Training
  // Portal' or a 'Shipping Label Service' is not an AI element; the same words still place a known AI element on
  // its MAESTRO layers (LAYERS).
  const AI_STRONG = /\b(ai|ml|machine learning|deep learning|llms?|large language|genai|gen ai|generative|neural|foundation models?|inference|rag|retrieval[- ]augmented|embeddings?|vector (?:stores?|databases?|db|index|indexes|search)|feature stores?|mlops|llmops|copilot|chatbots?|agentic|fine-?tun\w*|training (?:data|datasets?|corpus|jobs?|runs?|pipelines?)|model (?:training|serving|inference|registry|registries|weights|hub|development|performance|monitoring|evaluation|drift|lineage|artefacts?|artifacts?)|data label(?:l)?ing|data scientists?|hugging ?face|openai|anthropic|claude|gemini|chatgpt)\b/;
  const AI_WEAK = [/\bagents?\b/, /\bassistants?\b/, /\btrain(s|ing)?\b/, /\blabel\w*/, /\bmodels?\b/, /\bdatasets?\b/, /\bvector\w*/,
    /\b(gpus?|accelerators?)\b/, /\bprompts?\b/, /\bnotebooks?\b/, /\b(corpus|corpora)\b/, /\bcheckpoints?\b/, /\bweights\b/, /\bbias\b/];
  const aiWeak = text => AI_WEAK.filter(re => re.test(text)).length;
  const isAi = text => AI_STRONG.test(text) || aiWeak(text) >= 2;
  // An external entity is an AI element only when it is an AI service itself ('External AI Services'): an AI
  // word, then a service word after it. Two linear tests, not one backtracking pattern over a long label.
  const AI_SERVICE_AI = /\b(ai|ml|llms?|genai|models?)\b/;
  const AI_SERVICE_NOUN = /\b(services?|apis?|providers?|platforms?)\b/;
  const AI_SERVICE_NAME = /\b(openai|anthropic|claude|gemini|copilot|chatgpt|hugging ?face)\b/;
  const isAiService = label => {
    const m = AI_SERVICE_AI.exec(label);
    return (!!m && AI_SERVICE_NOUN.test(label.slice(m.index + m[0].length))) || AI_SERVICE_NAME.test(label);
  };

  // AI threat templates (MAESTRO layer, STRIDE-LM category, ATLAS techniques), and the elements they fit:
  // `types` are the element types a template is written for (processes and clusters unless it says).
  const AI_THREATS = [
    { key: 'data-poisoning', layers: ['L2'], code: 'T', types: ['process', 'cluster'], title: 'Training-data poisoning',
      techniques: ['AML.T0020', 'AML.T0019', 'AML.T0115.000'], fit: e => e.layers.has('L2') && e.type !== 'datastore',
      actor: 'Malicious or negligent insider (data / model operations)',
      sequence: ['Introduce crafted samples through a poisoned source or processing access', 'The samples pass cleansing and labelling into the training set', 'Models trained on the data learn the backdoor trigger or bias'],
      event: 'The adversary injects crafted samples into the training corpus at {label}, embedding a backdoor or targeted bias that is hard to detect and persists into every model trained on the data.',
      detect: 'Outlier and influence analysis on training data; evaluation on canary and trigger probes.' },
    { key: 'rag-poisoning', layers: ['L2'], code: 'T', types: ['datastore'], title: 'RAG index poisoning',
      techniques: ['AML.T0070', 'AML.T0071'], fit: e => e.layers.has('L2') && e.type === 'datastore',
      actor: 'Indirect-injection adversary (poisoned-content author)',
      sequence: ['Plant crafted content in a source the pipeline indexes', 'The content lands in {label} and its retrieval index', 'AI applications retrieve it into the model context'],
      event: 'The adversary poisons the retrieval (RAG) index held in {label}, so AI applications retrieve attacker-controlled content and pass it to the model as trusted context.',
      detect: 'Provenance checks on indexed content; retrieval logging; review of newly indexed sources.' },
    { key: 'dataset-erosion', layers: ['L2'], code: 'T', types: ['datastore'], title: 'Dataset-integrity erosion',
      techniques: ['AML.T0059', 'AML.T0020'], fit: e => e.layers.has('L2') && e.type === 'datastore',
      actor: 'Malicious or negligent insider (data / model operations)',
      sequence: ['Obtain write access to datasets in {label}', 'Make small, plausible changes to records and labels', 'Model quality and trust erode without a clear trigger'],
      event: 'Gradual, plausible changes to the datasets in {label} erode their integrity, degrading every model trained or grounded on them while staying below detection thresholds.',
      detect: 'Dataset versioning with integrity hashes; drift monitoring on data and labels.' },
    { key: 'unsafe-artefact', layers: ['L7'], code: 'T', types: ['process', 'cluster'], title: 'Malicious package / unsafe artefact',
      techniques: ['AML.T0011.000', 'AML.T0010.001', 'AML.T0010.003'], fit: e => e.layers.has('L7') && /develop|notebook|research|experiment/.test(e.text),
      actor: 'AI supply-chain adversary (malicious package or model author)',
      sequence: ['Publish a malicious package or model artefact', 'A developer loads it into {label}', 'Code embedded in the artefact runs with the developer’s access'],
      event: 'A data scientist at {label} loads a malicious package or an unsafe serialised model artefact, which executes code with the developer’s access to code, data and credentials.',
      detect: 'Model-file scanning for unsafe deserialisation; package allow-lists and AI-BOM checks.' },
    { key: 'model-backdoor', layers: ['L1'], code: 'T', types: ['process', 'cluster'], title: 'Model poisoning / backdoor',
      techniques: ['AML.T0018.000', 'AML.T0018.001', 'AML.T0020'], fit: e => e.layers.has('L1') && /train|fine-?tun/.test(e.text),
      actor: 'Malicious insider or AI supply-chain adversary',
      sequence: ['Gain access to the training job, data or checkpoints at {label}', 'Insert a backdoor into the model', 'The backdoored model passes evaluation and is promoted'],
      event: 'The adversary manipulates training at {label} to backdoor the model; it behaves normally until its trigger appears.',
      detect: 'Training-run provenance and reproducibility checks; backdoor scanning; signed checkpoints.' },
    { key: 'model-malware', layers: ['L1'], code: 'T', types: ['process', 'cluster'], title: 'Malware embedded in model',
      techniques: ['AML.T0018.002', 'AML.T0011.000'], fit: e => e.layers.has('L1') && /train|fine-?tun/.test(e.text),
      actor: 'Malicious insider or AI supply-chain adversary',
      sequence: ['Obtain write access to checkpoints at {label}', 'Embed executable code in the serialised model', 'The code runs wherever the model is loaded'],
      event: 'Malware embedded in model artefacts produced at {label} executes on every system that loads them, from evaluation to production serving.',
      detect: 'Scan serialised models before loading; prefer safe formats (e.g. safetensors); signed artefacts.' },
    { key: 'poisoned-model', layers: ['L7', 'L5'], code: 'T', types: ['process', 'cluster', 'datastore'], title: 'Poisoned published model',
      techniques: ['AML.T0058', 'AML.T0115.001', 'AML.T0010.003'], fit: e => /registry|model store|model hub|artefact|artifact/.test(e.text),
      actor: 'AI supply-chain adversary',
      sequence: ['Publish or substitute a poisoned model version', 'The version is registered in {label} with plausible lineage', 'Deployment picks it up and serves it'],
      event: 'A poisoned model version enters {label} and is promoted to production with plausible lineage.',
      detect: 'Signed model artefacts and lineage verification; evaluation gates before promotion.' },
    { key: 'corrupt-model', layers: ['L5'], code: 'T', types: ['process', 'cluster', 'datastore'], title: 'Corrupt model to evade scanning',
      techniques: ['AML.T0076', 'AML.T0031'], fit: e => /registry|model store|model hub|artefact|artifact/.test(e.text),
      actor: 'AI supply-chain adversary',
      sequence: ['Craft a model file that scanners mis-parse', 'Register it in {label}', 'The payload survives scanning and evaluation'],
      event: 'A deliberately corrupted model file in {label} defeats model scanning and evaluation, so a tampered model reaches production unchecked.',
      detect: 'Strict format validation; scan with more than one parser; quarantine failed loads.' },
    { key: 'direct-injection', layers: ['L1', 'L6'], code: 'E', title: 'Jailbreak / direct prompt injection',
      techniques: ['AML.T0051.000', 'AML.T0054', 'AML.T0068'], fit: e => e.layers.has('L3') || /application|chat|assistant|copilot|agent/.test(e.text),
      actor: 'External user / prompt-injection adversary',
      sequence: ['Craft prompts that override the system instructions', 'The model follows them past its guardrails', 'It discloses restricted data or produces unsafe output'],
      event: 'Users of {label} jailbreak the model with crafted prompts, bypassing guardrails and output controls to obtain restricted data or unsafe output.',
      detect: 'Prompt and response logging; jailbreak classifiers; guardrail telemetry.' },
    { key: 'indirect-injection', layers: ['L3', 'L1'], code: 'T', title: 'Indirect prompt injection',
      techniques: ['AML.T0051.001', 'AML.T0093', 'AML.T0080'], fit: e => e.layers.has('L3') || /application|chat|assistant|copilot|agent/.test(e.text),
      actor: 'Indirect-injection adversary (content author); no platform credentials required',
      sequence: ['Plant instructions in content the application retrieves (documents, web pages, tool output)', 'The content enters the model context of {label}', 'The model acts on the injected instructions'],
      event: 'Instructions hidden in content retrieved by {label} (RAG documents, tool output) hijack the model, which then acts for the adversary rather than the user.',
      detect: 'Separate trusted and retrieved content; injection detection on retrieved text; output review.' },
    { key: 'agent-abuse', layers: ['L3'], code: 'E', title: 'Agent tool abuse / excessive agency',
      techniques: ['AML.T0053', 'AML.T0086', 'AML.T0101'], fit: e => e.layers.has('L3') && /agent|tool|application|copilot|assistant/.test(e.text),
      actor: 'Compromised or rogue agent / tool',
      sequence: ['Steer the agent through injected instructions', 'The agent invokes tools beyond the task', 'Data is changed, destroyed or sent out through those tools'],
      event: 'Through {label}, the adversary drives the agent to invoke privileged tools beyond its task — exfiltrating or destroying data with the agent’s own permissions (excessive agency).',
      detect: 'Tool-invocation audit logs; least-privilege tool scopes; human approval for consequential actions.' },
    { key: 'tool-credentials', layers: ['L3'], code: 'I', title: 'Tool credential harvesting',
      techniques: ['AML.T0098', 'AML.T0083'], fit: e => e.layers.has('L3') && /agent|tool|application|copilot|assistant/.test(e.text),
      actor: 'Compromised or rogue agent / tool',
      sequence: ['Prompt the agent to reveal its configuration', 'Read the credentials its tools use', 'Reuse them outside the agent'],
      event: 'The adversary harvests the credentials that {label} holds for its tools and agent configuration, and reuses them directly against the connected systems.',
      detect: 'Keep tool secrets out of model context; short-lived, scoped tool tokens; alert on reuse outside the agent.' },
    { key: 'memory-poisoning', layers: ['L3'], code: 'T', types: ['datastore'], title: 'Agent memory poisoning',
      techniques: ['AML.T0080.000', 'AML.T0080.001', 'AML.T0080'], fit: e => e.layers.has('L3') && /memor|context|conversation|history|session/.test(e.text),
      actor: 'Indirect-injection adversary (content author), or an insider with write access',
      sequence: ['Plant instructions or false facts in content an agent will remember, or write them into {label}', 'The entries persist in {label} as trusted memory', 'Agents recall them in later sessions and act on them'],
      event: 'The adversary poisons the agent memory held in {label}, so agents recall attacker-planted instructions and false facts as trusted context in every later session.',
      detect: 'Provenance and review of memory writes; expire and re-validate long-lived memories; flag instruction-like content in memory.' },
    { key: 'memory-disclosure', layers: ['L3'], code: 'I', types: ['datastore'], title: 'Agent memory and secret theft',
      techniques: ['AML.T0085.002', 'AML.T0083'], fit: e => e.layers.has('L3') && /memor|context|conversation|history|session|config/.test(e.text),
      actor: 'Adversary with access to agent data (insider or compromised service)',
      sequence: ['Obtain read access to {label}', 'Read the stored conversations, memories and tool configuration', 'Reuse the personal data and the credentials the agents use'],
      event: 'The adversary reads the conversation history, memory and tool configuration held in {label}, exposing what users told the agents and the credentials the agents use.',
      detect: 'Scope and encrypt memory per user; keep tool secrets in a vault, not in agent memory; audit reads of the store.' },
    { key: 'model-extraction', layers: ['L1'], code: 'I', title: 'Model extraction (API)',
      techniques: ['AML.T0024.002', 'AML.T0005', 'AML.T0024'], fit: e => e.layers.has('L1') && /inferenc|serving|api|endpoint/.test(e.text),
      actor: 'Model-extraction adversary (API consumer)',
      sequence: ['Obtain access to the inference API', 'Issue systematic queries and record the responses', 'Train a functional copy of the model'],
      event: 'Through the inference API of {label}, the adversary replicates the model’s behaviour, extracting a functional copy of the model and its IP.',
      detect: 'Query-pattern and volume anomaly detection on the inference API; per-client rate limits.' },
    { key: 'model-inversion', layers: ['L1'], code: 'I', title: 'Inversion / membership inference',
      techniques: ['AML.T0024.001', 'AML.T0024.000', 'AML.T0137.002', 'AML.T0137.000'], fit: e => e.layers.has('L1') && /inferenc|serving|api|endpoint/.test(e.text),
      actor: 'Model-extraction adversary (API consumer)',
      sequence: ['Query {label} with crafted inputs', 'Analyse confidence scores and outputs', 'Infer training records or reconstruct sensitive attributes'],
      event: 'Queries against {label} reveal whether given records were in the training data and reconstruct sensitive training data, disclosing what the model learnt from.',
      detect: 'Output confidence rounding; differential-privacy training; anomaly detection on probing patterns.' },
    { key: 'system-prompt', layers: ['L1', 'L6'], code: 'I', title: 'System-prompt extraction',
      techniques: ['AML.T0056', 'AML.T0069.002'], fit: e => e.layers.has('L1') && /inferenc|serving|api|endpoint|application|chat|assistant/.test(e.text),
      actor: 'External user / prompt-injection adversary',
      sequence: ['Ask the model about its own instructions', 'Use prompt tricks to make it repeat them', 'Use the recovered prompt to craft better attacks'],
      event: 'The adversary recovers the system prompt and configuration of {label}, revealing guardrail logic and any secrets placed in it.',
      detect: 'Keep secrets out of system prompts; output filters for prompt leakage.' },
    { key: 'ai-dos', layers: ['L1', 'L5'], code: 'D', title: 'AI-service DoS / cost harvesting',
      techniques: ['AML.T0029', 'AML.T0034', 'AML.T0046'], fit: e => e.layers.has('L1') && /inferenc|serving|api|endpoint/.test(e.text),
      actor: 'External user or botnet operator',
      sequence: ['Find the expensive request shapes', 'Flood the service with them', 'Capacity and budget run out for legitimate users'],
      event: 'Resource-exhausting queries against {label} deny the AI service to legitimate users and run up compute cost.',
      detect: 'Per-client quotas and cost telemetry; latency and queue-depth alerting.' },
    { key: 'supply-chain', layers: ['L7'], code: 'T', title: 'AI supply-chain compromise',
      techniques: ['AML.T0010', 'AML.T0010.003', 'AML.T0010.001'], fit: e => /mlops|llmops|pipeline|ci\/cd|cicd|devops/.test(e.text),
      actor: 'AI supply-chain adversary',
      sequence: ['Compromise a supplier of models, data or packages', 'The pipeline at {label} imports the poisoned component', 'It is promoted into production with the pipeline’s trust'],
      event: 'A poisoned model, dataset or package from a supplier is imported by {label} and promoted with the pipeline’s own credentials.',
      detect: 'AI-BOM and signature verification on import; pinned, reviewed dependencies.' },
    { key: 'poisoned-tool', layers: ['L7', 'L3'], code: 'T', title: 'Poisoned agent tool (MCP)',
      techniques: ['AML.T0104', 'AML.T0010.005', 'AML.T0011.002', 'AML.T0110'], fit: e => /mlops|llmops|pipeline|ci\/cd|cicd|devops|agent|tool/.test(e.text),
      actor: 'AI supply-chain adversary',
      sequence: ['Publish or compromise an agent tool (for example an MCP server)', '{label} installs or updates it', 'Agents call the tool, which acts for the adversary'],
      event: 'A poisoned agent tool (for example an MCP server) adopted through {label} gives the adversary a foothold inside every agent that calls it.',
      detect: 'Tool allow-lists with pinned versions; review of tool definitions; monitoring of tool behaviour.' },
    // on the element that calls an external AI service, not on the service: an external entity can only be spoofed or
    // fail to be held to account (STRIDE-per-element), and the data leaves from the caller
    { key: 'ai-api-c2', layers: ['L7'], code: 'I', title: 'AI-service API C2 & exfiltration',
      techniques: ['AML.T0096', 'AML.T0072'], fit: e => e.aiServices.length > 0,
      actor: 'Compromised or rogue agent / tool',
      sequence: ['Gain execution on {label}, which is allowed to reach {service}', 'Encode commands and data in AI API requests and responses', 'Operate inside normal-looking AI traffic'],
      event: 'The adversary abuses the connection from {label} to {service} as a covert command-and-control and exfiltration channel, blending with sanctioned AI traffic.',
      detect: 'Volume and entropy anomalies to external AI endpoints; calls outside approved workflows.' },
    { key: 'eval-evasion', layers: ['L5'], code: 'T', title: 'Evaluation / monitoring evasion',
      techniques: ['AML.T0031', 'AML.T0015'], fit: e => e.layers.has('L5'),
      actor: 'Adversary seeking to keep manipulation hidden',
      sequence: ['Learn what evaluation and monitoring at {label} measure', 'Shape inputs or the model so the metrics stay normal', 'Manipulation persists undetected'],
      event: 'The adversary erodes model integrity in ways tuned to pass the evaluation and safety monitoring at {label}, masking manipulation over time.',
      detect: 'Independent evaluation sets; alert on monitoring blind spots.' },
  ];

  // ---------------------------------------------------------------- helpers

  const lower = s => String(s || '').toLowerCase();
  /** 'Edge exploit' -> 'edge exploit', but 'API Gateway pivot' and 'OT data' keep their capitals. */
  const lcFirst = s => (/^[A-Z][a-z]/.test(s) ? s[0].toLowerCase() + s.slice(1) : s);
  /** Whole words (plurals too): 'secret' matches 'integration secrets' but not 'secretariat'. */
  const has = (text, list) => list.some(w => new RegExp('(^|[^a-z0-9])' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(s|es)?([^a-z0-9]|$)').test(text));
  const byAttackId = (a, b) => String(a).localeCompare(String(b), undefined, { numeric: true });
  const unique = list => [...new Set(list)];
  const sentence = s => {
    const t = String(s || '').trim();
    return t ? t[0].toUpperCase() + t.slice(1) : t;
  };
  /** 'A', 'A and B', 'A, B and C'. */
  const andList = list => (list.length < 2 ? list.join('') : `${list.slice(0, -1).join(', ')} and ${list[list.length - 1]}`);
  /** Actors named in a sentence: 'A', 'A and B', 'A, B and C', or 'A, B and 3 other actors'. */
  const namesOf = list => (list.length <= 3 ? andList(list.map(a => a.name))
    : `${list[0].name}, ${list[1].name} and ${list.length - 2} other actors`);
  /**
   * Who a sentence citing these techniques is about: the profile's actors MITRE records using every one of them,
   * else those using any of them; null when none is recorded.
   */
  const actorsUsing = (ids, profile) => {
    const recorded = ids.filter(aid => profile.used.has(aid));
    const uses = a => aid => profile.used.get(aid).roots.has(a.id);
    const every = recorded.length ? profile.actors.filter(a => recorded.every(uses(a))) : [];
    const some = profile.actors.filter(a => recorded.some(uses(a)));
    return every.length ? every : some.length ? some : null;
  };
  /**
   * Lower-case text without its negated phrases ('no public access', 'not exposed to the internet',
   * 'non-public'), so a keyword test doesn't read them as the opposite. A negation runs to the next
   * punctuation mark, dash, spaced slash, line break or 'but' ('No WAF in front — internet-facing' and
   * 'No WAF / internet-facing' are still internet-facing); a hyphenated one negates only its own word
   * ('No-Trust Internet Zone' is still an internet zone).
   */
  const NEGATION = /\b(?:no|non|not)-[\w-]+|\b(?:no(?!\.?\s*\d)|not|non|never|without|nor|cannot|(?:isn|aren|wasn|weren|doesn|don|didn|hasn|haven|hadn|won|can|couldn|shouldn|wouldn)['’]t)\b(?:(?!\s[-/]|[-/]\s|\b(?:but|however|except|although|though|yet|while|whereas)\b)[^,;:.!?()[\]|—–―·•\n\r])*/g;
  const unnegated = s => lower(s).replace(NEGATION, ' ');
  /** MITRE descriptions carry markdown links and citations: keep the text. */
  function cleanMitre(text) {
    return String(text || '').replace(/\(Citation:[^)]*\)/g, '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
      .replace(/<code>|<\/code>/g, '').replace(/\s+/g, ' ').trim();
  }
  function firstSentences(text, max = 260) {
    const t = cleanMitre(text);
    if (t.length <= max) return t;
    const cut = t.slice(0, max);
    const stop = cut.lastIndexOf('. ');
    return stop > 80 ? cut.slice(0, stop + 1) : cut.replace(/\s+\S*$/, '') + '…';
  }

  /** Technique index over the loaded domains: lookups by ATT&CK / ATLAS ID. */
  function techniqueIndex(models) {
    const byId = new Map();
    for (const m of Object.values(models)) {
      if (!m) continue;
      const tacticName = new Map((m.byKind.tactic || []).map(t => [t.shortname, t.name]));
      for (const t of m.byKind.technique || []) {
        if (!t.attackId || byId.has(t.attackId)) continue;
        byId.set(t.attackId, { obj: t, model: m, tactics: (t.tactics || []).map(s => tacticName.get(s) || s) });
      }
    }
    return byId;
  }

  function mitigationsOf(entry) {
    const { obj, model } = entry;
    return model.to(obj.id, 'mitigates', 'mitigation').map(r => model.byId.get(r.source)).filter(m => m && m.active)
      .map(m => ({ id: m.attackId, name: m.name })).sort((a, b) => byAttackId(a.id, b.id))
      .filter((m, i, all) => all.findIndex(x => x.id === m.id) === i);
  }

  function detectionsOf(entry, models) {
    const { obj, model } = entry;
    const strategies = [];
    const sources = new Set();
    for (const r of model.to(obj.id, 'detects', 'detection-strategy')) {
      const ds = model.byId.get(r.source);
      if (!ds || !ds.active) continue;
      strategies.push(ds.name);
      for (const aid of ds.analyticRefs || []) {
        const a = model.byId.get(aid);
        if (!a || !a.active) continue;
        for (const l of a.logSources || []) {
          let dc = model.byId.get(l.dataComponent);
          if (!dc) for (const m of Object.values(models)) { dc = m && m.byId.get(l.dataComponent); if (dc) break; }
          if (dc && dc.name) sources.add(dc.name);
        }
      }
    }
    return { strategies: unique(strategies).sort(), dataSources: [...sources].sort() };
  }

  function caseStudiesOf(entry, limit = 2) {
    const { obj, model } = entry;
    return unique(model.to(obj.id, 'uses', 'case-study').map(r => r.source)).map(id => model.byId.get(id))
      .filter(c => c && c.active).sort((a, b) => byAttackId(b.attackId, a.attackId)).slice(0, limit)
      .map(c => ({ id: c.attackId, name: c.name }));
  }

  // ---------------------------------------------------------------- the profile

  /** The Threat Profile tab's profile in this model's terms: actors, their techniques (◆) and the evidence. */
  function profileOf(ctx, index) {
    const actors = [];
    const used = new Map();   // attackId -> { roots: Set(actor label), evidence: [text] }
    for (const [domain, m] of Object.entries(ctx.models || {})) {
      if (!m) continue;
      const r = global.SimEngine.analyzeDomain(m, ctx.selection || {}, Object.assign({}, ctx.opts || {}, { platforms: new Set() }));
      for (const root of r.roots) {
        if (!actors.some(a => a.id === root.id)) {
          actors.push({ id: root.id, attackId: root.attackId, name: root.name, kind: root.kind, domain });
        }
      }
      for (const t of r.techniques.values()) {
        const aid = t.tech.attackId;
        if (!aid || !index.has(aid)) continue;
        let u = used.get(aid);
        if (!u) used.set(aid, u = { roots: new Set(), evidence: [] });
        for (const id of t.roots) u.roots.add(id);
        for (const ev of t.evidence) if (ev.description) u.evidence.push(ev.description);
      }
    }
    // the software and campaigns MITRE ATT&CK records for the actors (their own, and their campaigns' software): what
    // Claude may name when it writes the register (shared decision I7)
    const software = new Map(), campaigns = new Map();
    const note = (map, o) => { if (o && o.active && o.attackId && !map.has(o.attackId)) map.set(o.attackId, { id: o.attackId, name: o.name }); };
    for (const a of actors) {
      const m = (ctx.models || {})[a.domain];
      if (!m || a.domain === 'atlas') continue;
      const camps = global.SimEngine.attributedTo ? global.SimEngine.attributedTo(m, a.id) : [];
      if (a.kind === 'software') note(software, m.byId.get(a.id));
      if (a.kind === 'campaign') note(campaigns, m.byId.get(a.id));
      for (const c of camps) note(campaigns, c);
      for (const src of [a.id, ...camps.map(c => c.id)]) for (const r of m.from(src, 'uses', 'software')) note(software, m.byId.get(r.target));
    }
    const name = a => `${a.name} (${a.attackId})`;
    const short = actors.length === 0 ? 'generic' : actors.length === 1 ? actors[0].name
      : actors.length === 2 ? `${actors[0].name} and ${actors[1].name}` : `${actors[0].name} +${actors.length - 1}`;
    return {
      actors, used,
      software: [...software.values()].sort((x, y) => byAttackId(x.id, y.id)),
      campaigns: [...campaigns.values()].sort((x, y) => byAttackId(x.id, y.id)),
      label: actors.length ? actors.map(name).join(', ') : 'No threat profile (generic attacker)',
      short,
      who: namesOf(actors),   // for sentences: 'A, B and C'
      nameOf: id => { const a = actors.find(x => x.id === id); return a ? name(a) : id; },
    };
  }

  // ---------------------------------------------------------------- run

  function run(model, ctx) {
    const models = ctx.models || {};
    const index = techniqueIndex(models);
    const profile = profileOf(ctx, index);
    const atlasModel = models.atlas || null;
    const warnings = [];

    const zoneById = new Map(model.zones.map(z => [z.id, z]));
    const elById = new Map(model.elements.map(e => [e.id, e]));
    const flowsIn = new Map(), flowsOut = new Map();
    for (const e of model.elements) { flowsIn.set(e.id, []); flowsOut.set(e.id, []); }
    for (const f of model.flows) {
      flowsOut.get(f.source).push(f); flowsIn.get(f.target).push(f);
      if (f.bidirectional) { flowsOut.get(f.target).push(Object.assign({}, f, { source: f.target, target: f.source })); flowsIn.get(f.source).push(Object.assign({}, f, { source: f.target, target: f.source })); }
    }

    // Zone trust: 0 untrusted / external, 1 DMZ / perimeter, 2 internal, 3 management / restricted.
    const zoneRank = id => {
      const label = unnegated(zoneById.get(id).label);
      if (/\b(internet|external|untrusted|public|third[- ]part|partner|vendor|supplier|outside)\b/.test(label)) return 0;
      if (/\b(dmz|perimeter|edge)\b/.test(label)) return 1;
      if (/\b(management|mgmt|admin|security|restricted|core|secure|vault)\b/.test(label)) return 3;
      return 2;
    };
    const EXTERNAL_TRUST = /\b(untrusted|external|public|internet|exposed)\b/;
    // An element's own trust: its zone's. Outside every zone, an external entity is untrusted; any other
    // element is part of the system, internal unless its trust context says it faces outside.
    const rankOf = e => (e.zone && zoneById.has(e.zone) ? zoneRank(e.zone)
      : e.type === 'entity' || EXTERNAL_TRUST.test(unnegated(e.context.trust)) ? 0 : 2);
    const zonePath = id => {
      const out = [];
      for (let z = zoneById.get(id); z && !out.includes(z.label); z = zoneById.get(z.parent)) out.push(z.label);
      return out;
    };

    // AI elements (MAESTRO): what an element is and does, not the data it holds. An external entity is one only
    // when it is an AI service itself (users of AI services aren't).
    const aiText = e => lower([e.label, e.context.purpose].join(' '));
    const plainlyAi = new Map(model.elements.map(e => [e.id, typeof e.ai === 'boolean' ? e.ai
      : e.type === 'entity' ? isAiService(lower(e.label)) : isAi(aiText(e))]));
    const aiOf = e => plainlyAi.get(e.id) || (typeof e.ai !== 'boolean' && e.type !== 'entity' && aiWeak(aiText(e)) > 0
      && [...flowsIn.get(e.id).map(fl => fl.source), ...flowsOut.get(e.id).map(fl => fl.target)]
        .some(id => id !== e.id && plainlyAi.get(id)));

    // Element facts (CSA §3.2 context): tags, platforms, exposure, sensitivity.
    const facts = new Map();
    for (const e of model.elements) {
      const text = lower([e.label, e.context.purpose].join(' '));
      const zoneText = unnegated(zonePath(e.zone).join('; '));   // (a negation ends with its own field)
      // an on-premises element that mentions the cloud it serves isn't a cloud service
      const onPrem = ON_PREM.test(text);
      const tags = new Set(TAGS.filter(([t, re]) => re.test(text) && !(t === 'cloud' && onPrem)).map(([t]) => t));
      if (e.type === 'entity') tags.add('people');
      if (tags.has('thirdparty') && e.type !== 'entity') tags.delete('people');
      // a cloud or SaaS service by name runs no server the attacker can reach; a passing mention of the cloud
      // in what an element does doesn't make it one
      const cloudHosted = tags.has('cloud') && CLOUD_TAG.test(lower(e.label));
      const platforms = new Set();
      // (an external OT source is not one of our embedded devices: it keeps the entity's open platform set)
      for (const t of tags) if (t !== 'ot' || e.type !== 'entity') for (const p of PLATFORMS_BY_TAG[t] || []) platforms.add(p);
      if (OFFICE_WORDS.test(text)) platforms.add('Office Suite');
      // a hypervisor or container platform runs Linux underneath, and a router, switch, firewall or WAF its own network
      // OS: neither is a Windows or macOS desktop (unless it says so)
      const name = lower(e.label);
      const device = !tags.has('virtualisation') && !NOT_A_DEVICE.test(name)
        && (NETWORK_DEVICE.test(name) || (/\bnetwork\b/.test(name) && NETWORK_GEAR.test(lower(e.context.purpose))));
      const desktop = !(tags.has('virtualisation') || device) || /\b(windows|hyper-?v|macos)\b/.test(text);
      if (e.type !== 'entity' && !cloudHosted) {
        for (const p of SERVER_PLATFORMS) if (desktop || p === 'Linux' || (p === 'Containers' && !device)) platforms.add(p);
      }
      // what the element holds, from its purpose and sensitivity; never its authentication or trust, which
      // mention credentials, secrets and cards without saying anything about the data held
      const held = unnegated([e.context.purpose, e.context.sensitivity].join('; '));
      const crownJewel = typeof e.crownJewel === 'boolean' ? e.crownJewel : has(held, CROWN_WORDS);
      const sensitive = crownJewel || has(held, SENSITIVE_WORDS);
      const ownRank = rankOf(e);
      const outward = ownRank <= 1 || has(zoneText, EXPOSED_WORDS) || EXTERNAL_TRUST.test(unnegated(e.context.trust));
      const crossing = flowsIn.get(e.id).filter(fl => elById.get(fl.source).zone !== e.zone);
      // Three readings of exposure. The skill's (stride_lm._is_exposed), for the STRIDE-LM gates and severity:
      // reachable from outside its own trust zone, or sitting in an untrusted one.
      const reachable = outward || crossing.length > 0;
      // In an intruder's path from the edge, for which themes bear on it and how many rows it carries: reached across
      // a boundary from an untrusted or perimeter zone, or from an external entity outside every zone.
      const exposed = outward || crossing.some(fl => rankOf(elById.get(fl.source)) <= 1);
      // Facing outside itself, for T1190 / T1133 and the attack sequences' ways in: its own zone or trust says so, or the
      // outside sends to it directly: an external entity, or anything drawn in the Internet or another party's zone (a
      // client app in the Internet zone), not the system's own DMZ, edge or public subnet. A server that a DMZ host calls
      // is reached from the edge, not exposed on it.
      const external = outward || flowsIn.get(e.id).some(fl => {
        const src = elById.get(fl.source);
        if (src.type === 'entity') return rankOf(src) <= 1;
        const where = unnegated(zonePath(src.zone).join('; '));
        return OUTSIDE_ZONE.test(where) && !SYSTEM_EDGE.test(where);
      });
      const aiLabel = lower(e.label);
      const ai = aiOf(e);
      let layers = new Set(LAYERS.filter(l => l.match.test(aiLabel)).map(l => l.id));
      if (!layers.size) layers = new Set(LAYERS.filter(l => l.match.test(text)).map(l => l.id));
      if (!ai) layers = new Set();
      else if (!layers.size) layers.add(e.type === 'datastore' ? 'L2' : 'L1');
      facts.set(e.id, { e, tags, platforms, cloudHosted, crownJewel, sensitive, exposed, reachable, external, ai, layers, text,
        auth: !!String(e.context.auth || '').trim(), rank: ownRank,
        reaches: unique(flowsOut.get(e.id).map(f => f.target)).filter(id => id !== e.id && elById.get(id).type !== 'entity'),
        crossesOut: flowsOut.get(e.id).some(f => elById.get(f.target).zone !== e.zone) });
    }

    for (const f of facts.values()) {
      f.reaches.sort((a, b) => Number(facts.get(b).crownJewel) - Number(facts.get(a).crownJewel) || facts.get(b).rank - facts.get(a).rank);
    }

    // ---- lenses (the Sectorial Threat Profile) from the profile's techniques

    const themeOf = (aid, entry) => THEMES.filter(th => th.ids.test(aid)
      || (th.tactics && (entry.obj.tactics || []).some(t => th.tactics.includes(t)) && !THEMES.some(o => o !== th && o.ids.test(aid)))
      || (th.platforms && (entry.obj.platforms || []).some(p => th.platforms.includes(p))
        && entry.obj.platforms.every(p => th.platforms.includes(p) || p === 'PRE')));
    const lensTechniques = new Map(THEMES.map(th => [th.key, []]));
    for (const aid of profile.used.keys()) {
      const entry = index.get(aid);
      if (!entry || entry.model.domain === 'atlas') continue;
      for (const th of themeOf(aid, entry)) lensTechniques.get(th.key).push(aid);
    }
    let lenses = THEMES.map(th => ({ theme: th, techniques: lensTechniques.get(th.key).sort(byAttackId), status: 'Observed' }))
      .filter(l => l.techniques.length)
      .sort((a, b) => b.techniques.length - a.techniques.length || THEMES.indexOf(a.theme) - THEMES.indexOf(b.theme));
    const generic = !profile.actors.length || !lenses.length;
    // why the ATT&CK pass is generic: no profile, or a profile whose techniques don't reach this architecture
    const profileIds = [...profile.used.keys()];
    const genericWhy = !profile.actors.length ? 'No threat profile was built on the Threat Profile tab: a generic attacker is assumed.'
      : `${!profileIds.length ? `MITRE records no techniques for ${profile.who}`
        : profileIds.every(aid => aid.startsWith('AML.')) ? `${profile.who} ${profile.actors.length > 1 ? 'have' : 'has'} no ATT&CK techniques that bear on this architecture (${profile.actors.length > 1 ? 'their' : 'its'} techniques are ATLAS-only)`
          : `None of the ATT&CK techniques MITRE records for ${profile.who} falls into a threat theme this model reads`}, so the ATT&CK pass uses generic STRIDE-LM techniques, extrapolated to the profile.`;
    if (generic) {
      if (profile.actors.length) warnings.push('The threat profile has no ATT&CK techniques to model this architecture with, so generic techniques are used.');
      lenses = [{ theme: { key: 'generic', name: 'Opportunistic external attack', short: 'External attack', categories: CODES,
        targets: {}, extra: {}, ending: 'unauthorised access to the affected element' }, techniques: [], status: 'Extrapolated' }];
    } else if (!lenses.some(l => l.theme.categories.includes('I')) && model.elements.some(e => facts.get(e.id).crownJewel)) {
      // The crown jewels are the objective whatever the actor's recorded habits: model their theft, marked as such.
      lenses.push({ theme: THEMES.find(t => t.key === 'collection'), techniques: [], status: 'Extrapolated' });
    }
    lenses.forEach((l, i) => {
      l.id = 'STP-' + (i + 1);
      l.name = l.theme.name + (l.status === 'Extrapolated' && !generic ? ' (extrapolated)' : '');
      const ev = [];
      for (const aid of l.techniques) {
        const u = profile.used.get(aid);
        const d = u && u.evidence.find(x => x && x.length > 30);
        if (d && !ev.some(x => x.text === d)) ev.push({ aid, text: d });
        if (ev.length >= 2) break;
      }
      l.evidence = ev.length ? ev.map(x => `${x.aid}: ${firstSentences(x.text, 220)}`).join(' ')
        : l.status === 'Extrapolated' ? (generic ? genericWhy
          : `Not recorded for ${profile.short} in MITRE ATT&CK; modelled because the architecture holds crown-jewel data.`)
          : '';
    });

    // ---- element x category walk

    const fitsTargets = (lens, f) => {
      const t = lens.theme.targets || {};
      if (!Object.keys(t).length) return true;
      if (t.nonEntity && f.e.type === 'entity') return false;
      // a theme the profile shows in only one or two techniques is a weak signal: it bears only on the
      // elements it is specifically about, not on every crown jewel or exposed element
      if (lens.status === 'Observed' && lens.techniques.length < 3) return !!(t.tags && t.tags.some(x => f.tags.has(x)));
      if (t.crown && f.crownJewel) return true;
      if (t.authExposed && f.auth && f.exposed && f.e.type !== 'datastore') return true;
      if (t.pivot && f.reaches.length && f.e.type !== 'entity'
        && (f.crossesOut || f.exposed || ['admin', 'network', 'virtualisation', 'identity', 'cicd'].some(x => f.tags.has(x)))) return true;
      if (t.types && t.types.includes(f.e.type)) return true;
      if (t.tags && t.tags.some(x => f.tags.has(x))) return true;
      if (t.exposed && f.exposed) return true;
      if (t.auth && f.auth && f.e.type !== 'datastore') return true;
      if (t.sensitive && f.sensitive) return true;
      if (t.reaches && f.reaches.length && f.e.type !== 'entity') return true;
      if (t.dependants && f.e.type !== 'entity' && unique([...flowsIn.get(f.e.id).map(x => x.source), ...flowsOut.get(f.e.id).map(x => x.target)]).length >= 4) return true;
      return false;
    };
    const platformFit = (entry, f) => {
      const ps = (entry.obj.platforms || []).filter(p => p !== 'PRE' && p !== 'None');
      if (!ps.length || !f.platforms.size) return true;
      return ps.some(p => f.platforms.has(p));
    };
    const strongFit = (aid, code) => CATEGORY_FIT[code].test(aid);
    const weakFit = (entry, code) => (entry.obj.tactics || []).some(t => CATEGORY_TACTICS[code].includes(t));
    // a technique for this element's own kind of platform (network devices, ESXi, cloud) says more than a generic one
    const specific = (entry, f) => {
      const ps = (entry.obj.platforms || []).filter(p => p !== 'PRE' && p !== 'None');
      return ps.length > 0 && ps.every(p => !SERVER_PLATFORMS.includes(p) || p === 'Containers') && ps.some(p => f.platforms.has(p));
    };

    /** Techniques for one cell: the lens's attributed techniques first (◆), then generic ones. */
    function techniquesFor(lens, code, f) {
      // what this element can be attacked with in this category, whatever the platform
      const allowed = (aid, entry) => (!/^T(1190|1133)\b/.test(aid) || f.external)   // only on what faces outside
        && (!(USER_SIDE.test(aid) || MAIL_SIDE.test(aid)) || f.e.type === 'entity' || f.tags.has('email'))
        && (!/ics/.test(entry.model.domain) || f.tags.has('ot'))                    // ICS techniques on OT elements only
        && (code !== 'T' || f.e.type !== 'datastore' || DATASTORE_TAMPERING.test(aid)
          || (GUARD_TAMPERING.test(aid) && (f.tags.has('secrets') || f.tags.has('identity'))))
        && (code !== 'R' || f.e.type !== 'datastore' || DATASTORE_REPUDIATION.test(aid))
        && (aid !== 'T1078.001' || f.e.type !== 'entity' || f.tags.has('admin') || DEVICE_WORDS.test(f.text));
      const usable = aid => {
        const entry = index.get(aid);
        return entry && platformFit(entry, f) && allowed(aid, entry);
      };
      let attributed = lens.techniques.filter(aid => usable(aid) && strongFit(aid, code));
      if (!attributed.length) attributed = lens.techniques.filter(aid => usable(aid) && weakFit(index.get(aid), code));
      // a profile that tampers only through host implants, or covers its tracks only on hosts, still threatens the data
      // and the records a store holds: the generic data-store techniques stand in, unattributed (the reference
      // register's 'Extrapolated' rows); for repudiation, any of the profile's evasion techniques counts (masquerading
      // or permission changes on a host become the store's own log and file techniques)
      const extrapolated = !attributed.length && (code === 'T' || code === 'R') && f.e.type === 'datastore'
        && lens.techniques.some(aid => {
          const en = index.get(aid);
          return en && platformFit(en, f) && (strongFit(aid, code) || (code === 'R' && weakFit(en, code)));
        });
      const rank = aid => (PREFER[code].test(aid) ? 3 : 0) + (specific(index.get(aid), f) ? 2 : 0)
        + ([...f.tags].some(tag => TAG_PREFER[tag] && TAG_PREFER[tag].test(aid)) ? 2 : 0)
        + (f.external && /^T(1190|1133)\b/.test(aid) ? 3 : 0)
        + ((profile.used.get(aid) || { evidence: [] }).evidence.length > 1 ? 1 : 0);
      attributed.sort((a, b) => rank(b) - rank(a) || byAttackId(a, b));
      const lead = attributed.length ? rank(attributed[0]) : 0;
      const chosen = attributed.slice(0, 4);
      // (a data store's tampering is its data's: the data-tampering candidates come before a theme's extras, and for a
      // store of keys or identities, the accounts and policies that guard them before those; a partner or supplier is
      // impersonated through the trust it is given)
      const storeT = code === 'T' && f.e.type === 'datastore';
      const guarded = storeT && (f.tags.has('secrets') || f.tags.has('identity'));
      const partner = code === 'S' && f.e.type === 'entity' && f.tags.has('thirdparty');
      const pool = unique([...(guarded ? GUARD_CANDIDATES : []), ...(storeT ? CANDIDATES.T.datastore : []),
        ...(partner ? ['T1199'] : []), ...(lens.theme.extra[code] || []),
        ...(f.cloudHosted ? CLOUD_CANDIDATES[code] : []), ...(CANDIDATES[code][f.e.type] || [])]);
      const add = strict => {
        for (const aid of pool) {
          if (chosen.length >= Math.max(2, Math.min(4, attributed.length))) break;
          if (chosen.includes(aid) || chosen.some(c => c.split('.')[0] === aid && profile.used.has(c))) continue;
          const entry = index.get(aid);
          if (!entry || entry.model.domain === 'atlas' || (strict && !platformFit(entry, f)) || !allowed(aid, entry)) continue;
          chosen.push(aid);
        }
      };
      add(true);
      if (!chosen.length) add(false);   // nothing for this element's platform: the category still applies
      return { ids: chosen, observed: attributed.length > 0, extrapolated, lead };
    }

    /** The contextual gate (skill: StrideLM._applies), after the structural one. */
    function applies(code, f, emphasised) {
      if (!APPLICABLE[f.e.type].has(code)) return false;
      if (emphasised) return code !== 'I' || f.sensitive || f.e.type === 'datastore';
      switch (code) {
        case 'S': return f.auth || f.reachable || f.e.type === 'entity';
        case 'T': case 'R': return f.e.type !== 'entity';
        case 'I': return f.sensitive || f.e.type === 'datastore';
        case 'D': return flowsIn.get(f.e.id).length > 0 || f.e.type !== 'entity';
        case 'E': return f.e.type === 'process' || f.e.type === 'cluster' || f.reachable;
        case 'LM': return f.reaches.length > 0 && f.e.type !== 'entity';
        default: return false;
      }
    }

    function severity(code, f, emphasised, observed) {
      let score = IMPACT[code] + (observed ? 1 : 0);
      if (f.crownJewel) score += 3; else if (f.sensitive) score += 1;
      if (f.reachable) score += 1;   // the skill's exposure: any boundary crossing counts
      if (emphasised) score += 1;
      if (code === 'LM' && f.crossesOut) score += 1;
      return { score, severity: score >= 6 ? 'High' : score >= 4 ? 'Medium' : 'Low' };
    }

    // how specifically a theme is about this element: one aimed at a kind of element (hypervisors, network
    // devices) outranks a broad one (host compromise) on the elements it is about
    const specificity = (lens, f) => {
      const tags = (lens.theme.targets && lens.theme.targets.tags) || [];
      const hits = tags.filter(t => f.tags.has(t)).length;
      return hits ? hits / tags.length : 0;
    };

    const raised = [];          // { f, code, lens, ids, observed, sev }
    const coverage = new Map(); // element id -> { code: 'X' | 'o' | 'n/a' }
    const capped = new Map();   // element id -> cells that passed every gate but were left out (the cap)
    const lensInPlay = new Set();   // lenses that could raise a cell somewhere
    const lensBears = new Set();    // lenses that bear on some element (whether or not a technique fits)
    const bearsOn = new Map();      // element id -> the lenses that bear on it
    const stoodIn = new Map();      // element id -> the lenses whose cells generic techniques stand in for
    const found = [];
    for (const e of model.elements) {
      const f = facts.get(e.id);
      const cells = {};
      const bore = new Set();
      const spare = [];   // per category, the best lens that bears here but has no technique of the profile's that fits
      for (const code of CODES) {
        if (!APPLICABLE[e.type].has(code)) { cells[code] = 'n/a'; continue; }
        cells[code] = 'o';
        let best = null, strength = 0, top = -Infinity, alt = null;
        for (const lens of lenses) {
          if (!lens.theme.categories.includes(code) || !fitsTargets(lens, f)) continue;
          // a theme emphasises its first two categories; the generic lens none (the skill's default lens)
          const emphasised = lens.theme.key !== 'generic' && lens.theme.categories.slice(0, 2).includes(code);
          if (!applies(code, f, emphasised)) continue;
          lensBears.add(lens);
          bore.add(lens);
          const t = techniquesFor(lens, code, f);
          if (!t.ids.length) continue;
          const pos = lens.theme.categories.indexOf(code);
          const spec = specificity(lens, f);
          if (!t.observed && !t.extrapolated && lens.status === 'Observed') {
            const fit = (pos === 0 ? 3 : pos === 1 ? 1 : 0) + 1.5 * spec;
            if (!alt || fit > alt.fit) alt = { code, lens, ids: t.ids, emphasised, fit };
            continue;
          }
          lensInPlay.add(lens);
          // an extrapolated data-store tampering is still the profile's: it is recorded tampering with this
          // kind of host, only the data-level technique is generic
          const sev = severity(code, f, emphasised, t.observed || t.extrapolated);
          const score = (t.observed ? 20 : 0) + (pos === 0 ? 3 : pos === 1 ? 1 : 0) + t.lead + sev.score / 10;
          strength = Math.max(strength, Math.min(4, lens.techniques.length));
          top = Math.max(top, score);
          // which lens tells this cell: the best score, with a lens about this kind of element ahead of a broad one
          const fit = score + 1.5 * spec;
          if (!best || fit > best.fit || (fit === best.fit && spec > best.spec)) {
            best = { f, code, lens, ids: t.ids, observed: t.observed, sev, score, fit, spec };
          }
        }
        if (best) { found.push(Object.assign(best, { strength, top })); cells[code] = 'X'; } else if (alt) spare.push(alt);
      }
      bearsOn.set(e.id, bore);
      // A theme of the profile's bears on this element, but none of the profile's techniques runs here (a cloud tenancy
      // under a profile of host and ESXi techniques): rather than leave the element out of the model, generic STRIDE-LM
      // techniques stand in, unattributed and marked extrapolated, rated as a data store's extrapolated tampering is.
      if (!found.length && spare.length) {
        for (const s of spare) {
          lensInPlay.add(s.lens);
          const sev = severity(s.code, f, s.emphasised, true);
          found.push({ f, code: s.code, lens: s.lens, ids: s.ids, observed: false, sev, score: s.fit + sev.score / 10,
            strength: Math.min(4, s.lens.techniques.length), top: s.fit + sev.score / 10 });
          cells[s.code] = 'X';
        }
        stoodIn.set(e.id, unique(spare.map(s => s.lens)));
      }
      // the most-targeted elements carry the most events, as in a hand-built register
      const cap = ctx.uncapped ? Infinity : e.type === 'entity' ? 2 : f.crownJewel && f.exposed ? 5 : f.crownJewel || f.exposed ? 4 : 3;
      // keep what matters most here, and what the profile shows most of (a theme seen in one technique is a weak
      // signal), whichever lens tells the cell
      const weight = r => r.sev.score * 2 + r.strength;
      found.sort((a, b) => weight(b) - weight(a) || b.top - a.top || CODES.indexOf(a.code) - CODES.indexOf(b.code));
      for (const r of found.slice(cap)) cells[r.code] = 'o';
      if (found.length > cap) capped.set(e.id, found.slice(cap));
      raised.push(...found.slice(0, cap));
      found.length = 0;
      coverage.set(e.id, cells);
    }
    // a lens no row is drawn from says why, rather than sit in the threat profile unexplained
    for (const l of lenses) {
      if (raised.some(r => r.lens === l)) continue;
      const n = l.techniques.length;
      const why = lensInPlay.has(l) ? 'where it applies, another lens tells the threat better or the cell was left out to keep the register focused'
        : lensBears.has(l) ? 'its techniques fit none of its STRIDE-LM categories on the elements it bears on'
          : l.status === 'Observed' && n < 3 ? `the profile shows it in only ${n === 1 ? 'one technique' : 'two techniques'}, too few to bear on an element it is not specifically about`
            : 'it bears on no element of this architecture';
      l.evidence = `${l.evidence ? l.evidence + ' ' : ''}No register row is drawn from this lens: ${why}.`;
    }

    // ---- numbering (threat-event locations) in reading order: rows of zones, then position

    const orderOf = readingOrder(model);
    const attackLocations = model.elements.filter(e => raised.some(r => r.f.e.id === e.id)).sort((a, b) => orderOf(a) - orderOf(b));
    const dfdOf = new Map(attackLocations.map((e, i) => [e.id, i + 1]));

    // ---- events

    const actorFor = ids => {
      if (!profile.actors.length) return 'Generic external attacker (opportunistic)';
      const roots = new Set();
      for (const aid of ids) for (const r of (profile.used.get(aid) || { roots: [] }).roots) roots.add(r);
      const list = profile.actors.filter(a => roots.has(a.id));
      if (!list.length) return `${profile.actors.map(a => `${a.name} (${a.attackId})`).join(', ')} — extrapolated`;
      return list.map(a => `${a.name} (${a.attackId})`).join(', ');
    };
    const zoneLabel = e => (e.zone ? zoneById.get(e.zone).label : 'Outside defined zones');
    const flowName = fl => (fl.label ? fl.label : `the flow from ${elById.get(fl.source).label}`);
    const entryOf = f => {
      const inbound = flowsIn.get(f.e.id);
      const crossing = inbound.filter(fl => elById.get(fl.source).zone !== f.e.zone)
        .sort((a, b) => rankOf(elById.get(a.source)) - rankOf(elById.get(b.source)));
      if (crossing.length) return `via ${flowName(crossing[0])} from ${elById.get(crossing[0].source).label}, crossing a trust boundary`;
      if (inbound.length) return `via ${flowName(inbound[0])} from ${elById.get(inbound[0].source).label}`;
      if (f.external) return 'via its externally reachable interface';
      return 'from an already-compromised neighbouring element';
    };
    const techLabel = aid => index.get(aid).obj.name;
    const nameOf = aid => `${techLabel(aid)} (${aid})`;
    const hasTactic = (aid, list) => (index.get(aid).obj.tactics || []).some(t => list.includes(t));
    /** The data an element holds, from its sensitivity context: 'PII and national security data'. */
    const dataOf = (e, f) => {
      const raw = String(e.context.sensitivity || '').replace(/\s+/g, ' ').trim();
      const dash = raw.split(/\s+[—–-]\s+/);
      let text = dash.length > 1 ? dash.slice(1).join(' — ') : raw;
      // 'Confidential (customer data, transaction history)': the detail is in the brackets
      const m = /^([^()]*)\(([^()]+)\)$/.exec(text);
      if (m && (!m[1].trim() || isClassification(m[1].trim()))) text = m[2].trim();
      text = text.replace(/^(carries|holds|stores|contains|hosts|processes|keeps|handles)\s+/i, '');
      if (!text) return f.crownJewel ? 'crown-jewel data' : 'sensitive data';
      if (isClassification(text.replace(/\s+data$/i, ''))) return `${lower(text).replace(/\s+data$/, '')} data`;
      text = text.replace(CLASSIFICATION_HEAD, w => w.toLowerCase());   // 'Public / licensed data' mid-sentence
      // 'API keys, integration secrets' -> 'API keys and integration secrets'
      const items = text.split(/,\s+/);
      if (items.length > 1 && !/\b(and|or)\b|&/i.test(text) && !items.slice(1).some(x => /^(including|incl\b|such as|e\.g\.|for example|which|that|plus)/i.test(x))) {
        text = `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
      }
      if (DATA_NOUN.test(text)) return text;
      return /^(every|all|each|any)\b/i.test(text) ? `the data of ${text}` : `${text} data`;
    };
    /**
     * What a technique does to a data store, as [verb, verb for several actors, object]: for the step that cites it
     * ('…to alter the data it holds') and the event ('UNC3886 alters the data held in Model Registry').
     */
    const storeChange = aid => (/^T(1485|1561|0809)\b/.test(aid) ? ['destroys', 'destroy', 'the data held in {}', 'the data it holds']
      : /^T1486\b/.test(aid) ? ['encrypts', 'encrypt', 'the data held in {}', 'the data it holds']
        : /^T1491\b/.test(aid) ? ['defaces', 'deface', 'the content {} serves', 'the content it serves']
          : /^T(1195|1525)\b/.test(aid) ? ['plants', 'plant', 'tampered data or software in {}', 'tampered data or software in it']
            : GUARD_TAMPERING.test(aid) ? ['changes', 'change', 'the accounts, permissions or policies that guard {}', 'the accounts, permissions or policies that guard it']
              : ['alters', 'alter', 'the data held in {}', 'the data it holds']);
    /**
     * A sentence's subject: the actors MITRE records using every technique it cites (else any of them); when none
     * is recorded for those, the actors recorded for any of the row's techniques; else all of the profile's.
     */
    const subjectFor = (cited, ids) => {
      if (!profile.actors.length) return { name: 'An external attacker', plural: false };
      const who = actorsUsing(cited, profile) || actorsUsing(ids, profile) || profile.actors;
      return { name: namesOf(who), plural: who.length > 1 };
    };
    /** 'UNC3886 using T1190, T1068' or, for several actors, 'UNC3886 using T1190; Volt Typhoon using T1078'. */
    const recordedUse = ids => profile.actors.map(a => {
      const own = ids.filter(aid => profile.used.get(aid).roots.has(a.id));
      return own.length ? `${a.name} using ${own.join(', ')}` : '';
    }).filter(Boolean).join('; ');
    /** The nearest crown jewel past the hops already named (breadth first over what each element reaches). */
    const crownBeyond = (f, hops) => {
      const seen = new Set([f.e.id, ...hops]);
      let frontier = hops;
      while (frontier.length) {
        const next = [];
        for (const id of frontier) {
          for (const to of facts.get(id).reaches) {
            if (seen.has(to)) continue;
            if (facts.get(to).crownJewel) return to;
            seen.add(to);
            next.push(to);
          }
        }
        frontier = next;
      }
      return null;
    };

    function texts(r) {
      const { f, code, lens } = r;
      const e = f.e;
      const label = e.label;
      const z = e.zone ? zoneLabel(e) : '';
      const zone = !z ? '' : /\b(zone|layer|plane|environment|tier|network|segment|dmz|internet|cloud)\)?$/i.test(z) ? ` (${z})` : ` (${z} zone)`;
      // the event's subject: who MITRE records using the technique the sentence cites
      const as = cited => {
        const s = subjectFor(cited.filter(Boolean), r.ids);
        return { A: s.name, vb: (one, many) => (s.plural ? many : one), its: s.plural ? 'their' : 'its' };
      };
      // each step cites the technique that does what the step says, by its tactics; a step no chosen technique
      // fits keeps its generic wording
      const pick = (test, not = []) => r.ids.find(aid => !not.includes(aid) && test(aid)) || null;
      const name1 = nameOf(r.ids[0]);
      const entry = entryOf(f);
      const next = f.reaches.slice(0, 2).map(id => elById.get(id).label);
      const beyond = crownBeyond(f, f.reaches.slice(0, 2));
      const target = beyond ? elById.get(beyond).label : null;
      const sens = dataOf(e, f);
      const dependants = unique(flowsOut.get(e.id).map(fl => elById.get(fl.target).label)).slice(0, 2);
      const ending = lens.theme.ending;
      let seq, event;
      if (code === 'S') {
        const theft = pick(aid => CREDENTIAL_THEFT.test(aid) || (hasTactic(aid, ['credential-access']) && !AUTH_USE.test(aid)));
        const auth = pick(aid => AUTH_USE.test(aid), [theft]);
        const keep = pick(aid => hasTactic(aid, HOLD_TACTICS), [theft, auth]);
        const { A, vb } = as([auth || theft || r.ids[0]]);
        if (e.type === 'entity') {
          // spoofing an external entity: posing as it to the elements it talks to (STRIDE-per-element)
          const out = flowsOut.get(e.id).filter(fl => elById.get(fl.target).type !== 'entity');
          const via = out.length ? out : flowsIn.get(e.id).filter(fl => elById.get(fl.source).type !== 'entity');
          const peers = unique(via.map(fl => elById.get(out.length ? fl.target : fl.source).label));
          const to = peers.length ? andList(peers.slice(0, 2)) : 'the system';
          const first = via[0] && via[0].label ? `, over ${via[0].label}` : '';
          seq = [`Steal or forge the credentials of ${label}${theft ? ` with ${nameOf(theft)}` : ''}`,
            `${auth ? `${nameOf(auth)} to authenticate` : 'Authenticate'} to ${peers[0] || 'the system'} as ${label}${first}`,
            `Act within the access granted to ${label}, unnoticed`];
          event = `${A} ${vb('impersonates', 'impersonate')} ${label}${zone} to ${to}`
            + `${auth ? ` through ${nameOf(auth)}` : theft ? ` with credentials stolen through ${nameOf(theft)}` : ` through ${name1}`}, leading to ${ending}.`;
        } else {
          seq = [`Gather identity material for ${label} (${entry})${theft ? ` with ${nameOf(theft)}` : ''}`,
            auth ? `${nameOf(auth)} to authenticate as a trusted user or service` : 'Authenticate as a trusted user or service with that material',
            keep ? `${nameOf(keep)} to keep that access` : `Act on ${label} as that identity, unnoticed`];
          event = `${A} ${vb('authenticates', 'authenticate')} to ${label}${zone} as a legitimate user or service`
            + `${auth ? ` through ${nameOf(auth)}` : theft ? ` with identity material taken through ${nameOf(theft)}` : ` through ${name1}`}, leading to ${ending}.`;
        }
      } else if (code === 'T') {
        // step 3: a persistence technique keeps the change, a stealth one hides it; one that is itself the change
        // (an ICS command message, an impact technique) does neither
        const change = aid => hasTactic(aid, ['impact', 'impair-process-control', 'inhibit-response-function']);
        const persist = pick(aid => hasTactic(aid, ['persistence', 'persistence-ics']) && !change(aid), [r.ids[0]]);
        const hide = persist ? null : pick(aid => hasTactic(aid, HOLD_TACTICS) && !change(aid), [r.ids[0]]);
        const store = e.type === 'datastore';
        const [one, many, what, it] = storeChange(r.ids[0]);
        const { A, vb } = as([r.ids[0]]);
        seq = [`Gain write access to ${label} (${entry})`, `${name1} to ${store ? `${many} ${it}` : 'alter its data, code or configuration'}`,
          persist ? `${nameOf(persist)} so the change persists` : hide ? `${nameOf(hide)} to keep the change hidden`
            : 'Suppress integrity checks so the change persists unnoticed'];
        // a data store's tampering is its data's, whatever lens it came through: the lens's ending only when
        // the profile's own technique does it
        event = store
          ? `${A} ${vb(one, many)} ${what.replace('{}', label + zone)} through ${name1}${r.observed ? `, leading to ${ending}` : ''}; what depends on it now runs on tampered ground.`
          : `${A} ${vb('alters', 'alter')} the code, configuration or data of ${label}${zone} through ${name1}, leading to ${ending}; what depends on it now runs on tampered ground.`;
      } else if (code === 'R') {
        const { A, vb, its } = as([r.ids[0]]);
        seq = [`Obtain access to ${label}`, 'Carry out the consequential action', `${name1} so the activity cannot be attributed`];
        event = `${A} ${vb('covers its', 'cover their')} tracks on ${label}${zone} through ${name1}, so ${its} actions cannot be attributed afterwards — obstructing investigation and eroding the evidential value of the records.`;
      } else if (code === 'I') {
        const read = pick(aid => !hasTactic(aid, ['exfiltration'])) || r.ids[0];
        const exfil = pick(aid => hasTactic(aid, ['exfiltration']), [read]);
        const { A, vb } = as([read]);
        seq = [`Identify ${label} as holding ${sens}`, `Obtain read access (${entry}) with ${nameOf(read)}`,
          exfil ? `Stage the data and exfiltrate it with ${nameOf(exfil)}` : 'Stage, compress and exfiltrate the data'];
        event = `${A} ${vb('obtains', 'obtain')} ${sens} from ${label}${zone} through ${nameOf(read)}, resulting in ${ending}.`;
      } else if (code === 'D') {
        const { A, vb } = as([r.ids[0]]);
        seq = [`Map ${label} and what depends on it`, `${name1} against it`,
          dependants.length ? `${andList(dependants)} ${dependants.length === 1 ? 'loses' : 'lose'} service` : 'Dependent services lose service'];
        event = `${A} ${vb('makes', 'make')} ${label}${zone} unavailable through ${name1}, disrupting ${dependants.length ? andList(dependants) : 'the services that depend on it'}.`;
      } else if (code === 'E') {
        const foothold = pick(aid => FOOTHOLD.test(aid));
        const escalate = pick(aid => hasTactic(aid, ['privilege-escalation', 'privilege-escalation-ics']), [foothold]);
        const run = pick(aid => hasTactic(aid, ['execution', 'execution-ics']), [foothold, escalate]);
        const hold = pick(aid => hasTactic(aid, ['persistence', 'persistence-ics']), [foothold, escalate, run]);
        seq = [`Obtain a foothold on ${label} (${entry})${foothold ? ` with ${nameOf(foothold)}` : ''}`,
          escalate ? `${nameOf(escalate)} to gain administrative rights` : run ? `${nameOf(run)} to run code with administrative rights`
            : 'Exploit a vulnerability or misconfiguration to gain administrative rights',
          hold ? `Hold those rights with ${nameOf(hold)}` : escalate && run ? `Run commands with those rights through ${nameOf(run)}`
            : 'Operate with administrative or service-account rights'];
        const how = [foothold, escalate, run].filter(Boolean).slice(0, 2);
        const { A, vb } = as(how.length ? how : [r.ids[0]]);
        event = `${A} ${vb('gains', 'gain')} administrative control of ${label}${zone} through ${how.length ? andList(how.map(nameOf)) : name1}, removing the authorisation limits that contained the intrusion.`;
      } else {
        const { A, vb, its } = as([r.ids[0]]);
        seq = [`Compromise ${label}`, 'Harvest credentials or reuse its trusted connections', `${name1} to move to ${next[0] || 'adjacent systems'}`];
        if (target) seq.push(`Repeat toward ${target}`);
        event = `${A} ${vb('pivots', 'pivot')} from ${label}${zone} to ${andList(next) || 'adjacent systems'} through ${name1}${target ? `, extending ${its} reach toward ${target}` : ''}.`;
      }
      const ownIds = r.ids.filter(id => profile.used.has(id));
      const note = !profile.actors.length ? ''
        : ownIds.length ? ` MITRE ATT&CK records ${recordedUse(ownIds)}.`
          : ` The techniques are STRIDE-LM-derived for this element; MITRE ATT&CK does not record them for ${profile.who}.`;
      return { sequence: seq, event: event + note };
    }

    /**
     * What tampering with a data store amounts to. What the store is called comes before what it holds: a 'Model
     * Registry' keeps versioned models with their lineage, an 'Audit Logs & Model Lineage' store is a log.
     */
    function storeTampering(f, text, lead) {
      const name = lower(f.e.label);
      // a store of keys or secrets: its policies changed (the guards' techniques), or the keys themselves
      const keys = () => (GUARD_TAMPERING.test(lead) ? 'Key-policy tampering' : /^T(1485|1561)\b/.test(lead) ? 'Key destruction'
        : 'Key / secret tampering');
      if (/\b(log|logs|audit|siem|lineage)\b/.test(name)) return 'Log tampering';
      if (/\bregistry\b|\bmodels?\b/.test(name)) return 'Model swap / implant';
      if (/\b(key|keys|kms|hsm|secrets?|vault|certificates?|pki)\b/.test(name)) return keys();
      if (/\b(log|logs|audit|siem)\b/.test(text)) return 'Log tampering';
      if (/\bregistry\b|\bmodel (store|hub|repository|weights|artefacts?|artifacts?|versions?)\b/.test(text)) return 'Model swap / implant';
      return f.tags.has('secrets') ? keys() : 'Data manipulation';
    }

    /** A short octagon title that says what happens to this element (the reference's style), else the technique's. */
    function titleFor(code, f, ids, taken) {
      const text = lower(f.e.label + ' ' + f.e.context.purpose);
      const singular = entityNoun(f.e.label);
      const own = {
        I: f.tags.has('secrets') ? 'Secret extraction' : /backup/.test(text) ? 'Backup theft'
          : /registry|weights|checkpoint/.test(text) ? 'Model weight theft' : /lake|feature|dataset|data warehouse/.test(text) ? 'Dataset exfiltration'
            : /\b(log|logs|audit|lineage)\b/.test(text) ? 'Audit data theft' : f.ai && /application|assistant|chat/.test(text) ? 'Prompt / output collection'
              : f.e.type === 'datastore' ? 'Bulk data theft' : f.tags.has('virtualisation') ? 'Guest data theft'
                : f.tags.has('network') && ids.some(aid => /^T(1040|1557)/.test(aid)) ? 'Traffic capture'
                  : f.tags.has('cicd') ? 'Pipeline secret theft' : f.tags.has('identity') ? 'Credential theft'
                    : f.ai && /\btrain/.test(text) ? 'Checkpoint theft' : /develop|notebook|\bcode\b/.test(text) ? 'Code & secret theft'
                      : f.ai && /inferenc|serving/.test(text) ? 'In-memory weight theft'
                        : f.ai && /process|\betl\b|label/.test(text) ? 'Training data theft'
                          : /ingest|connector/.test(text) ? 'Connector data theft' : null,
        T: f.e.type === 'datastore' ? storeTampering(f, text, ids[0]) : null,
        R: /\b(log|logs|audit|siem|monitoring)\b/.test(text) ? 'Audit log deletion' : null,
        S: f.e.type === 'entity' && singular ? `Spoofed ${singular}` : null,
        LM: f.reaches.length ? `Pivot to ${shortLabel(elById.get(f.reaches[0]).label)}` : null,
      }[code];
      const candidates = [own, ...ids.map(aid => TITLES[aid] || TITLES[aid.split('.')[0]])].filter(Boolean);
      const pick = candidates.find(t => !taken.has(t));
      if (pick) return pick;
      return code === 'LM' && f.reaches.length ? `Pivot to ${shortLabel(elById.get(f.reaches[0]).label)}` : CATEGORY_TITLES[code];
    }

    const events = [];
    const titlesAt = new Map();
    const rankSev = { High: 3, Medium: 2, Low: 1 };
    raised.sort((a, b) => dfdOf.get(a.f.e.id) - dfdOf.get(b.f.e.id) || rankSev[b.sev.severity] - rankSev[a.sev.severity]
      || CODES.indexOf(a.code) - CODES.indexOf(b.code));
    for (const r of raised) {
      const e = r.f.e;
      const { sequence, event } = texts(r);
      const taken = titlesAt.get(e.id) || new Set();
      const title = titleFor(r.code, r.f, r.ids, taken);
      taken.add(title);
      titlesAt.set(e.id, taken);
      events.push({
        sn: events.length + 1, ai: false, lens: r.lens.id, threat: `${r.lens.id} ${r.lens.name}`,
        element: e.id, dfd: dfdOf.get(e.id), category: CAT[r.code].name, code: r.code,
        stride: `${CAT[r.code].name} (${r.code})`, maestro: null,
        actor: actorFor(r.ids),
        techniques: r.ids.map(aid => ({ id: aid, name: techLabel(aid), tactics: index.get(aid).tactics, attributed: profile.used.has(aid), atlas: false })),
        sequence, event, title, severity: r.sev.severity, score: r.sev.score,
        mitigations: r.ids.map(aid => ({ technique: aid, items: mitigationsOf(index.get(aid)) })), mitigationNote: '',
        detections: r.ids.map(aid => Object.assign({ technique: aid }, detectionsOf(index.get(aid), models))), detectionNote: '',
      });
    }

    // ---- AI pass: MAESTRO layers, ATLAS techniques

    const aiEvents = [];
    const casesOf = new Map();   // 'template element' -> the case studies an AI event cites
    let aiProfile = [];
    const aiElements = model.elements.filter(e => facts.get(e.id).ai);
    const atlasUsed = new Set([...profile.used.keys()].filter(aid => aid.startsWith('AML.')));
    if (aiElements.length && !atlasModel) {
      warnings.push('AI elements were found, but MITRE ATLAS isn’t loaded: pull ATLAS on the Data page to add the AI (MAESTRO / ATLAS) pass.');
    }
    if (aiElements.length && atlasModel) {
      const aiHits = [];
      // the external AI services each element sends data to (its C2 and exfiltration channel to the outside)
      const aiServicesOf = e => (e.type === 'entity' ? []
        : unique(flowsOut.get(e.id).map(fl => elById.get(fl.target)).filter(t => t.type === 'entity' && facts.get(t.id).ai).map(t => t.label)));
      for (const e of model.elements) {
        const f = facts.get(e.id);
        const aiServices = aiServicesOf(e);
        if (!f.ai && !aiServices.length) continue;
        const fitFacts = { type: e.type, layers: f.layers, text: f.text, aiServices };
        for (const th of AI_THREATS) {
          // only the element types a template is written for, within STRIDE-per-element (no exception); an element that
          // only calls an AI service, without being an AI element itself, gets only the AI-service C2 row
          if (!(th.types || ['process', 'cluster']).includes(e.type) || !APPLICABLE[e.type].has(th.code)
            || (!f.ai && th.key !== 'ai-api-c2') || !th.fit(fitFacts)) continue;
          const ids = th.techniques.filter(id => index.has(id) && index.get(id).model.domain === 'atlas').slice(0, 4);
          if (!ids.length) continue;
          aiHits.push({ e, f, th, ids, service: andList(aiServices.slice(0, 2)) });
        }
      }
      const aiOrder = model.elements.filter(e => aiHits.some(h => h.e.id === e.id)).sort((a, b) => orderOf(a) - orderOf(b));
      const aiDfd = new Map(aiOrder.map((e, i) => [e.id, attackLocations.length + i + 1]));
      aiHits.sort((a, b) => aiDfd.get(a.e.id) - aiDfd.get(b.e.id));
      for (const h of aiHits) {
        const { e, f, th } = h;
        const layers = th.layers.filter(l => f.layers.has(l)).length ? th.layers.filter(l => f.layers.has(l)) : [th.layers[0]];
        // 'L1/L6': the layers it touches, in layer order (an en dash would read as a range)
        const layerText = unique([...layers, ...th.layers]).sort(byAttackId).join('/');
        const score = IMPACT[th.code] + (f.crownJewel ? 3 : f.sensitive ? 1 : 0) + (f.reachable ? 1 : 0) + 2;
        const sev = score >= 6 ? 'High' : score >= 4 ? 'Medium' : 'Low';
        const found = h.ids.flatMap(id => caseStudiesOf(index.get(id)));
        const cases = found.filter((c, i) => found.findIndex(x => x.id === c.id) === i).slice(0, 2).map(c => `${c.name} (${c.id})`);
        casesOf.set(th.key + ' ' + e.id, cases);
        aiEvents.push({
          sn: 0, ai: true, aiThreat: th.key, lens: layers[0], threat: `MAESTRO ${layerText} — AI threat`,
          element: e.id, dfd: aiDfd.get(e.id), category: CAT[th.code].name, code: th.code,
          stride: `${CAT[th.code].name} (${th.code}) — via MAESTRO ${layerText}`, maestro: layerText,
          actor: h.ids.some(id => atlasUsed.has(id)) ? `${th.actor}; per the profile: ${actorFor(h.ids)}` : th.actor,
          techniques: h.ids.map(aid => ({ id: aid, name: techLabel(aid), tactics: index.get(aid).tactics, attributed: atlasUsed.has(aid), atlas: true })),
          sequence: th.sequence.map(s => s.replace('{label}', e.label).replace('{service}', h.service)),
          event: th.event.replace('{label}', e.label).replace('{service}', h.service)
            + `  [AI extension — MAESTRO ${layerText}${cases.length ? '; example: ' + cases.join('; ') : ''}]`,
          title: th.title, severity: sev, score,
          mitigations: h.ids.map(aid => ({ technique: aid, items: mitigationsOf(index.get(aid)) })), mitigationNote: '',
          detections: [], detectionNote: `AI telemetry logging (ATLAS AML.M0024). ${th.detect}`,
        });
      }
      aiProfile = LAYERS.filter(l => aiEvents.some(ev => ev.maestro.split('/').includes(l.id)))
        .map(l => {
          const ids = unique(aiEvents.filter(ev => ev.maestro.split('/').includes(l.id)).flatMap(ev => ev.techniques.map(t => t.id))).sort(byAttackId);
          const cases = unique(ids.flatMap(id => caseStudiesOf(index.get(id), 1).map(c => `${c.name} (${c.id})`))).slice(0, 3);
          return { layer: l.id, layerName: l.name, lens: l.lens, summary: l.summary, techniques: ids, caseStudies: cases.join('; ') };
        });
    }
    const allEvents = events.concat(aiEvents);
    allEvents.forEach((ev, i) => { ev.sn = i + 1; });

    // ---- locations

    const locations = [];
    for (const pass of [false, true]) {
      const byDfd = new Map();
      for (const ev of allEvents.filter(x => x.ai === pass)) {
        if (!byDfd.has(ev.dfd)) byDfd.set(ev.dfd, []);
        byDfd.get(ev.dfd).push(ev);
      }
      for (const [dfd, evs] of [...byDfd].sort((a, b) => a[0] - b[0])) {
        locations.push({
          dfd, element: evs[0].element, ai: pass, events: evs.map(x => x.sn), titles: unique(evs.map(x => x.title)),
          severity: evs.reduce((s, x) => (rankSev[x.severity] > rankSev[s] ? x.severity : s), 'Low'),
          layers: pass ? unique(evs.flatMap(x => x.maestro.split('/'))).join('·') : null,
        });
      }
    }

    // ---- attack sequences (CSA Table of Attack)

    const sequences = attackSequences({ model, facts, locations, events, elById, profile, flowsIn, flowsOut, models, index });
    sequences.push(...aiSequences({ model, facts, locations, aiEvents, elById, casesOf }));

    // ---- coverage tables

    const coverageRows = model.elements.slice().sort((a, b) => (dfdOf.get(a.id) || 1e6) - (dfdOf.get(b.id) || 1e6) || orderOf(a) - orderOf(b))
      .map(e => {
        const cells = coverage.get(e.id);
        const notes = [];
        if (e.type === 'entity') notes.push('External entity: only spoofing and repudiation apply (STRIDE-per-element).');
        const lensList = list => andList(list.slice().sort((a, b) => lenses.indexOf(a) - lenses.indexOf(b))
          .map(l => `${l.id} (${lcFirst(l.theme.short)})`));
        const bore = [...bearsOn.get(e.id)];
        if (!Object.values(cells).includes('X') && e.type !== 'entity') {
          notes.push(bore.length ? `${lensList(bore)} ${bore.length === 1 ? 'bears' : 'bear'} on this element, but no technique fits it; review the omissions.`
            : 'No profile theme bears on this element; review the omissions.');
        }
        const stand = stoodIn.get(e.id);
        if (stand) {
          notes.push(`${lensList(stand)} ${stand.length === 1 ? 'bears' : 'bear'} on this element, but none of the techniques MITRE records for ${profile.who} in ${stand.length === 1 ? 'that theme' : 'those themes'} fits it: generic STRIDE-LM techniques stand in, marked extrapolated.`);
        }
        // cells that passed every gate but fell below the per-element cap: shown, so the walk stays auditable
        const left = capped.get(e.id);
        if (left) notes.push(`Also in play, not raised to keep the register focused: ${left.map(r => `${CAT[r.code].name} (${r.sev.severity})`).join(', ')}.`);
        return { element: e.id, dfd: dfdOf.get(e.id) || null, cells, raised: Object.values(cells).filter(v => v === 'X').length, notes: notes.join(' ') };
      });
    const maestroCoverage = locations.filter(l => l.ai).map(l => ({
      element: l.element, dfd: l.dfd,
      layers: Object.fromEntries(LAYERS.map(x => [x.id, l.layers.split('·').includes(x.id)])),
      events: l.events.length,
    }));

    // ---- result

    const count = (list, s) => list.filter(x => x.severity === s).length;
    const knowledge = Object.values(models).filter(Boolean).filter(m => m.meta)
      .map(m => ({ domain: m.domain, name: ((global.AttackDB && AttackDB.DOMAINS || []).find(d => d.id === m.domain) || {}).title || m.domain,
        version: m.meta.version || '' }))
      .filter(k => k.domain !== 'atlas' || aiEvents.length || atlasUsed.size);
    const resolved = Object.assign({}, model, {
      elements: model.elements.map(e => Object.assign({}, e, { crownJewel: facts.get(e.id).crownJewel, ai: facts.get(e.id).ai })),
    });
    return {
      version: 1,
      system: ctx.system || model.name || 'the system',
      generatedAt: new Date().toISOString(),
      model: resolved,
      profile: {
        label: profile.label, short: profile.short,
        actors: profile.actors.map(a => ({ attackId: a.attackId, name: a.name, kind: a.kind, domain: a.domain })),
        knowledge,
        software: profile.software, campaigns: profile.campaigns,   // [{ id, name }], for the Claude enrichment
      },
      lenses: lenses.map(l => ({ id: l.id, name: l.name, evidence: l.evidence, techniques: l.techniques, status: l.status,
        categories: l.theme.categories })),
      aiProfile,
      events: allEvents,
      locations,
      sequences,
      coverage: coverageRows,
      maestroCoverage,
      stats: {
        elements: model.elements.length, flows: model.flows.length,
        zones: model.zones.length,   // every trust zone of the decomposition, a zone that only holds other zones too
        locations: locations.filter(l => !l.ai).length, aiLocations: locations.filter(l => l.ai).length,
        events: events.length, high: count(events, 'High'), medium: count(events, 'Medium'), low: count(events, 'Low'),
        aiEvents: aiEvents.length, aiHigh: count(aiEvents, 'High'), aiMedium: count(aiEvents, 'Medium'), aiLow: count(aiEvents, 'Low'),
        techniques: unique(allEvents.flatMap(ev => ev.techniques.map(t => t.id))).length,
        attributed: unique(allEvents.flatMap(ev => ev.techniques.filter(t => t.attributed).map(t => t.id))).length,
      },
      method: { decomposition: (model.source && model.source.method) || 'manual', enrichment: 'offline' },
      warnings: unique([...(model.warnings || []), ...warnings]),
    };
  }

  /** Reading order for numbering: zones in rows (top to bottom, then left to right), then position in the zone. */
  function readingOrder(model) {
    const zoneOf = new Map(model.zones.map(z => [z.id, z]));
    const leaf = e => (e.zone ? zoneOf.get(e.zone) : null);
    const pos = new Map();
    const withGeo = model.elements.filter(e => e.geometry);
    if (withGeo.length === model.elements.length && withGeo.length) {
      // band rows by zone top, so a zone's elements stay together; an element outside every zone joins the row of
      // the zone level with its centre (a zone's top is always above its own elements)
      const zoned = model.zones.filter(z => z.geometry);
      const rowTop = e => {
        const cy = e.geometry.y + e.geometry.h / 2;
        const level = zoned.filter(z => z.geometry.y <= cy && cy <= z.geometry.y + z.geometry.h)
          .sort((a, b) => b.geometry.y - a.geometry.y)[0];
        return level ? level.geometry.y : e.geometry.y;
      };
      const top = e => { const z = leaf(e); return z && z.geometry ? z.geometry.y : rowTop(e); };
      const left = e => { const z = leaf(e); return z && z.geometry ? z.geometry.x : e.geometry.x; };
      const tops = unique(model.elements.map(top)).sort((a, b) => a - b);
      const h = Math.max(1, ...model.elements.map(e => e.geometry.h));
      const band = y => tops.filter(t => t <= y + h / 2).length;   // tops within half an element height share a row
      const sorted = model.elements.slice().sort((a, b) => band(top(a)) - band(top(b)) || left(a) - left(b)
        || (a.geometry.x + a.geometry.w / 2) - (b.geometry.x + b.geometry.w / 2) || a.geometry.y - b.geometry.y);
      // within a zone: columns left to right, top to bottom in each
      const zoneRank = new Map();
      sorted.forEach(e => { const k = e.zone || '-' + e.id; if (!zoneRank.has(k)) zoneRank.set(k, zoneRank.size); });
      const col = e => Math.round((e.geometry.x + e.geometry.w / 2) / (h * 1.5));
      const final = model.elements.slice().sort((a, b) => zoneRank.get(a.zone || '-' + a.id) - zoneRank.get(b.zone || '-' + b.id)
        || col(a) - col(b) || a.geometry.y - b.geometry.y);
      final.forEach((e, i) => pos.set(e.id, i));
    } else {
      const zoneIndex = new Map(model.zones.map((z, i) => [z.id, i]));
      model.elements.slice().sort((a, b) => (a.zone ? zoneIndex.get(a.zone) : -1) - (b.zone ? zoneIndex.get(b.zone) : -1)
        || model.elements.indexOf(a) - model.elements.indexOf(b)).forEach((e, i) => pos.set(e.id, i));
    }
    return e => pos.get(e.id);
  }

  /** A label without its bracketed detail or second half (before ' / ' or ' & '), at most four words. */
  function shortLabel(s) {
    const plain = String(s).replace(/\s*\([^)]*\)\s*/g, ' ').trim();
    let head = plain.split(/\s+[/&]\s+|,\s+/)[0].trim();
    if (!head.includes(' ')) head = plain;   // 'Storage & Backup', not 'Storage'
    const w = head.split(/\s+/).slice(0, 4);
    while (w.length > 1 && /^(&|\/|-|and|of|the|for|to)$/i.test(w[w.length - 1])) w.pop();
    return w.join(' ');
  }

  /** What an external entity is, singular: 'Third-Party Vendors' -> 'vendor', 'External AI Services' -> 'AI service'. */
  function entityNoun(label) {
    const plain = String(label).replace(/\s*\([^)]*\)\s*/g, ' ').trim();
    let words = plain.split(/\s+[/&]\s+|,\s+/)[0].trim().split(/\s+/);
    if (words.length === 1 && words[0].length <= 3) words = plain.split(/\s+/);
    words = words.filter(w => /[A-Za-z]/.test(w));
    if (!words.length) return '';
    const sing = w => (/ies$/i.test(w) ? w.slice(0, -3) + 'y' : /ss$/i.test(w) ? w : w.replace(/s$/i, ''));
    const keepCase = w => (/[A-Z].*[A-Z]/.test(w) ? w : w.toLowerCase());
    const last = words[words.length - 1];
    // 'Partner B', 'Site 2': the identifier names the entity, so keep it with its noun as written
    if (words.length > 1 && /^([A-Za-z]|\d+)$/.test(last)) return `${keepCase(words[words.length - 2])} ${last}`;
    const out = [sing(last)];
    if (/^(sources?|systems?|services?|providers?|data|users?|clients?|devices?|support)$/i.test(last) && words.length > 1) out.unshift(words[words.length - 2]);
    return out.map(keepCase).join(' ');
  }

  // ---------------------------------------------------------------- attack sequences

  /**
   * Entry points to crown jewels over the data-flow graph (either direction: an attacker rides trust,
   * not just data, though against a one-way flow costs more), from one threat-event location to the next.
   * Diverse paths first; up to seven.
   */
  function attackSequences({ model, facts, locations, events, elById, profile, flowsIn, flowsOut, models, index }) {
    const locs = locations.filter(l => !l.ai);
    const locOf = new Map(locs.map(l => [l.element, l]));
    if (locs.length < 2) return [];
    const adj = new Map(model.elements.map(e => [e.id, []]));
    for (const f of model.flows) {
      adj.get(f.source).push({ to: f.target, cost: 1 });
      adj.get(f.target).push({ to: f.source, cost: f.bidirectional ? 1 : 1.4 });
    }
    /**
     * The shortest routes from one entry to every location it can reach, through threat-event locations only: an
     * element without a threat event is no step of a sequence of threat events, and a hop past it would skip it on the
     * diagram. One search per entry, with a binary heap; ties go to the element reached first.
     */
    const routesFrom = from => {
      const dist = new Map([[from, 0]]), prev = new Map(), seen = new Map([[from, 0]]), done = new Set();
      const heap = [[0, 0, from]];   // [distance, order first reached, element]
      const less = (a, b) => a[0] < b[0] || (a[0] === b[0] && a[1] < b[1]);
      const push = item => {
        heap.push(item);
        for (let i = heap.length - 1; i > 0;) {
          const up = (i - 1) >> 1;
          if (!less(heap[i], heap[up])) break;
          [heap[i], heap[up]] = [heap[up], heap[i]];
          i = up;
        }
      };
      const pop = () => {
        const top = heap[0], last = heap.pop();
        if (heap.length) {
          heap[0] = last;
          for (let i = 0; ;) {
            const l = 2 * i + 1, r = l + 1;
            let m = i;
            if (l < heap.length && less(heap[l], heap[m])) m = l;
            if (r < heap.length && less(heap[r], heap[m])) m = r;
            if (m === i) break;
            [heap[i], heap[m]] = [heap[m], heap[i]];
            i = m;
          }
        }
        return top;
      };
      while (heap.length) {
        const [d, , u] = pop();
        if (done.has(u) || d > dist.get(u)) continue;
        done.add(u);
        for (const { to: v, cost } of adj.get(u)) {
          if (!locOf.has(v) || done.has(v)) continue;
          const nd = d + cost;
          if (!dist.has(v) || nd < dist.get(v)) {
            if (!seen.has(v)) seen.set(v, seen.size);
            dist.set(v, nd);
            prev.set(v, u);
            push([nd, seen.get(v), v]);
          }
        }
      }
      return to => {
        if (!dist.has(to)) return null;
        const out = [to];
        while (out[0] !== from) out.unshift(prev.get(out[0]));
        return out;
      };
    };
    // a hop that follows a flow (or a two-way one), rather than running against a one-way flow
    const follows = (a, b) => flowsOut.get(a).some(fl => fl.target === b);
    const byElement = new Map(model.elements.map(e => [e.id, []]));
    for (const ev of events) byElement.get(ev.element).push(ev);
    const evAt = id => byElement.get(id);
    const sevRank = { High: 3, Medium: 2, Low: 1 };
    const entryScore = id => {
      const f = facts.get(id);
      const evs = evAt(id);
      const techs = evs.flatMap(ev => ev.techniques.map(t => t.id));
      return (f.external && f.e.type !== 'entity' ? 3 : 1) + (f.rank === 1 ? 1 : 0)
        // where the outside comes in: an external entity sends to it directly
        + (flowsIn.get(id).some(fl => facts.get(fl.source).e.type === 'entity' && facts.get(fl.source).rank <= 1) ? 1 : 0)
        + (techs.some(t => /^T(1190|1133)\b/.test(t)) ? 3 : techs.some(t => /^T(1199|1195|1566)\b/.test(t)) ? 2 : 0)
        + Math.max(0, ...evs.map(ev => sevRank[ev.severity])) / 3;
    };
    const lensShort = ev => {
      const th = THEMES.find(t => ev.threat.includes(t.name));
      return th ? th.short : 'Initial access';
    };
    const is = (tid, root) => tid === root || tid.startsWith(root + '.');
    // the way in, most telling first, and what to call a path that starts with it
    const ENTRY = [['T1190', 'Edge exploitation'], ['T1133', 'Remote-access abuse'], ['T1199', 'Trusted-party abuse'],
      ['T1195', 'Supply-chain compromise'], ['T1566', 'Phishing'], ['T1210', 'Remote exploitation'],
      ['T1556', 'Authentication bypass'], ['T1078', 'Credential abuse']];
    /** How the attacker gets in at an entry: the event, the technique it cites for that, and the path's name. */
    const entryOf = id => {
      const evs = evAt(id).slice().sort((x, y) => sevRank[y.severity] - sevRank[x.severity]);
      const found = (roots, list) => {   // an event that leads with the way in, then one that uses it at all
        for (const [root, name] of roots) { const ev = list.find(x => is(x.techniques[0].id, root)); if (ev) return { ev, tid: ev.techniques[0].id, name }; }
        for (const [root, name] of roots) {
          for (const ev of list) { const t = ev.techniques.find(x => is(x.id, root)); if (t) return { ev, tid: t.id, name }; }
        }
        return null;
      };
      // reached through a supplier or partner rather than the public: the trusted relationship is the way in
      const from = flowsIn.get(id).map(fl => facts.get(fl.source)).filter(src => src.e.zone !== facts.get(id).e.zone && src.rank <= 1);
      const trusted = from.length && from.every(src => src.tags.has('thirdparty'))
        && found([['T1195', 'Supply-chain compromise'], ['T1199', 'Trusted-party abuse'], ['T1078', 'Trusted-party abuse']], evs);
      if (trusted) return trusted;
      const entry = found(ENTRY, evs);
      if (entry) return entry;
      // otherwise spoofing, escalation or an initial-access technique; never the theft or disruption that comes later
      const ev = evs.find(x => x.code === 'E' || x.code === 'S');
      if (ev) return { ev, tid: ev.techniques[0].id, name: lensShort(ev) };
      for (const x of evs) {
        const t = x.techniques.find(y => (y.tactics || []).includes('Initial Access'));
        if (t) return { ev: x, tid: t.id, name: lensShort(x) };
      }
      return null;
    };
    const supplier = id => facts.get(id).tags.has('thirdparty') && evAt(id).some(ev => /^T(1199|1195|1078)/.test(ev.techniques[0].id));
    const entries = locs.map(l => l.element)
      .filter(id => (facts.get(id).external && ['process', 'cluster'].includes(facts.get(id).e.type)) || (facts.get(id).e.type === 'entity' && supplier(id)))
      .filter(id => entryOf(id))   // a way in the register shows
      .sort((a, b) => entryScore(b) - entryScore(a)).slice(0, 6);
    // what the attacker is after: a crown jewel of the system (not an external entity)
    const targets = locs.map(l => l.element).filter(id => facts.get(id).crownJewel && facts.get(id).e.type !== 'entity');
    if (!entries.length || !targets.length) return [];
    const candidates = [];
    for (const a of entries) {
      const route = routesFrom(a);
      const start = entryScore(a) * 3;
      for (const b of targets) {
        if (a === b) continue;
        const steps = route(b);
        if (!steps || steps.length < 2 || steps.length > 6) continue;
        const weight = steps.reduce((s, id) => s + Math.max(...evAt(id).map(ev => sevRank[ev.severity])), 0);
        // a path of three to five threat events tells the story best (CSA Table of Attack), one that follows the
        // flows better than one that runs against them
        const n = steps.length;
        const against = steps.slice(1).filter((id, k) => !follows(steps[k], id)).length;
        candidates.push({ steps, score: start + (weight / n) * 2 + Math.min(n, 5) * 0.6
          - Math.max(0, n - 5) * 1.5 - (n < 3 ? 2 : 0) - against * 1.5 });
      }
    }
    candidates.sort((x, y) => y.score - x.score);
    const chosen = [];
    for (const c of candidates) {
      const set = new Set(c.steps);
      const clash = chosen.some(s => {
        const overlap = s.steps.filter(id => set.has(id)).length / Math.min(s.steps.length, c.steps.length);
        return s.steps[s.steps.length - 1] === c.steps[c.steps.length - 1] || overlap >= 0.6;
      }) || chosen.filter(s => s.steps[0] === c.steps[0]).length >= 2;
      if (!clash) chosen.push(c);
      if (chosen.length >= 7) break;
    }
    // A crown jewel no sequence ends at still gets its best route while slots remain, even one that shares most of its
    // steps with a chosen sequence; not a route every step of which a chosen sequence already walks.
    for (const c of candidates) {
      if (chosen.length >= 7) break;
      const end = c.steps[c.steps.length - 1];
      if (chosen.some(s => s.steps[s.steps.length - 1] === end || c.steps.every(id => s.steps.includes(id)))) continue;
      chosen.push(c);
    }
    chosen.sort((x, y) => y.score - x.score);   // most telling first, as the first pass chose them
    const objective = id => {
      const evs = evAt(id);
      const codes = new Set(evs.map(ev => ev.code));
      return codes.has('I') ? 'data theft' : codes.has('T') ? 'tampering' : codes.has('D') ? 'disruption' : 'compromise';
    };
    /** What a step's technique does, in the octagon's words: the event's own title when it is about this technique. */
    const techTitle = (ev, tid) => TITLES[tid] || TITLES[tid.split('.')[0]] || ev.techniques.find(t => t.id === tid).name;
    const stepTitle = (ev, tid) => {
      const aboutOne = ev.techniques.some(t => (TITLES[t.id] || TITLES[t.id.split('.')[0]]) === ev.title);
      return ev.code !== 'LM' && (aboutOne ? ev.title === techTitle(ev, tid) : tid === ev.techniques[0].id) ? ev.title : techTitle(ev, tid);
    };
    // which of the narrative's actors MITRE records using a step's technique
    const usersOf = (tid, who) => who.filter(a => profile.used.has(tid) && profile.used.get(tid).roots.has(a.id));
    // a step names who uses its technique when only some of the narrative's actors do, and on a path otherwise recorded
    // for them, says so when none does (a path with nothing recorded is marked extrapolated as a whole)
    const tell = (s, who, recorded) => {
      const by = usersOf(s.tid, who);
      const note = !who.length || by.length === who.length ? ''
        : by.length ? `, used by ${namesOf(by)}` : recorded ? `, not recorded for ${who.length === 1 ? who[0].name : 'any of them'}` : '';
      const cite = `${s.tid}${note}`;
      return s.pivot ? `pivot to ${shortLabel(elById.get(s.pivot).label)} (${cite})` : `${lcFirst(stepTitle(s.ev, s.tid))} (${cite})`;
    };
    /** A narrative's subject: the actors MITRE records using every step it cites, else any (all when none is). */
    const subjectOf = ids => {
      if (!profile.actors.length) return { name: 'The attacker', plural: false, list: [] };
      const recorded = actorsUsing(ids, profile);
      const list = recorded || profile.actors;
      return { name: namesOf(list), plural: list.length > 1, list, recorded: !!recorded };
    };
    // each actor's MITRE campaigns, with the techniques each campaign used
    const campaignsOf = new Map();
    for (const a of profile.actors) {
      const m = models[a.domain];
      if (!m || !global.SimEngine.attributedTo) continue;
      campaignsOf.set(a.id, global.SimEngine.attributedTo(m, a.id).map(c => ({ name: c.name, attackId: c.attackId,
        uses: new Set(m.from(c.id, 'uses', 'technique').map(r => (m.byId.get(r.target) || {}).attackId).filter(Boolean)) })));
    }
    /** Real-world examples for a path: the campaigns of its own actors, those that used the path's techniques first. */
    const campaignNote = (who, ids) => {
      const own = who.flatMap(a => campaignsOf.get(a.id) || []).filter((c, k, all) => all.findIndex(x => x.attackId === c.attackId) === k);
      if (!own.length) return '';
      const names = namesOf(who);
      const used = own.map(c => ({ c, ids: ids.filter(id => c.uses.has(id)) })).filter(x => x.ids.length)
        .sort((x, y) => y.ids.length - x.ids.length);
      if (!used.length) {
        return `MITRE ATT&CK campaigns attributed to ${names}: ${own.slice(0, 3).map(c => `${c.name} (${c.attackId})`).join('; ')}; none of them is recorded using a technique on this path.`;
      }
      return `MITRE ATT&CK campaigns attributed to ${names} that used techniques on this path: `
        + `${used.slice(0, 3).map(x => `${x.c.name} (${x.c.attackId}), using ${andList(x.ids.slice(0, 4))}`).join('; ')}.`;
    };
    return chosen.map((c, i) => {
      const first = c.steps[0], last = c.steps[c.steps.length - 1];
      const way = entryOf(first);
      // the event that tells each step: the way in, then movement to the next step, then the objective
      const goal = objective(last);
      const goalCode = { 'data theft': 'I', tampering: 'T', disruption: 'D' }[goal];
      const stepEvents = c.steps.map((id, k) => {
        const label = elById.get(id).label;
        if (k === 0) return { id, label, ev: way.ev, tid: way.tid };
        const evs = evAt(id).slice().sort((x, y) => sevRank[y.severity] - sevRank[x.severity]);
        if (k === c.steps.length - 1) {
          const ev = evs.find(x => x.code === goalCode) || evs[0];
          return { id, label, ev, tid: ev.techniques[0].id };
        }
        // a pivot only where this element reaches the next step; otherwise what the attacker does here
        const next = c.steps[k + 1];
        const lm = facts.get(id).reaches.includes(next) && evs.find(x => x.code === 'LM');
        if (lm) return { id, label, ev: lm, tid: lm.techniques[0].id, pivot: next };
        const ev = ['E', 'S', 'T', 'R', 'I', 'D', 'LM'].map(code => evs.find(x => x.code === code)).find(Boolean);
        return { id, label, ev, tid: ev.techniques[0].id };
      });
      const cited = stepEvents.map(s => s.tid);
      const onPath = unique(stepEvents.flatMap(s => s.ev.techniques.filter(t => t.attributed).map(t => t.id)));
      const subj = subjectOf(cited.some(aid => profile.used.has(aid)) ? cited : onPath);
      const vb = (one, many) => (subj.plural ? many : one);
      const [head, ...rest] = stepEvents;
      const tail = rest.pop();
      const tellOf = x => tell(x, subj.list, subj.recorded);
      const narrative = `${subj.name} ${vb('gets', 'get')} in at ${head.label} — ${tellOf(head)}. `
        + (rest.length ? `From there ${vb('it reaches', 'they reach')} ${rest.map(x => `${x.label} — ${tellOf(x)}`).join('; then ')}. ` : '')
        + `${vb('It ends', 'They end')} at ${tail.label} — ${tellOf(tail)}.`;
      const pathIds = unique(stepEvents.flatMap(s => [s.tid, ...s.ev.techniques.map(t => t.id)]));
      const examples = [campaignNote(subj.list, pathIds),
        onPath.length ? `ATT&CK techniques recorded for the profile on this path: ${onPath.slice(0, 8).join(', ')}.` : '',
        !onPath.length ? 'Path built from STRIDE-LM-derived techniques; not observed for the profile in MITRE ATT&CK.' : '']
        .filter(Boolean).join(' ');
      // 'Government Data theft', not 'Government Data data theft'
      const where = shortLabel(elById.get(last).label);
      const what = goal === 'data theft' && /\bdata$/i.test(where) ? 'theft' : goal;
      // a way in MITRE doesn't record for the actors named (or a path with nothing recorded) is extrapolated, as in a
      // hand-built register
      const extrapolated = profile.actors.length > 0 && (!subj.recorded || !usersOf(way.tid, subj.list).length);
      return {
        id: String(i + 1), ai: false,
        title: `${way.name} to ${where} ${what}${extrapolated ? ' (extrapolated)' : ''}`,
        entry: `${elById.get(first).label} — ${facts.get(first).e.zone ? model.zones.find(z => z.id === facts.get(first).e.zone).label : 'outside defined zones'}`,
        // the threat actor is whom the narrative names
        actor: !profile.actors.length ? way.ev.actor
          : `${subj.list.map(a => `${a.name} (${a.attackId})`).join(', ')}${extrapolated ? ' — extrapolated' : ''}`,
        steps: c.steps.map(id => locOf.get(id).dfd),
        path: c.steps,
        narrative: sentence(narrative), examples, layers: null,
      };
    });
  }

  /** The AI attack sequences that this architecture's AI elements make possible. */
  function aiSequences({ model, facts, locations, aiEvents, elById, casesOf }) {
    const locs = locations.filter(l => l.ai);
    const at = key => locs.filter(l => aiEvents.some(ev => ev.element === l.element && ev.aiThreat === key));
    const one = key => at(key)[0] || null;
    const patterns = [
      { title: 'Indirect prompt injection to agentic data exfiltration',
        roles: [['rag-poisoning'], ['indirect-injection', 'agent-abuse'], ['model-extraction', 'ai-dos'], ['ai-api-c2']], need: 2,
        entry: e => `${e} — attacker-controlled content retrieved into the application's context`,
        actor: 'Indirect-injection adversary (content author); no platform credentials required',
        narrative: 'The adversary plants instructions in content the retrieval pipeline indexes. A user query pulls the poisoned content into the model context; the injected instructions hijack the application or agent, which invokes tools and sends data out through an external AI service.' },
      { title: 'Data and model poisoning to backdoored decision support',
        roles: [['data-poisoning'], ['model-backdoor'], ['poisoned-model'], ['model-extraction', 'ai-dos'], ['direct-injection']], need: 2,
        entry: e => `${e} — poisoned training data or a compromised training step`,
        actor: 'Malicious insider or AI supply-chain adversary',
        narrative: 'Crafted samples or a manipulated training step plant a backdoor in the model. The backdoored version passes evaluation, is registered and promoted, and is then served to the applications whose decisions it quietly steers.' },
      { title: 'AI supply-chain compromise to production',
        roles: [['unsafe-artefact', 'supply-chain', 'poisoned-tool'], ['poisoned-model'], ['model-extraction', 'ai-dos']], need: 2,
        entry: e => `${e} — a poisoned model, package or agent tool from a supplier`,
        actor: 'AI supply-chain adversary',
        narrative: 'A poisoned model, package or agent tool enters through development or the MLOps pipeline, is promoted with the pipeline’s own trust, and runs in production with access to the data and tools of the serving platform.' },
      { title: 'Model extraction and training-data inference via the API',
        roles: [['direct-injection'], ['model-extraction', 'model-inversion']], need: 1,
        entry: e => `${e} — the inference API, with legitimate or stolen access`,
        actor: 'Model-extraction adversary (API consumer)',
        narrative: 'With legitimate or stolen API access, the adversary queries the model systematically to reconstruct it, infer whether given records were in its training data and recover its system prompts.' },
    ];
    const out = [];
    for (const p of patterns) {
      const steps = [], keys = [];   // each role's location, and the threat that puts it there
      for (const roles of p.roles) {
        const key = roles.find(k => one(k));
        const loc = key ? one(key) : null;
        if (loc && !steps.includes(loc)) { steps.push(loc); keys.push(key); }
      }
      if (steps.length < p.need || (p.need === 1 && !steps.some(s => s === one('model-extraction') || s === one('model-inversion')))) continue;
      // two real-world examples from the threats on the path, each once
      const examples = unique(steps.flatMap((s, i) => casesOf.get(keys[i] + ' ' + s.element) || [])).slice(0, 2);
      // the MAESTRO layers the path crosses, in path order: those of the threat that puts each step on it
      const layers = unique(steps.flatMap((s, i) => {
        const ev = aiEvents.find(x => x.element === s.element && x.aiThreat === keys[i]);
        return ev ? ev.maestro.split('/') : [];
      }));
      out.push({
        id: 'AI-' + (out.length + 1), ai: true, title: p.title,
        entry: p.entry(elById.get(steps[0].element).label), actor: p.actor,
        steps: steps.map(s => s.dfd), path: steps.map(s => s.element),
        narrative: p.narrative,
        examples: examples.join('; '),
        layers: layers.join(' → '),
      });
    }
    return out;
  }

  // ---------------------------------------------------------------- Claude enrichment

  /**
   * What Claude needs to write richer, actor-specific text (no IDs it could change): the draft register, the profile's
   * MITRE-recorded software and campaigns (the only ones it may name), and each event's flows, so a sequence follows
   * the way the diagram connects the element (shared decision I7).
   */
  function enrichmentRequest(result) {
    const elById = new Map(result.model.elements.map(e => [e.id, e]));
    const zoneById = new Map(result.model.zones.map(z => [z.id, z]));
    const zone = id => (zoneById.has(id) ? zoneById.get(id).label : 'Outside defined zones');
    // dir 'in': from the peer to the element; 'out': from the element to the peer (a two-way flow is both)
    const flowsOf = new Map(result.model.elements.map(e => [e.id, []]));
    const side = (fl, at, peer, dir) => {
      const p = elById.get(peer);
      if (p && flowsOf.has(at)) flowsOf.get(at).push({ dir, peer: p.label, label: fl.label || '', zone: zone(p.zone) });
    };
    for (const fl of result.model.flows) {
      side(fl, fl.source, fl.target, 'out');
      side(fl, fl.target, fl.source, 'in');
      if (fl.bidirectional) { side(fl, fl.source, fl.target, 'in'); side(fl, fl.target, fl.source, 'out'); }
    }
    const named = list => (Array.isArray(list) ? list : []).map(x => ({ id: String(x.id), name: String(x.name || '') }));
    return {
      system: result.system,
      profile: result.profile.label,
      lenses: result.lenses.map(l => ({ id: l.id, name: l.name, evidence: l.evidence })),
      software: named(result.profile.software),
      campaigns: named(result.profile.campaigns),
      events: result.events.map(ev => {
        const e = elById.get(ev.element);
        return {
          sn: ev.sn, ai: ev.ai, element: e.label, type: e.type, zone: zone(e.zone),
          context: e.context, category: ev.stride, lens: ev.threat, actor: ev.actor,
          techniques: ev.techniques.map(t => `${t.id} ${t.name}${t.attributed ? ' (attributed to the profile)' : ''}`),
          title: ev.title, sequence: ev.sequence, event: ev.event,
          flows: flowsOf.get(ev.element) || [],
        };
      }),
      sequences: result.sequences.map(s => ({ id: s.id, title: s.title, entry: s.entry, actor: s.actor,
        path: s.path.map(id => elById.get(id).label), narrative: s.narrative })),
    };
  }

  /** Claude's text as it will be stored: compatibility forms folded (full-width digits), invisible characters gone. */
  const cleanText = s => String(s).normalize('NFKC').replace(/\p{Cc}/gu, ' ').replace(/[\p{Cf}\p{Default_Ignorable_Code_Point}]/gu, '');
  // Letters from other scripts (and small capitals) that look like Latin ones: 'Т1059' with a Cyrillic Т reads
  // as T1059, 'evіl.com' with a Cyrillic і as evil.com.
  const FOLD = {};
  for (const [to, from] of Object.entries({
    A: 'ΑАᎪꓮᴀ', B: 'ΒВᏴꓐʙ', C: 'ϹСᏟꓚᴄ', D: 'ᎠꓓԀᴅ', E: 'ΕЕᎬꓰᴇ', G: 'ᏀԌꓖɢ', H: 'ΗНᎻꓧʜ', I: 'ΙІӀꓲɪ', J: 'ЈᎫꓙᴊ',
    K: 'ΚКᏦꓗᴋ', L: 'ᏞꓡⳐʟ', M: 'ΜМᎷꓟᴍ', N: 'Νꓠɴ', O: 'ΟОՕꓳᴏ', P: 'ΡРᏢꓑᴘ', R: 'Ꮢꓣʀ', S: 'ЅᏚꓢꜱ', T: 'ΤТᎢꓔⲦᴛ',
    U: 'ꓴᴜ', V: 'Ꮩꓦᴠ', W: 'Ꮃꓪᴡ', X: 'ΧХꓫ', Y: 'ΥҮꓬʏ', Z: 'ΖᏃꓜᴢ',
    a: 'аɑα', c: 'сϲ', d: 'ԁ', e: 'еҽ', g: 'ɡց', h: 'һ', i: 'іιɩ', j: 'ј', k: 'κ', l: 'ӏ', m: 'м', o: 'оοօ',
    p: 'рρ', q: 'ԛ', s: 'ѕ', t: 'тτ', u: 'υս', v: 'νѵ', w: 'ԝ', x: 'хχ', y: 'уγ',
  })) for (const ch of from) FOLD[ch] = to;
  const FOLDABLE = new RegExp(`[${Object.keys(FOLD).join('')}]`, 'gu');
  /**
   * A text as its reader sees it, for the checks only: accents, other combining marks and invisible characters
   * gone, look-alike letters folded to Latin, and O / l between digits read as 0 / 1 ('T1O59').
   */
  const shown = s => s.normalize('NFKD').replace(/[\p{M}\p{Default_Ignorable_Code_Point}]/gu, '').replace(FOLDABLE, ch => FOLD[ch])
    .replace(/[Oo](?=\d)|(?<=\d)[Oo]/g, '0').replace(/[Il|](?=\d)|(?<=\d)[Il|]/g, '1').normalize('NFKC');
  // Every identifier shape Claude could write: ATT&CK techniques, tactics, mitigations, groups, software,
  // campaigns, data sources, detection strategies and analytics; ATLAS techniques, mitigations and case studies;
  // CVEs. With blanks, dashes or underscores inside ('T 1059', 'T‑1059', 'T 1 0 5 9', 'AML . T0051'), a slash or a dot
  // after the letter ('T/1059', 'T.1059'), wrapped in markdown ('_T1059_') or glued to a word ('viaT1059',
  // 'throughCVE-2024-3400'); but a possessive or a contraction before a year isn't one ('the vendor's 2024 advisory').
  // Numbers follow MITRE's: groups G0001-G1999, software S0001-S1999 and S9001- (ATT&CK v20), campaigns C0001-C0999,
  // so a 'Catalyst C9300' switch or an 'S3000' array is a product. Every family is read in any case when the digits
  // follow at once or after a dash or underscore ('ds0017', 'Ta-0001'); after a blank, tactics, data sources, detection
  // strategies and analytics only in capitals ('an 8443 port' is no analytic).
  const SEP = String.raw`[\s\p{Pd}_·⠀]{0,3}`;
  const TIGHT = String.raw`[\p{Pd}_·⠀]{0,3}`;   // no blank
  const DIGITS = String.raw`(?:[\s\p{Pd}_·⠀]?\d){3}(?:${SEP}\.${SEP}\d{3})?(?!\d)`;   // after the first digit
  // which families may be in lower case: the one-letter ones (T, M, G, S, C), the longer ones (TA, DS, DET, AN)
  const family = (sep, single, longer) => {
    const c = (l, any) => (any ? [...l].map(x => `[${x}${x.toLowerCase()}]`).join('') : l);
    return `(?:(?:${['TA', 'DS', 'DET', 'AN'].map(l => c(l, longer)).join('|')}|${c('T', single)}|${c('M', single)})${sep}\\d`
      + `|${c('G', single)}${sep}[01]|${c('S', single)}${sep}[019]|${c('C', single)}${sep}0)${DIGITS}`;
  };
  const START = String.raw`(?<![\p{L}\p{N}])`;   // '(T1059)' and '_T1059_' start an identifier; 'XT1059' doesn't
  const ID_SHAPES = new RegExp(String.raw`[Aa][Mm][Ll]${SEP}\.${SEP}(?:[Tt]|[Mm]|[Cc][Ss])${SEP}\d{4}(?:${SEP}\.${SEP}\d{3})?(?!\d)`
    + String.raw`|[Cc][Vv][Ee]${SEP}\d{4}${SEP}\d{4,7}(?!\d)`
    + `|${START}${family(TIGHT, true, true)}|(?<=\\p{Ll})${family('', false, false)}`
    + `|(?<!\\p{L}['’ʼ])${START}${family(SEP, true, false)}|${START}${family('[./]', false, false)}`, 'gu');
  const normId = id => id.toUpperCase().replace(/[^A-Z0-9.]/g, '').replace(/^(AML\.)?([A-Z]+)\.(?=\d)/, '$1$2');
  const idsIn = text => (shown(cleanText(text || '')).match(ID_SHAPES) || []).map(normId);
  // an ID-like token (one to three letters before four digits) with a letter that is still not Latin after
  // folding: a look-alike the fold doesn't know ('Ƭ1059')
  const LOOKALIKE = new RegExp(String.raw`(?<![\p{L}\p{N}])(?=\p{L}{0,2}(?![A-Za-z])\p{L})\p{L}{1,3}(?:\.\p{L}{1,2})?${SEP}\d{4}`, 'u');
  // Links and addresses: nothing in a register sends its reader anywhere. A dotted name is a host when it ends in a
  // top-level domain: a country code (but not .py, .sh, .md, .rs, .so, .tf or .id, which name files and fields far
  // more often) or a generic one in common use. Code ('pickle.load', 'user.id'), files ('setup.py') and products
  // ('Node.js', 'ASP.NET') look like hosts but aren't addresses.
  const TLDS = new Set(('ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo bq br bs bt '
    + 'bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo '
    + 'fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu ie il im in io iq ir is it je jm jo jp ke '
    + 'kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw '
    + 'mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw qa re ro ru rw sa sb sc sd se '
    + 'sg si sk sl sm sn sr ss st su sv sx sy sz tc td tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg '
    + 'vi vn vu wf ws ye yt za zm zw '
    + 'com net org info biz pro mobi int gov edu mil aero arpa asia cat coop jobs museum post tel travel xxx onion example '
    + 'test invalid local localdomain internal corp lan intranet xyz top online site shop store club vip icu fun live link '
    + 'click page website blog news app dev tech cloud space digital agency services solutions support systems software '
    + 'center company group global world today life work works one plus zone team help wiki guide fyi codes download review '
    + 'trade ltd llc inc bar rest buzz monster cyou sbs cfd bond quest uno ninja rocks cool guru expert win bid loan loans '
    + 'men racing party science accountant cricket faith webcam gdn kim country best cam ink press pics mom beauty hair skin '
    + 'makeup autos homes boats yachts lol wtf fail sucks art design studio media social events video games bet casino '
    + 'academy institute foundation community education university school finance bank money credit insurance legal law '
    + 'health care energy city market business ventures partners management consulting marketing technology engineering '
    + 'computer hosting domains tips kiwi tokyo nyc london paris berlin moscow amsterdam africa lat').split(' '));
  const PRODUCT = /^(?:asp|vb|ado|ml|ext|system|microsoft|[cfj]#)\.net$|^(?:socket|draw)\.io$|^diagrams\.net$/i;
  // what ends a file name rather than a host ('docker-compose.yml', 'app.py:12')
  const FILE_TYPE = /^(?:txt|log|md|json|ya?ml|xml|html?|css|[cm]?js|jsx|tsx?|py[cw]?|ipynb|sh|bash|zsh|ps1|psm1|psd1|bat|cmd|vbs|hta|exe|dll|sys|msi|jar|war|apk|dmg|pkg|deb|rpm|iso|img|vmdk|vhdx?|ova|ovf|qcow2|bin|dat|db|sqlite|sql|bak|tmp|cfg|conf|config|ini|toml|env|properties|lock|pem|crt|cer|der|key|pfx|p12|jks|csr|pub|gpg|asc|sig|zip|gz|tgz|tar|bz2|xz|7z|rar|cab|zst|pdf|docx?|xlsx?|xlsm|pptx?|csv|tsv|rtf|png|jpe?g|gif|svg|bmp|ico|tiff?|webp|mp[34]|mov|avi|wav|eml|msg|pst|evtx|pcap|pcapng|har|onnx|pth?|pkl|pickle|joblib|h5|ckpt|safetensors|gguf|tflite|pb|npz|npy|parquet|c|h|cpp|hpp|cc|cs|java|go|rb|rs|php|aspx?|jsp|pl|pm|lua|r|swift|kt|scala|tf|tfvars|hcl|drawio|vsdx|so|dylib|ko|efi|rom|elf)$/i;
  const HOST = /^((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+)([a-z]{2,24})\.?(:\d{1,5})?(?:[/?#]\S*)?$/i;
  const IDN_HOST = /^(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?\.)+(\p{L}{2,24})\.?(?:[/?#]\S*)?$/u;
  const FETCHED = /^[a-z0-9.-]+\.[a-z]{2,24}(?::\d{1,5})?\/\S*\.(?:exe|dll|msi|ps1|bat|cmd|scr|hta|vbs|jar|apk|dmg|iso|pkg|deb|rpm|bin|zip|rar|7z|sh|py|js)$/i;
  const IPV6 = /^\[?((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(?:%[\w.-]+)?\]?(?::\d{1,5})?(?:[/?#]\S*)?$/i;
  /** Whether one token names a host: a known top-level domain, or any name with a hyphenated label or a port. */
  function isHost(tok) {
    if (/(?:^|\.)xn--[a-z0-9]/i.test(tok) && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+\.?(?:[:/?#]\S*)?$/i.test(tok)) return true;   // punycode
    const idn = IDN_HOST.exec(tok);
    if (idn && /[^\x00-\x7f]/.test(idn[1])) return true;   // a name in another script ('пример.рф')
    const m = HOST.exec(tok);
    if (!m || !/[a-z]/i.test(m[1]) || PRODUCT.test(tok.split(/[/?#:]/)[0])) return false;   // ('5.0.GA' is a version)
    return TLDS.has(m[2].toLowerCase()) || (!FILE_TYPE.test(m[2]) && (m[1].includes('-') || !!m[3]));
  }
  /** Whether one token is an IPv6 address: compressed ('fe80::1%eth0', '[2001:db8::1]:8443') or all eight groups. */
  function isIPv6(tok) {
    if (tok.includes('::') && /^[0-9a-f:.]+$/i.test(tok) && /[0-9a-f]:|:[0-9a-f]/i.test(tok)) return true;   // '::ffff:192.0.2.1'
    const m = IPV6.exec(tok);
    return !!m && (m[1].includes('::') ? /[0-9a-f]/i.test(m[1]) : m[1].split(':').length === 8);
  }
  /** Whether one token, without the punctuation around it, is a URL, e-mail address, host or IP address. */
  function isAddress(raw) {
    const tok = raw.replace(/^[("'‘“<[{]+/, '').replace(/[)"'’”>\]},.;:!?]+$/, '');
    if (!tok) return false;
    if (/^(?:mailto|javascript|vbscript|tel|sms|callto|magnet):\S|^data:[a-z]+\/[\w.+-]+[;,]|^www\.\S|^h[x*]{2}ps?:/i.test(tok)) return true;
    if (/^[^@]+@[^@]+\.[a-z]{2,}$/i.test(tok)) return true;
    if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:[/?#]\S*)?$/.test(tok) && tok.split(/[.:/?#]/, 4).every(n => Number(n) <= 255)) return true;
    return isIPv6(tok) || isHost(tok) || FETCHED.test(tok);
  }
  // a dot written out, or spaced, before a common top-level domain ('evil dot com', 'evil . com')
  const SPELLED_DOT = /[\p{L}\p{N}](?:\s+dot\s+|\s+\.\s+)(?:com|net|org|info|biz|io|ru|cn|xyz|top|online|site)\b/iu;
  /** Whether a text holds a URL (defanged too), e-mail address, host, IP address, UNC path or phone number. Linear. */
  function hasLink(text) {
    if (/\+\d[\d\s().-]{6,}\d/.test(text)) return true;
    // (an ideographic full stop or a middle dot between Latin letters reads as a dot: 'evil。com', 'evil·com')
    const t = text.replace(/(?<=[a-z0-9])[。｡·‧・∙⋅](?=[a-z0-9])/gi, '.');
    if (SPELLED_DOT.test(t)) return true;
    for (const raw of t.split(/\s+/)) {
      if (/:\/\/|:\\\\|^\\\\\w|^\/\/\w|\[[.:@]\]|\((?:\.|dot|at)\)|\[(?:dot|at)\]|\{(?:\.|dot)\}/i.test(raw)) return true;
      // a scheme with one slash or a backslash ('https:/evil.com/fix.exe', 'https:\evil.com')
      if (/(?:^|[^a-z])(?:https?|ftps?|sftp|file|smb|wss?|ssh|ldaps?):[/\\]/i.test(raw)) return true;
      if (isAddress(raw)) return true;
      // Markdown, quotes, brackets, dashes, arrows and possessives glued to an address aren't part of it ('**evil.com**',
      // '`ops@evil.com`', 'mirror—evil.com—today', 'evil.com’s', '_evil.com_'), nor is a word before a ':' or '/'
      // ('via:evil.com/fix.exe'): each piece is tested, and again from each ':' or '/' where a dotted name starts
      // (the first twelve; past them the dotted name alone, so a long token stays linear).
      for (const part of raw.replace(/[^\p{L}\p{N}.@:/_-]+/gu, ' ').split(' ')) {
        const piece = part.replace(/^_+|_+$/g, '');
        if (!piece) continue;
        if (piece !== raw && isAddress(piece)) return true;
        let tried = 0;
        const at = /[:/]/g, head = /[^:/]*/y;
        for (let m = at.exec(piece); m; m = at.exec(piece)) {
          head.lastIndex = m.index + 1;
          const name = head.exec(piece)[0];
          if (!/[.@]/.test(name)) continue;
          if (tried++ < 12 ? isAddress(piece.slice(m.index + 1)) : isAddress(name)) return true;
        }
      }
    }
    return false;
  }
  const clip = (s, n) => String(s || '').replace(/\s+/g, ' ').trim().slice(0, n).replace(/[\uD800-\uDBFF]$/, '').trim();
  /**
   * One field of Claude's text, cleaned and clipped, or null when it can't be used: not a string, without a
   * letter, a link or address, a look-alike ID, or an identifier that `own` (what the event already carries)
   * doesn't hold. The checks read the text as it will be stored and shown.
   */
  function vetted(text, own, max) {
    if (typeof text !== 'string') return null;
    const t = clip(cleanText(text), max);
    if (!/\p{L}/u.test(t)) return null;
    const seen = shown(t);
    if (hasLink(seen) || LOOKALIKE.test(seen)) return null;
    // an identifier is written plainly: one that appears only once marks and look-alikes are read is disguised
    const ids = seen.match(ID_SHAPES) || [];
    if (ids.length !== (t.match(ID_SHAPES) || []).length) return null;
    return ids.every(id => own.has(normId(id))) ? t : null;
  }
  // an AI event's note, as the engine writes it; any imitation in Claude's text (another dash, unclosed) goes
  const AI_SUFFIX = /\[AI extension —[^\]]*\]/;
  const AI_NOTE_LIKE = /\[\s*AI extension\b[^\]]*(?:\]|$)/gi;

  /**
   * Merge Claude's text into the result. Only event titles, sequences and texts, and sequence titles and
   * narratives, change; technique IDs, mitigations, detections and severities never come from Claude. A field
   * is used only when every MITRE or CVE identifier in it is one the event already carries (its techniques,
   * mitigations, the case studies and IDs of its offline text), one of the profile's actors, or software or a campaign
   * the request listed for the profile, and it has no link or address; otherwise it keeps the offline text. An AI
   * event keeps its '[AI extension — …]' note.
   */
  function applyEnrichment(result, reply) {
    let changed = 0, refused = 0;
    // the profile's actors, and the software and campaigns the request listed for it (I7)
    const actors = [...(result.profile.actors || []).map(a => a.attackId),
      ...[...(result.profile.software || []), ...(result.profile.campaigns || [])].map(x => x && x.id)]
      .map(id => normId(String(id || ''))).filter(Boolean);
    const carried = ev => new Set([...actors, ...ev.techniques.map(t => normId(t.id)),
      ...(ev.mitigations || []).flatMap(m => (m.items || []).map(x => normId(x.id))),
      ...[ev.title, ev.event, ev.mitigationNote, ev.detectionNote, ev.actor, ...(ev.sequence || [])].flatMap(idsIn)]);
    const take = (obj, key, value) => {
      if (value === null) { refused++; return; }
      if (JSON.stringify(obj[key]) !== JSON.stringify(value)) { obj[key] = value; changed++; }
    };
    const bySn = new Map(result.events.map(ev => [ev.sn, ev]));
    const seen = new Set();   // an event or sequence answered twice counts once, as first answered
    for (const r of (reply && Array.isArray(reply.events) ? reply.events : [])) {
      const ev = r && bySn.get(Number(r.sn));
      if (!ev || seen.has(ev)) continue;
      seen.add(ev);
      const own = carried(ev);
      if (r.title !== undefined) take(ev, 'title', vetted(r.title, own, 40));
      if (r.sequence !== undefined) {
        const steps = Array.isArray(r.sequence) && r.sequence.length >= 2 && r.sequence.length <= 6
          ? r.sequence.map(x => vetted(x, own, 240)) : [null];
        take(ev, 'sequence', steps.every(x => x !== null) ? steps : null);
      }
      if (r.event !== undefined) {
        // an AI event's note (its MAESTRO layers and real-world examples) is the engine's, whatever Claude wrote
        const note = ev.ai ? (ev.event.match(AI_SUFFIX) || [''])[0] : '';
        const body = typeof r.event === 'string' ? cleanText(r.event).replace(AI_NOTE_LIKE, ' ') : r.event;
        const text = vetted(body, own, note ? Math.max(300, 900 - note.length - 2) : 900);
        take(ev, 'event', text === null ? null : note ? `${text}  ${note}` : text);
      }
    }
    const seqById = new Map(result.sequences.map(s => [s.id, s]));
    for (const r of (reply && Array.isArray(reply.sequences) ? reply.sequences : [])) {
      const s = r && seqById.get(String(r.id));
      if (!s || seen.has(s)) continue;
      seen.add(s);
      const own = new Set([...actors, ...idsIn(s.narrative), ...idsIn(s.examples), ...idsIn(s.actor),
        ...result.events.filter(ev => s.path.includes(ev.element) && ev.ai === s.ai).flatMap(ev => [...carried(ev)])]);
      if (r.title !== undefined) take(s, 'title', vetted(r.title, own, 90));
      if (r.narrative !== undefined) take(s, 'narrative', vetted(r.narrative, own, 1200));
    }
    for (const l of result.locations) {
      l.titles = unique(l.events.map(sn => bySn.get(sn).title));
    }
    if (refused) {
      result.warnings.push(`${refused} of Claude’s text field${refused === 1 ? '' : 's'} ${refused === 1 ? 'was' : 'were'} not used (blank, a link or address, or an identifier the event doesn’t carry): ${refused === 1 ? 'it keeps' : 'they keep'} the offline engine’s text.`);
    }
    if (changed) result.method = Object.assign({}, result.method, { enrichment: 'claude' });
    return changed;
  }

  global.TMEngine = {
    run, CATEGORIES, THEMES, LAYERS, AI_THREATS, APPLICABLE, enrichmentRequest, applyEnrichment, readingOrder,
  };
})(window);
