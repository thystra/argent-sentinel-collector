# Changelog

## 0.4.4 — 2026-07-24

- Move the redirected test-mode notice to the very top of individual abuse
  reports and close it with a matching marker, leaving the production message
  body visually intact beneath the test-only wrapper.

## 0.4.3 — 2026-07-24
- Reformat individual Nginx abuse reports to match the established operator-facing report structure.
- Include source ports, public destination IPs, internally observed destination IPs, destination ports, Host headers, protocols, statuses, categories, targets, and user agents.
- Resolve or configure public target addresses without misreporting private reverse-proxy/NAT destinations.
- Attach a XARF v4.2.0 `connection/vulnerability_scan` `xarf.json` containing standard destination fields, hashed evidence, and every correlated connection tuple.
- Preserve test-mode recipient isolation and annotate the production suppression disposition.
- Permit `AF_NETLINK` in the packaged collector unit so Postfix sendmail can enumerate local interfaces.
- Add regression tests for MIME formatting, XARF content, target-address selection, and systemd packaging.


## 0.4.2 — 2026-07-24

- Make the configured test-mode recipient override authoritative for incident reports.
- Send test reports only to the override address; administrative Bcc delivery is disabled in test mode.
- Continue redirected test delivery when RDAP/RIPE enrichment is unavailable.
- Bypass trusted, non-global, and CrowdSec-allowlisted source suppression only in test mode.
- Label test mail prominently and record the production suppression or protection-check result in the message and audit detail.
- Preserve production source-protection behavior and all age, cutoff, duplicate, cooldown, daily-limit, and per-run guardrails.

## 0.4.1 — 2026-07-24

- Recognize OpenSSH `Invalid user ... from ... port ...` preauthentication probes as privacy-preserving SSH failure events.
- Avoid double-counting paired invalid-user close and failed-authentication records.
- Give the central API a dedicated runtime socket while retaining compatibility with the v0.4.0 socket path.
- Keep all shared runtime directories traversable by Nginx and preserved across one-shot service exits.
- Add regression coverage for IPv6 invalid-user probes, duplicate suppression, runtime paths, and version consistency.

## 0.4.0 — 2026-07-24

- Added mTLS remote node delivery through `sentinel.argentwolf.org`.
- Added an idempotent Unix-socket central ingestion API with node/site authorization.
- Added privacy-preserving OpenSSH failure collection and report policies.
- Ported high-confidence Nginx exploit-probe and bounded scanner classification from the legacy reporter.
- Added legacy sent-marker import and guarded test/production cutover tooling.
- Added source/destination tuple evidence for WordPress, Nginx, and SSH reports.
- Added operator-gated CIDR escalation mail with duplicate suppression.
- Extended Debian packages with agent/API services, PKI helpers, and remote configuration.

## 0.3.1 — 2026-07-24

- Add reproducible Debian binary-package builds for `common`, `agent`, `server`,
  and combined installations.
- Add package-owned systemd units under `/usr/lib/systemd/system`.
- Preserve existing live configuration and create a consistent SQLite backup
  before package-driven schema migration.
- Add a dedicated idempotent `migrate` command and schema-version metadata.
- Safely archive legacy systemd overrides only when they point at the previous
  `/usr/local/libexec` installation.
- Keep the v0.3.1 agent package limited to local spooling and onboarding; remote
  HTTPS delivery remains the v0.4 boundary.

## 0.3.0 — 2026-07-24

- Add normalized Nginx abuse-context JSON/JSONL ingestion.
- Add network observation, correlation, and network-case SQLite tables.
- Correlate WordPress events with network tuples by trusted request ID, with a
  bounded timestamp/path fallback.
- Include source/destination ports and protocols in abuse reports when evidence
  is available.
- Include recent qualifying CIDR context in individual incident reports.
- Add manual `network-list` and `network-set` commands without automatic CIDR
  enforcement.
- Add stable node/FQDN/central-service configuration for the future remote agent.
- Add WordPress and Nginx onboarding/staging helpers.
- Improve cutoff suppression details to include the incident `last_seen` value.

## 0.2.2 — 2026-07-23

- Add abuse-report activation cutoff, age gate, per-run limit, recipient
  cooldown, recipient daily limit, retry backoff, audit history, and test-mode
  constraints.
- Preserve cross-filesystem safe batch claiming and enrichment/status fixes.
