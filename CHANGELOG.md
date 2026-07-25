# Changelog
## 0.5.0.1 — 2026-07-25
- Deliver the dashboard configuration through a systemd read-only credential,
  fixing startup when `/etc/argent-sentinel` is root-only.
- Establish `argent_site_access` as the complete per-site Nginx format while
  retaining filtered `argent_sentinel_json` as the security correlation feed.
- Normalize legacy combined and current extended records into per-site AWStats
  streams instead of passing all mixed-format logs to every site.
- Consolidate `www` aliases, skip ambiguous shared hostless records, and make
  sites without matching logs non-fatal.
- Add proposed-inventory, inspection, and per-site stream commands.
- Document the dashboard, two-log architecture, AWStats migration, and all new
  commands in README.md.

## 0.5.0 — 2026-07-25
- Add a read-only operator dashboard designed for
  `sentinel.argentwolf.org`.
- Generate bounded dashboard snapshots from the collector database under the
  existing shared lock; the unprivileged web process never opens SQLite.
- Add LAN plus HTTP Basic authentication Nginx configuration while preserving
  mTLS enforcement for `/v1/ingest`.
- Add per-site static AWStats discovery, configuration, update, and report
  generation using `%virtualname` filtering for shared extended Nginx logs.
- Add cross-log repeated-source, crawler, incident, report, Fail2ban, and
  network-case views.
- Add an operator crawler policy that permits `FacebookExternalHit` and blocks
  `Meta-ExternalAgent` with HTTP 403 responses.
- Exclude configured policy-denied User-Agents from generic high-volume
  scanner materialization while retaining hostile-path detection.
- Correct 429 review classification so sustained-path enumeration requires one
  source address; distributed crawler groups no longer receive both labels.
## 0.4.10.1 — 2026-07-25
- Permit the hardened daily-review service to write only within the collector
  state directory so SQLite can manage WAL shared-memory state.
- Retain URI `mode=ro`, `PRAGMA query_only=ON`, and the shared collector lock
  inside the review process.
- Add a SQLite busy timeout for the review connection.
- Correct operator validation documentation to use the actual
  `network_observations.occurred_at` and `occurred_epoch` columns.

## 0.4.10 — 2026-07-25
- Open the daily review database under the collector lock using SQLite
  query-only read-only mode under the collector lock so the hardened systemd unit can read the WAL-mode
  database without write access to the collector directory.
- Add a minute-level Nginx access-log tailer that exports HTTP 429 responses as
  review-only abuse-context observations.
- Canonicalize crawler identities and group distributed IPv6 pressure by `/48`
  while retaining sustained single-source path enumeration as a separate
  review signal.
- Prefer RDAP `registered_cidr` for network-case grouping and fall back to
  locally derived IPv4 `/24` and IPv6 `/64` candidate prefixes.
- Add review-only 180- and 365-day CIDR block recommendations based on distinct
  hostile addresses, incidents, and active days.
- Include CIDR cases and suggested expiration periods in the 07:00 operator
  digest; automatic CIDR enforcement remains disabled.

## 0.4.9 — 2026-07-25

- Treat externally sourced OpenSSH failures as immediately reportable after
  trusted-address checks.
- Treat Nginx requests deliberately returned as HTTP 444 as immediate hostile
  web incidents while keeping HTTP 429 traffic review-only.
- Expand the WordPress correlation window to 15 minutes without lowering its
  five-failure threshold.
- Record local Fail2ban ban notices as immutable audit events.
- Add a daily 07:00 local operator review digest for HTTP 429 pressure,
  Fail2ban bans, incidents, and report failures.
- Group distributed IPv6 crawler pressure at `/48` by default.
- Add `ARCHITECTURE.md`, `TODO.md`, and Fail2ban/review policy documentation.
- Record the missing WordPress WP-CLI `setup` subcommand as the next plugin
  blocker; the dashboard remains deferred.
- Preserve the complete SSH and Nginx evidence segment after an immediate
  one-event trigger instead of truncating the incident to its first row.
- Preserve existing nested operator configuration during package migration;
  only explicitly introduced release keys are added to existing sections.
- Record `85.203.47.0/24` and `193.37.32.0/24` as operator-review CIDR
  investigation examples rather than automatic deny rules.

## 0.4.8 — 2026-07-24

- Fix OpenSSH account-token normalization for canonical v0.4.7
  `account_key` event payloads.
- Continue accepting legacy v0.4.6 `account_hash` payloads.
- Add regression coverage through `normalize_batch()` so tests exercise the
  complete payload-normalization path rather than calling the database layer
  directly.
- Verify normalized SSH batches retain distinct pseudonymous accounts and can
  satisfy the credential-spray correlation rule.

## 0.4.7 — 2026-07-24

- Emit canonical `account_key` values for new OpenSSH event batches.
- Accept legacy v0.4.6 `account_hash` values while importing parked batches.
- Append required remote event and abuse-context globs to preserved configs
  without replacing operator reporting, policy, or node settings.
- Run the backed-up, idempotent config migration from server `postinst`.
- Rename collector counters from WordPress files to event batch files.
- Expand new-system, configuration, and WordPress onboarding documentation.
- Document the current WordPress admin-diagnostics limitation; plugin UI fixes
  are deferred until the collector path is stable.

## 0.4.6 — 2026-07-24

- Package the dedicated Nginx abuse-context logrotate service and hourly timer.
- Install a default logrotate rule when one is not already configured.
- Preserve an existing operator-managed logrotate rule during upgrades.
- Archive recognized temporary local Nginx logrotate units so package-owned
  units become authoritative.
- Enable and start the Nginx logrotate timer from the server package postinst.
- Use logrotate's standard shared state so hourly and system-wide runs cannot
  independently rotate the same active file.
- Stop and disable the timer during package removal.
- Add packaging regression tests that materialize the server package root and
  verify the new units and default rule are installed.

## 0.4.5 — 2026-07-24

- Preserve complete Nginx incident evidence after a sliding window first
  reaches the hostile-probing threshold.
- Split web-probe candidates into contiguous segments, so a later unrelated
  probe group is not pulled into an earlier incident.
- Retain redirected test-mode delivery safeguards: only the configured
  recipient override receives test reports.

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
