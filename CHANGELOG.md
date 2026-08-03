## 0.5.5.1
### Debian revision 0.5.5.1-2

- Do not execute the PHP-FPM event-mechanism configuration probe when the
  operator accepts any mechanism. The hardened watchdog service cannot open the
  PHP-FPM main and pool log paths under `ProtectSystem=strict`, and a diagnostic
  probe must not make otherwise healthy service checks fail.
- Preserve explicit event-mechanism enforcement. A failed or indeterminate
  enforced probe remains a warning, and private status records include bounded
  return-code, timeout, and stderr-tail diagnostics.
- Retain observe-only PHP-FPM behavior and the hardened systemd filesystem
  boundary; no PHP-FPM or Sentinel service recovery behavior is added.


- Discover the active versioned PHP-FPM systemd service instead of assuming
  PHP 8.5, and derive the matching command, log path, and process name.
- Preserve explicit operator overrides for the PHP-FPM service, command, log,
  process name, and expected event mechanism.
- Scope zombie detection to direct children of the selected PHP-FPM master and
  version rather than counting unrelated PHP-FPM processes system-wide.
- Rebase incremental log analysis when either the positive master PID or the
  selected PHP-FPM target changes, preventing cross-version shutdown churn from
  contaminating the replacement epoch.
- Treat the event mechanism as diagnostic unless an operator explicitly sets
  `expected_event_mechanism`; retain mismatch warnings for explicit policy.
- Keep PHP-FPM observe-only and retain the migrated Unbound remediation module.

## 0.5.5.0

- Add a package-managed modular watchdog runner with disabled package defaults
  under `/usr/lib/argent-sentinel/watchdog.d/`, opt-in operator overrides under
  `/etc/argent-sentinel/watchdog.d/`, and bounded per-module process isolation.
- Add independent multi-address administrative and emergency notification
  categories, transition deduplication, concise individual emergency delivery,
  and daily administrative summaries.
- Migrate the existing five-minute Unbound watchdog into the framework while
  preserving pre-restart evidence collection, bounded restart, recovery
  verification, retention, and administrative reporting.
- Accept harmless horizontal whitespace in the recognized legacy Unbound
  systemd/configuration directives so migration matches the actual production
  units without weakening the known-implementation guard.
- Add an observe-only PHP-FPM 8.5 watchdog for master/service health, zombies,
  FastCGI queues, event mechanism, incremental rapid-exit/epoll log analysis,
  and local application probes.
- Treat each positive PHP-FPM master PID as a separate log-analysis epoch:
  rebase the incremental log cursor when the master changes while continuing
  current-state checks, so a former master shutdown is not attributed to its
  replacement.
- Require two consecutive unhealthy PHP-FPM samples before notification and do
  not enable automatic PHP recovery in this release.
- Add root-only current state and transition history plus a sanitized watchdog
  snapshot and read-only Watchdogs dashboard page with stale-state detection.
- Present the Debconf local-protection recommendation as the prominent note
  heading and render discovery details as real paragraphs instead of literal
  escaped newline sequences.
- Fix the time-sensitive network-candidate unit fixture so the complete test
  suite remains deterministic after its original July 2026 evidence window.
- Defer Prometheus/Grafana export and PHP automatic remediation until the native
  watchdog framework has production history.

## 0.5.4.0

- Add dynamic public-IPv6 local-address protection inventories for enrolled
  agents, with `host`, `lan-prefix`, `manual`, and `off` modes.
- Discover qualifying addresses on selected or IPv6-default-route interfaces,
  excluding loopback, link-local, multicast, unspecified, tentative,
  DAD-failed, deprecated, container, and tunnel interfaces by default.
- Recommend conservative `/128` host protection for virtualized, cloud, VPS,
  or uncertain systems; recommend LAN-prefix protection only for physical
  router-advertised/dynamic environments and require explicit ownership
  confirmation before broadening protection.
- Add Debian Debconf selection on first install or upgrade when no prior local
  protection choice exists, plus `dpkg-reconfigure argent-sentinel-agent`.
  Noninteractive installs use unconfirmed dynamic host mode and never silently
  protect an entire interface prefix.
- Send changed inventories immediately and periodic heartbeats through the
  existing mTLS/idempotent agent transport, prioritizing protection updates
  ahead of ordinary telemetry backlogs.
- Add schema version 9 current and immutable history tables for per-node
  inventories, bounded freshness/grace handling, and an atomically published
  effective-protection state file.
- Merge fresh and grace-period node inventories with static protected CIDRs in
  dashboard review, while the root-owned processor independently loads the
  current state and fails closed when that state is missing, invalid, or stale.
- Bound remote dynamic inventory prefixes to no broader than `/24` IPv4 or
  `/48` IPv6; unsafe connected prefixes fall back to host protection.
- Add dashboard visibility for node mode, confirmation source, freshness,
  discovered addresses, effective CIDRs, and publication health.
- Keep automatic CIDR blocking disabled.

## 0.5.3.1

- Add a dedicated `enforcement_protection.protected_cidrs` policy that blocks
  CrowdSec enforcement without exempting the protected network from telemetry.
- Continue treating `trusted_cidrs` as enforcement-protected for backward
  compatibility.
- Mark CIDR proposals that overlap configured protections in dashboard snapshots,
  suppress 180- and 365-day block actions, and show the matching protected CIDR.
- Add an audited `Acknowledge protected network` action that closes the current
  proposal revision without creating a CrowdSec decision.
- Preserve an independent root-processor refusal for both trusted and dedicated
  protected CIDRs.
- Keep schema version 8 and automatic CIDR blocking disabled.

## 0.5.3.0

- Add schema version 8 for deterministic bounded CIDR proposals and immutable
  network review-action history.
- Preserve the registered allocation as the ownership scope while selecting the
  strongest bounded `/24` IPv4 or `/48` IPv6 evidence group and narrowing it to
  the most-specific common prefix.
- Record proposal revision, hostile-address count, incident/event count, active
  days, address-space coverage, derivation basis, review state, and CrowdSec
  range-decision state.
- Add audited 180-day and 365-day range blocks, keep-observing, reject, note,
  and range-removal actions through the existing write-only dashboard spool and
  root-owned review processor.
- Refuse stale proposals, prefixes broader than policy, targets outside the
  registered case, trusted-prefix overlap, unsupported durations, and block
  requests without operator justification.
- Keep failed or dry-run range enforcement open and record command outcomes in
  `network_review_actions`.
- Add network-review counts, proposal evidence, action controls, and recent CIDR
  audit history to the dashboard and daily review digest.
- Keep automatic CIDR and VPN-endpoint blocking disabled pending audited manual
  production history.

## 0.5.2.1

- Automatically close no-contact review items only after local CrowdSec IP
  enforcement is verified as applied or already existing.
- Keep failed, refused, stale, and dry-run no-contact enforcement visible for
  operator review and retry.
- Add explicit approve, keep-suppressed, duplicate/subsumed, contact-refresh,
  and note actions for suppressed WordPress credential-spray incidents.
- Return refreshed abuse contacts to the review queue without sending mail.
- Separate credential-spray and unresolved no-contact counts on the dashboard.

## 0.5.2.0

- Replace the report-attempt review count with a deduplicated incident queue.
- Add audited acknowledge, retry, suppression, permanent-no-contact, and note
  actions through a write-only spool and root-owned processor.
- Render dashboard timestamps in the server-local timezone while preserving UTC
  in machine-readable values and HTML metadata.
- Treat overlapping scheduled collector cycles as successful skipped runs.
- Remove generated Python bytecode and Debian build output from source control.

## 0.5.1.1

### Debian revision 0.5.1.1-2

- Quiesce the minute collector before package-time configuration and database
  migration, preventing shared-lock collisions at minute boundaries.
- Migrate the new bounded-grouping and report-state keys into preserved live
  collector configurations without replacing operator policy.
- Add missing dashboard-snapshot top-level reporting paths to preserved
  configurations.


- Bound provider-report groups independently from broad registered allocations.
- Preserve registered ownership scope while adding explicit batch CIDR context.
- Publish hourly run state, queued groups, outbound messages, and ban-only
  suppressions on the read-only Reports dashboard.
- Record the completed 2026-07-29 production reporting cutover and retire stale
  OpenSSH XARF follow-up items.

## 0.5.1.0

- Separate immediate enforcement from hourly CIDR provider reporting.
- Add Meta/Facebook ban-only report suppression.
- Add SSH and WordPress XARF login-attack attachments.
- Add WordPress collector inventory and reusable agent profile documentation.

## 0.5.0.5

- Treat unrestricted per-site PHP-FPM pools as a security-hardening failure.
- Stop unattended onboarding unless the operator explicitly accepts no open_basedir.
- Add clear interactive warnings and regression coverage.

## 0.5.0.4

- Restart matching PHP-FPM services automatically after successful WordPress onboarding.
- Add an explicit `--no-restart-php-fpm` maintenance-window opt-out.
- Deduplicate and verify restarts across matching pools.

## 0.5.0.3

- Add PHP-FPM open_basedir inspection and optional safe append to WordPress onboarding.
- Correct WordPress site-parent permissions and verify WP-CLI setup discovery.

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
