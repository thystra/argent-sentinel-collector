# Argent Sentinel Roadmap

## Stabilization

- Validate single-event OpenSSH reporting outside trusted networks.
- Validate single-event Nginx 444 reporting.
- Keep HTTP 429 handling review-only while tuning prefix and duration
  thresholds.
- Link Fail2ban ban events to the native events that caused the ban.
- Add cross-jail and cross-source deduplication.
- Add recidive escalation without sending duplicate provider reports.
- Add per-rule CrowdSec/Fail2ban ban durations.

## Dashboard/AWStats stabilization — 2026-07-25

Current handoff state for later chats and agents:

- [x] Dashboard is reachable through Basic Auth from the LAN.
- [x] Combined Nginx host uses `ssl_verify_client optional`; `/v1/ingest`
  independently requires successful client-certificate verification.
- [x] LAN access rules include the globally routed IPv6 prefix; `fc00::/7`
  alone was insufficient.
- [x] Live filesystem access was repaired with execute-only `www-data`
  traversal on `/var/lib/argent-sentinel` and `root:www-data` permissions on
  the sanitized dashboard publication tree.
- [x] Scheduled AWStats completed successfully for `wolfandraven.blog`; the
  earlier status `-13` was associated with a diagnostic stream closed early.
- [ ] Apply and deploy the stabilization changes from `fafnir`.
- [ ] Package the execute-only ACL and publication directory repair so upgrades
  do not recreate the Nginx/dashboard permission failure.
- [ ] Convert snapshot `PermissionError` into a controlled dashboard HTTP 503
  instead of an empty upstream response and Nginx 502.
- [ ] Emit explicit AWStats `Show*` settings and regenerate reports so linked
  `urldetail` and `allrobots` pages return HTTP 200.
- [ ] Verify `/dashboard-healthz` through Nginx and the dashboard Unix socket.
- [ ] Add a traffic-review view that separates `wp-login.php` requests by HTTP
  status, source, network, rate, and correlated WordPress authentication result;
  raw page hits alone are not proof of failed authentication.
- [ ] Compare AWStats corrupted-record totals on later runs to determine whether
  they are a fixed historical-format backlog or continue increasing.
- [ ] Keep this dated handoff section current after each deployment or major
  diagnostic session. Host/path conventions are in `AGENTS.md`.

## WordPress plugin next task

Observed failure:

```text
argent-sentinel-onboard-wordpress ...
Error: 'setup' is not a registered subcommand of 'argent-sentinel'.
```

Required work:

- Register and test `wp argent-sentinel setup`.
- Ensure `status`, `setup`, and `export` are present in the same plugin build.
- Add an administrator setup/status page.
- Display whether the current nonce/check token is valid.
- Display the configured site ID, node ID, and drop directory.
- Detect a missing drop directory.
- Provide a clear root-side command to create the directory when WordPress
  cannot safely create it itself.
- Test writability as the actual PHP-FPM pool user.
- Show ownership, group, and mode failures clearly.
- Make the onboarding helper inspect available WP-CLI subcommands before
  invoking `setup` and fail with actionable diagnostics.
- Add end-to-end tests for a newly installed site, including
  allaboardbouncers.com and wolfandraven.blog deployment patterns.

## HTTP 429 and crawler review

- Distinguish delayed requests from rejected requests in Nginx telemetry.
- Keep gallery image/static asset limits separate from dynamic gallery pages.
- Aggregate IPv6 crawlers above `/64` when they distribute requests across
  many subnets.
- Verify claimed crawler identities by network ownership before allowlisting.
- Add operator classifications: legitimate crawler, excessive crawler,
  scraper, false positive, and block candidate.
- Use review decisions to tune later automated policy.

## Daily review

- Deliver at 07:00 local time.
- Include 429 pressure groups, Fail2ban bans, incidents, failed/deferred
  reports, and events lacking classification.
- Add CSV/JSON attachments after the text format stabilizes.
- Record operator acknowledgement and disposition in the future dashboard.

## CIDR and network-prefix escalation

- Correlate hostile incidents across addresses in the same registered CIDR,
  allocation, ASN, and operator network.
- Detect sequential or distributed probing where many addresses from one
  prefix each remain below an individual-address threshold.
- Support operator-reviewed long-duration CIDR decisions, including six- and
  twelve-month local blocks.
- Require evidence across multiple addresses and/or active days before
  automatically recommending a prefix-wide block.
- Preserve the exact registered CIDR from RDAP instead of assuming every IPv4
  case is a `/24`.
- Treat VPN, proxy, hosting, and cloud exit networks as higher-risk context,
  not sufficient evidence by themselves.
- Add safeguards for shared-access providers, search crawlers, CDNs, mobile
  carriers, and other networks where a broad block could affect legitimate
  users.
- Record examples such as repeated hostile activity in `85.203.47.0/24` and
  `193.37.32.0/24` as investigation candidates, not hard-coded deny rules.
- Include network-case evidence and proposed expiration in the daily review
  before a long-duration prefix block is enacted.
- Support manual exceptions inside a blocked prefix.

## Abuse-contact delivery failures

- Detect delivery-status notifications and associate them with the original
  report, incident, recipient, message ID, and network.
- Distinguish nonexistent mailboxes, permanent policy rejection, temporary
  SMTP deferral, connection timeout, and DNS/MX failure.
- Record first failure, latest failure, retry count, and final disposition.
- Consider a dedicated envelope-sender/bounce address while retaining an
  operator-facing `Reply-To` address.
- Do not silently treat SMTP queue acceptance as confirmed delivery.
- Surface nonresponsive or invalid abuse contacts in the 07:00 review digest
  and future dashboard.
- Suppress repeated futile mail attempts after a confirmed permanent failure.
- Require persistent failure or a permanent status before treating a provider
  as lacking a functioning abuse mechanism.

## Future dashboard write and control workflows

- Add reviewed notes, acknowledgements, and dispositions without granting the
  web worker direct database access.
- Add authenticated and auditable generation of proposed Nginx, CrowdSec, and
  nftables policy fragments.
- Route allowlist, trusted-network, Fail2ban, and CrowdSec changes through a
  narrowly privileged helper with explicit confirmation and audit records.
- Add 429 crawler disposition, daily-summary annotations, and multi-node health
  while retaining the snapshot/read-only boundary.

## Implemented in 0.4.10

- Open the review database under a shared collector lock with SQLite query-only
  read-only URI mode while retaining the read-only systemd database mount.
- Tail current Nginx access logs for HTTP 429 responses and import them as
  review-only abuse-context observations.
- Canonicalize crawler identities across rotating addresses and User-Agent
  platform variants.
- Group network cases by RDAP `registered_cidr` where available, with fallback
  candidate prefixes.
- Add operator-review recommendations for 180- and 365-day CIDR blocks without
  enabling automatic range enforcement.
- Include active CIDR cases and proposed block durations in the 07:00 digest.

## Dashboard follow-up after 0.5.0

- Add reviewed dashboard write workflows for notes and dispositions without
  granting the web worker direct database access.
- Add authenticated, auditable generation of proposed Nginx, CrowdSec, and
  nftables policy fragments.
- Add longer retention aggregates for traffic cost, request time, upstream
  response time, bytes, and cache status once the extended Nginx format records
  those fields on every site.
- Add verified-bot ownership checks using forward-confirmed reverse DNS or
  provider-published ranges before granting crawler-specific exceptions.
- Add report-delivery bounce ingestion and nonresponsive abuse-contact cases.
- Keep CIDR recommendations in observation until enough history accumulates.

## Implemented in 0.5.0.2 — slow-burn WordPress policy

- [x] Add a site-scoped 24-hour WordPress credential-spray policy.
- [x] Trigger at six failures against two accounts.
- [x] Add a twelve-failure single-account persistent rule.
- [x] Exclude evidence already linked to stronger short-window WordPress rules.
- [x] Merge repeat evidence without creating an incident on every run.
- [x] Apply normal CrowdSec decision handling.
- [x] Suppress provider reporting by default with an explicit review detail.
- [x] Add schema migration 6 with nullable incident `site_id`.
- [x] Add threshold, site isolation, duplicate-evidence, merge, trusted-source,
  enforcement, reporting, and disablement tests.
- [x] Render SSH/sshd report tuples with `scheme=ssh`, not the HTTP fallback.
- [x] Add regression coverage for SSH connection details and normalized evidence.
- [ ] Review production incident volume before enabling persistent-policy
  provider reporting.
- [x] Complete the existing Allaboard Acres WordPress onboarding TODO.

## WordPress onboarding follow-up — 2026-07-26

- [x] Make the helper inspect matching PHP-FPM pools.
- [x] Warn when pool-level open_basedir excludes the protected drop.
- [x] Offer an interactive append, plus explicit append/warn/ignore modes.
- [x] Back up the pool file and validate PHP-FPM after an automatic edit.
- [x] Add an optional matching PHP-FPM restart.
- [x] Create the site parent as root:sentinel 0750 and incoming as 2770.
- [x] Inspect WP-CLI command discovery before invoking setup.
- [x] Validate the revised helper through a clean second-site onboarding.

## WordPress onboarding completion — 2026-07-26

- [x] Restart matching PHP-FPM services automatically after successful onboarding.
- [x] Delay restart until spool, open_basedir, plugin setup, status, and test export succeed.
- [x] Verify the restarted service is active.
- [x] Deduplicate restarts when several pools for the same user use one PHP version.
- [x] Retain `--restart-php-fpm` as an explicit compatibility option.
- [x] Add `--no-restart-php-fpm` for controlled maintenance windows.
- [x] Add service-discovery, restart, help, and missing-pool regression tests.
- [x] Validate the automatic restart through a clean third-site web-UI onboarding.

## PHP-FPM unrestricted-pool detection — 2026-07-26

- [x] Treat a missing pool-level open_basedir as a security-hardening failure.
- [x] Stop non-interactive onboarding by default before WordPress configuration.
- [x] Require explicit interactive confirmation or `--no-open-basedir-action continue`.
- [x] Preserve `--open-basedir-mode ignore` as an expert opt-out.
- [x] Explain that open_basedir is defense in depth, not a complete sandbox.
- [x] Print a reviewed example pool directive without silently inventing site requirements.
- [x] Add helper-policy and integration regression tests.
- [ ] Audit the earlier per-user PHP pool creation script and add a secure open_basedir template.
- [ ] Backfill restrictions to existing unrestricted per-user pools after review.

## Implemented in 0.5.1.0 — hourly CIDR reporting checkpoint

- [x] Preserve immediate per-IP CrowdSec enforcement.
- [x] Queue provider communication when hourly batching is enabled.
- [x] Add the hourly report-batch service and timer.
- [x] Group reports by CIDR, activity family, and recipient set.
- [x] Split large groups by a configurable maximum incidents per message.
- [x] Count distinct outbound Message-ID values for recipient limits.
- [x] Add Meta/Facebook ban-only suppression using ASN and CIDR ownership.
- [x] Keep User-Agent-only suppression disabled by default.
- [x] Attach XARF to OpenSSH and WordPress authentication reports.
- [x] Use XARF `login_attack` for authentication incidents.
- [x] Add a WordPress collector inventory command.
- [x] Add `AGENTS-PROFILE.md` and reference it from project agent notes.
- [x] Clean `dist/deb` before release packaging.
- [ ] Validate a controlled hourly batch in redirected test mode.
- [ ] Validate production batching after the test message structure is
  reviewed.
- [ ] Confirm all four WordPress sites reach `seen`; generate one controlled
  failed login for any site that remains `provisioned-no-import`.
- [ ] Add dashboard visibility for queued hourly groups and ban-only
  suppressions.
- [ ] Evaluate provider-specific minimum batch sizes and longer cooldowns.

## Implemented in 0.5.1.1 — operational provider reporting — 2026-07-29
- [x] Confirm all four production WordPress connector sites as `seen`.
- [x] Validate redirected hourly batching and XARF attachments.
- [x] Retire the legacy Nginx abuse sender and daily cron scheduler.
- [x] Enable production hourly batching with a fresh cutoff timestamp.
- [x] Validate the first production delivery and Message-ID accounting.
- [x] Suppress Meta provider email by ASN and explicit IPv4/IPv6 policy while
  preserving local enforcement.
- [x] Bound broad registered allocations to `/24` IPv4 and `/48` IPv6 report
  prefixes while retaining ownership scope.
- [x] Publish reporting mode, run state, queued groups, recent messages, broad
  allocation warnings, and ban-only suppressions through the sanitized
  dashboard snapshot.
- [x] Mark the OpenSSH XARF attachment defect complete and remove duplicate
  follow-up sections.
- [ ] Review several days of production persistent-WordPress incident volume
  before enabling provider email for that rule.
- [x] Repair the 0.5.1.1 Debian upgrade race and preserved-config migration in package revision `0.5.1.1-2`.

## Implemented in 0.5.2.0 — dashboard review workflow — 2026-07-29
- [x] Replace report-attempt counts with one open review item per incident.
- [x] Exclude ordinary future cooldown deferrals from operator work.
- [x] Add acknowledge, retry, suppress, permanent-no-contact, and note actions.
- [x] Preserve the dashboard/SQLite write boundary through a request spool and
  root-owned processor.
- [x] Add stale-form rejection, request UUID idempotency, and append-only audit.
- [x] Render human-facing dashboard times in the server-local timezone while
  retaining canonical UTC values.
- [x] Treat overlapping minute collector runs as harmless skipped cycles.
- [x] Stop tracking `__pycache__`, `.pyc`, and `dist/deb` build artifacts.
- [ ] Review persistent WordPress production volume and decide whether provider
  reporting should be enabled for newly created incidents.

## Implemented in 0.5.2.1 — review refinements — 2026-07-29
- [x] Verify/apply a local IP decision before auto-closing no-contact incidents.
- [x] Preserve unresolved local-enforcement failures as open review work.
- [x] Add explicit provider-report approval and closure dispositions for
  suppressed WordPress credential-spray incidents.
- [x] Add cached-contact refresh that returns the result to review without
  automatically sending provider mail.
- [x] Publish separate credential-spray and no-contact review counts.
- [ ] Add audited most-specific CIDR review and enforcement in 0.5.3.0.
