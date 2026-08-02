# Argent Sentinel Architecture

## Modular watchdog plane

Argent Sentinel 0.5.5.0 adds a root-owned local watchdog plane that is separate
from event ingestion and abuse-reporting policy. A one-minute systemd timer runs
the common scheduler. Package and local JSON definitions select dynamically
imported, package-owned modules and their independent intervals. Package
definitions ship disabled and local overrides opt services into monitoring. Each
module executes in a separately bounded process group. Modules return versioned
state objects; the runner owns locking, persistence, recipient routing, retention,
history, and transition suppression.

Unbound retains bounded automatic recovery and captures evidence before restart.
PHP-FPM is observe-only and uses an inode/offset log cursor so historical churn
is not reclassified as a new incident. Positive systemd master-PID changes begin
a new log-analysis epoch and rebase the cursor at the current log end; current
service, zombie, queue, mechanism, and probe checks still run during that same
sample. Current state is stored privately beneath
`/var/lib/argent-sentinel/watchdogs`. The root snapshot process publishes only
sanitized status, metrics, recent transitions, and public diagnostic summaries
to the existing dashboard publication tree. Private diagnostics and recipient
addresses remain in root-only state. The unprivileged dashboard has no systemd,
mail, service restart, or watchdog-configuration access.

Prometheus/Grafana integration is a future read-only export layer; local checks
and recovery must remain functional without that stack.


## Purpose

Argent Sentinel separates immediate local protection from evidence retention,
correlation, operator review, and guarded abuse reporting.

## Data flow

```text
WordPress plugin       OpenSSH journal       Nginx structured logs
       |                      |                       |
       +---------- local immutable evidence ----------+
                              |
               Argent Sentinel agent + IPv6 discovery
                              |
              mTLS events and protection inventories
                              |
                 normalized central SQLite store
                              |
          correlation / review / CrowdSec / reporting
```

Fail2ban remains the fast local enforcement layer. Argent Sentinel records its
ban notices as audit events but does not duplicate a native SSH or Nginx report
solely because Fail2ban also banned the address.

## Slow-burn WordPress correlation

Persistent WordPress correlation is site scoped. It evaluates a rolling
24-hour window of confirmed failed logins, excludes trusted sources and event
evidence already linked to a stronger short-window WordPress incident, and
stores the site ID on the incident. Persistent incidents enter the normal
CrowdSec decision workflow. Provider reporting is suppressed by default during
the initial production review.

## Policy classes

- OpenSSH: trusted source addresses are excluded; external failed
  authentication is high confidence because password login is disabled.
- Nginx 444: the request already matched a deliberate hostile-request rule and
  qualifies immediately.
- WordPress login failures: customer-facing sites retain a wider tolerance
  window. Credential stuffing is detected by repeated attempts and account
  diversity.
- HTTP 429: review telemetry. Distributed crawler pressure is grouped by
  network prefix, host, user agent, duration, and distinct paths. A 429 alone
  never creates a provider report or permanent block.
- Fail2ban bans: authoritative local-action audit events used in the daily
  review and future evidence linkage.

## Trust boundaries

- Producer files and journal cursors are root-controlled.
- Remote transport uses per-node mTLS identity and idempotent envelopes.
- Local-protection inventories are authenticated by the same node certificate,
  bound to the envelope digest, validated again by the collector, and retained
  in immutable history before contributing to the effective protection set.
- The collector validates all event and inventory fields before database insertion.
- Usernames, cookies, passwords, and authentication secrets are not included
  in outbound reports.
- Test mode redirects all abuse mail to the configured override.
- `/var/lib/argent-sentinel` remains `root:sentinel 0750` and is not listable by
  the web tier. The `www-data` presentation group receives execute-only ACL
  traversal on that ancestor.
- Sanitized dashboard output is published beneath a `root:www-data 0750`
  subtree with `root:www-data 0640` files. Nginx is not added to the broader
  `sentinel` group.
- The long-running dashboard worker receives `www-data` only as a supplementary
  read group and has no collector database or enforcement write interface.

## Scheduled services

- Agent collection: every minute.
- Collector correlation: every minute.
- Nginx staging: hourly.
- Fail2ban ban export: every minute.
- Operator review digest: 07:00 local time daily.

## Future dashboard write workflows

The read-only dashboard is implemented. Future notes, dispositions, allowlist
changes, and enforcement actions must use explicit authenticated and auditable
proposal interfaces. The web worker must not gain direct database or policy
write access and must not introduce a second source of truth.

## HTTP 429 review ingestion

The `argent-sentinel-nginx-429-export` timer tails configured current Nginx
access logs, parses extended combined-format entries whose final response is
HTTP 429, and writes deterministic JSONL observations into the established
abuse-context drop tree. The collector stores these as network observations;
it does not materialize them as hostile web incidents.

The daily review groups 429 pressure by network prefix and canonical client
identity. Distributed crawlers are aggregated across rotating addresses and
superficial browser-platform User-Agent variations. Sustained single-address
path enumeration is a separate review condition. Neither condition creates an
automatic ban.

## Enforcement-protected networks

The collector configuration separates enforcement protection from event trust.
`trusted_cidrs` remain exempt from selected source-processing paths and are also
never blockable. `enforcement_protection.protected_cidrs` are never blockable but
remain visible to telemetry and incident correlation. Dashboard suppression is a
usability control; the root-owned review processor repeats the overlap check at
action time and is authoritative.

Version 0.5.4.0 derives dynamic protection from enrolled-agent inventories.
Host mode recalculates `/128` protections from every current qualifying public
IPv6 address. Confirmed LAN-prefix mode recalculates the current connected
prefixes; an unconfirmed LAN choice falls back to host mode. Virtualized or
uncertain environments are recommended for host mode because a provider-visible
`/64` does not prove operator control of that prefix.

The agent sends an inventory when its canonical protection state changes and at
a bounded heartbeat interval. The collector retains the most recent inventory
per node plus immutable history, holds stale inventory protections through a
configured grace period, and publishes one atomic effective-state file. The
root-owned review processor reloads that file at action time and fails closed
when it is missing, invalid, or older than the configured state-file limit.
Static `protected_cidrs` and the legacy `trusted_cidrs` enforcement guard remain
independent safety layers.

## Registered-CIDR cases

Network cases use `registered_cidr` returned by enrichment when available and
fall back to the local candidate prefix otherwise. The registered allocation is
an ownership and correlation scope, not automatically the enforcement target.

Schema version 9 retains the schema-8 deterministic proposal from the
strongest bounded evidence scope: `/24` for IPv4 or `/48` for IPv6 by default. Within that scope,
the proposal is narrowed to the smallest common prefix containing the selected
hostile addresses. The case records the proposal revision, distinct hostile
addresses, incidents, events, active days, address-space coverage, and
derivation basis. A materially changed evidence set produces a new revision and
reopens an observe/reject review.

The dashboard submits network actions to the same immutable review spool used
for incident review. The root-owned processor validates the case timestamp,
proposal revision, registered-allocation containment, configured prefix bound,
trusted-prefix overlap, approved duration, and operator justification before
calling CrowdSec with `decisions add --range`. It never uses
`--bypass-allowlist`. Applied, existing, failed, refused, removed, and absent
results are recorded in `network_review_actions`; failed enforcement remains
open. Automatic CIDR enforcement remains disabled.

## v0.5 dashboard and traffic analysis

The operator dashboard is deliberately separated from the collector database.
A root-owned snapshot service takes the shared collector lock, opens SQLite in
URI read-only/query-only mode, and atomically publishes a bounded JSON snapshot.
The long-running dashboard service runs as `argent-sentinel-dashboard`, reads
only that snapshot and static AWStats files, and has no enforcement or database
write interface.

Nginx hosts the dashboard on `sentinel.argentwolf.org` alongside the existing
mTLS ingestion endpoint. Server-level client-certificate verification becomes
optional; `/v1/ingest` explicitly requires a successfully verified node
certificate. Dashboard and static AWStats locations require both an allowed LAN
address and HTTP Basic authentication.

AWStats is used for conventional per-site traffic reporting. Generated
configurations consume per-site normalized combined streams. Shared extended
logs are host-filtered before records reach AWStats, while ambiguous hostless
records are skipped. The generated configuration explicitly enables report
sections used by the AWStats static-page builder so links to detail reports have
matching files. Reports are generated as static HTML; browser-triggered AWStats
updates and CGI exposure remain disabled.

The combined Nginx host exposes `/healthz` for the ingestion API and a separate
authenticated `/dashboard-healthz` for the dashboard. Server-level client
certificate verification is optional so browsers can negotiate TLS, while
`/v1/ingest` still requires successful node-certificate verification. LAN
allowlists must account for globally routed IPv6 prefixes as well as RFC 1918
IPv4 and IPv6 ULA space.

`Meta-ExternalAgent` is an explicit operator policy block. The packaged Nginx
map permits `FacebookExternalHit` for link previews and blocks
`Meta-ExternalAgent` with HTTP 403 when the enforcement snippet is included in
a public server block. Known policy-denied agents are excluded from generic
high-volume scanner materialization, while requests for independently hostile
paths still qualify normally.

## Two-log Nginx and traffic-analysis boundary

Each monitored virtual host keeps a complete `argent_site_access` file for
traffic accounting. A second conditional `argent_sentinel_json` file carries
only security and review telemetry. AWStats consumes normalized streams built
from each site's own current and historical files; Sentinel consumes the
filtered JSONL and application/plugin events. Shared hostless access records
are never guessed into a virtual host.

## Enforcement and provider-report separation

The central collector has two independent cadences:

- **Minute path:** import, validate, correlate, and submit per-source CrowdSec
  decisions.
- **Hourly path:** select report-eligible incidents after a grace period,
  enrich them, apply ban-only communication policy, group by CIDR/activity/
  recipient set, and deliver provider summaries.

This preserves fast containment while reducing outbound-message
amplification. The same collector process lock serializes both paths.

Provider-rate accounting uses distinct message IDs. One hourly email can be
linked to many incident rows without consuming the recipient limit once per
incident.

XARF remains incident-scoped: a grouped email contains multiple independent
XARF documents rather than a nonstandard multi-source XARF object.

## Bounded provider-report aggregation in 0.5.1.1

Provider ownership and evidence aggregation are separate concepts.
`registered_cidr` remains the ownership scope used to resolve the responsible
provider and recipient. `batch_cidr` is the bounded evidence scope used for the
hourly group and subject line. Registered IPv4 allocations broader than `/24`
and IPv6 allocations broader than `/48` are narrowed to a source-containing
prefix by default. Both values are retained for operator review.

The hourly process writes an atomic sanitized run-state document beneath the
collector state directory. The root-owned dashboard snapshot process combines
that document, read-only SQLite queries, and non-secret reporting settings into
the published snapshot. The dashboard service itself continues to read only the
sanitized snapshot.

## Audited review-action boundary in 0.5.2.0

The dashboard remains unable to write SQLite directly. It validates an
operator action and writes an immutable JSON request to a group-writable spool.
A root-owned path-activated processor reacquires the collector lock, rejects
stale forms, applies one transaction, appends the `review_actions` audit row,
and publishes a new sanitized snapshot. Direct enforcement controls remain out
of scope for the dashboard.

## No-contact and credential-spray review policy in 0.5.2.1

The hourly report batcher owns automatic no-contact reconciliation because it
already performs RDAP lookup and uses the collector's guarded CrowdSec decision
path. It appends an automatic audit row only after `applied` or `existing` is
returned. Operator credential-spray approvals remain spool requests; refreshed
contacts are returned to the review queue before any provider delivery.
