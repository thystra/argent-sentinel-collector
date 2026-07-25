# Argent Sentinel Architecture

## Purpose

Argent Sentinel separates immediate local protection from evidence retention,
correlation, operator review, and guarded abuse reporting.

## Data flow

```text
WordPress plugin       OpenSSH journal       Nginx structured logs
       |                      |                       |
       +---------- local immutable evidence ----------+
                              |
                    Argent Sentinel agent/API
                              |
                 normalized central SQLite store
                              |
          correlation / review / CrowdSec / reporting
```

Fail2ban remains the fast local enforcement layer. Argent Sentinel records its
ban notices as audit events but does not duplicate a native SSH or Nginx report
solely because Fail2ban also banned the address.

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
- The collector validates all event fields before database insertion.
- Usernames, cookies, passwords, and authentication secrets are not included
  in outbound reports.
- Test mode redirects all abuse mail to the configured override.

## Scheduled services

- Agent collection: every minute.
- Collector correlation: every minute.
- Nginx staging: hourly.
- Fail2ban ban export: every minute.
- Operator review digest: 07:00 local time daily.

## Future dashboard

A web dashboard is intentionally deferred until collection, policy,
deduplication, review output, and production reporting are stable. The
dashboard should consume the same database and policy interfaces rather than
introducing a second source of truth.

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

## Registered-CIDR cases

Network cases use `registered_cidr` returned by enrichment when available and
fall back to the local candidate prefix otherwise. Review thresholds can
recommend 180- or 365-day prefix blocks, but automatic CIDR enforcement remains
disabled. An operator must review shared-network risk, evidence, exceptions,
and the proposed expiration before changing a case to `blocked`.

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
configurations include `%virtualname`, allowing shared extended Nginx logs to be
filtered by each site's `SiteDomain` and aliases. Reports are generated as
static HTML; browser-triggered AWStats updates and CGI exposure remain disabled.

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
