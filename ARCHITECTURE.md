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
