# Changelog

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
