<!-- Source: /home/alan/src/argent-sentinel-collector/docs/operational-reporting-0.5.1.1.md -->
# Operational reporting in 0.5.1.1

Argent Sentinel 0.5.1.1 records the production reporting cutover completed on
2026-07-29.

Validated production state:

- the legacy Nginx sender and its daily cron definition are retired;
- hourly provider batching is enabled while minute-level enforcement remains
  immediate;
- redirected test mode and the first production delivery both completed
  successfully;
- all four WordPress connector sites reached collector status `seen`;
- Meta AS32934, `2a03:2880::/32`, and the observed `57.141.18.0/24` range are
  ban-only provider-report suppressions;
- persistent WordPress provider reporting remains disabled pending production
  volume review.

## Bounded report prefixes

Ownership enrichment may return allocations much broader than the evidence.
For example, source `38.133.142.106` resolved to registered allocation
`38.0.0.0/8`. Version 0.5.1.1 retains that registered allocation for ownership
and recipient selection but uses `38.133.142.0/24` as the report batch prefix.

Defaults:

```json
{
  "report_batching": {
    "grouping": {
      "minimum_ipv4_prefix_length": 24,
      "minimum_ipv6_prefix_length": 48
    }
  }
}
```

A registered allocation at least as specific as the configured minimum remains
the batch prefix. A broader allocation is bounded to the configured evidence
prefix, while both values remain visible in the message, run state, and
dashboard.

## Dashboard visibility

The root-owned snapshot process reads the collector configuration and hourly
run-state file and publishes only sanitized operational fields. The unprivileged
dashboard continues to read the snapshot rather than SQLite or the private
collector configuration.

The Reports page includes:

- production/test/disabled mode and production cutoff;
- last run, computed next run, groups, sent, failed, eligible, and suppressed;
- current queued groups with batch and registered prefixes;
- warnings for broad registered allocations;
- recent outbound message IDs;
- recent ban-only suppressions and their reasons;
- the existing per-incident report-attempt table.

<!-- EOF: /home/alan/src/argent-sentinel-collector/docs/operational-reporting-0.5.1.1.md -->
