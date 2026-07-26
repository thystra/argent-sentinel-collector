<!-- Source: /home/alan/src/argent-sentinel-collector/docs/hourly-report-batching.md -->
# Hourly CIDR Abuse-Report Batching

Argent Sentinel separates enforcement from provider communication:

1. The minute collector imports events and immediately applies eligible
   per-source CrowdSec decisions.
2. When `report_batching.enabled` is true, the minute collector leaves
   provider-report work queued.
3. At five minutes past each hour, the report-batch timer processes incidents
   whose last evidence is at least `grace_minutes` old.
4. Incidents are enriched and grouped by effective CIDR, activity family, and
   recipient set.
5. One email is sent per group/chunk. Each independently qualifying incident
   receives its own XARF JSON attachment.

This avoids provider and operator email floods while preserving immediate
blocking.

## Configuration

```json
"report_batching": {
  "enabled": true,
  "grace_minutes": 5,
  "max_candidate_incidents": 1000,
  "max_incidents_per_message": 50,
  "max_messages_per_run": 10,
  "ban_only": {
    "asns": [32934],
    "cidrs": ["2a03:2880::/32"],
    "user_agent_tokens": ["meta-externalagent"],
    "allow_user_agent_only": false
  }
}
```

The Meta defaults suppress provider email only. A source must still
independently qualify as hostile before a local decision is submitted.
User-Agent-only suppression is disabled because User-Agent strings are
attacker controlled; ASN and CIDR ownership are the primary signals.

## Timer

The packaged timer runs at `HH:05`, with a small randomized delay. A five-minute
grace period closes the previous hourly window while allowing delayed log
rotation and ingestion.

## XARF

Immediate and batched reports attach XARF for Nginx, OpenSSH, and WordPress
incidents when `abuse_reporting.attach_xarf` is true. Authentication attacks
use XARF connection type `login_attack`; web scanning uses
`vulnerability_scan`.

A single-incident message uses `xarf.json`. Multi-incident batches use
numbered filenames such as `xarf-001-12345678.json`.

## Rate limits

Recipient cooldown and rolling daily limits count distinct outbound
`Message-ID` values. One CIDR email covering fifty incidents therefore counts
as one provider message, not fifty.

<!-- EOF: /home/alan/src/argent-sentinel-collector/docs/hourly-report-batching.md -->
