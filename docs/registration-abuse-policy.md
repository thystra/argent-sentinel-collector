# Access Guard registration-abuse policy (`registration_abuse_policy`)

Release: 0.5.6.0 (unreleased, shares the mail package bump). Not deployed.

ArgentWolf Access Guard owns the WordPress registration decision. It hands
`registration_abuse` evidence to the Argent Sentinel WordPress connector
(0.2.6+, hook `argentwolf_access_guard_sentinel_external_event_v1`), or writes a
schema-1 batch directly into a protected drop. Either way the collector sees an
ordinary `service: wordpress` batch. This policy turns that evidence into
per-IP reputation and, only when an operator allows it, CrowdSec decisions.

## Ingest is site agnostic

- The collector glob `/var/lib/argent-sentinel/drop/wordpress/*/incoming/*.json`
  ingests every provisioned site. There is no site allowlist in code or config;
  the first live producer will be wolfandraven.blog, but any site works.
- Site identity is the batch `source.site_id`. The `<dir>` in
  `drop/wordpress/<dir>/incoming` is compared with it:
  `wordpress_drop.site_mismatch: "warn"` (default) logs and imports;
  `"reject"` moves the batch to `rejected_dir` with an `.error.txt`.
- Events keep the connector schema: `event_type: registration_abuse`,
  `outcome: denied|observed`, `source_ip`, `request`, and Access Guard
  `score`, `confidence`, `rule_ids`, `producer_schema`, `policy_action`, and
  `fingerprint_signature` in `metadata`. `metadata.request_id` feeds the
  existing Nginx correlation.

## Evaluation

Each collector run, when `enabled` is true, takes all `registration_abuse`
events from every WordPress site inside `window_seconds`, drops trusted
sources (`trusted_cidrs`), and groups by **source IP**.

A *qualifying* event is `outcome == "denied"`, `score >= min_score`, and
`confidence` in `accepted_confidences`. `observed` events never qualify; they
only add review context.

| Rule | Condition (per source IP, in window) |
| --- | --- |
| `wordpress-registration-abuse-high-confidence` | ≥ `high_confidence_event_threshold` qualifying events with `confidence == "high"` and `score >= high_confidence_score` |
| `wordpress-registration-abuse` | ≥ `event_threshold` qualifying events, **or** qualifying events on ≥ `cross_site_distinct_sites` distinct sites |

Incidents are cross-site (`site_id` NULL, `site_count` records the sites) and
merge within `incident_merge_seconds`. Provider reporting starts `suppressed`
unless `abuse_reporting_enabled` is true; XARF tags are
`attack:registration-abuse`, `service:wordpress`.

## Enforcement is operator-gated

Two independent switches must both be on before any `cscli` call:

1. `crowdsec.enabled` (global, default false);
2. `registration_abuse_policy.crowdsec_enforcement` (default false).

Otherwise the incident stays `decision_status: dry-run` with a detail naming
the gate. When the operator later enables enforcement, existing dry-run
incidents still inside `policy.max_enforcement_age_days` are applied on the
next run. Decisions are **per IP only** (`cscli decisions add --ip`,
`--duration ban_duration`, reason `<reason_prefix>/<rule>`), after the usual
trusted/non-global/CrowdSec-allowlist protection checks. There is no country
or ASN automatic ban, and `network_reporting.automatic_cidr_blocking` remains
disallowed.

## Review-only campaigns

`argent-sentinel status` includes `registration_abuse_campaigns`: events in the
window grouped by Access Guard `fingerprint_signature` when at least
`campaign_review_distinct_ips` source IPs share it. Each entry lists sites,
event counts, top rule IDs, sample IPs, bounded prefix proposals (≥
`campaign_prefix_min_ips` IPs per `/24` or `/48`), and cached-ASN groups.
Everything is `review_only: true`; nothing here creates incidents or decisions.

## Defaults

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Evaluate the policy at all (events are always stored). |
| `crowdsec_enforcement` | `false` | Per-policy CrowdSec gate (dry-run while false). |
| `window_seconds` | `86400` | Rolling window. |
| `min_score` | `6.0` | Minimum Access Guard score (AG default reject score). |
| `accepted_confidences` | `["high","medium"]` | Confidences that may qualify. |
| `event_threshold` | `3` | Qualifying events from one IP. |
| `cross_site_distinct_sites` | `2` | Distinct sites that qualify one IP (min 2). |
| `high_confidence_score` | `9.0` | Score for the high-confidence rule. |
| `high_confidence_event_threshold` | `2` | High-confidence events from one IP. |
| `incident_merge_seconds` | `86400` | Incident merge window. |
| `ban_duration` | `"168h"` | Per-IP CrowdSec duration. |
| `abuse_reporting_enabled` | `false` | Provider reports start suppressed. |
| `campaign_review_distinct_ips` | `3` | IPs per fingerprint before a review entry. |
| `campaign_prefix_min_ips` | `2` | IPs per bounded prefix before a proposal. |
| `max_campaign_sample_ips` | `10` | Sample IPs listed per campaign. |
| `wordpress_drop.site_mismatch` | `"warn"` | `warn` or `reject` on drop-dir/site_id mismatch. |

## Layering

fail2ban remains the first, per-source layer. The existing WordPress login
policies (`policy`, `persistent_wordpress_policy`) are unchanged and never
evaluate `registration_abuse`.

## Suggested rollout (operator, after approval)

1. Install connector 0.2.6 and Access Guard with the bridge in `auto` mode on
   one site; confirm `registration_abuse` rows appear in `state.sqlite3`.
2. Set `registration_abuse_policy.enabled: true` with `crowdsec_enforcement:
   false`; review dry-run incidents and `registration_abuse_campaigns`.
3. Set `crowdsec_enforcement: true` once thresholds look right.
