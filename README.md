# Argent Sentinel Host Collector 0.2.2

This collector is the privileged bridge between immutable WordPress event batches and host-level response. It imports atomic JSON files, deduplicates `batch_uuid` and `event_uuid`, correlates credential attacks, enriches hostile IPs with RDAP/ASN data, records `/24` or `/64` aggregation candidates, and can request a CrowdSec decision and send a sanitized abuse report.

The collector is intentionally separate from WordPress. PHP never runs `cscli`, edits nftables, performs RDAP lookups, or sends third-party abuse reports.

Version 0.2.2 adds production abuse-report guardrails: a mandatory activation cutoff, maximum incident age, per-run processing limit, per-recipient cooldown and rolling 24-hour limit, retry backoff, explicit test mode, and a durable SQLite audit trail. It retains the 0.2.1 status and enrichment fixes.

## Initial policy

A source IP creates an incident when either rule is satisfied:

- **Credential spray:** at least 5 `login_failed` events against at least 2 resolved WordPress accounts within 60 seconds.
- **Single-account brute force:** at least 10 failures against one resolved account within 60 seconds.

The configured IP decision is 720 hours (30 days). New incidents older than seven days are retained as evidence but are not newly enforced. Trusted CIDRs and CrowdSec centralized allowlists are checked before any decision is requested.

CIDR aggregation is evidence-only in this release:

- IPv4 is grouped by `/24`.
- IPv6 is grouped by `/64`.
- 3 independently hostile IPs in the same candidate network during 7 days produce a review candidate.
- 5 hostile IPs, or activity on 3 distinct days, produces an escalation-review candidate.
- No CIDR or ASN is automatically blocked.

## Security behavior

Incoming files are atomically moved into a root-controlled processing directory before parsing. The collector rejects symlinks, non-regular files, malformed UUIDs, malformed IP addresses, unsupported schemas, oversized files, duplicate UUIDs inside one batch, and invalid timestamps. Imported raw batches are retained in a protected archive; malformed batches and bounded error details go to the rejected directory.

The SQLite state database uses WAL mode, foreign keys, and full synchronous writes. Complete batch and event UUID deduplication makes a plugin-side retry safe after a crash between file publication and queue-state update.

Abuse reports contain source IP, UTC interval, counts, site count, incident/event UUIDs, ASN/network context, and at most two bounded user-agent examples. They do not include usernames, WordPress user IDs, email addresses, passwords, cookies, request bodies, or authentication tokens.

## Install

Run from this collector directory:

```bash
sudo ./scripts/install.sh
```

The installer:

- installs the collector at `/usr/local/libexec/argent-sentinel/collector.py`;
- installs a root-only configuration at `/etc/argent-sentinel/collector.json`;
- creates protected state, processing, archive, and rejected directories;
- installs a hardened systemd oneshot service and one-minute timer; and
- enables the timer with CrowdSec and abuse reporting disabled.

Create the WordPress drop directory:

```bash
sudo ./scripts/create-wordpress-drop.sh wolfandraven-blog wolfandraven
```

Expected path:

```text
/var/lib/argent-sentinel/drop/wordpress/wolfandraven-blog/incoming
```

It is owned by the PHP-FPM user, grouped to `sentinel`, and mode `2770`. The path must exactly match `ARGENT_SENTINEL_DROP_DIRECTORY` in `wp-config.php`.

## Dry-run validation

Validate the configuration:

```bash
sudo /usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json validate-config
```

Export one WordPress batch:

```bash
cd /var/www/wolfandraven.blog/public_html
sudo -u wolfandraven wp argent-sentinel status --format=json
sudo -u wolfandraven wp argent-sentinel export --format=json
```

Run the collector immediately rather than waiting for the timer:

```bash
sudo systemctl start argent-sentinel-collector.service
sudo systemctl status argent-sentinel-collector.service --no-pager -l
sudo journalctl -u argent-sentinel-collector.service -n 100 --no-pager
```

Inspect state:

```bash
sudo /usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json status
```

By default, dry-run collection does not perform external RDAP or RIPEstat calls. This keeps the one-minute collector fast while CrowdSec enforcement and abuse reporting are disabled. Set `enrichment.enrich_when_actions_disabled` to `true` only when background enrichment without actions is intentionally desired.

Incidents should initially show:

```text
decision_status: dry-run
report_status: disabled
```

The `recent_incidents` section includes the evidence counts and action states. `network_candidates` is review-only and always reports `automatic_block: false`.

## Enable CrowdSec decisions

First verify the existing CrowdSec allowlists and firewall bouncer. Then edit:

```text
/etc/argent-sentinel/collector.json
```

Change:

```json
"crowdsec": {
  "enabled": true,
  "cscli_path": "/usr/bin/cscli",
  "command_timeout_seconds": 20
}
```

Validate and run:

```bash
sudo /usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json validate-config
sudo systemctl start argent-sentinel-collector.service
sudo cscli decisions list
```

Previously recorded dry-run incidents are retried when enforcement becomes enabled, provided they remain inside `max_enforcement_age_days`. The collector checks both its configured trusted CIDRs and `cscli allowlists check` before adding a decision.

## Enable abuse reporting

Reporting now has two explicit modes.

### Controlled test mode

Test mode requires a recipient override and never uses the provider address returned by RDAP:

```json
"abuse_reporting": {
  "enabled": true,
  "test_mode": true,
  "from": "postmaster@argentwolf.org",
  "admin_copy": "postmaster@argentwolf.org",
  "recipient_override": "goshawk066@gmail.com",
  "sendmail_path": "/usr/sbin/sendmail",
  "send_timeout_seconds": 30,
  "subject_prefix": "[Argent Sentinel]",
  "message_id_domain": "argentwolf.org",
  "operator_contact": "postmaster@argentwolf.org",
  "max_evidence_uuids": 20,
  "max_reports_per_run": 1,
  "max_report_age_hours": 24,
  "recipient_cooldown_minutes": 0,
  "max_reports_per_recipient_per_day": 10,
  "report_not_before_utc": "",
  "retry_backoff_minutes": 60
}
```

`recipient_override` is rejected unless `test_mode` is true. Test reports add `TEST` to the subject and state that the RDAP provider contact was not used.

### Production provider reporting

Production mode rejects a recipient override and requires an absolute UTC cutoff. Set the cutoff to the activation time so the historical incident backlog cannot be mailed:

```json
"abuse_reporting": {
  "enabled": true,
  "test_mode": false,
  "from": "postmaster@argentwolf.org",
  "admin_copy": "postmaster@argentwolf.org",
  "recipient_override": "",
  "sendmail_path": "/usr/sbin/sendmail",
  "send_timeout_seconds": 30,
  "subject_prefix": "[Argent Sentinel]",
  "message_id_domain": "argentwolf.org",
  "operator_contact": "postmaster@argentwolf.org",
  "max_evidence_uuids": 20,
  "max_reports_per_run": 3,
  "max_report_age_hours": 24,
  "recipient_cooldown_minutes": 15,
  "max_reports_per_recipient_per_day": 10,
  "report_not_before_utc": "2026-07-23T20:30:00Z",
  "retry_backoff_minutes": 60
}
```

Guardrail behavior:

- Incidents older than `max_report_age_hours` are permanently marked `suppressed`.
- Incidents before `report_not_before_utc` are permanently marked `suppressed` without RDAP or mail activity.
- At most `max_reports_per_run` incidents are enriched and processed during one collector run.
- A provider recipient is deferred during `recipient_cooldown_minutes` after a successful report.
- A recipient is deferred after `max_reports_per_recipient_per_day` successful reports in a rolling 24-hour window.
- Mail and enrichment failures set `next_report_after_epoch` according to `retry_backoff_minutes`.
- `disabled`, `no-contact`, `failed`, and `deferred` incidents can be reconsidered when eligible; `sent` and `suppressed` incidents are final.
- Every sent, failed, deferred, suppressed, and no-contact outcome is recorded in `report_attempts`.

Validate before restarting the timer:

```bash
sudo /usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json validate-config
```

Review the audit trail:

```bash
sudo sqlite3 -header -column \
  /var/lib/argent-sentinel/collector/state.sqlite3 \
  'SELECT attempted_at, recipient, status, detail, test_mode, message_id
     FROM report_attempts ORDER BY attempt_id DESC LIMIT 25;'
```

The status command also exposes `abuse_reporting_guardrails` and `recent_report_attempts`.

## ASN classification

RDAP and RIPEstat provide registration and ASN facts, but network type is an operator policy. Add known ASN classifications to `enrichment.asn_classifications`:

```json
"asn_classifications": {
  "14061": "hosting",
  "7922": "retail"
}
```

Accepted values are `hosting`, `retail`, `mobile`, `institutional`, and `unknown`. Classification is recorded for review; this release does not automatically block an ASN or expand an IP decision based on classification.

## Operations

Show timer state:

```bash
systemctl list-timers argent-sentinel-collector.timer --all
```

Show recent service results:

```bash
sudo journalctl -u argent-sentinel-collector.service --since today --no-pager
```

Check database integrity:

```bash
sudo sqlite3 /var/lib/argent-sentinel/collector/state.sqlite3 \
  'PRAGMA integrity_check;'
```

Back up at minimum:

```text
/etc/argent-sentinel/collector.json
/var/lib/argent-sentinel/collector/state.sqlite3
/var/lib/argent-sentinel/collector/archive/
```

Do not expose any collector directory through Nginx.

## Tests

```bash
python3 -m py_compile src/collector.py
python3 tests/test_collector.py
python3 tests/test_reporting_guardrails.py
bash -n scripts/install.sh scripts/create-wordpress-drop.sh scripts/status.sh
```

## Source repository

This source snapshot includes `VERSION`, `CHANGELOG.md`, `.gitignore`, and
`REPOSITORY-INIT.md` so it can be used as the initial commit of the maintained
collector repository. Runtime configuration and state remain outside Git.
