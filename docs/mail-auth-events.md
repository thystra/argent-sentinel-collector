# Mail authentication events and account slow-burn policy

Argent Sentinel 0.5.6.0 adds an agent collector for Dovecot and Postfix SMTP
AUTH (SASL) authentication failures. Ingest itself is observe-only. The
collector's account-keyed slow-burn policy (`mail_account_policy`, see below)
is the only consumer of these events and ships **disabled**.

## Design: one `mail` service

Dovecot and Postfix are collected as a single batch service named `mail`:

- One journald reader follows `dovecot.service` and `postfix@-.service`
  (configurable `mail.units`). Repeated `journalctl -u` options are OR-ed, so
  both units share one interleaved stream and one durable cursor
  (`/var/lib/argent-sentinel/agent/mail.cursor`).
- Account names are HMAC-SHA256 pseudonymised with the existing agent privacy
  key (`/etc/argent-sentinel/agent-privacy.key`) in a dedicated `mail` domain
  (`HMAC(key, "mail\0NODE\0casefold(account)")`). The same mailbox therefore has
  the same token whether it is attacked over IMAP, POP3, Submission, or SMTP
  AUTH, which is what a later account-keyed slow-burn policy needs. Mail tokens
  never collide with OpenSSH tokens (`sshd` domain). Raw account names, SASL
  challenge strings, and session IDs are never exported.
- Batches use `service: "mail"`, `site_id: "mail-NODE"`, and
  `site_url: "mail://FQDN/"`. Every event has `event_type: "mail_auth_failed"`
  and `outcome: "denied"`. That event type is matched only by
  `mail_account_policy`, so ingest cannot trigger WordPress or OpenSSH rules.

## Accepted journal lines

Only high-confidence summary lines are counted, so one failed connection
produces one event:

| Component | Example | Notes |
| --- | --- | --- |
| Dovecot login process | `imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<a@example.org>, method=PLAIN, rip=198.51.100.7, lip=203.0.113.25, TLS, session=<…>` | Also `Disconnected (auth failed …)`, `Aborted login (auth failed …)`, `Login aborted: … (auth failed …) (auth_failed)`, optional `Info:` level prefix; protocols `imap`, `pop3`, `managesieve`, `submission`. `attempts` is preserved in metadata. |
| Postfix smtpd | `warning: unknown[198.51.100.23]: SASL LOGIN authentication failed: UGFzc3dvcmQ6[, sasl_username=a@example.org]` | Any `postfix*/…/smtpd` syslog identifier. `postfix/smtpd` → `smtp`, `postfix/submission/smtpd` → `submission`, `postfix/smtps/smtpd` → `smtps`. |

Ignored: Dovecot `auth`/`auth-worker` companion lines (`passwd-file(…)`,
`pam(…)`), `no auth attempts`, successful logins, Postfix `lost connection
after AUTH`, and non-smtpd identifiers.

Event fields: source IP (IPv4-mapped IPv6 is folded to IPv4), source port when
Dovecot logs `rport=`, destination IP from Dovecot `lip=` or the configured
`mail.destination_ip`, destination port from Dovecot `lport=` or
`mail.postfix_service_ports`, `TCP`, application protocol (`IMAP`, `POP3`,
`MANAGESIEVE`, `SUBMISSION`, `SMTP`), and metadata `mail_component`,
`protocol`, `auth_mechanism`, `attempts`, `account_class`
(`submitted`/`empty`/`unresolved`), plus `tls` (Dovecot) or
`postfix_service`/`sasl_stage` (Postfix).

Dovecot does not log ports by default. To get complete tuples, add
`rport=%{rport} lport=%{lport}` to `login_log_format_elements`. Postfix only
logs `sasl_username` on failure in releases that support it; otherwise the
event has no account token (`account_class: unresolved`).

## Enabling (when deployment is approved)

1. Agent: set `mail.enabled: true` in `/etc/argent-sentinel/agent.json` (or
   `argent-sentinel-configure-agent … --mail`), confirm `mail.units` matches
   the host's unit names, and set `mail.destination_ip`.
2. Server: add `"mail"` to the node's `services` in
   `/etc/argent-sentinel/nodes.d/NODE.json`; otherwise the API answers 403.
3. Collector: no change for ingest. API-delivered batches land in
   `/var/lib/argent-sentinel/drop/remote/NODE/events/incoming/*-mail.json`,
   already covered by the default `incoming_globs`. Enforcement is a separate,
   later step (below).

## Account-keyed slow-burn policy (`mail_account_policy`)

fail2ban (Dovecot/Postfix jails) stays the **first layer**: it bans a single
source that hammers quickly. This policy covers what fail2ban cannot see: one
mailbox attacked slowly from many addresses, each staying below fail2ban's
per-IP rate.

Unlike the WordPress persistent policy (keyed on site + source IP), the key
is the **target account token** (`SITE_ID:account:HMAC`), aggregated across all
source IPs inside a rolling window. Events without a token
(`account_class: empty`/`unresolved`) and sources in `trusted_cidrs` are
ignored. One event is one failed connection (Dovecot `attempts` is not
multiplied in).

### Decision rule

For each account token inside `window_seconds`:

1. **Campaign qualifies** when failures ≥ `failure_threshold` (N) **and**
   distinct source IPs ≥ `distinct_source_ips` (M).
2. Every participating source IP with ≥ `min_failures_per_ip` failures on that
   account gets its **own per-IP incident** (rule `mail-account-slow-burn`, or
   `mail-protected-account-slow-burn` for a protected mailbox) and therefore its
   own per-IP CrowdSec decision (`cscli decisions add --ip`, duration
   `ban_duration`). CrowdSec is **operator-gated**: the decision is only
   issued when both the global `crowdsec.enabled` and
   `mail_account_policy.crowdsec_enforcement` (default `false`) are true;
   otherwise the incident is recorded with decision status `dry-run`
   (incident monitor only). The usual guards also apply: CrowdSec
   allowlists, `trusted_cidrs`, non-global addresses, max enforcement age.
3. One-shot sources below `min_failures_per_ip` are not banned; they remain
   visible in the campaign's review-only prefix/ASN proposals.
4. **Prefix and ASN aggregation is review-only.** Each campaign records bounded
   prefix proposals (`/24` IPv4, `/48` IPv6, narrowed to the smallest common
   prefix) and ASN groups from locally cached enrichment. They appear in
   `argent-sentinel status`, the dashboard snapshot, the dashboard Mail page
   (`/mail`, also embedded in Incidents as `#mail`), and the
   daily review digest. Nothing creates range, ASN, or country decisions; the
   per-IP incidents also feed the existing audited CIDR review queue, where any
   range decision still needs an operator action.

### Defaults (conservative; tune after observing production volume)

| Setting | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Policy off until approved |
| `window_seconds` | `86400` | 24 h rolling window |
| `failure_threshold` (N) | `10` | Failures on one account |
| `distinct_source_ips` (M) | `5` | Distinct source IPs on that account (minimum 2) |
| `min_failures_per_ip` | `2` | Per-IP evidence needed before that IP is banned |
| `protected_failure_threshold` | `6` | N for protected mailboxes |
| `protected_distinct_source_ips` | `3` | M for protected mailboxes |
| `ban_duration` | `168h` | Per-IP CrowdSec duration (shorter than the 720 h default: CGNAT/mobile collateral) |
| `incident_merge_seconds` | `86400` | Merge repeat evidence into the same per-IP incident |
| `abuse_reporting_enabled` | `false` | Incidents start `suppressed`; set `true` to send XARF `login_attack` reports |
| `campaign_review_distinct_ips` | `3` | Record review-only campaigns from this many IPs even below N/M |
| `campaign_prefix_min_ips` | `2` | IPs per bounded prefix before a prefix proposal is listed |

Rationale: a single user with a stale password on one device produces failures
from one or two addresses, so M=5 (M=3 for protected) keeps them out; a slow
distributed guesser typically touches dozens of addresses per day. Requiring 2
failures per IP avoids banning one-shot botnet/CGNAT addresses that will not
return, while the prefix proposals still surface them for review.

When reporting is enabled, provider reports reuse the XARF `login_attack` type
(`scan_type: credential_attack`, tag `service:mail`, service `smtp`/`imap`/
`pop3`/`mail` from the evidence). Reports and XARF contain only connection
tuples; account tokens and mailbox names are never included.

### Protected mailboxes

Real mailboxes (the owners' primary personal mailboxes, `postmaster@`,
`merchant@`, …) get **priority treatment**: lower N/M, a separate rule id, and
they are always listed as campaigns (even from one IP) with an operator label.
**Never commit their addresses**: the repository may be mirrored publicly.
Configure them only on the collector host, in one of two ways (both match on the
same `mail` HMAC domain the agent uses at ingest:
`HMAC(agent-privacy.key, "mail\0NODE\0casefold(account)")`).

**Preferred — precomputed tokens in `/etc/argent-sentinel/collector.json`:**

```bash
sudo argent-sentinel --config /etc/argent-sentinel/collector.json mail-account-token
# type one mailbox per line, then Ctrl-D (stdin, so nothing lands in shell
# history or the process list); prints one token per line:
# mail-nidhoggur:account:<64 hex>
```

```json
"mail_account_policy": {
  "enabled": true,
  "protected_account_tokens": [
    {"token": "mail-nidhoggur:account:<64 hex>", "label": "owner-primary"},
    {"token": "mail-nidhoggur:account:<64 hex>", "label": "postmaster"}
  ]
}
```

A bare 64-hex token is also accepted. `--node NODE` and
`--privacy-key-file PATH` compute tokens for a remote agent node (use that
node's key). Labels are exported to status/dashboard/digest, so they must not
contain `@`; configuration validation rejects plaintext addresses in either
field.

**Alternative — root-only plaintext file hashed at runtime:**

```bash
sudo install -m 0600 -o root -g root /dev/null /etc/argent-sentinel/mail-protected-accounts
sudoedit /etc/argent-sentinel/mail-protected-accounts
#   one mailbox per line, optional label after a space; '#' comments
```

```json
"mail_account_policy": {
  "protected_accounts_file": "/etc/argent-sentinel/mail-protected-accounts",
  "privacy_key_file": "/etc/argent-sentinel/agent-privacy.key"
}
```

The collector hashes each line with the local agent key and `node.id`; a file
readable by group/other is ignored with an error. This only works for mailboxes
collected by the same host's agent.

Owner devices: keep home/VPN/office networks in `trusted_cidrs` or a CrowdSec
allowlist so a stale client password on a protected mailbox cannot ban its
owner.

### Enabling on nidhoggur (after approval)

1. Confirm mail ingest is live and review a few days of `mail_auth_failed`
   volume (`SELECT COUNT(DISTINCT source_ip), COUNT(*) FROM events WHERE
   service='mail' GROUP BY account_key ORDER BY 2 DESC`).
2. Add protected tokens as above; `argent-sentinel --config
   /etc/argent-sentinel/collector.json validate-config`.
3. Incident monitor / dry-run soak: set `mail_account_policy.enabled: true`
   and leave `mail_account_policy.crowdsec_enforcement: false` (the default).
   Incidents and campaigns are recorded, decisions show `dry-run`, and no
   CrowdSec ban is issued even when the global `crowdsec.enabled` is true
   (other policies keep enforcing):

   ```json
   "mail_account_policy": {
     "enabled": true,
     "crowdsec_enforcement": false,
     "abuse_reporting_enabled": false
   }
   ```

4. Inspect `argent-sentinel status` → `mail_account_campaigns` and the
   dashboard Mail page (`/mail`: policy state and thresholds, campaigns,
   failures by source, and individual recent failures), then set `crowdsec_enforcement: true` to issue
   per-IP bans; leave `abuse_reporting_enabled: false` until reviewed.

Packages older than 0.5.6.1 have no `crowdsec_enforcement` key for this policy:
on 0.5.6.0 with global CrowdSec on, `enabled: true` issues real bans. Install
0.5.6.1 before enabling the policy.
