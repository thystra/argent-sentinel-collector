# Mail authentication events (observe-only)

Argent Sentinel 0.5.6.0 adds an **observe-only** agent collector for Dovecot and
Postfix SMTP AUTH (SASL) authentication failures. Events are delivered and
stored centrally; no policy, CrowdSec decision, abuse report, or prefix
proposal is generated from them in this release.

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
  and `outcome: "denied"`. That event type is matched by no collector policy,
  so ingest cannot trigger WordPress or OpenSSH rules.

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
3. Collector: no change. API-delivered batches land in
   `/var/lib/argent-sentinel/drop/remote/NODE/events/incoming/*-mail.json`,
   already covered by the default `incoming_globs`.
