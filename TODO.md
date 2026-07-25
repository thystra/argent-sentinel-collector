# Argent Sentinel Roadmap

## Stabilization

- Validate single-event OpenSSH reporting outside trusted networks.
- Validate single-event Nginx 444 reporting.
- Keep HTTP 429 handling review-only while tuning prefix and duration
  thresholds.
- Link Fail2ban ban events to the native events that caused the ban.
- Add cross-jail and cross-source deduplication.
- Add recidive escalation without sending duplicate provider reports.
- Add per-rule CrowdSec/Fail2ban ban durations.

## WordPress plugin next task

Observed failure:

```text
argent-sentinel-onboard-wordpress ...
Error: 'setup' is not a registered subcommand of 'argent-sentinel'.
```

Required work:

- Register and test `wp argent-sentinel setup`.
- Ensure `status`, `setup`, and `export` are present in the same plugin build.
- Add an administrator setup/status page.
- Display whether the current nonce/check token is valid.
- Display the configured site ID, node ID, and drop directory.
- Detect a missing drop directory.
- Provide a clear root-side command to create the directory when WordPress
  cannot safely create it itself.
- Test writability as the actual PHP-FPM pool user.
- Show ownership, group, and mode failures clearly.
- Make the onboarding helper inspect available WP-CLI subcommands before
  invoking `setup` and fail with actionable diagnostics.
- Add end-to-end tests for a newly installed site, including
  allaboardbouncers.com and wolfandraven.blog deployment patterns.

## HTTP 429 and crawler review

- Distinguish delayed requests from rejected requests in Nginx telemetry.
- Keep gallery image/static asset limits separate from dynamic gallery pages.
- Aggregate IPv6 crawlers above `/64` when they distribute requests across
  many subnets.
- Verify claimed crawler identities by network ownership before allowlisting.
- Add operator classifications: legitimate crawler, excessive crawler,
  scraper, false positive, and block candidate.
- Use review decisions to tune later automated policy.

## Daily review

- Deliver at 07:00 local time.
- Include 429 pressure groups, Fail2ban bans, incidents, failed/deferred
  reports, and events lacking classification.
- Add CSV/JSON attachments after the text format stabilizes.
- Record operator acknowledgement and disposition in the future dashboard.

## CIDR and network-prefix escalation

- Correlate hostile incidents across addresses in the same registered CIDR,
  allocation, ASN, and operator network.
- Detect sequential or distributed probing where many addresses from one
  prefix each remain below an individual-address threshold.
- Support operator-reviewed long-duration CIDR decisions, including six- and
  twelve-month local blocks.
- Require evidence across multiple addresses and/or active days before
  automatically recommending a prefix-wide block.
- Preserve the exact registered CIDR from RDAP instead of assuming every IPv4
  case is a `/24`.
- Treat VPN, proxy, hosting, and cloud exit networks as higher-risk context,
  not sufficient evidence by themselves.
- Add safeguards for shared-access providers, search crawlers, CDNs, mobile
  carriers, and other networks where a broad block could affect legitimate
  users.
- Record examples such as repeated hostile activity in `85.203.47.0/24` and
  `193.37.32.0/24` as investigation candidates, not hard-coded deny rules.
- Include network-case evidence and proposed expiration in the daily review
  before a long-duration prefix block is enacted.
- Support manual exceptions inside a blocked prefix.

## Abuse-contact delivery failures

- Detect delivery-status notifications and associate them with the original
  report, incident, recipient, message ID, and network.
- Distinguish nonexistent mailboxes, permanent policy rejection, temporary
  SMTP deferral, connection timeout, and DNS/MX failure.
- Record first failure, latest failure, retry count, and final disposition.
- Consider a dedicated envelope-sender/bounce address while retaining an
  operator-facing `Reply-To` address.
- Do not silently treat SMTP queue acceptance as confirmed delivery.
- Surface nonresponsive or invalid abuse contacts in the 07:00 review digest
  and future dashboard.
- Suppress repeated futile mail attempts after a confirmed permanent failure.
- Require persistent failure or a permanent status before treating a provider
  as lacking a functioning abuse mechanism.

## Future web dashboard

- Authentication and LAN/reverse-proxy access controls.
- Incident queue, evidence view, and report history.
- Allowlist and trusted-network management.
- Fail2ban/CrowdSec state and manual action controls.
- 429 crawler review and disposition.
- Daily-summary history and annotations.
- Multi-node health and transport status.
