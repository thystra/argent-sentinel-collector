# Fail2ban and review policy

Fail2ban remains enabled as the first enforcement layer.

Recommended local policy:

- `sshd-invaliduser`: one failure, 30-day ban.
- `sshd`: four failures in one hour, 30-day ban.
- Nginx rules that deliberately return 444: one match, long ban.
- Customer-facing WordPress login failures: five failures in 15 minutes,
  initially a 15-minute ban.
- Repeated WordPress stuffing: escalate through recidive policy.
- HTTP 429: do not ban from one response. Review sustained pressure grouped by
  network prefix and client identity.

Argent Sentinel v0.4.9 records Fail2ban ban notices for audit and daily review.
It does not create a second incident merely because a native SSH or Nginx event
and a Fail2ban ban describe the same activity.
