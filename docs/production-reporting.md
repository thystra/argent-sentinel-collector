# Production reporting controls

Provider reporting remains explicitly activated. Package installation never
enables mail. The reporting cutoff is compared to incident activity time, not
the time the collector evaluates the incident.

Individual reports include source/destination tuple evidence when available,
registered network and ASN data, bounded event UUIDs, CIDR-level qualifying
history, and the enforcement action. WordPress and SSH account identifiers are
not disclosed.

CIDR escalation remains operator-controlled. To mark a reviewed network blocked
and send its one-time escalation report:

```bash
sudo argent-sentinel --config /etc/argent-sentinel/collector.json \
  network-set --cidr 198.51.100.0/24 --status blocked \
  --note 'operator approved after review' --send-report
```

A network escalation is sent at most once; network updates are limited to one
successful update per UTC day and remain subject to recipient guardrails.
