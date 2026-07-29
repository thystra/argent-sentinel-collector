# Dashboard review workflow

Argent Sentinel 0.5.2.0 replaces the report-attempt count previously labeled
“Reports needing review” with a deduplicated incident review queue.

## Queue membership

One incident creates at most one open item. The queue includes:

- failed provider delivery;
- incidents with no usable abuse contact;
- deferred incidents that are overdue or repeatedly deferred; and
- policies explicitly held for production review, including persistent
  WordPress reporting.

An ordinary cooldown deferral that is still scheduled for automatic retry is
not operator work and does not increase the open-item count. Each item includes
its recent delivery-attempt history, registered allocation, bounded network,
ASN, decision context, and existing operator notes. A closed failed/deferred
item reopens automatically when a newer delivery attempt fails.

## Available actions

- **Acknowledge** closes the review item without changing enforcement or the
  report state.
- **Retry next batch** changes the report state to `pending`, clears the prior
  delivery identity, and makes the incident eligible for the next hourly run.
- **Suppress report** changes the provider-report state to `suppressed` while
  retaining local enforcement.
- **Permanent no contact** closes an unusable-contact case as a suppression
  with an explicit audited disposition.
- **Add note** records operator context while leaving the item open.

## Security boundary

The dashboard worker never opens the collector SQLite database for writing.
An authenticated POST creates a small validated JSON request in:

```text
/var/spool/argent-sentinel/review/incoming
```

The root-owned `argent-sentinel-review-processor.path` activates a oneshot
processor. The processor acquires the shared collector lock, revalidates the
incident timestamp to reject stale forms, applies one transaction, appends to
`review_actions`, and archives the request under `processed` or `failed`.
Request UUIDs are unique and make repeated delivery idempotent.

The dashboard derives the audit operator from the existing HTTP Basic
`Authorization` header after Nginx has authenticated it. Arbitrary client-sent
identity headers are ignored. The public dashboard virtual host therefore does
not require a new identity-forwarding header.

## Time display

Snapshots and database records remain UTC. The HTML dashboard renders times in
the server-local timezone and retains the canonical UTC value in the `<time
 datetime>` attribute and tooltip.
