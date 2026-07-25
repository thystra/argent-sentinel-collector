# Operator validation

## HTTP 429 observations

`network_observations` uses `occurred_at` and `occurred_epoch`. It does not
contain an `observed_at` or `observed_epoch` column.

```bash
db=/var/lib/argent-sentinel/collector/state.sqlite3

sqlite3 -header -column "$db" <<'SQL'
SELECT
    COUNT(*) AS total_429,
    COUNT(DISTINCT source_ip) AS source_ips,
    MIN(occurred_at) AS first_seen,
    MAX(occurred_at) AS last_seen
FROM network_observations
WHERE http_status = 429;

SELECT
    source_ip,
    host,
    request_uri,
    user_agent,
    occurred_at
FROM network_observations
WHERE http_status = 429
ORDER BY occurred_epoch DESC
LIMIT 20;
SQL
```

## Daily review

First verify the review directly:

```bash
/usr/sbin/argent-sentinel-review-digest   --config /etc/argent-sentinel/collector.json   --stdout
```

Then verify it inside the packaged systemd sandbox:

```bash
systemctl start argent-sentinel-review-digest.service

journalctl   -u argent-sentinel-review-digest.service   --since '5 minutes ago'   --no-pager
```

The systemd unit grants write access only to the collector state directory and
runtime lock directory. The SQLite connection remains URI read-only and enables
`PRAGMA query_only=ON`.
