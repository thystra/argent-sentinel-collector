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

## Modular watchdogs

Validate global configuration and merged package/local definitions before
starting the timer:

```bash
/usr/sbin/argent-sentinel-watchdog \
  --config /etc/argent-sentinel/watchdog.json \
  validate-config
```

Package definitions are disabled. Enable a module with a local override, then
run it once without mail:

```bash
/usr/sbin/argent-sentinel-watchdog \
  --config /etc/argent-sentinel/watchdog.json \
  run --force --watchdog php_fpm --no-notify

/usr/sbin/argent-sentinel-watchdog \
  --config /etc/argent-sentinel/watchdog.json \
  status --json
```

After reviewing the root-only state beneath
`/var/lib/argent-sentinel/watchdogs/status`, start the packaged scheduler and
refresh the sanitized dashboard publication:

```bash
systemctl enable --now argent-sentinel-watchdog.timer
systemctl start argent-sentinel-watchdog.service
systemctl start argent-sentinel-dashboard-snapshot.service

systemctl status \
  argent-sentinel-watchdog.timer \
  argent-sentinel-watchdog.service \
  --no-pager --full

journalctl \
  -u argent-sentinel-watchdog.service \
  --since '10 minutes ago' \
  --no-pager
```

Confirm that the dashboard snapshot contains no recipient addresses or private
module diagnostics before exposing a new module through the Watchdogs page.

<!-- EOF: /home/alan/src/argent-sentinel-collector/docs/operator-validation.md -->
