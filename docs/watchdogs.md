<!-- Source: /home/alan/src/argent-sentinel-collector/docs/watchdogs.md -->
# Modular watchdog framework

Argent Sentinel 0.5.5.0 adds a package-managed watchdog runner for local
service-health checks, evidence capture, bounded remediation, notifications,
and dashboard publication.

## Layout

```text
/etc/argent-sentinel/watchdog.json              global runner and notification policy
/etc/argent-sentinel/watchdog.d/*.json           operator overrides and local modules
/usr/lib/argent-sentinel/watchdog.d/*.json       package-owned module definitions
/usr/lib/argent-sentinel/watchdogs/              package-owned Python module implementations
/var/lib/argent-sentinel/watchdogs/status/       current machine-readable module state
/var/lib/argent-sentinel/watchdogs/incidents/    retained pre-recovery evidence
```

Definitions are merged by `id`: package defaults load first and local files load
second. Packaged modules ship disabled so a generic installation never probes or
restarts a service merely because the implementation is present. A small local
file enables a module or overrides one threshold without copying the entire
definition.

Example:

```json
{
  "id": "php_fpm",
  "enabled": true
}
```

Each module runs in a separate bounded process group. Its `timeout_seconds`
limits the module and all commands it launches; a timed-out module is terminated
and published as an error without blocking later watchdogs indefinitely.

## Notification categories

`watchdog.json` has independent recipient lists:

```json
"notifications": {
  "admin_recipients": [
    "sysadmin1@example.org",
    "sysadmin2@example.org"
  ],
  "emergency_recipients": [
    "phone1email@example.org",
    "phone2email@example.org"
  ]
}
```

Administrative recipients receive routine reports, state transitions, and
successful automatic-recovery reports. Emergency recipients receive short,
high-signal messages for critical incidents and failed remediation. Addresses
present in both groups are deduplicated. Emergency delivery is individual so
email-to-SMS gateways do not expose or combine destinations.

## Included watchdogs

### Unbound

The Unbound module preserves the pre-existing production behavior:

- run every five minutes;
- query a configured domain through `127.0.0.1`;
- on first failure, collect diagnostics before mutation;
- optionally capture GDB backtraces when GDB is installed;
- restart `unbound.service`;
- verify DNS recovery;
- retain a compressed incident bundle;
- notify administrators for every automatic recovery;
- notify emergency recipients only when recovery fails.

The server-package upgrade recognizes the known legacy
`/usr/local/sbin/unbound-watchdog.sh` and its local systemd units. Only when the
assets match the known production implementation does it create a local enable
override, migrate `EMAIL_TO` into the administrative recipient list, disable the
old timer, and archive the old assets. Custom legacy watchdogs are left intact.

### PHP-FPM 8.5

The first PHP-FPM module is intentionally observe-only. It checks:

- service state and master PID;
- zombie PHP-FPM processes;
- maximum FastCGI socket receive queue;
- effective FPM event mechanism;
- new rapid worker exits since the prior check;
- new `epoll: unable to remove fd` records;
- configured local HTTPS application probes.

The package definition is disabled and has no site-specific probes. The
production nidhoggur override supplies the Nextcloud, Friendica, and Wolf & Raven
probes and enables the module. The log cursor starts at the current end of the
FPM log, so installation does not alert on historical failures. Cursor rotation
is inode-aware. PHP-FPM warnings or critical results must persist for two
consecutive checks before email is sent. No PHP restart is available in 0.5.5.0.

## Commands

```bash
sudo argent-sentinel-watchdog \
  --config /etc/argent-sentinel/watchdog.json \
  validate-config

sudo argent-sentinel-watchdog \
  --config /etc/argent-sentinel/watchdog.json \
  run --force --watchdog php_fpm --no-notify

sudo argent-sentinel-watchdog \
  --config /etc/argent-sentinel/watchdog.json \
  status --json
```

The package timer runs the scheduler every minute. Each definition supplies its
own `interval_seconds`, so the common timer does not force every module to run
at the same cadence.

## Dashboard

The root-owned snapshot builder reads only the current status files and publishes
a sanitized `watchdogs` section. The unprivileged dashboard renders a Watchdogs
page showing current and stale state, mode, last check, consecutive failures,
transition timestamps, recent state history, metrics, sanitized diagnostic
detail, and notification delivery counts. Recipient addresses and private module
diagnostics are never copied into the dashboard snapshot. The dashboard cannot
execute or reconfigure watchdogs.

## Prometheus and Grafana

Prometheus-compatible metrics are intentionally deferred until the native state,
transition, and notification behavior has production history. A later release
can export watchdog health and counters without making local detection or
recovery dependent on Prometheus, Alertmanager, Grafana, or network access.

<!-- EOF: /home/alan/src/argent-sentinel-collector/docs/watchdogs.md -->
