# Collector lock contention and the nidhoggur journald gap (2026-11-19)

Status: fix on branch `fix/collector-lock-wait`; not released or deployed.

## Symptoms reported

1. `argent-sentinel-collector.service` failed intermittently in
   `ExecStartPre=/usr/bin/argent-sentinel --config /etc/argent-sentinel/collector.json migrate`
   (status 1) but the same command succeeded when run by hand.
2. Other runs logged `ERROR argent-sentinel Another collector process is already running`.
3. `journalctl -u argent-sentinel-collector.service` showed nothing, even for a
   `systemd-run` test unit.

## Confirmed fault 1: fail-fast lock in `migrate` (code)

Every command that writes collector state shares one `flock(2)` lock,
`/run/argent-sentinel/collector.lock`:

| Taker | Mode | Behaviour when busy (0.5.7.0) |
|---|---|---|
| `argent-sentinel migrate` (collector + report-batch `ExecStartPre`, postinst) | `LOCK_EX\|LOCK_NB` (`process_lock`) | exit 1 |
| `argent-sentinel run` (collector `ExecStart`) | `LOCK_EX\|LOCK_NB` | exit 0, `skipped/lock-busy` |
| `argent-sentinel protection-state-refresh` (postinst), `ban-sync-merge` | `LOCK_EX\|LOCK_NB` | exit 1 |
| `argent-sentinel-report-batch` (hourly :05) | `LOCK_EX\|LOCK_NB` | exit 1 |
| `argent-sentinel-dashboard-snapshot` (every minute) | `LOCK_SH`, blocking | waits |
| `argent-sentinel-review-digest` (07:00) | `LOCK_SH`, blocking | waits |
| `argent-sentinel-review-processor` (path unit) | `LOCK_EX`, blocking | waits |

The collector and dashboard-snapshot timers both use `OnUnitActiveSec=1min`,
so once their phases align the overlap repeats for many consecutive minutes.
The snapshot holds its shared lock for ~10–15 s per run.

Evidence (read-only, nidhoggur syslog 2026-11-18 00:00 → 2026-11-19 14:28,
correlating systemd `Starting`/`Finished`/`Control process exited` lines):

- 2269 collector starts, 548 failures; 39 report-batch starts, 14 failures.
- 562/562 failures happened while another lock holder was active: 538
  collector failures overlapped the dashboard snapshot, 5 the report batcher,
  4 both, 1 the review digest; all 14 report-batch failures overlapped the
  snapshot. Zero failures with no other holder.
- Example: 12:40:04 snapshot starts → 12:40:17 collector starts and fails →
  12:40:19 snapshot finishes; 12:39:14 snapshot finished → 12:39:16 collector
  succeeded.
- 14:05:05 `ERROR ... Another collector process is already running` is
  journald-attributed to `_SYSTEMD_UNIT=argent-sentinel-report-batch.service`
  (its `ExecStartPre` migrate colliding with the running collector).

Fix: `process_lock(path, wait_seconds)` polls for up to `lock_wait_seconds`
(default 45 s) before raising the unchanged error. Tests:
`tests/test_v0580_collector_lock_wait.py` reproduce the overlap with a real
second process (fail-fast exit 1, bounded wait success, stuck holder still
fails).

## Confirmed fault 2: host-wide journald gap after the 2026-11-19 reboot (host, not code)

- At boot (10:25:53) journald logged `system.journal corrupted or uncleanly
  shut down, renaming and replacing` (previous shutdown: fail2ban stop
  timeout).
- The current `system.journal` starts at **12:37:58**; no archived system file
  covers 10:25:53–12:37:57. For that window there are no PID 1, kernel,
  journald or root-service entries at all (only non-root services, which are
  stored in per-UID `user-*.journal` files).
- rsyslog, fed from journald's forwarding socket, recorded the same window
  normally (PID 1 and collector lines present in `/var/log/syslog`), so
  journald received the messages; the system journal file for that period is
  gone.
- This explains "unit-filtered journalctl is empty, even for a systemd-run
  test unit": the tests ran inside the missing window. It is not a sandbox,
  `LogNamespace=`, `StandardOutput=` or rate-limit effect: `LogNamespace=` is
  empty, no rate limits are configured, `Storage=persistent`, and since 12:37:58
  attribution works (`_SYSTEMD_UNIT` is set correctly on report-batch lines).
- Today the collector unit journal is empty only because the
  `90-logging.conf` drop-in sends stdout/stderr to
  `/var/lib/argent-sentinel/collector/service.log` (expected).

Hypothesis (unconfirmed): the replacement system file created at 10:25:53 was
lost when all journal files rotated at 12:37:58. No operator command for that
rotation is recorded.

## Rollback

Set `"lock_wait_seconds": 0` in `/etc/argent-sentinel/collector.json` for the
old behaviour without a downgrade, or reinstall the previous package.
