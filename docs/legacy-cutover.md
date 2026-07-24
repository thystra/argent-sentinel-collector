# Legacy web-abuse reporter cutover

Argent Sentinel 0.4 ports the high-confidence exploit-path categories used by
the legacy Nginx reporter, plus its bounded high-volume scanner rule. It also
imports legacy `<date>-<ip>.sent` markers so already-reported activity is not
resent.

The cutover tool never deletes the old scripts, logs, reports, or marker state.
In test mode it leaves legacy cron active. In production mode it backs up and
comments root-crontab and `/etc/cron.d` entries invoking
`nginx-abuse-draft-reports.py` or `nginx-abuse-send-reports.py`.

Run a redirected test first:

```bash
sudo argent-sentinel-cutover-reporting \
  --mode test --recipient your-address@example.com --apply
```

After a new qualifying incident is received and verified, run the production
cutover. It creates a new UTC cutoff and disables the old cron entries:

```bash
sudo argent-sentinel-cutover-reporting --mode production --apply
```

Every cutover creates a rollback directory under
`/var/backups/argent-sentinel/cutover-TIMESTAMP/`.
