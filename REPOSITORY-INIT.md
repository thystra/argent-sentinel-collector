# Repository initialization

This archive is a clean source snapshot for Argent Sentinel Host Collector 0.2.2.
It intentionally excludes live configuration, SQLite state, logs, locks, secrets,
and a `.git` directory.

Initialize a repository:

```bash
git init -b main
git add .
git commit -m "Import Argent Sentinel collector v0.2.2"
git tag -a v0.2.2 -m "Argent Sentinel collector v0.2.2"
```

Keep the following outside Git:

- `/etc/argent-sentinel/collector.json`
- `/var/lib/argent-sentinel/collector/`
- `/var/lib/argent-sentinel/drop/`
- `/run/argent-sentinel/`
- mail credentials, secrets, logs, and generated reports

For a fresh installation use `sudo ./scripts/install.sh`. For an existing
0.2.1/0.2.2 installation, review and use
`sudo ./scripts/install-v0.2.2-reporting-guardrails.sh`.

## Debian packages

Build v0.3.1 packages with `./scripts/build-debs.sh`; see `docs/debian-packaging.md`.
