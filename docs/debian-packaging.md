# Debian packages

Argent Sentinel 0.3.1 builds four architecture-independent packages:

- `argent-sentinel-common`: shared collector engine, CLI, examples, and documentation.
- `argent-sentinel-agent`: local WordPress and Nginx submission/onboarding helpers. Remote HTTPS delivery is intentionally deferred to v0.4.
- `argent-sentinel-server`: the central collector service and timer.
- `argent-sentinel`: a metapackage that installs both agent and server on a combined host.

## Build

On Ubuntu 24.04 or later:

```bash
sudo apt install build-essential python3
./scripts/build-debs.sh
```

Packages and `SHA256SUMS` are written to `dist/deb/`.

The build uses `dpkg-deb` directly and does not require `debhelper`. It normalizes ownership and timestamps and can be made reproducible by setting `SOURCE_DATE_EPOCH`.

## Install on the combined central host

```bash
sudo apt install ./dist/deb/argent-sentinel_0.3.1-1_all.deb
```

APT will install the exact-version `common`, `agent`, and `server` dependencies when all four files are in the same directory and are supplied together:

```bash
sudo apt install ./dist/deb/argent-sentinel-common_0.3.1-1_all.deb \
  ./dist/deb/argent-sentinel-agent_0.3.1-1_all.deb \
  ./dist/deb/argent-sentinel-server_0.3.1-1_all.deb \
  ./dist/deb/argent-sentinel_0.3.1-1_all.deb
```

Existing `/etc/argent-sentinel/collector.json` and SQLite state are preserved. A consistent SQLite backup is placed under `/var/backups/argent-sentinel/` during server package configuration.

Legacy `/etc/systemd/system/argent-sentinel-collector.*` files installed by the earlier source installer are archived only when they reference `/usr/local/libexec/argent-sentinel/collector.py`. Customized overrides are preserved and generate a warning.

## Agent-only hosts

```bash
sudo apt install ./dist/deb/argent-sentinel-common_0.3.1-1_all.deb \
  ./dist/deb/argent-sentinel-agent_0.3.1-1_all.deb
```

In 0.3.1 this provides local spool and onboarding helpers. It does not yet send batches to `sentinel.argentwolf.org`; that transport is the v0.4 boundary.
