# Argent Sentinel 0.3.1

Argent Sentinel imports immutable WordPress security-event batches into a
root-controlled SQLite state database, detects credential spraying, optionally
requests CrowdSec decisions, enriches sources, and sends bounded abuse reports.

Version 0.3.0 added the first unified web-abuse evidence layer:

- Nginx `abuse_context` JSON/JSONL ingestion, disabled until explicitly enabled;
- exact WordPress-to-Nginx correlation using a trusted request ID;
- bounded fallback correlation by source IP, path, and timestamp;
- source/destination IP, port, transport, HTTP, and TLS evidence in abuse mail;
- recent qualifying CIDR context in individual reports;
- persistent network cases with `observing`, `review`, `escalation-review`,
  `blocked`, and `closed` states;
- manual network-case commands that do not alter firewall enforcement;
- stable node identity and future central service metadata; and
- a host-side WordPress onboarding helper that does not edit `wp-config.php`.

Automatic CIDR blocking and automatic network-level provider email are rejected
by configuration in this release. A `blocked` network-case status records an
operator decision only; it does not run `cscli`. Remote HTTPS/mTLS delivery to
`sentinel.argentwolf.org` remains the v0.4 transport boundary.

## Build Debian packages

```bash
./scripts/build-debs.sh
```

The build writes these architecture-independent packages to `dist/deb/`:

```text
argent-sentinel-common_0.3.1-1_all.deb
argent-sentinel-agent_0.3.1-1_all.deb
argent-sentinel-server_0.3.1-1_all.deb
argent-sentinel_0.3.1-1_all.deb
```

Install all four on the combined central host:

```bash
sudo apt install \
  ./dist/deb/argent-sentinel-common_0.3.1-1_all.deb \
  ./dist/deb/argent-sentinel-agent_0.3.1-1_all.deb \
  ./dist/deb/argent-sentinel-server_0.3.1-1_all.deb \
  ./dist/deb/argent-sentinel_0.3.1-1_all.deb
```

The server package preserves `/etc/argent-sentinel/collector.json`, creates a
consistent SQLite backup under `/var/backups/argent-sentinel/`, migrates the
database, and enables the existing `argent-sentinel-collector.timer` unit name.
See `docs/debian-packaging.md` for package roles and agent-only installation.

## Migration command

```bash
sudo argent-sentinel \
  --config /etc/argent-sentinel/collector.json \
  migrate --backup-dir /var/backups/argent-sentinel/manual-migration
```

The command uses SQLite's online backup API before applying idempotent schema
changes and records the current schema version.

## Status and network cases

```bash
sudo argent-sentinel \
  --config /etc/argent-sentinel/collector.json status

sudo argent-sentinel \
  --config /etc/argent-sentinel/collector.json network-list

sudo argent-sentinel \
  --config /etc/argent-sentinel/collector.json network-set \
  --cidr 198.51.100.0/24 --status review \
  --note 'Operator review requested'
```

## Additional WordPress sites

After installing WordPress connector v0.2.1, use the command printed by its
settings page, or run:

```bash
sudo ./scripts/onboard-wordpress-site.sh \
  --wordpress-path /path/to/wordpress \
  --site-id example-site \
  --node-id nidhoggur \
  --php-user example-fpm
```

The collector continues to discover all site-specific directories through:

```text
/var/lib/argent-sentinel/drop/wordpress/*/incoming/*.json
```

See `docs-abuse-context.md` for Nginx configuration and safe log staging.
