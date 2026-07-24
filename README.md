# Argent Sentinel Host Collector 0.3.0

Argent Sentinel imports immutable WordPress security-event batches into a
root-controlled SQLite state database, detects credential spraying, optionally
requests CrowdSec decisions, enriches sources, and sends bounded abuse reports.

Version 0.3.0 adds the first unified web-abuse evidence layer:

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

## Upgrade

```bash
python3 -m py_compile src/collector.py
python3 tests/test_collector.py
python3 tests/test_reporting_guardrails.py
python3 tests/test_network_context.py
sudo ./scripts/install-v0.3.0.sh
```

The installer backs up the installed collector and live configuration, preserves
all existing reporting values, adds missing v0.3.0 defaults, migrates SQLite in
place, and leaves `abuse_context` disabled.

## Status and network cases

```bash
sudo /usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json status

sudo /usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json network-list

sudo /usr/local/libexec/argent-sentinel/collector.py \
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
