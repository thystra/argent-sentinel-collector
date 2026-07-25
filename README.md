# Argent Sentinel

Argent Sentinel is a self-hosted security event collector, correlation engine,
CrowdSec decision bridge, and guarded abuse-reporting system.

Version 0.4.7 separates producers, authenticated node transport, and central
policy:

```text
WordPress / Nginx / OpenSSH
          | local immutable spool or journald cursor
          v
argent-sentinel-agent
          | HTTPS + per-node mTLS certificate
          v
sentinel.example.org
          | Nginx verified-client proxy
          v
argent-sentinel-api -> central collector -> CrowdSec / abuse reporting
```

A combined host may run both the agent and server packages. Remote nodes run the
agent package and submit immutable event batches to the central API.

## Packages

- `argent-sentinel-common`: collector, agent, API engines, shared command-line
  programs, configuration examples, and documentation.
- `argent-sentinel-agent`: node timer, WordPress/Nginx staging helpers, SSH
  journald collection, and enrollment helpers.
- `argent-sentinel-server`: ingestion API, collector timer, Nginx log rotation,
  PKI helpers, config migration, and reporting cutover tools.
- `argent-sentinel`: combined agent/server metapackage.

Installing packages never enables provider abuse reporting automatically.
Validate redirected test mode before production delivery.

## Configuration files

| File | Purpose | Important options |
| --- | --- | --- |
| `/etc/argent-sentinel/collector.json` | Central ingestion, correlation, enforcement, and reporting policy | `incoming_globs`, `abuse_context`, `policy`, `sshd_policy`, `web_policy`, `trusted_cidrs`, `crowdsec`, `enrichment`, `abuse_reporting` |
| `/etc/argent-sentinel/agent.json` | Node transport and SSH collection | `enabled`, `node`, `central_url`, certificate paths, local WordPress/Nginx globs, `sshd` |
| `/etc/argent-sentinel/server-api.json` | Unix-socket ingestion API | `socket_path`, `socket_group`, `nodes_dir`, `receipt_db`, `event_drop_root` |
| `/etc/argent-sentinel/nodes.d/NAME.json` | Per-node enrollment and service authorization | `node_id`, `enabled`, allowed `services`, allowed WordPress `site_ids` |
| `/etc/logrotate.d/argent-sentinel-nginx` | Hourly rotation and staging of the filtered Nginx JSONL log | retention, compression, stage helper |
| `/etc/nginx/conf.d/argent-sentinel-log-format.conf` | Dedicated structured Nginx format and conditional logging maps | JSON fields and suspicious-request conditions |
| `/etc/argent-sentinel/agent-privacy.key` | HMAC secret used to pseudonymize SSH account names | root-readable, at least 32 bytes |
| `/etc/argent-sentinel/pki/` | Sentinel CA, node certificate, and private key material | protect private keys as root-only |

Package examples are installed under `/usr/share/argent-sentinel/`.

### Collector input paths

`collector.json` must include both local and API-delivered event batches:

```json
"incoming_globs": [
  "/var/lib/argent-sentinel/drop/wordpress/*/incoming/*.json",
  "/var/lib/argent-sentinel/drop/remote/*/events/incoming/*.json"
]
```

`abuse_context.incoming_globs` should include local and remote Nginx inputs:

```json
[
  "/var/lib/argent-sentinel/drop/nginx/*/incoming/*.jsonl",
  "/var/lib/argent-sentinel/drop/nginx/*/incoming/*.json",
  "/var/lib/argent-sentinel/drop/remote/*/abuse-context/incoming/*.jsonl",
  "/var/lib/argent-sentinel/drop/remote/*/abuse-context/incoming/*.json"
]
```

The v0.4.7 server package appends missing required paths to preserved
configurations without replacing custom settings.

## New combined server installation

The example assumes Debian or Ubuntu, Nginx, DNS for the Sentinel API hostname,
and locally built `.deb` files.

1. Install all packages together:

   ```bash
   sudo apt install      ./argent-sentinel-common_0.4.7-1_all.deb      ./argent-sentinel-agent_0.4.7-1_all.deb      ./argent-sentinel-server_0.4.7-1_all.deb      ./argent-sentinel_0.4.7-1_all.deb
   ```

2. Review the generated configuration:

   ```bash
   sudoedit /etc/argent-sentinel/collector.json
   sudoedit /etc/argent-sentinel/agent.json
   sudoedit /etc/argent-sentinel/server-api.json
   ```

3. Set stable `node.id` and `node.fqdn` values.

4. Configure the API virtual host from:

   ```text
   /usr/share/argent-sentinel/nginx-sentinel.conf.example
   ```

   Replace hostname and certificate paths, then:

   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

5. Initialize the client-certificate CA and enroll nodes. Put node
   authorizations in `/etc/argent-sentinel/nodes.d/`. See
   `docs/remote-transport.md`.

6. Validate configuration:

   ```bash
   sudo argent-sentinel      --config /etc/argent-sentinel/collector.json validate-config

   sudo argent-sentinel-agent      --config /etc/argent-sentinel/agent.json validate-config

   sudo argent-sentinel-api      --config /etc/argent-sentinel/server-api.json validate-config
   ```

7. Enable the runtime:

   ```bash
   sudo systemctl enable --now      argent-sentinel-agent.timer      argent-sentinel-collector.timer      argent-sentinel-nginx-logrotate.timer      argent-sentinel-api.service
   ```

8. Verify schedules:

   ```bash
   systemctl list-timers --all |
     grep -E 'argent-sentinel-(agent|collector|nginx-logrotate)'
   ```

## New agent-only node

Install `argent-sentinel-common` and `argent-sentinel-agent`, enroll the node
certificate, authorize the node on the central server, and configure:

```json
{
  "enabled": true,
  "node": {
    "id": "remote-node",
    "fqdn": "remote-node.example.org"
  },
  "central_url": "https://sentinel.example.org/",
  "cert_file": "/etc/argent-sentinel/pki/node.crt",
  "key_file": "/etc/argent-sentinel/pki/node.key",
  "sshd": {
    "enabled": true,
    "unit": "ssh.service",
    "initial_lookback_minutes": 60,
    "destination_ip": "PUBLIC_TARGET_IP",
    "destination_port": 22
  }
}
```

The lookback is used only when no journald cursor exists.

## Adding a WordPress site

Use one stable lowercase site ID per installation. The PHP-FPM account must be
able to create files under:

```text
/var/lib/argent-sentinel/drop/wordpress/SITE_ID/incoming
```

The packaged onboarding helper creates the directory, grants the PHP-FPM user
membership in the `sentinel` group, configures plugin options with WP-CLI, and
runs a test export:

```bash
sudo argent-sentinel-onboard-wordpress   --wordpress-path /var/www/example-site   --site-id example-site   --node-id "$(hostname -s)"   --php-user www-data   --plugin-zip /root/argent-sentinel-wordpress.zip
```

When the plugin is installed already, omit `--plugin-zip`.

The lower-level directory helper is:

```bash
sudo argent-sentinel-create-wordpress-drop SITE_ID PHP_FPM_USER
```

It creates the directory with setgid mode `2770` and group `sentinel`. Restart
the relevant PHP-FPM service after group membership changes.

### Manual WP-CLI setup and checks

```bash
sudo -u PHP_FPM_USER -- wp --path=/var/www/example-site   argent-sentinel setup   --site-id=example-site   --source-host="$(hostname -s)"   --drop-directory=/var/lib/argent-sentinel/drop/wordpress/example-site/incoming   --format=json

sudo -u PHP_FPM_USER -- wp --path=/var/www/example-site   argent-sentinel status --format=json

sudo -u PHP_FPM_USER -- wp --path=/var/www/example-site   argent-sentinel export --format=json
```

Verify the filesystem independently:

```bash
namei -l /var/lib/argent-sentinel/drop/wordpress/example-site/incoming

sudo -u PHP_FPM_USER --   test -w /var/lib/argent-sentinel/drop/wordpress/example-site/incoming
```

For exact WordPress-to-Nginx request correlation, add this to every monitored
PHP-FPM location:

```nginx
fastcgi_param ARGENT_SENTINEL_REQUEST_ID $request_id;
```

### WordPress plugin limitation in v0.4.7

The plugin admin diagnostics/setup page is not yet reliable for showing nonce
validity or provisioning/writability failures. Until the plugin follow-up
release, treat WP-CLI status, the onboarding helper, and direct filesystem tests
as authoritative. The plugin should not be expected to create a missing system
drop directory by itself.

## Nginx web-probe collection

The active structured log is normally:

```text
/var/log/nginx/argent-sentinel-abuse-context.jsonl
```

The package-owned timer rotates it hourly. Rotated files are staged by
`/usr/sbin/argent-sentinel-stage-abuse-context` and imported on the next
collector cycle.

## SSH collection

The agent reads `journalctl -u ssh.service`, pseudonymizes account names with
HMAC-SHA256, and submits `ssh_auth_failed` events. It never sends usernames.
SSH thresholds are controlled by `sshd_policy` in `collector.json`.

## Redirected test reporting

Before production, use test mode:

```json
"abuse_reporting": {
  "enabled": true,
  "test_mode": true,
  "recipient_override": "operator@example.org",
  "max_reports_per_run": 2,
  "max_reports_per_recipient_per_day": 10,
  "recipient_cooldown_minutes": 15
}
```

Provider abuse contacts and administrative Bcc recipients are not used in test
mode. Production also requires `report_not_before_utc`; see
`docs/production-reporting.md`.

## Operational checks

```bash
argent-sentinel --version

systemctl status   argent-sentinel-agent.timer   argent-sentinel-collector.timer   argent-sentinel-nginx-logrotate.timer   argent-sentinel-api.service   --no-pager
```

Database inventory:

```bash
sqlite3 -header -column   /var/lib/argent-sentinel/collector/state.sqlite3 '
SELECT service, event_type, COUNT(*) AS events
FROM events
GROUP BY service, event_type;

SELECT rule_id, report_status, COUNT(*) AS incidents
FROM incidents
GROUP BY rule_id, report_status;

SELECT attempted_at, recipient, status, test_mode, detail
FROM report_attempts
ORDER BY attempt_id DESC
LIMIT 20;
'
```

`pending_reports: 0` means no report is currently awaiting work. It does not
mean there are no events or incidents; eligible reports are normally processed
during the same collector run.

See `docs/` for packaging, remote enrollment, SSH privacy, web-probe policy,
XARF reporting, production reporting, and legacy migration.

## Architecture and roadmap

See `ARCHITECTURE.md`, `TODO.md`, and `docs/fail2ban-review-policy.md`.
