# Argent Sentinel Agent and Operator Notes

This file is the cross-session handoff for coding agents and operators. Keep it
current when host roles, paths, packaging, or deployment conventions change.
Do not place passwords, private keys, certificate contents, API tokens, or
other secrets here.

## Repository and branch

- Public repository: `https://github.com/thystra/argent-sentinel-collector`
- Normal branch: `main`
- Before applying a patch, run `git status --short` and preserve any local work.
- Patch paths in ChatGPT such as `/mnt/data/file.patch` exist only in the
  ChatGPT sandbox. Download the artifact before using it on a real host.

## `fafnir`: desktop/development workstation

- Normal user: `alan`
- Normal checkout: `~/src/argent-sentinel-collector`
- Browser downloads: `~/Downloads/` **with the plural `Downloads`**
- Normal Debian output: `~/src/argent-sentinel-collector/dist/deb`
- Build and test changes here before production deployment.

Typical workflow on `fafnir`:

```bash
cd ~/src/argent-sentinel-collector
git status --short
python3 ~/Downloads/apply-argent-sentinel-dashboard-awstats-stabilization-v3.py
git diff --check
python3 tests/test_v0501.py
python3 packaging/build_debs.py --revision NEXT --output-dir dist/deb
```

Use a Debian revision greater than the currently installed revision. Do not
assume `-2` is always next; confirm the installed version on the server.

## `nidhoggur`: production/server host

- Operating system: Ubuntu 24.04
- Primary role: central Argent Sentinel collector/API/dashboard, Nginx, AWStats,
  WordPress, and related services
- Administrative work is normally performed with `sudo` or a root shell.

Important live paths:

```text
/etc/argent-sentinel/                       persistent configuration and PKI
/usr/lib/argent-sentinel/                   installed Python implementation
/usr/sbin/argent-sentinel-*                 installed command wrappers
/var/lib/argent-sentinel/                   private state and publication root
/var/lib/argent-sentinel/dashboard/         sanitized dashboard snapshot
/var/lib/argent-sentinel/dashboard/awstats/ static AWStats reports
/run/argent-sentinel-api/                   API Unix socket runtime directory
/run/argent-sentinel-dashboard/             dashboard Unix socket runtime directory
/etc/awstats/                               generated AWStats site configuration
/var/lib/awstats/                           AWStats data/history
/etc/nginx/sites-available/                 Nginx source virtual hosts
/etc/nginx/sites-enabled/                   active Nginx virtual hosts
/var/log/nginx/                             Nginx logs
```

The active Sentinel host is normally:

```text
/etc/nginx/sites-enabled/sentinel.argentwolf.org.conf
```

The live file is operator-managed. Package updates install examples under
`/usr/share/argent-sentinel/`; they must not silently replace the live virtual
host.

## Current dashboard security boundary

- Server-level `ssl_verify_client` is `optional` so ordinary browsers can reach
  the dashboard.
- Exact `/v1/ingest` access still requires `$ssl_client_verify = SUCCESS`.
- Dashboard and AWStats locations use `satisfy all`: permitted network **and**
  HTTP Basic Authentication are both required.
- LAN allowlists must include the actual globally routed IPv6 prefix when
  clients use global IPv6; `fc00::/7` covers only ULA addresses.
- `/healthz` checks the ingestion API. `/dashboard-healthz` checks the dashboard.
- `/var/lib/argent-sentinel` remains private (`root:sentinel 0750`). The
  presentation group receives only execute/traverse ACL access on that ancestor.
- Sanitized files beneath `/var/lib/argent-sentinel/dashboard` are published as
  `root:www-data`, directories `0750`, files `0640`.
- Do not add Nginx broadly to the `sentinel` group.

## Deployment and verification

Transfer built `.deb` files from `fafnir` to an explicitly chosen staging
location on `nidhoggur`; do not assume a ChatGPT sandbox path exists there.
After installation or upgrade:

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl start argent-sentinel-dashboard-snapshot.service
sudo systemctl restart argent-sentinel-dashboard.service
sudo systemctl start argent-sentinel-awstats.service
```

Verify services and paths:

```bash
sudo namei -l /var/lib/argent-sentinel/dashboard/snapshot.json
sudo getfacl -p /var/lib/argent-sentinel
sudo -u www-data test -r \
  /var/lib/argent-sentinel/dashboard/snapshot.json
curl --unix-socket /run/argent-sentinel-dashboard/dashboard.sock \
  http://localhost/healthz
sudo journalctl -u argent-sentinel-dashboard.service -n 50 --no-pager -l
sudo journalctl -u argent-sentinel-awstats.service -n 100 --no-pager -l
```

## Documentation continuity

After implementation or deployment decisions, review and update:

- `README.md` for operator-facing commands and expected results
- `ARCHITECTURE.md` for trust boundaries and data flow
- `TODO.md` for dated current state, completed tasks, unresolved defects, and
  exact next steps
- this file for stable host/path/environment conventions

## Cross-project profile

- Read `AGENTS-PROFILE.md` alongside this project handoff.
- `AGENTS-PROFILE.md` contains reusable communication, command, generated-file,
  release, and general host-layout preferences.
- Keep project-specific versions, live paths, security policy, and deployment
  state in this `AGENTS.md`.
- New generated files should include their full source path near the top and a
  commented EOF marker when the format supports comments.

## Current reporting checkpoint
- Version 0.5.1.1 is the operational reporting baseline.
- The 2026-07-29 production cutover retired the legacy Nginx sender and
  validated the first hourly provider delivery.
- Immediate per-IP enforcement remains independent of hourly provider email.
- Provider ownership uses the registered allocation; report aggregation uses a
  bounded batch CIDR, `/24` for IPv4 and `/48` for IPv6 by default.
- The Reports dashboard is fed only through the root-generated sanitized
  snapshot and shows queued groups, run state, message IDs, and ban-only
  suppressions.
- Meta/Facebook provider email is suppressed for configured ASN/CIDR matches
  while local decisions remain active.
- Persistent WordPress provider reporting remains disabled pending production
  volume review.
- `argent-sentinel-wordpress-sites` confirms all four production WordPress
  connector sites as `seen`.
