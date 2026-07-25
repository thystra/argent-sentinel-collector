# Dashboard and traffic analysis

## Security model

The v0.5 dashboard is read-only. A root-owned oneshot service opens the
collector database under the existing shared lock, writes a bounded sanitized
JSON snapshot, and exits. The long-running dashboard process runs as the
unprivileged `argent-sentinel-dashboard` user and can read only the snapshot and
static AWStats output.

The packaged Nginx example for `sentinel.argentwolf.org` requires both:

- a source address in the configured LAN/ULA ranges; and
- HTTP Basic authentication.

The existing `/v1/ingest` endpoint continues to require a successfully verified
Argent Sentinel node certificate. Because the dashboard and ingestion endpoint
share one TLS virtual host, the server-level setting is `ssl_verify_client
optional`; the ingestion location explicitly rejects any request whose
`$ssl_client_verify` value is not `SUCCESS`.

## Initial setup

Create the dashboard password:

```bash
sudo argent-sentinel-dashboard-setup admin
```

Review the combined Nginx example:

```text
/usr/share/argent-sentinel/nginx-sentinel-dashboard.conf.example
```

Back up the current Sentinel virtual host, merge or replace it with the example,
then validate before reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Generate the first snapshot:

```bash
sudo systemctl start argent-sentinel-dashboard-snapshot.service
sudo systemctl restart argent-sentinel-dashboard.service
```

## AWStats per-site reports

Install AWStats:

```bash
sudo apt install awstats
```

Discover hostnames present in the extended Nginx logs:

```bash
sudo argent-sentinel-awstats \
  --config /etc/argent-sentinel/traffic-sites.json \
  discover
```

Review the output, then add missing hostnames automatically:

```bash
sudo argent-sentinel-awstats \
  --config /etc/argent-sentinel/traffic-sites.json \
  discover --write-missing
```

Edit aliases and disable unwanted entries in
`/etc/argent-sentinel/traffic-sites.json`, then generate reports:

```bash
sudo systemctl start argent-sentinel-awstats.service
sudo systemctl start argent-sentinel-dashboard-snapshot.service
```

AWStats is configured with `%virtualname`; records outside each site's
`SiteDomain` and `HostAliases` are discarded even when several virtual hosts
share one extended access log. Reports are static HTML and browser-triggered
updates are disabled.

## Meta crawler policy

Install the Nginx map and enforcement snippet:

```bash
sudo argent-sentinel-install-crawler-policy
```

Activate it for reviewed site files:

```bash
sudo argent-sentinel-install-crawler-policy \
  /etc/nginx/sites-available/photos.argentwolf.org \
  /etc/nginx/sites-available/wolfandraven.blog
```

The script backs up edited files, inserts the enforcement include in each
`server` block, runs `nginx -t`, restores files on validation failure, and
reloads Nginx only after a successful test.

`FacebookExternalHit` remains allowed for Facebook link previews.
`Meta-ExternalAgent` receives HTTP 403. Sentinel retains the traffic data and
excludes the known agent from generic high-volume scanner materialization, but
independently hostile request paths still qualify as incidents.
