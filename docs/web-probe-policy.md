# Nginx hostile web-probe policy

When `abuse_context.enabled` is true, v0.4 independently evaluates Nginx
observations instead of using them only as tuple evidence for WordPress.

High-confidence categories include sensitive-file probes, WordPress PHP
backdoor/plugin/theme paths, command-style REST probes, path traversal, and CGI
shell probes. Three suspicious requests within ten
minutes qualify by default; one suspicious request producing a 5xx response also qualifies, matching the legacy reporter. A separate compatibility rule qualifies at least
100 non-429/non-444 4xx/5xx requests to 25 distinct targets, excluding dominant
recognized search-bot user agents.

Authenticated Nextcloud WebDAV writes are excluded when `remote_user`, method,
path, and client user-agent identify a legitimate DAV operation.
