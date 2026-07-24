# Argent Sentinel

Argent Sentinel is a self-hosted security event collector, correlation engine,
CrowdSec decision bridge, and guarded abuse-reporting system.

Version 0.4.3 separates producers, node transport, and central policy:

```text
WordPress / Nginx / OpenSSH
          │ local immutable spool or journald cursor
          ▼
argent-sentinel-agent
          │ HTTPS + per-node mTLS certificate
          ▼
sentinel.argentwolf.org
          │ Nginx verified-client proxy
          ▼
argent-sentinel-api → central collector → CrowdSec / abuse reporting
```

On a combined host such as Nidhoggur, local WordPress batches may continue to be
read directly while the agent is configured `--ssh-only`. Remote Hermod and
Heimdall nodes use the same stable central service name.

## Packages

- `argent-sentinel-common`: collector, agent, API engines and shared files.
- `argent-sentinel-agent`: remote transport timer and node-side helpers.
- `argent-sentinel-server`: ingestion API, collector timer, PKI and cutover tools.
- `argent-sentinel`: combined-host metapackage.

Installation does not enable provider reporting. Use the documented redirected
test and production cutover procedure after Nginx `abuse_context`, mail sender,
RDAP enrichment, and client-certificate ingestion have been verified.

See `docs/` for remote enrollment, SSH privacy, web-probe policy, CIDR reporting,
and legacy migration.
