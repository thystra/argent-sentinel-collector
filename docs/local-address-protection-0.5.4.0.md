# Dynamic local-address protection in Argent Sentinel 0.5.4.0

Argent Sentinel must not use its own CrowdSec integration to block an enrolled
node or an operator-controlled local IPv6 LAN. This protection is distinct from
source trust: protected addresses remain visible to telemetry, correlation,
review, and provider-reporting policy.

## Modes

- `host` recalculates one `/128` for every current qualifying public IPv6
  address. It is the conservative VPS, cloud, virtual-machine, and uncertain
  environment choice.
- `lan-prefix` recalculates the connected prefix reported with each qualifying
  address. It is effective only after the operator confirms ownership or
  control of the complete prefix. Without confirmation, the runtime inventory
  falls back to host `/128` protection.
- `manual` publishes only the operator-entered CIDRs. Dynamic inventory
  entries are bounded to no broader than `/24` for IPv4 and `/48` for IPv6;
  broader organization-owned protections belong in the central static policy.
- `off` publishes no dynamic CIDRs. Static `protected_cidrs` and legacy trusted
  enforcement protection remain active.

Discovery starts with IPv6 default-route interfaces unless the operator selects
interfaces explicitly. Loopback, link-local, multicast, unspecified,
tentative, DAD-failed, deprecated, container, and tunnel addresses/interfaces
are excluded by default. ULA addresses are excluded unless explicitly enabled.
A connected IPv6 prefix broader than `/48` is never published dynamically;
LAN-prefix mode falls back to the host's current `/128` addresses instead.

## Debian configuration

The package Debconf configuration script performs self-contained discovery
before package files are unpacked. It prompts on a first installation and on an
upgrade where `/etc/argent-sentinel/agent.json` lacks
`local_address_protection`. Ordinary upgrades preserve an existing choice.

Virtualization produces a host-mode recommendation. A physical environment
with public IPv6 and router-advertisement/dynamic signals may produce a
LAN-prefix recommendation, but the package requires a separate ownership
confirmation. Noninteractive installation always records unconfirmed host mode
and never silently broadens protection beyond `/128`.

Reopen the selection with:

```bash
sudo dpkg-reconfigure argent-sentinel-agent
```

## Authenticated inventory flow

Every enabled agent evaluates discovery on each minute run. It stages an
inventory when the canonical state changes or when the configured heartbeat
expires. Protection envelopes are delivered before ordinary pending telemetry,
use the existing per-node mTLS identity, and retain the existing idempotent
transport UUID and payload-digest checks.

The central API validates the authenticated node ID, inventory UUID, timestamp,
mode, booleans, bounded CIDR list, and host-mode `/128` restriction. The
collector validates again, stores one current row per node, appends immutable
history, and publishes an atomic effective-state file.

## Freshness and enforcement safety

The central state distinguishes active, stale-grace, and expired node
inventories. Stale-grace CIDRs remain protected to tolerate a temporary node or
transport outage. Expired inventories remain visible in the dashboard but stop
contributing dynamic CIDRs.

The dashboard snapshot uses the effective state to suppress impossible block
actions. This is only a usability control. The root-owned review processor
reloads the configured state at action time and refuses all protected overlaps.
When the state file is missing, malformed, unsupported, or older than its
strict publication-age limit, CIDR enforcement fails closed.

Automatic CIDR enforcement remains disabled.

## Acceptance checks

The initial VPS acceptance target is a newly enrolled KVM/VPS client node:

- KVM detection recommends `host`.
- The public interface address is protected as `/128`, not its provider `/64`.
- The tunnel ULA is excluded by default.
- `dpkg-reconfigure argent-sentinel-agent` reproduces the choice.
- The collector receives the mTLS-authenticated inventory and identifies the enrolled VPS
  node as the protection source.

A residential-LAN acceptance check should separately confirm that a changed
public IPv6 address or prefix replaces the effective inventory without manual
JSON edits and without creating a CrowdSec decision.

<!-- EOF: /home/alan/src/argent-sentinel-collector/docs/local-address-protection-0.5.4.0.md -->
