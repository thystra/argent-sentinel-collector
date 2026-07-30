<!-- Source: docs/enforcement-protection-0.5.3.1.md -->

# Enforcement-protected CIDRs in 0.5.3.1

Argent Sentinel 0.5.3.1 introduces a dedicated static protection list for
addresses and prefixes that must never receive a Sentinel-managed CrowdSec IP or
range decision.

## Configuration

```json
{
  "enforcement_protection": {
    "protected_cidrs": [
      "2600:1702:6530:bdff::/64"
    ]
  }
}
```

`trusted_cidrs` remain enforcement-protected for compatibility. The dedicated
list differs because it does not make the protected network trusted telemetry;
events may still be observed, correlated, and reviewed.

## Dashboard and processor behavior

When a proposal overlaps a trusted or protected CIDR, the dashboard identifies
the matching protection and does not offer 180- or 365-day block actions. The
operator may add a note or acknowledge the protected proposal revision. An
acknowledgment closes that revision with an immutable audit entry and creates no
CrowdSec decision.

The dashboard is not the security boundary. The root-owned review processor
reloads the collector policy and refuses protected overlaps independently before
any CrowdSec command.

## Dynamic protection roadmap

Static CIDRs are the immediate safety layer. Version 0.5.4.0 is planned to add
signed per-node public-address inventories and explicit `host`, `lan-prefix`,
`manual`, and `off` modes. Dynamic addresses will refresh without rewriting the
main configuration. A VPS will default to public `/128` protection; a broader
LAN prefix will require explicit operator confirmation.

<!-- EOF: docs/enforcement-protection-0.5.3.1.md -->
