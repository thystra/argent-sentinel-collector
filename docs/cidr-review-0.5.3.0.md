<!-- Source: docs/cidr-review-0.5.3.0.md -->

# Audited CIDR review and enforcement in 0.5.3.0

Argent Sentinel 0.5.3.0 adds a guarded operator workflow for CrowdSec range
blocks. Automatic CIDR enforcement remains disabled.

## Ownership scope and enforcement proposal

`network_cases.network_cidr` remains the registered allocation returned by RDAP
when available. It identifies ownership and the provider reporting scope. It is
not automatically the range that will be blocked.

For each case, the collector evaluates qualifying incidents within the network
review window:

1. Group IPv4 sources into `/24` scopes and IPv6 sources into `/48` scopes by
   default.
2. Select the strongest bounded group by distinct hostile addresses, incident
   count, active days, and recency.
3. Narrow that group to the smallest common prefix containing its hostile
   addresses.
4. Refuse to propose a prefix outside the registered case or broader than the
   configured boundary.
5. Store a deterministic proposal revision derived from the selected evidence.

The case stores the proposed CIDR, distinct hostile addresses, incidents,
events, active days, address-space coverage percentage, and derivation basis.
A block action is offered only when the proposal contains at least two hostile
addresses or has activity on at least two days.

## Dashboard trust boundary

The dashboard remains read-only with respect to SQLite and CrowdSec. It reads a
root-generated sanitized snapshot and writes an immutable JSON request into:

```text
/var/spool/argent-sentinel/review/incoming
```

`argent-sentinel-review-processor.path` activates the root-owned processor. The
processor takes the collector lock, validates the request, applies any permitted
CrowdSec command, updates the database, and archives the request and result.

## Operator actions

Open escalation and long-block cases may expose:

- Block proposed CIDR for 180 days.
- Block proposed CIDR for 365 days.
- Keep observing.
- Reject recommendation.
- Add note.

Blocked cases expose:

- Remove existing CIDR block.
- Add note.

Block actions require a nonempty operator justification.

## Enforcement validation

Before a range decision, the processor verifies:

- The case still exists.
- `updated_at` matches the dashboard snapshot.
- The proposal revision and proposed CIDR are unchanged.
- The proposed CIDR is canonical and contained by the registered case.
- IPv4 proposals are no broader than `/24` and IPv6 proposals are no broader
  than `/48`, unless configured more narrowly.
- The proposal does not overlap any `trusted_cidrs` entry.
- The requested duration is exactly the configured 180- or 365-day policy.
- The operator identity is present and the block justification is nonempty.
- The request UUID has not already been processed.

The processor uses CrowdSec range operations without `--bypass-allowlist`:

```text
cscli decisions list --range CIDR --output json
cscli decisions add --range CIDR --duration HOURS --reason REASON
cscli decisions delete --range CIDR
```

Applied and existing decisions close the review as blocked. Failed, refused, or
dry-run enforcement remains open. Removal returns the case to open review.

## Audit data

`network_review_actions` records each processed action with:

- Request UUID.
- Registered case and proposed CIDR.
- Proposal revision.
- Action, operator, and note.
- Previous and resulting case/review states.
- Requested duration.
- CrowdSec status and bounded command detail.
- Requested and applied timestamps.

Observe and reject dispositions remain closed while the proposal revision is
unchanged. Materially changed evidence creates a new proposal revision and
reopens the review. Active blocked cases remain blocked until an audited removal
succeeds.

## Deferred automatic policies

0.5.3.0 does not enable either policy below:

- Automatic CIDR blocking based on a configurable hostile-address count or
  percentage of a separately defined bounded candidate scope. The displayed
  minimal-proposal coverage is descriptive and must not be reused directly as
  an automatic threshold because the smallest-common-prefix derivation biases
  it upward.
- Automatic blocking of commercial VPN endpoints based on RDAP or ASN naming.

Initial future candidates include 10 or 20 hostile addresses, 25% or 50%
bounded-scope coverage, and configurable case-insensitive VPN patterns against RDAP
network name/handle and ASN holder. VPN classification should first appear as a
manual review flag with exceptions for false positives and shared networks.

<!-- EOF: docs/cidr-review-0.5.3.0.md -->
