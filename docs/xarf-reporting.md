# XARF incident reports

Argent Sentinel 0.4.3 attaches a XARF v4.2.0 `xarf.json` document to
individual Nginx hostile-probing reports.

The report uses the XARF `connection` / `vulnerability_scan` type and includes
the hostile source identifier and source port, public destination IP,
targeted destination ports and services, first/last observation times, and
base64-encoded evidence with SHA-256 integrity hashes.

Because a reverse proxy or NAT can expose a public address while Nginx records
an internal destination, the attachment also includes the extension fields
`public_target_ips`, `observed_destination_ips`, and `connection_tuples`.
The standard XARF fields remain populated for automated abuse-desk handling.

`abuse_reporting.public_target_ips` may be either a list used for every site,
or an object containing a `*` fallback and per-host lists:

```json
{
  "abuse_reporting": {
    "attach_xarf": true,
    "xarf_version": "4.2.0",
    "xarf_max_evidence_lines": 20,
    "resolve_target_dns": true,
    "resolve_source_rdns": true,
    "public_target_ips": {
      "*": [
        "108.226.59.220",
        "2600:1702:6530:bdff:abac:7ca7:c15a:6646"
      ],
      "example.org": ["108.226.59.220"]
    }
  }
}
```

Configured public target addresses take precedence over DNS-derived addresses.
A globally routable destination observed directly in the event may also be
used. Private or loopback observed destinations are retained only as observed
destinations and are not misrepresented as the public target.

Exact original Nginx log lines are not currently retained as a dedicated field.
The message and attachment therefore label their evidence as sanitized,
normalized evidence generated from stored event and network-observation data.
Routing contacts discovered through RDAP are deliberately not embedded in the
XARF report; they are used only to select the production recipient.
