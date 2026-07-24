# Changelog

## 0.2.2

- Add production abuse-reporting guardrails:
  - mandatory activation cutoff for production reporting;
  - explicit test mode and recipient override restrictions;
  - maximum reports per run;
  - maximum report age;
  - per-recipient cooldown and rolling daily limit;
  - retry backoff;
  - durable SQLite report-attempt audit records.
- Add report-generation metadata, affected site identifiers, network details,
  operator contact, and configurable Message-ID domain.
- Add safe cross-filesystem file moves. Incoming batches are copied to a hidden
  destination-side temporary file, flushed, atomically published, and only then
  removed from the source filesystem when `rename(2)` returns `EXDEV`.
- Add regression coverage for cross-filesystem batch claims and reporting
  guardrails.

## 0.2.1

- Allow read-only status output while the scheduled collector holds its run lock.
- Correct RIPE ASN object parsing and IPv6 RDAP URL handling.
- Cache enrichment results and failures during a run.
- Skip external enrichment when both CrowdSec and abuse reporting are disabled.
- Improve SQLite busy handling and enrichment network-error handling.

## 0.2.0

- Initial host collector release.
- Import immutable WordPress JSON batches into SQLite.
- Deduplicate batches and event UUIDs.
- Detect WordPress credential spraying and single-account brute force.
- Submit optional long-lived CrowdSec decisions.
- Perform RDAP/ASN enrichment and generate sanitized abuse reports.
- Track `/24` IPv4 and `/64` IPv6 review candidates without automatic CIDR bans.
