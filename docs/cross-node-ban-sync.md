# Cross-node ban sync (0.5.8.0)
<!-- /home/alan/src/argent-sentinel/argent-sentinel/docs/cross-node-ban-sync.md -->

Goal: when one Argent Sentinel host bans a hostile IP, every other enrolled
host bans it proactively on its next update cycle. Example: an address that
CrowdSec, fail2ban or the collector bans on Nidhoggur is also banned on
Hermod within about five minutes, and the reverse.

Everything is **disabled by default**. Once enabled, the agent apply step is
**dry-run by default**. Nothing changes CrowdSec on a node until the operator
turns off `ban_sync.apply.dry_run` on that node.

Decisions Alan made on PR #8 (17 Nov 2026):

| topic | decision |
|---|---|
| ban length | keep each ban's original duration, capped at **30 days (720 h)** |
| fail2ban | sync bans from **all jails**; permanent bans are capped at 30 days |
| signing | **Ed25519 detached signature** over every downstream response (this PR) |
| Nidhoggur | an **ordinary node**: its agent reports its bans and pulls the merged list like Hermod; there is no central direct-read path |
| protected list | Hermod `134.199.206.240/32` and home `108.226.59.220/32` go into the protected CIDRs and Hermod's `apply.local_allowlist` before enabling |

## 1. Architecture

```
 every node agent (hermod, nidhoggur, future)   central services (nidhoggur)
 ────────────────────────────────────────────   ─────────────────────────────────────
 cscli decisions list ─┐                         nginx :443 sentinel.argentwolf.org
 fail2ban.sqlite3 ─────┤ upstream report         ssl_verify_client → X-Argent-Client-DN
                       └─ kind "decisions" ────▶ POST /v1/ingest ──▶ server_api (unix socket)
                          (existing mTLS            nodes.d CN + service "decisions"
                           envelope, UUID +         ReceiptDB UUID/sha256 dedupe
                           sha256 dedupe)           drop/remote/<node>/decisions/incoming/
                                                              │
                                                    collector (every minute, root)
                                                    ├─ ingest node reports ─▶ ban-sync.sqlite3
                                                    ├─ protection filter + 30-day cap
                                                    ├─ reconcile effective set (seq cursor)
                                                    └─ publish ban-sync-status.json
                                                              │
 every N min (default 5):                                     ▼
 GET /v1/decisions?cursor=C ◀──── mTLS ─────────── server_api serve_decisions
 verify Ed25519 signature (pinned key)              (CN + service "decisions",
 verify sha256 of view, merge delta                  withholds bans the node itself
 re-check local protection                           reports, signs with the
 cscli decisions add/delete (owned only)             central Ed25519 key)
 state file + cursor (idempotent)
```

* **Upstream (agent → central).** Each `argent-sentinel-agent run` collects
  local CrowdSec decisions (`cscli decisions list -o json --limit 0`; origins
  `crowdsec` and `cscli`; scopes `Ip` and `Range`; type `ban`; not
  simulated) and, when enabled, current fail2ban bans from **every jail**,
  read from the fail2ban SQLite database in read-only mode. The agent builds
  a `decisions` report, which is a full current snapshot of what the node
  bans. It stages the report as a normal transport envelope only when the
  report digest changes or the heartbeat runs out
  (`upstream.heartbeat_seconds`, default 15 min). The envelope goes over the
  existing mTLS transport, with the UUID + payload-SHA-256 replay protection
  that already exists.
* **Nidhoggur is a node like any other.** Nidhoggur's own agent reports
  Nidhoggur's local CrowdSec decisions, including the collector's
  `argent-sentinel/<rule>` policy bans, which are the main source of hostile
  IPs. It also pulls the merged list. The collector has **no** special path
  that reads central CrowdSec directly. Rows that a pre-release build read
  directly (channel `central`) are purged on the first merge and ignored by
  the filter. Adding another host takes three steps: enroll it, add the
  `decisions` service, and install the agent.
* **Central merge (collector on Nidhoggur).** Every collector run calls
  `run_ban_sync_merge` after it publishes the effective protection state,
  throttled to `refresh_seconds` (default 60 s). The merge:
  1. imports the reports from `drop/remote/*/decisions/incoming/` and
     archives or rejects the files;
  2. applies loop prevention, the origin allow-list, the protection filter
     and the expiry cap;
  3. reconciles the **effective set**.

  Errors are logged and never fail the collector run.
* **Downstream (central → agents).** `GET /v1/decisions?cursor=N` on the
  existing `sentinel.argentwolf.org` vhost requires the same client
  certificate as ingest. The API returns a signed snapshot or delta
  (section 4).
* **Apply (agent).** Within the same `run` cycle, at most every
  `apply.interval_minutes` (default 5), the agent:
  1. pulls the view;
  2. verifies the signature (once a key is pinned) and the view digest;
  3. merges the view into its local mirror;
  4. re-checks local protection;
  5. converges CrowdSec.

  Run `argent-sentinel-agent ban-sync [--force]` to pull immediately. The
  agent is in charge only of CrowdSec decisions whose reason starts with
  `argent-sentinel:`.

### Why not push, and why not CrowdSec's own multi-LAPI sharing

* With a pull schedule, the API stays a passive Unix-socket service behind
  nginx, and nodes never accept inbound connections.
* CrowdSec's LAPI/agent split and central blocklists would need CrowdSec
  credentials and a LAPI shared across hosts, which is a second trust domain.
  Ban sync reuses the node CA, `nodes.d` and the protection inventory that
  already exist.

## 2. Data model and migration

The collector database schema does **not** change, so there is no collector
migration. Ban sync keeps its own SQLite store (WAL) at
`/var/lib/argent-sentinel/server/ban-sync.sqlite3`. The collector creates it
on first use with `CREATE TABLE IF NOT EXISTS` and records it as store
`schema_version` 1 in `meta`. A future version will refuse to open a store
whose schema is newer than it understands. Pre-release stores get the
`effective.contributors` column through `ALTER TABLE` when opened. To roll
back, disable the feature and delete the file. Nothing else reads it.

| table | purpose |
|---|---|
| `meta` | `schema_version`, `set_id` (random UUID per store), `head_seq`, `min_cursor`, last merge run |
| `report_receipts` | report UUID → sha256: replay of the same UUID is a duplicate, and the same UUID with different content is rejected |
| `node_reports` | latest accepted report per node. Older `generated_at` values are ignored as stale |
| `node_decisions` | node-sourced decisions: node, source (`crowdsec`/`fail2ban`), scope, value, origin, scenario, reason, started, until (NULL = permanent fail2ban), first seen. A new report fully replaces that node's rows |
| `effective` | one row per target `id = sha256("<scope>|<value>")[:32]`: scope, value, until, reason, scenario, origin, winning `origin_node`, `contributors` (every node currently reporting the target), active flag, removed_reason, `seq`, updated time. Removed rows stay as **tombstones** until `tombstone_retention_seconds` (8 days) |
| `node_pulls` | per node: first/last pull, requested/served cursor, reset flag, served entries, pull count. This feeds the lag display and the watchdog |

`seq` increases monotonically. Every insert, change (until, reason,
origin_node or contributors) or removal sets `seq = ++head_seq`. If a
reconcile finds no change, the cursor does not move. When tombstones are
garbage-collected, the highest collected `seq` is recorded as `min_cursor`. A
client whose cursor is below that value gets a full snapshot.

If several nodes ban the same target, the effective entry keeps the **latest
capped expiry**, plus the reason and origin node of whichever entry supplied
that expiry. Every reporting node is recorded in `contributors`.

## 3. Filtering, cap and loop prevention

### Loop prevention

Synced decisions carry the marker reason
`argent-sentinel:<origin_node>:<reason>`. The colon form is reserved for
sync:

1. Agents never report a decision whose reason or scenario starts with
   `argent-sentinel:` (upstream filter).
2. Central drops any such decision when it takes in a report. This check
   runs *before* reasons are sanitised, because sanitising would rewrite the
   colon. A second check runs in the merge.
3. A node never receives an entry that it is itself currently reporting (it
   is one of the entry's `contributors`), so it never gets its own ban back
   as a redundant synced decision. Such a decision would churn every time
   the winning origin changed. Once the node stops reporting the target
   because its local ban ended, the entry becomes visible to it on the next
   merge if another node still bans it.
4. Removal only ever deletes `argent-sentinel:` decisions, by decision id.

The collector's own `argent-sentinel/<rule>` bans (slash form) are ordinary
local bans. Nidhoggur's agent reports them, and the other nodes receive
them. Because a node only reports bans that it did not receive through sync,
a ban propagates exactly once. The round-trip test runs two nodes through
two cycles and checks that the cursor and CrowdSec stay unchanged
(`NodePathTest`).

### Central filter order (`compute_effective`)

1. **Loop prevention** (above). Rows from the legacy `central` channel are
   ignored as well.
2. **Origin allow-list.** `crowdsec`, `cscli`, `fail2ban`. `CAPI`, `lists`
   and the community blocklist are always excluded, and validation rejects
   configs that list them.
3. **Target safety.** Addresses must be globally routable. IPv4 ranges must
   be /24 or narrower, and IPv6 ranges /48 or narrower.
4. **Protection.** No overlap is allowed with `trusted_cidrs`,
   `enforcement_protection.protected_cidrs`, `ban_sync.protected_cidrs`, the
   dynamic protected CIDRs, or **any** node's effective protection inventory
   (`effective-protection-state.json`). If that state file is missing or
   older than `dynamic_state_max_age_seconds`, the merge **fails closed**: it
   publishes nothing new, and the current entries simply expire on the nodes.
5. **Expiry cap.** `until = min(original until, start + max_duration_seconds)`.
   The start is the decision's own start time (CrowdSec `start_at` or
   fail2ban `timeofban`), or central's first sighting. The default cap is
   **30 days (2 592 000 s = 720 h)**, so Nidhoggur's 719–720 h collector
   bans keep their original duration. Permanent fail2ban bans
   (`bantime < 0`) get `timeofban + 30 days`. With the cap set to 0 they get
   a 30-day ceiling. An entry whose capped expiry has already passed is
   dropped.

### Agent-side checks before every add

The target must not overlap any of these:

* any address on the node's own interfaces (`ip -j address show`);
* the agent's local protection inventory (`local_address_protection`:
  manual, SSH and discovered CIDRs). If the inventory cannot be built, the
  sync run is skipped (fail closed);
* `ban_sync.apply.local_allowlist`;
* CrowdSec allowlists (`cscli allowlists check`, when
  `check_crowdsec_allowlists` is set).

## 4. API and signing

`GET /v1/decisions?cursor=<int>` on `sentinel.argentwolf.org` (nginx
`location = /v1/decisions`, GET only).

* **Authentication:** nginx verifies the client certificate against the node
  CA and overwrites `X-Argent-Client-Verify` / `X-Argent-Client-DN`. The API
  takes the CN, then requires `/etc/argent-sentinel/nodes.d/<CN>.json` with
  `enabled: true` and `"decisions"` in `services`. Otherwise it returns 403.
* `404` when `ban_sync.enabled` is false in `server-api.json`. `503` when
  the store does not exist yet or is busy, when signing fails, or when
  `require_signing` is set and the key is missing. `400` for a malformed
  cursor.
* Response (JSON, `Cache-Control: no-store`):

```json
{
  "schema_version": 1,
  "set_id": "6c1f…",
  "node_id": "hermod",
  "cursor": 42,
  "requested_cursor": 37,
  "reset": false,
  "generated_at": "2026-11-17T14:05:00Z",
  "generated_epoch": 1795442700,
  "count": 118,
  "snapshot_sha256": "<sha256 of the full active view for this node>",
  "entries": [],
  "upserts": [{"id": "…", "scope": "Ip", "value": "203.0.113.7",
               "until": "2026-12-16T13:00:00Z",
               "reason": "argent-sentinel/sshd-credential-spray",
               "origin_node": "nidhoggur"}],
  "removals": [{"id": "…", "reason": "revoked"}],
  "signature": {"alg": "ed25519", "key_id": "3f9c0a…16 hex", "value": "<base64 64 bytes>"}
}
```

`reset: true` (cursor 0, unknown `set_id`, cursor ahead of head or below
`min_cursor`) means `entries` holds the complete view and the client
replaces its mirror. Otherwise `upserts` and `removals` are applied on top
of the mirror. A removal's reason is `revoked`, `expired`, `origin-node`,
`protected: …` or `unsafe: …`.

### View digest

`snapshot_sha256` is SHA-256 over the canonical JSON of the node's active
view: entries sorted by id, with the fields `id, scope, value, until,
reason, origin_node`, active as of `generated_epoch`. After merging a delta,
the agent recomputes the digest over its mirror. If it does not match, the
agent discards the mirror, refetches with cursor 0, and applies nothing
unless the snapshot verifies. This catches a delta applied to the wrong
base, truncation, and local state corruption.

### Ed25519 detached signature

* **Signed message:** the fixed prefix
  `argent-sentinel-ban-sync-view-v1\n` followed by the canonical JSON
  (sorted keys, no whitespace) of `schema_version, set_id, node_id, cursor,
  requested_cursor, reset, generated_epoch, count, snapshot_sha256` plus
  `body_sha256`. `body_sha256` is SHA-256 over the canonical JSON of the
  exact `entries`, `upserts` and `removals` that were sent. The signature
  therefore binds the resulting state (digest), the delta content (body), the
  cursor pair, the requesting node, the store identity and the server time.
* **Algorithm and tooling:** pure Ed25519 (RFC 8032), produced and checked
  with the `openssl` CLI (`pkeyutl -sign|-verify -rawin`). The packages
  already depend on `openssl`, and the code stays stdlib-only. The
  signature is computed per response because views are per node and per
  cursor. That costs one signing operation per pull.
* **Central key:** `/etc/argent-sentinel/ban-sync/signing.key`, created by
  `argent-sentinel-api ban-sync-keygen`.
  * The key file is Ed25519 PEM, mode `0600`, owned by root (the API service
    runs as root). The directory is `0700`.
  * The public key is written next to it as `signing.key.pub` (`0644`).
  * The API refuses to sign with a key file that group or others can access,
    and answers 503.
  * The key is never in the repository, the packages, the reports or the
    dashboard. Tests generate throwaway keys at run time, and a test fails
    if any tracked file contains a private-key PEM block.
* **Key id:** the first 16 hex characters of SHA-256 over the DER
  SubjectPublicKeyInfo. It selects the pinned key and shows up in status.
* **Agent pinning:** `ban_sync.apply.signing_public_key_files` is a list of
  public-key paths, e.g. `/etc/argent-sentinel/pki/ban-sync-signing.pub`. A
  list allows rotation overlap: pin the new and old keys, switch the server
  to the new key, then drop the old one.
* **Policy:**
  * **No key pinned** (rollout phase): signatures are optional. Status
    reports `unsigned` or `unverified (no pinned key)`.
  * **Key(s) pinned:** the response must carry a valid signature by a pinned
    key and must pass these checks:
    * `node_id` equals this node;
    * `requested_cursor` equals the cursor this request sent (stops replay of
      another request's delta);
    * `generated_epoch` is within `max_view_age_seconds` (900) of local time;
    * `generated_epoch` is not older than the last accepted response (stops
      rollback).

    Unsigned responses, unknown keys and bad signatures are all
    **rejected**. A pinned key file that cannot be read fails closed too.
* **On verification failure:** the agent rejects the whole response. Mirror,
  cursor and CrowdSec stay unchanged. The run status is `signature-failed`,
  `last_error` explains why, and `signature.failures` /
  `signature.last_failure_at` count failures. These show in
  `argent-sentinel-agent status` (`signature_status`,
  `signature_failures`). After 30 minutes without a good pull, the lag
  watchdog fires.
* **Server side:** the API signs whenever the key file exists.
  `require_signing: true` in `server-api.json` makes it refuse (503) rather
  than ever serve an unsigned view. Set it once every agent pins the key.

Threat model: TLS with server verification and node client certificates
already authenticates the channel. The signature adds end-to-end integrity
that survives a TLS-terminating proxy compromise, a mis-issued server
certificate, or tampering anywhere between the API process and the agent.
Replay and rollback protection come on top. It does not protect against a
compromised API process on Nidhoggur, which can read the key. That process
also controls the decision source itself.

## 5. Agent state, idempotency and ownership

`apply.state_file` (`/var/lib/argent-sentinel/agent/ban-sync-state.json`,
mode 0600) holds `set_id`, `cursor`, `last_generated_epoch`, the verified
`mirror`, `applied` (id → applied until and CrowdSec reason), the signature
status, the last results, and the `would_apply` / `would_remove` preview
lists (capped at `max_preview_entries`).

* An entry that was already applied, with the same reason and an expiry
  within `update_tolerance_seconds`, causes no cscli call. Repeated pulls
  with no central change make zero mutations.
* Add: `cscli decisions add --ip|--range <value> --duration <remaining>s
  --reason 'argent-sentinel:<origin_node>:<reason>' --type ban`. Only
  entries with at least `min_remaining_seconds` (60 s) left are added.
* When an entry is extended or changed, the agent deletes the owned decision
  and adds it again with the new remaining duration.
* Remove: the agent lists the decisions for that exact value and deletes, by
  decision **id** only, the ones whose reason starts with
  `argent-sentinel:`. Local CrowdSec bans, collector `argent-sentinel/…`
  bans and manual bans on the same IP are never touched.
* At most `max_changes_per_run` (500) mutations run per cycle. The rest wait
  for the next cycle.
* If `cscli` is missing, the agent does nothing and reports
  `crowdsec-absent`. When `dry_run` is true, the agent pulls, verifies and
  computes the plan, but makes no cscli mutation.

## 6. Security and trust boundaries

| boundary | control |
|---|---|
| node → central reports | node client cert (CA-signed), CN = node id, `decisions` service required in `nodes.d`, `node_id` in the payload must equal the CN, the drop path is derived from the CN, the collector re-validates `node_id` against the drop directory |
| report contents | strict schema, ≤ 20 000 decisions, ≤ 8 MiB file; sync-marker decisions are dropped before sanitising; reasons sanitized to `[A-Za-z0-9._/@+-]` (max 64 chars); targets normalized with `ipaddress`; non-global addresses and over-broad ranges are dropped |
| central → node view | TLS server verification and client cert; the view is filtered for the requesting CN only; Ed25519 signature checked against the pinned key, bound to node, cursor and time; digest-verified; response capped at 16 MiB |
| central signing key | `/etc/argent-sentinel/ban-sync/signing.key`, 0600 root, directory 0700; group/other-readable keys are refused; never in the repo or packages |
| applying to CrowdSec | protection re-checked locally; argument-vector subprocess calls (no shell); dry-run default; only `argent-sentinel:` decisions are ever deleted |
| a compromised node | can make other nodes ban **non-protected, global** addresses for up to the cap (30 days). It cannot ban protected/trusted/inventory addresses, cannot remove other nodes' bans, and cannot impersonate another node. Remove its `decisions` service in `nodes.d` to cut it off. Its rows disappear on the next merge after its report is cleared or goes stale |
| store and status | the store is readable only by the collector and API (`/var/lib/argent-sentinel/server`); the dashboard and watchdog read only the sanitized `ban-sync-status.json` (no report UUIDs, no entries) |

The 30-day cap widens what a compromised node could do, compared with the 7
days first proposed. The protected list (section 10, step 2) and the
`decisions` service switch in `nodes.d` are the controls that limit it.

## 7. Failure modes

| failure | behaviour |
|---|---|
| central unreachable / 5xx | the agent keeps its mirror and CrowdSec decisions, which still expire on their own durations; status `error`; after 30 min the watchdog flags the node as lagging |
| signature missing/invalid with a pinned key | response rejected, nothing applied, status `signature-failed`, failure counter increases |
| signing key missing on the server | unsigned views while `require_signing` is false; 503 once it is true |
| clock skew > `max_view_age_seconds` with a pinned key | responses rejected as stale; fix NTP |
| digest mismatch | full resync. If the snapshot still mismatches, nothing is applied and status is `error` |
| `set_id` changed (store recreated) | the agent treats it as a reset and reconciles toward the new view, removing owned decisions that are no longer present |
| protection state stale or missing on central | the merge fails closed with `protection-unavailable`; no new entries are published |
| local inventory unavailable on the agent | sync skipped (`protection-unavailable`) |
| cscli add/delete fails | counted in `failed`, retried next cycle, other entries continue |
| node stops reporting | its last report stays in use until its decisions expire. The capped `until` bounds how stale a ban can get |
| Nidhoggur's agent down | Nidhoggur's local bans stop propagating, and the lag watchdog fires for `nidhoggur`. Other nodes' bans keep flowing |
| fail2ban DB locked / missing | the fail2ban source is skipped with an error in the upstream status; the CrowdSec source is still reported |

## 8. Observability

* `argent-sentinel-agent status` → `ban_sync`:
  * pull state: `mode` (dry-run/apply), `last_pull_at`, `last_status`,
    `last_error`, `cursor`, `mirror_entries`;
  * results: `applied`, `removed`, `failed`, `skipped_protection`,
    `would_apply`, `would_remove`;
  * signature: `signature_required`, `signature_status`,
    `signature_failures`, `signature_last_failure_at`;
  * upstream: `upstream_last_staged_at`.
* `argent-sentinel status` → `ban_sync`: last merge, counts by
  filter stage, active entries.
* The collector publishes `/var/lib/argent-sentinel/collector/ban-sync-status.json`.
  The dashboard snapshot shows it on **Networks → Cross-node ban sync**
  (per-node last pull, lag, cursor behind head, served entries, and reports
  per node). The Overview card *Ban-sync nodes lagging* shows the nodes that
  have not pulled for 30 minutes.
* Watchdog `30-ban_sync_lag` (observe mode, disabled by default): it is
  critical when a node in `expected_nodes` has not pulled for
  `max_pull_age_seconds` (1800) or has never pulled, and a warning when the
  status file is stale.

## 9. Configuration keys

`collector.json` → `ban_sync` (central merge):

| key | default | meaning |
|---|---|---|
| `enabled` | `false` | run the merge |
| `store_db` | `/var/lib/argent-sentinel/server/ban-sync.sqlite3` | store |
| `incoming_globs` | `[drop/remote/*/decisions/incoming/*.json]` | report files |
| `archive_dir` / `rejected_dir` | under `/var/lib/argent-sentinel/collector/` | processed files |
| `max_file_bytes` | 8 MiB | report size cap |
| `allowed_origins` | `["crowdsec","cscli","fail2ban"]` | origins eligible to sync (CAPI/lists rejected) |
| `max_duration_seconds` | `2592000` (30 d = 720 h) | expiry cap; `0` = no cap (30-day ceiling for permanent bans) |
| `protected_cidrs` | `[]` (example: Hermod + home IPv4) | extra never-ban CIDRs for sync |
| `tombstone_retention_seconds` | `691200` (8 d) | how long removals are kept for deltas |
| `refresh_seconds` | `60` | minimum time between merges |
| `status_file` | `/var/lib/argent-sentinel/collector/ban-sync-status.json` | sanitized status |

`include_central_crowdsec` and `central_origins` (pre-release) were removed.
They are ignored if present.

`server-api.json` → `ban_sync`:

| key | default | meaning |
|---|---|---|
| `enabled` | `false` | serve `/v1/decisions` |
| `store_db` | as above | |
| `signing_key_file` | `/etc/argent-sentinel/ban-sync/signing.key` | sign responses when this file exists |
| `require_signing` | `false` | refuse (503) instead of serving unsigned |
| `openssl_path` | `openssl` | |

`agent.json` → `ban_sync`:

| key | default | meaning |
|---|---|---|
| `enabled` | `false` | master switch (upstream and apply) |
| `cscli_path` / `command_timeout_seconds` | `/usr/bin/cscli` / 20 | |
| `upstream.enabled` | `true` | report local bans |
| `upstream.crowdsec_origins` | `["crowdsec","cscli"]` | |
| `upstream.fail2ban_enabled` / `fail2ban_db` | `true` / `/var/lib/fail2ban/fail2ban.sqlite3` | fail2ban source, **all jails** |
| `upstream.fail2ban_jails` | `[]` = all jails | optional restriction; leave empty |
| `upstream.heartbeat_seconds` | `900` | re-send an unchanged report |
| `upstream.max_decisions` | `20000` | report size bound |
| `apply.enabled` | `true` | pull and apply (still subject to `dry_run`) |
| `apply.dry_run` | **`true`** | compute and record only |
| `apply.endpoint_path` | `/v1/decisions` | appended to the agent's `central_url` |
| `apply.interval_minutes` | `5` | pull cadence |
| `apply.local_allowlist` | `[]` (example: Hermod + home IPv4) | never-ban CIDRs on this node |
| `apply.check_crowdsec_allowlists` | `true` | consult `cscli allowlists check` |
| `apply.signing_public_key_files` | `[]` | pinned central key(s); non-empty = signatures required |
| `apply.max_view_age_seconds` | `900` | freshness window for signed responses |
| `apply.openssl_path` | `openssl` | |
| `apply.min_remaining_seconds` / `update_tolerance_seconds` | 60 / 300 | |
| `apply.max_changes_per_run` | 500 | |
| `apply.max_response_bytes` / `max_preview_entries` | 16 MiB / 200 | |

`nodes.d/<node>.json`: add `"decisions"` to `services`. Nginx: add the
`location = /v1/decisions` block from the shipped examples.

## 10. Rollout (needs Alan's OK before any step on a host)

1. **Build and install 0.5.8.0** on Nidhoggur and Hermod the usual way.
   Every new switch is off, so the install changes no behaviour.
2. **Protected list. Do this before enabling anything.** On Nidhoggur, add
   Hermod's public IPv4 address and the home IPv4 address to the protected
   CIDRs:
   ```json
   "enforcement_protection": {"protected_cidrs": ["134.199.206.240/32", "108.226.59.220/32", …]},
   "ban_sync": {"protected_cidrs": ["134.199.206.240/32", "108.226.59.220/32"]}
   ```
   Putting them in `enforcement_protection.protected_cidrs` also keeps the
   collector's own enforcement from ever banning them. `ban_sync.protected_cidrs`
   is the sync-only list and matches the shipped example. On Hermod, set
   `ban_sync.apply.local_allowlist` to
   `["134.199.206.240/32", "108.226.59.220/32"]`, and the same on
   Nidhoggur's agent. Check with `argent-sentinel validate-config`
   and `argent-sentinel-agent validate-config`.
3. **Nidhoggur, central services:**
   * add the `location = /v1/decisions` block to the sentinel vhost, run
     `nginx -t`, and reload;
   * add `"decisions"` to `services` in `/etc/argent-sentinel/nodes.d/hermod.json`
     **and** `nidhoggur.json`. Services are read from `nodes.d`, so no
     re-signing is needed;
   * generate the signing key with `sudo argent-sentinel-api ban-sync-keygen`,
     and confirm `/etc/argent-sentinel/ban-sync/signing.key` is `0600 root`;
   * set `ban_sync.enabled: true` in `server-api.json` (leave
     `require_signing: false`) and restart `argent-sentinel-api`. Responses
     are now signed;
   * set `ban_sync.enabled: true` in `collector.json`, then run
     `argent-sentinel ban-sync-merge` and
     `argent-sentinel status`.
4. **Agents, Nidhoggur's own agent and Hermod, both as ordinary nodes:**
   * copy `signing.key.pub` to `/etc/argent-sentinel/pki/ban-sync-signing.pub`
     on each node (public, `0644`);
   * set `ban_sync.enabled: true` and
     `apply.signing_public_key_files: ["/etc/argent-sentinel/pki/ban-sync-signing.pub"]`,
     and leave `apply.dry_run: true`. From this point signatures are
     **required** on that node;
   * run `argent-sentinel-agent ban-sync --force`, then
     `argent-sentinel-agent status`. Expect `signature_status: verified (<key_id>)`.
5. **One day of dry-run.** Review the would-apply lists:
   `jq '.would_apply' /var/lib/argent-sentinel/agent/ban-sync-state.json` on
   each node, plus `skipped` (protection hits) and the dashboard Networks
   section. Check that no admin, home, monitoring or partner address shows
   up, and that `signature_failures` is 0.
6. **Enable after Alan confirms:**
   * set `apply.dry_run: false`, first on Hermod, then on Nidhoggur;
   * set `require_signing: true` in `server-api.json`;
   * enable watchdog `30-ban_sync_lag` with
     `expected_nodes: ["hermod","nidhoggur"]`.
7. **Rollback:** set `apply.dry_run: true` (stops mutations). To clear the
   synced decisions, delete the decisions whose reason starts with
   `argent-sentinel:`. CrowdSec keeps every other decision. They also expire
   on their own within the cap.
8. **Key rotation:**
   1. generate a new key to a new path;
   2. add its `.pub` to every agent's `signing_public_key_files`, next to the
      old one;
   3. point `signing_key_file` at the new key and restart the API;
   4. remove the old `.pub` from the agents.

## 11. Open questions

* None blocking. These are worth confirming during the dry-run day:
  * Are any monitoring or partner addresses missing from the protected list?
  * Is the 15-minute report heartbeat right for Nidhoggur's volume of
    collector bans? Reports are only re-sent on change or heartbeat, and the
    cap is 20 000 decisions per report.

<!-- EOF: /home/alan/src/argent-sentinel/argent-sentinel/docs/cross-node-ban-sync.md -->
