# Cross-node ban sync (0.5.8.0)
<!-- /home/alan/src/argent-sentinel/argent-sentinel/docs/cross-node-ban-sync.md -->

Goal: when one Argent Sentinel host bans a hostile IP, every other enrolled
host bans it too on its next update cycle. Example: an address that CrowdSec
or the collector bans on Nidhoggur is also banned on Hermod within about five
minutes, and the reverse.

Everything is **disabled by default**. Once enabled, the agent apply step is
**dry-run by default**. Nothing changes CrowdSec on a node until the operator
turns off `ban_sync.apply.dry_run` on that node.

## 1. Architecture

```
 node agent (hermod, nidhoggur)                 central (nidhoggur)
 ──────────────────────────────                 ─────────────────────────────────────
 cscli decisions list ─┐                         nginx :443 sentinel.argentwolf.org
 fail2ban.sqlite3 ─────┤ upstream report         ssl_verify_client → X-Argent-Client-DN
                       └─ kind "decisions" ────▶ POST /v1/ingest ──▶ server_api (unix socket)
                          (existing mTLS            nodes.d CN + service "decisions"
                           envelope, UUID +         ReceiptDB UUID/sha256 dedupe
                           sha256 dedupe)           drop/remote/<node>/decisions/incoming/
                                                              │
                                                    collector (every minute, root)
                                                    ├─ ingest reports  ─▶ ban-sync.sqlite3
                                                    ├─ central cscli decisions (non-CAPI)
                                                    ├─ protection filter + 7d cap
                                                    ├─ reconcile effective set (seq cursor)
                                                    └─ publish ban-sync-status.json
                                                              │
 every N min (default 5):                                     ▼
 GET /v1/decisions?cursor=C ◀──── mTLS ─────────── server_api serve_decisions
 verify sha256 of view, merge delta                 (CN + service "decisions",
 re-check local protection                           withholds the node's own bans)
 cscli decisions add/delete (owned only)
 state file + cursor (idempotent)
```

* **Upstream (agent → central).** Each `argent-sentinel-agent run` collects
  local CrowdSec decisions (`cscli decisions list -o json --limit 0`; origins
  `crowdsec` and `cscli`; scopes `Ip` and `Range`; type `ban`; not
  simulated) and, when enabled, current fail2ban bans from the fail2ban
  SQLite database (read-only). The agent builds a `decisions` report, which
  is a full current snapshot of what the node bans. It stages the report as a
  normal transport envelope only when the report digest changes or the
  heartbeat runs out (`upstream.heartbeat_seconds`, default 15 min). The
  envelope goes over the existing mTLS transport, with the UUID +
  payload-SHA-256 replay protection that already exists.
* **Central merge (collector on Nidhoggur).** Every collector run calls
  `run_ban_sync_merge` after it publishes the effective protection state. The
  merge is throttled to `refresh_seconds` (default 60 s). It imports the
  reports from `drop/remote/*/decisions/incoming/`, archives or rejects the
  files, reads Nidhoggur's own CrowdSec decisions, applies loop prevention,
  the origin allow-list, the protection filter and the expiry cap, and then
  reconciles the **effective set**. Errors are logged and never fail the
  collector run.
* **Downstream (central → agents).** `GET /v1/decisions?cursor=N` on the
  existing `sentinel.argentwolf.org` vhost requires the same client
  certificate as ingest. The API returns a snapshot or a delta (section 4).
* **Apply (agent).** Within the same `run` cycle, at most every
  `apply.interval_minutes` (default 5), the agent pulls, verifies the view
  digest, merges it into its local mirror, re-checks local protection, and
  converges CrowdSec. Run `argent-sentinel-agent ban-sync [--force]` to pull
  immediately. The agent is in charge only of CrowdSec decisions whose reason
  starts with `argent-sentinel:`.

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
whose schema is newer than it understands. To roll back, disable the feature
and delete the file. Nothing else reads it.

| table | purpose |
|---|---|
| `meta` | `schema_version`, `set_id` (random UUID per store), `head_seq`, `min_cursor`, last merge run |
| `report_receipts` | report UUID → sha256: replay of the same UUID is a duplicate, and the same UUID with different content is rejected |
| `node_reports` | latest accepted report per `(node_id, channel)`. Older `generated_at` values are ignored as stale |
| `node_decisions` | node-sourced decisions: node, channel (`agent` or `central`), source (`crowdsec`/`fail2ban`), scope, value, origin, scenario, reason, started, until (NULL = permanent fail2ban), first seen. A new report fully replaces that node's rows |
| `effective` | one row per target `id = sha256("<scope>|<value>")[:32]`: scope, value, until, reason, scenario, origin, origin_node, active flag, removed_reason, `seq`, updated time. Removed rows stay as **tombstones** until `tombstone_retention_seconds` (8 days) |
| `node_pulls` | per node: first/last pull, requested/served cursor, reset flag, served entries, pull count. This feeds the lag display and the watchdog |

`seq` increases monotonically. Every insert, change (until, reason or
origin_node) or removal sets `seq = ++head_seq`. If a reconcile finds no
change, the cursor does not move. When tombstones are garbage-collected, the
highest collected `seq` is recorded as `min_cursor`. A client whose cursor is
below that value gets a full snapshot.

If two nodes ban the same target, the effective entry keeps the **latest
capped expiry**, plus the reason and origin node of whichever entry supplied
that expiry.

## 3. Filtering, cap and loop prevention

Central filter order (`compute_effective`):

1. **Loop prevention.** Any reason that starts with `argent-sentinel:` is
   dropped, because it is a decision a node received through sync. Node
   (agent-channel) decisions whose reason starts with `argent-sentinel` are
   dropped too. On top of that, agents never report such decisions. The
   collector's own `argent-sentinel/<rule>` bans on Nidhoggur are
   **included**, because they are the main source of hostile IPs.
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
   The start is the decision's own start time, or central's first sighting.
   The default cap is 7 days. Permanent fail2ban bans get the cap, or 30 days
   when the cap is 0. An entry whose capped expiry has already passed is
   dropped.

On each agent, before every add, the target must not overlap any of these:

* any address on its own interfaces (`ip -j address show`);
* the agent's local protection inventory (`local_address_protection`:
  manual, SSH and discovered CIDRs). If the inventory cannot be built, the
  sync run is skipped (fail closed);
* `ban_sync.apply.local_allowlist`;
* CrowdSec allowlists (`cscli allowlists check`, when
  `check_crowdsec_allowlists` is set).

The node also never receives its own bans back (`origin_node` is withheld),
so Hermod's own CrowdSec ban is not duplicated into a second decision on
Hermod.

## 4. API

`GET /v1/decisions?cursor=<int>` on `sentinel.argentwolf.org` (nginx
`location = /v1/decisions`, GET only).

* **Authentication:** nginx verifies the client certificate against the node
  CA and overwrites `X-Argent-Client-Verify` / `X-Argent-Client-DN`. The API
  takes the CN, then requires `/etc/argent-sentinel/nodes.d/<CN>.json` with
  `enabled: true` and `"decisions"` in `services`. Otherwise it returns 403.
* `404` when `ban_sync.enabled` is false in `server-api.json`. `503` when
  the store does not exist yet or is busy. `400` for a malformed cursor.
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
               "until": "2026-11-24T13:00:00Z",
               "reason": "argent-sentinel/sshd-credential-spray",
               "origin_node": "nidhoggur"}],
  "removals": [{"id": "…", "reason": "revoked"}]
}
```

`reset: true` (cursor 0, unknown `set_id`, cursor ahead of head or below
`min_cursor`) means `entries` holds the complete view and the client
replaces its mirror. Otherwise `upserts` and `removals` are applied on top
of the mirror. A removal's reason is `revoked`, `expired`, `origin-node`,
`protected: …` or `unsafe: …`.

### Digest instead of signing

The response carries `snapshot_sha256`, which is SHA-256 over the canonical
JSON of the node's active view (entries sorted by id, fields `id, scope,
value, until, reason, origin_node`, active as of `generated_epoch`). After
merging, the agent recomputes the digest over its mirror. If it does not
match, the agent discards the mirror, refetches with cursor 0, and applies
nothing unless the snapshot verifies.

The authenticity of the response comes from TLS: the agent verifies the
server certificate for `sentinel.argentwolf.org` against the configured CA
bundle and authenticates with its node client certificate. A detached
signature would only add protection against a compromised Nidhoggur nginx
or API process. Those processes also hold the decision source itself, so a
signature key on the same host gains little. It would also add key
distribution and rotation for every node. The digest gives what matters
here: it detects a delta applied to the wrong base, a truncated response,
and local state corruption. A signature can be added later as a new field
without changing the schema (open question below).

## 5. Agent state, idempotency and ownership

`apply.state_file` (`/var/lib/argent-sentinel/agent/ban-sync-state.json`,
mode 0600) holds `set_id`, `cursor`, the verified `mirror`, `applied`
(id → applied until and CrowdSec reason), the last results, and the
`would_apply` / `would_remove` preview lists (capped at
`max_preview_entries`).

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
| report contents | strict schema, ≤ 20 000 decisions, ≤ 8 MiB file, reasons sanitized to `[A-Za-z0-9._/@+-]` (max 64 chars), targets normalized with `ipaddress`; non-global addresses and over-broad ranges are dropped |
| central → node view | TLS server verification and client cert; the view is filtered for the requesting CN only; digest-verified; response capped at 16 MiB |
| applying to CrowdSec | protection re-checked locally; argument-vector subprocess calls (no shell); dry-run default; only `argent-sentinel:` decisions are ever deleted |
| a compromised node | can make other nodes ban **non-protected, global** addresses for up to the cap (7 days). It cannot ban protected/trusted/inventory addresses, cannot remove other nodes' bans, and cannot impersonate another node. Remove its `decisions` service in `nodes.d` to cut it off. Its rows disappear on the next merge after its report is cleared or goes stale |
| store and status | the store is readable only by the collector and API (`/var/lib/argent-sentinel/server`); the dashboard and watchdog read only the sanitized `ban-sync-status.json` (no report UUIDs, no entries) |

Node certificates and keys are never part of the repository or the
reports.

## 7. Failure modes

| failure | behaviour |
|---|---|
| central unreachable / 5xx | the agent keeps its mirror and CrowdSec decisions, which still expire on their own durations; status `error`; after 30 min the watchdog flags the node as lagging |
| digest mismatch | full resync. If the snapshot still mismatches, nothing is applied and status is `error` |
| `set_id` changed (store recreated) | the agent treats it as a reset and reconciles toward the new view, removing owned decisions that are no longer present |
| protection state stale or missing on central | the merge fails closed with `protection-unavailable`; no new entries are published |
| local inventory unavailable on the agent | sync skipped (`protection-unavailable`) |
| cscli add/delete fails | counted in `failed`, retried next cycle, other entries continue |
| node stops reporting | its last report stays in use until its decisions expire. The capped `until` bounds how stale a ban can get |
| fail2ban DB locked / missing | the fail2ban source is skipped with an error in the upstream status; the CrowdSec source is still reported |
| clock skew | expiry is evaluated against the server's `generated_epoch` for the digest. The agent computes the remaining duration from its own clock, so keep NTP enabled |

## 8. Observability

* `argent-sentinel-agent status` → `ban_sync`: `mode` (dry-run/apply),
  `last_pull_at`, `last_status`, `last_error`, `cursor`, `mirror_entries`,
  `applied`, `removed`, `failed`, `skipped_protection`, `would_apply`,
  `would_remove`, `upstream_last_staged_at`.
* `argent-sentinel-collector status` → `ban_sync`: last merge, counts by
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
| `archive_dir` / `rejected_dir` | under `/var/lib/argent-sentinel/server/` | processed files |
| `max_file_bytes` | 8 MiB | report size cap |
| `include_central_crowdsec` | `true` | include Nidhoggur's own decisions |
| `central_origins` | `["crowdsec","cscli"]` | origins read from central CrowdSec |
| `allowed_origins` | `["crowdsec","cscli","fail2ban"]` | origins eligible to sync (CAPI/lists rejected) |
| `max_duration_seconds` | `604800` (7 d) | expiry cap; `0` = no cap (30-day ceiling for permanent bans) |
| `protected_cidrs` | `[]` | extra never-ban CIDRs for sync only |
| `tombstone_retention_seconds` | `691200` (8 d) | how long removals are kept for deltas |
| `refresh_seconds` | `60` | minimum time between merges |
| `status_file` | `/var/lib/argent-sentinel/collector/ban-sync-status.json` | sanitized status |

`server-api.json` → `ban_sync`: `enabled` (`false`), `store_db`.

`agent.json` → `ban_sync`:

| key | default | meaning |
|---|---|---|
| `enabled` | `false` | master switch (upstream and apply) |
| `cscli_path` / `command_timeout_seconds` | `/usr/bin/cscli` / 20 | |
| `upstream.enabled` | `true` | report local bans |
| `upstream.crowdsec_origins` | `["crowdsec","cscli"]` | |
| `upstream.fail2ban_enabled` / `fail2ban_db` / `fail2ban_jails` | `true` / `/var/lib/fail2ban/fail2ban.sqlite3` / `[]` (all) | |
| `upstream.heartbeat_seconds` | `900` | re-send an unchanged report |
| `upstream.max_decisions` | `5000` | report size bound |
| `apply.enabled` | `true` | pull and apply (still subject to `dry_run`) |
| `apply.dry_run` | **`true`** | compute and record only |
| `apply.endpoint_path` | `/v1/decisions` | appended to the agent's `central_url` |
| `apply.interval_minutes` | `5` | pull cadence |
| `apply.local_allowlist` | `[]` | never-ban CIDRs on this node |
| `apply.check_crowdsec_allowlists` | `true` | consult `cscli allowlists check` |
| `apply.min_remaining_seconds` / `update_tolerance_seconds` | 60 / 300 | |
| `apply.max_changes_per_run` | 500 | |
| `apply.max_response_bytes` / `max_preview_entries` | 16 MiB / 200 | |

`nodes.d/<node>.json`: add `"decisions"` to `services`. Nginx: add the
`location = /v1/decisions` block from the shipped examples.

## 10. Rollout (needs Alan's OK before any step on a host)

1. **Build and install 0.5.8.0** on Nidhoggur and Hermod the usual way.
   Every new switch is off, so the install changes no behaviour.
2. **Nidhoggur, central:**
   * add the `location = /v1/decisions` block to the sentinel vhost, run
     `nginx -t`, and reload;
   * add `"decisions"` to `services` in `/etc/argent-sentinel/nodes.d/hermod.json`
     and `nidhoggur.json`. Services are read from `nodes.d`, so no
     re-signing is needed;
   * set `ban_sync.enabled: true` in `server-api.json` and restart
     `argent-sentinel-api`;
   * add Hermod's public IPv4 address(es) and the home IPv4 address to
     `enforcement_protection.protected_cidrs` (or `ban_sync.protected_cidrs`);
   * set `ban_sync.enabled: true` in `collector.json`, then run
     `argent-sentinel-collector ban-sync-merge` and
     `argent-sentinel-collector status`.
3. **Agents (Nidhoggur's own agent and Hermod):** set `ban_sync.enabled:
   true` and leave `apply.dry_run: true`. Fill `apply.local_allowlist` with
   the home and admin addresses. Run `argent-sentinel-agent ban-sync --force`,
   then `argent-sentinel-agent status`.
4. **One day of dry-run.** Review the would-apply lists:
   `jq '.would_apply' /var/lib/argent-sentinel/agent/ban-sync-state.json` on
   each node, plus `skipped` (protection hits) and the dashboard Networks
   section. Check that no admin, home, monitoring or partner address shows
   up.
5. **Enable after Alan confirms:** set `apply.dry_run: false`, first on
   Hermod, then on Nidhoggur. Enable watchdog `30-ban_sync_lag` with
   `expected_nodes: ["hermod","nidhoggur"]`.
6. **Rollback:** set `apply.dry_run: true` (stops mutations). To clear the
   synced decisions, delete the decisions whose reason starts with
   `argent-sentinel:`. CrowdSec keeps every other decision. They also expire
   on their own within the cap.

## 11. Open questions

* Hermod's IPv4 address and the home IPv4 address are not in the IPv6-only
  protection inventory. They should be added to
  `enforcement_protection.protected_cidrs` or `ban_sync.protected_cidrs`
  before enabling.
* Is the 7-day cap right, given that Nidhoggur's collector bans run 720 h?
* Should fail2ban bans sync at all, and if so, which jails?
* Should a detached signature (Ed25519 over `snapshot_sha256`) be added
  later?

<!-- EOF: /home/alan/src/argent-sentinel/argent-sentinel/docs/cross-node-ban-sync.md -->
