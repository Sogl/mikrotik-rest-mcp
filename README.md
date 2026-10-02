English | [Русский](README_RU.md)

<!-- mcp-name: io.github.Sogl/mikrotik-rest-mcp -->

# MikroTik REST MCP

MCP server that gives coding agents structured access to a RouterOS 7 device over its REST API — reads, filtered queries, guarded writes, a scheduled rollback guard, container shell, and file transfer. One MCP server over stdio.

Built for real ops work: the agent can inventory the router, diff firewall/routing state, poke containers, watch counters, and apply changes — with a human confirmation gate in front of anything disruptive.

## Features

- **Broad read coverage**
  - ~60 curated `get_*` tools for the common collections (firewall, routes, DHCP, DNS, interfaces, WireGuard, containers, scheduler, logs, system resources).
  - 200+ additional `get_*` endpoints stay callable by name through the same filter pipeline — they are deliberately unlisted so the tool schema stays small. `catalog_search` makes them discoverable.
  - `routeros_get` takes any `/rest/` path directly, plus `routeros_batch` for up to 16 parallel reads in one call.
- **Real query power**
  - Client-side `where` filters with `__contains`, `__in`, `__not`, `__gt`, `__gte`, `__lt`, `__lte`, `__startswith`, `__endswith`.
  - `fields` projection, `sort_by`, `limit`, `compact` (one-line-per-item output that saves a lot of tokens).
  - RouterOS-native `.proplist` / `.query` pass-through for server-side filtering.
- **Guarded mutations**
  - `MIKROTIK_MODE=readonly`: mutation/execution tools are not registered at all — the protocol surface itself is read-only, not just policy-gated.
  - `MIKROTIK_MODE=careful` (default): operations classified as disruptive return `requires_confirmation` — the agent relays it to the user and re-runs with `confirm: true` after approval. MCP elicitation shows a native dialog where supported. **The confirmation flag is a UX gate, not a security boundary — the RouterOS account permissions are what actually limits the agent.**
  - Method-aware policy: `PUT` only on known collections, `PATCH`/`DELETE` only on `collection/<id>` items, `POST` only on an explicit action allowlist (`ping`, `traceroute`, `fetch`, `file/read`, `script/run`, `dns flush`, `backup/save`, `export`, container shell — see `catalog.py`).
  - `MIKROTIK_STRICT_CONFIRM=1` gates **every** mutation.
  - `MIKROTIK_MODE=yolo` removes all gates and can switch to a separate full-privilege account (`MIKROTIK_YOLO_USERNAME` / `MIKROTIK_YOLO_PASSWORD_FILE`) — for supervised automation windows only.
- **Scheduled rollback guard** (not RouterOS Safe Mode — this works over plain REST)
  - `apply_safe` snapshots the target, arms an on-router scheduler, then applies the mutation. Once armed, the rollback no longer depends on the MCP process or client staying alive — `commit_safe` disarms it within `window_seconds`.
  - Supported methods: `PATCH` (restores the snapshotted values of changed fields — not transactional, no concurrent-edit detection) and `DELETE` (best-effort recreate; list position and generated fields are not preserved — the response says so). `PUT` is rejected because a created item's `.id` can't be known until after it exists.
  - Ambiguous transport failures leave the rollback armed rather than silently disarming; `commit_safe` keeps the pending record if disarm fails so it can be retried.
  - `safe_status` reports currently armed rollbacks.
- **Container & diagnostics**
  - `container_shell` runs commands inside RouterOS containers by name or `.id` — off by default (`MIKROTIK_ENABLE_CONTAINER_SHELL`), confirmation-gated in careful mode, and the generic `routeros_write` path can't bypass the flag.
  - `interface_traffic` measures live rx/tx bps and pps over a sampling window; `routeros_watch` diffs numeric fields across samples — counter deltas without two manual reads.
  - `run_ping`, `run_traceroute`, `run_fetch`, `run_wifi_monitor`, `describe_path` (field introspection before you write filters).
- **File ops with a sandbox**
  - Router-side file create/read/update/rename/delete plus chunked `download_file` / `upload_file`.
  - Host filesystem access is off by default; `MIKROTIK_ENABLE_LOCAL_FILES` + `MIKROTIK_LOCAL_ROOT` confine it to one directory; transfers are capped at 8 MiB and `download_file` requires `overwrite: true` to replace an existing local file.
- **Secret hygiene**
  - Credentials come from `MIKROTIK_PASSWORD_FILE` (recommended) or `MIKROTIK_PASSWORD`.
  - Every response passes through a scrubber that masks `password`/`secret`/`psk`/`token`/`private-key`-shaped fields (`MIKROTIK_REDACT=0` disables). Redaction is field-name based — secrets embedded in free-form text (comments, script bodies, log lines, file contents) are not reliably detected.
  - Tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) on every tool so clients can enforce their own policy.

## Requirements

- Python **3.10+** (developed on 3.13).
- RouterOS **7.1+** with REST reachable (integration-tested on **7.24.5**, hAP ax³ — REST, containers, scheduler rollback, file ops). HTTPS via `www-ssl` recommended; plain HTTP via `www` requires RouterOS **7.9+** and should be used only on isolated networks — REST uses Basic auth, readable on the wire.
- A RouterOS user with `read` + `api` + `rest-api` for read-only use. Add `write` + `test` for mutations/diagnostics, `ftp` for file tools (`download_file`, `/file/read`). Script entries have their own `policy` attribute — the account only needs `write` to run them, and cannot run a script with broader policy than it possesses.

## Installation

```bash
pipx install mikrotik-rest-mcp-server   # or: uvx mikrotik-rest-mcp-server
```

This exposes the `mikrotik-rest-mcp-server` console script. For development: `git clone` + `pip install -e .`

## Configuration

Point your MCP client at the server:

```json
{
  "mcpServers": {
    "mikrotik_rest": {
      "command": "mikrotik-rest-mcp-server",
      "env": {
        "MIKROTIK_BASE": "https://192.168.88.1",
        "MIKROTIK_USERNAME": "mcp-agent",
        "MIKROTIK_PASSWORD_FILE": "/path/to/password-file"
      }
    }
  }
}
```

See `.env.example` for the full variable list (modes, capability flags, timeouts, TLS verification).

### Recommended RouterOS account

```routeros
# ops account — reads, config writes, diagnostics; no user/policy management,
# no sensitive fields, no reboot
/user group add name=agent policy=read,write,api,rest-api,test,ftp
/user add name=mcp-agent group=agent password=<random>

# monitoring-only account (pair with MIKROTIK_MODE=readonly)
/user group add name=monitor policy=read,api,rest-api,test
```

For `yolo` mode, create a second account in `full` and wire it via `MIKROTIK_YOLO_*`. Omit `ftp` if you don't need file tools.

## Using it with agents

Typical flow an agent follows:

```
get_dhcp_leases {compact: true}                     → quick device list
routeros_batch {requests: [...]}                    → status in one call
describe_path {path: "/rest/interface/ethernet"}    → field names before filtering
interface_traffic {name: "ether1", seconds: 2}      → live throughput
routeros_watch {path: ..., diff: true}              → counter deltas
routeros_write {method: "PATCH", ...}               → routine config edit
routeros_write {method: "DELETE", ...}              → stops for confirmation
apply_safe {method: "PATCH", path: "…/<.id>", window_seconds: 60}
                                                    → rollback armed on router; commit_safe to keep
```

`run_script_inline` creates a temporary RouterOS script, runs it, and removes it (always confirmed in careful mode). `container_shell` and host file transfer need their opt-in flags.

## Layout

```text
src/mikrotik_rest_mcp/
  client.py      — REST transport, TLS, env config
  catalog.py     — endpoint/tool tables (pure data)
  policy.py      — risk tiers, confirmation gate, mutation allowlist
  output.py      — secret redaction, filters, compact serialization
  files.py       — local file sandbox + router file helpers
  safe_apply.py  — snapshot/rollback machinery
  server.py      — tool list, dispatch, resources, entrypoint
```

## Tests

```bash
pytest tests/
```

Unit tests run without a router (REST calls are mocked).

## Security

See `SECURITY.md`. Don't point this at routers you don't administer; treat `yolo` as a loaded gun and `container_shell` as remote code execution (because it is).
