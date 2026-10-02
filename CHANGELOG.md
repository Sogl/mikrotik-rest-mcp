# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-10-02

Initial public release.

### Added
- ~60 curated `get_*` read tools + 200+ catalog endpoints callable by name (`catalog_search` for discovery)
- Generic `routeros_get` / `routeros_write` / `routeros_batch` (up to 16 parallel reads)
- Client-side filtering: `where` suffixes, `fields`, `sort_by`, `limit`, `compact` one-line output
- `describe_path` field introspection, `interface_traffic` live bps/pps, `routeros_watch` counter diffs
- `apply_safe` / `commit_safe` — scheduler-armed auto-rollback (exact for PATCH, best-effort for DELETE, fail-closed PUT)
- `container_shell` (opt-in), router file tools with local sandbox (`MIKROTIK_LOCAL_ROOT`), chunked download/upload
- Modes: `readonly` (no mutation tools registered), `careful` (confirmation gate + MCP elicitation), `yolo` (unrestricted, separate account), `MIKROTIK_STRICT_CONFIRM`
- Field-name secret redaction in all tool/resource output (`MIKROTIK_REDACT`)
- MCP resources for router status snapshots (`routeros://` URIs)
- Tool risk annotations (`readOnlyHint`/`destructiveHint`) on every tool
- HTTPS transport, password-file credentials, least-privilege RouterOS group recipe

### Security
- Host filesystem access disabled by default; sandboxed under `MIKROTIK_LOCAL_ROOT` with streaming size cap and explicit `overwrite` flag
- `container_shell` disabled by default (`MIKROTIK_ENABLE_CONTAINER_SHELL`), confirmation-gated, and unreachable via the generic writer
- Method-aware mutation policy: POST restricted to an explicit action allowlist, PUT to known collections, PATCH/DELETE to validated item paths; paths are canonicalized (`..`, `//`, `%`-encoding rejected)
- `apply_safe` limited to PATCH/DELETE with pre-armed router-side rollback; ambiguous transport failures keep the rollback armed
- Error text and all responses pass through the secret scrubber (covers RouterOS sensitive field names: password, preshared-key, cak, pin, encryption-key, …)
