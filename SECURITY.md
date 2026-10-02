# Security Policy

This MCP server can mutate a real RouterOS device — treat it as infrastructure tooling.

## Trust model
- The server holds full REST credentials. Run it only for MCP clients you trust.
- `MIKROTIK_MODE=careful` (default) asks for confirmation on destructive/disruptive operations (DELETE on config objects, action endpoints like reboot/remove/stop, writes to interface/user/service paths).
- `MIKROTIK_MODE=yolo` removes all confirmation gates and can use a separate full-privilege account — intended for supervised automation only.
- `MIKROTIK_ENABLE_CONTAINER_SHELL`, `MIKROTIK_ENABLE_LOCAL_FILES` are off by default; enable them only on isolated hosts.
- `apply_safe`/`commit_safe` provide timed auto-rollback via an on-router scheduler — the rollback is best-effort for DELETE (recreates the object) and exact for PATCH of changed fields.
- Responses are scrubbed for password/secret/token-shaped fields (`MIKROTIK_REDACT`, default on).

## Reporting
Open a private security advisory on GitHub — do not file public issues for vulnerabilities.
