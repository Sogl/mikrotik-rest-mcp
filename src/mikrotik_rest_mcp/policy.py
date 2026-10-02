from __future__ import annotations

import os
import re
import urllib.parse
from typing import Any

from mcp.types import TextContent

from .client import client, run_request, RouterOSError
from .catalog import MUTATION_ALLOWLIST, PATCHABLE_COLLECTIONS
from .output import one_text

# --- Risk tiers: destructive ops need user confirmation unless MIKROTIK_MODE=yolo ---

# Action endpoints (POST /rest/<coll>/<action>) considered disruptive/destructive.
DANGEROUS_ACTION_SUFFIXES = frozenset(
    {
        "remove",
        "stop",
        "reboot",
        "shutdown",
        "reset",
        "reset-configuration",
        "restore",
        "load",
        "install",
        "upgrade",
        "uninstall",
        "flush",
        "kill",
        "import",
        "renew",
        "release",
        "remove-all",
        "disable-all",
    }
)

# Collections whose items must not be deleted without confirmation.
CONFIRM_DELETE_PREFIXES = (
    "/rest/user",
    "/rest/system",
    "/rest/certificate",
    "/rest/interface",
    "/rest/ip/route",
    "/rest/routing",
    "/rest/ip/address",
    "/rest/container",
    "/rest/ip/dhcp-server",
    "/rest/queue",
    "/rest/ip/firewall/address-list",
    "/rest/ip/firewall/nat",
    "/rest/ip/firewall/mangle",
    "/rest/ip/firewall/filter",
    "/rest/ip/firewall/raw",
    "/rest/ip/firewall/connection",
    "/rest/ppp",
    "/rest/ip/dns/static",
    "/rest/ip/pool",
    "/rest/ip/ipsec",
    "/rest/ipv6",
    "/rest/snmp",
    "/rest/caps-man",
    "/rest/user-manager",
    "/rest/zerotier",
    "/rest/disk",
    "/rest/partition",
)

# Writes (PUT/PATCH/POST-create) into these paths can disrupt service or lock out access.
CONFIRM_WRITE_PREFIXES = (
    "/rest/ip/service",
    "/rest/user",
    "/rest/system/scheduler",
    "/rest/system/script",
    "/rest/system/package",
    "/rest/system/ntp/client",
    "/rest/interface",
    "/rest/container",
    "/rest/ip/settings",
    "/rest/ipv6/settings",
    "/rest/certificate",
    "/rest/ip/cloud",
    "/rest/snmp",
)


# Action paths that stay unrestricted even under destructive prefixes.
CONFIRM_EXEMPT = frozenset()


STRICT_CONFIRM = os.environ.get("MIKROTIK_STRICT_CONFIRM", "").strip().lower() in ("1", "true", "yes", "on")


def is_mutation_denied(method: str, path: str) -> bool:
    """readonly mode: every non-GET mutation is refused at the gate."""
    return client.mode == "readonly" and method.upper() != "GET"


def requires_confirmation(method: str, path: str) -> bool:
    """Return True when the mutation is destructive/disruptive in careful mode."""
    if client.mode == "yolo":
        return False
    normalized = path.rstrip("/")
    if normalized in CONFIRM_EXEMPT:
        return False
    m = method.upper()
    if STRICT_CONFIRM and m != "GET":
        return True
    if m == "POST" and normalized not in BENIGN_ACTIONS:
        return True
    if m == "DELETE":
        if any(normalized.startswith(prefix + "/") or normalized == prefix for prefix in CONFIRM_DELETE_PREFIXES):
            return True
    tail = normalized.rsplit("/", 1)[-1]
    if m == "POST" and tail in DANGEROUS_ACTION_SUFFIXES:
        return True
    if m in ("PUT", "PATCH", "POST"):
        if any(normalized == prefix or normalized.startswith(prefix + "/") for prefix in CONFIRM_WRITE_PREFIXES):
            return True
    return False


async def gate_confirmation(method: str, path: str, data: Any | None, tool: str, arguments: dict[str, Any]) -> list[TextContent] | None:
    """Return a pending/declined response when confirmation is needed, None when cleared to proceed."""
    if not requires_confirmation(method, path):
        return None
    if arguments.get("confirm"):
        return None
    summary = f"{method} {path}"
    try:
        from .server import server
        result = await server.request_context.session.elicit(
            message=f"Destructive/disruptive RouterOS operation: {summary}. Approve?",
            schema={
                "type": "object",
                "properties": {"confirm": {"type": "boolean", "title": "Approve"}},
                "required": ["confirm"],
            },
        )
        if result.action == "accept" and (result.content or {}).get("confirm"):
            return None
        if result.action in ("decline", "cancel"):
            return one_text({"ok": False, "declined": True, "method": method, "path": path})
    except Exception:
        pass
    return pending_confirmation(method, path, data, tool)


def pending_confirmation(method: str, path: str, data: Any | None, tool: str) -> list[TextContent]:
    return one_text(
        {
            "ok": False,
            "requires_confirmation": True,
            "mode": client.mode,
            "pending": {"tool": tool, "method": method, "path": path, "data": data},
            "how_to_confirm": "This operation is destructive/disruptive. Ask the user; if approved, re-run the SAME call with confirm=true.",
        }
    )


# POST on RouterOS REST is a universal command invoker — <collection>/<action> maps to
# CLI verbs like disable/enable/send. Only explicitly listed action paths are allowed;
# unknown POST paths are denied outright (not merely confirm-gated).
ACTION_ALLOWLIST = frozenset(
    {
        "/rest/ip/dns/cache/flush",
        "/rest/system/script/run",
        "/rest/system/scheduler/remove",
        "/rest/ping",
        "/rest/tool/traceroute",
        "/rest/tool/fetch",
        "/rest/interface/wifi/monitor",
        "/rest/file/read",
        "/rest/file/remove",
        "/rest/file/set",
        "/rest/export",
        "/rest/system/backup/save",
    }
)

# Action paths that additionally require MIKROTIK_ENABLE_CONTAINER_SHELL=1 — the generic
# writer must not bypass the dedicated handler's capability flag.
ACTION_FLAG_GATED = {"/rest/container/shell": "enable_container_shell"}

# POST actions that never need confirmation (pure reads/diagnostics in disguise).
BENIGN_ACTIONS = frozenset(
    {
        "/rest/ping",
        "/rest/tool/traceroute",
        "/rest/interface/wifi/monitor",
        "/rest/file/read",
    }
)

_ITEM_ID_RE = re.compile(r"^[\*\w\-.]{1,64}$")


def _canonical_rest_path(path: str) -> str:
    normalized = urllib.parse.unquote(str(path)).strip().rstrip("/")
    if (
        not normalized.startswith("/rest/")
        or ".." in normalized
        or "//" in normalized
        or "?" in normalized
        or "#" in normalized
    ):
        raise RouterOSError(f"invalid REST path: {path}")
    return normalized


def is_mutation_path_allowed(method: str, path: str) -> bool:
    if client.mode == "yolo":
        return True
    normalized = _canonical_rest_path(path)
    m = method.upper()
    if m == "POST":
        if normalized in ACTION_FLAG_GATED:
            return getattr(client, ACTION_FLAG_GATED[normalized], False)
        return normalized in ACTION_ALLOWLIST or normalized in MUTATION_ALLOWLIST
    if m in ("PATCH", "DELETE"):
        for prefix in PATCHABLE_COLLECTIONS:
            if normalized.startswith(prefix + "/") and _ITEM_ID_RE.match(normalized[len(prefix) + 1 :]):
                return True
        # item ops on explicitly allowlisted collections (scripts, schedulers, files)
        for prefix in MUTATION_ALLOWLIST:
            if normalized.startswith(prefix + "/") and _ITEM_ID_RE.match(normalized[len(prefix) + 1 :]):
                return True
        return False
    if m == "PUT":
        return normalized in PATCHABLE_COLLECTIONS or normalized in MUTATION_ALLOWLIST
    return False


