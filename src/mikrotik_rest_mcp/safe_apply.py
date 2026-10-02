from __future__ import annotations

import asyncio
import re
import secrets
from datetime import datetime, timedelta
from typing import Any

from .client import client, run_request, RouterOSError
from .policy import gate_confirmation, is_mutation_path_allowed
from .output import one_text, success_payload

# --- safe-apply: snapshot + timed rollback -------------------------------------

SAFE_OPS: dict[str, dict[str, Any]] = {}


def mark_deadline(token: str, window_seconds: int) -> None:
    if token in SAFE_OPS:
        import time as _t
        SAFE_OPS[token]["deadline"] = _t.monotonic() + window_seconds


def parse_router_clock(clock: dict[str, Any]) -> datetime:
    """RouterOS clock date format varies by version: 'oct/02/2026' vs ISO '2026-10-02'."""
    stamp = f"{clock.get('date', '')} {clock.get('time', '00:00:00')}"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%b/%d/%Y %H:%M:%S", "%b/%d/%y %H:%M:%S"):
        try:
            return datetime.strptime(stamp, fmt)
        except ValueError:
            continue
    raise RouterOSError(f"unparseable router clock: {stamp!r}")

READONLY_ITEM_FIELDS = frozenset(
    {
        ".id",
        "dynamic",
        "default",
        "invalid",
        "inactive",
        "runtime",
        "bytes",
        "packets",
        "running",
        "slave",
        "type",
        "last-link-up-time",
        "link-downs",
        "last-link-down-time",
        "uptime",
        "creation-time",
        "time",
    }
)


def rest_to_menu_and_id(path: str) -> tuple[str, str | None]:
    parts = [p for p in path[len("/rest/") :].split("/") if p]
    item_id = None
    if parts and parts[-1].startswith("*"):
        item_id = parts.pop()
    menu = "/" + " ".join(parts)
    return menu, item_id


def cli_value(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value)
    if text.lower() in ("true", "yes", "on"):
        return "yes"
    if text.lower() in ("false", "no", "off"):
        return "no"
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return text
    escaped = (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    return '"%s"' % escaped


def build_rollback_script(menu: str, kind: str, item_id: str | None, snapshot: dict[str, Any] | None, changed_fields: dict[str, Any] | None, sched_name: str) -> str:
    self_clean = f'/system scheduler remove [find name="{sched_name}"]'
    if kind == "patch":
        # restore only the fields the caller is about to change
        pairs = []
        for key in changed_fields or {}:
            old = (snapshot or {}).get(key)
            pairs.append(f"{key}={cli_value(old if old is not None else '')}")
        return f"{menu} set {item_id} " + " ".join(pairs) + f"; {self_clean}"
    if kind == "delete":
        pairs = [f"{k}={cli_value(v)}" for k, v in (snapshot or {}).items() if k not in READONLY_ITEM_FIELDS and not k.startswith(".")]
        return f"{menu} add " + " ".join(pairs) + f"; {self_clean}"
    # kind == "create": remove what was added
    return f"{menu} remove {item_id}; {self_clean}"


async def register_rollback(token: str, menu: str, kind: str, item_id: str | None, snapshot: dict[str, Any] | None, changed_fields: dict[str, Any] | None, window_seconds: int, fallback: tuple[str, str, Any]) -> str:
    """Router-side scheduler rollback if writable; otherwise an in-process asyncio timer. Returns mechanism name."""
    sched_name = f"mcp-rb-{token}"
    script = build_rollback_script(menu, kind, item_id, snapshot, changed_fields, sched_name)
    clock = await run_request("GET", "/rest/system/clock")
    router_dt = parse_router_clock(clock)
    fire_dt = router_dt + timedelta(seconds=window_seconds)
    start_date = fire_dt.strftime("%b/%d/%Y").lower()
    start_time = fire_dt.strftime("%H:%M:%S")
    try:
        await run_request(
            "PUT",
            "/rest/system/scheduler",
            {
                "name": sched_name,
                "start-date": start_date,
                "start-time": start_time,
                "interval": "0s",
                "on-event": script,
                "comment": "mikrotik-mcp safe-apply rollback",
            },
        )
        mechanism = "router-scheduler"
    except RouterOSError:
        mechanism = "process-timer"

    async def _process_rollback() -> None:
        await asyncio.sleep(window_seconds)
        op = SAFE_OPS.pop(token, None)
        if op is not None and op.get("rollback") == "process-timer":
            try:
                await run_request(*fallback)
            except RouterOSError:
                pass

    task = None
    if mechanism == "process-timer":
        task = asyncio.create_task(_process_rollback())
    SAFE_OPS[token]["rollback"] = mechanism
    SAFE_OPS[token]["task"] = task
    return mechanism


async def handle_apply_safe(arguments: dict[str, Any]) -> list[TextContent]:
    method = str(arguments["method"]).upper()
    path = arguments["path"].rstrip("/")
    data = arguments.get("data") or {}
    window = int(arguments.get("window_seconds", 60))
    if method not in ("PATCH", "DELETE"):
        raise RouterOSError(
            "apply_safe supports PATCH/DELETE on item paths only; "
            "PUT cannot guarantee a rollback target until the object exists"
        )
    if not is_mutation_path_allowed(method, path):
        raise RouterOSError(f"path is not whitelisted for mutation: {path}")

    gated = await gate_confirmation(method, path, data, "apply_safe", arguments)
    if gated is not None:
        return gated

    menu, item_id = rest_to_menu_and_id(path)
    token = secrets.token_hex(4)
    snapshot = None
    kind = "create"
    fallback: tuple[str, str, Any] | None = None

    if not item_id:
        raise RouterOSError("apply_safe PATCH/DELETE requires an item path (/rest/<collection>/<.id>)")
    snapshot = await run_request("GET", path)
    if not isinstance(snapshot, dict):
        raise RouterOSError(f"unexpected snapshot response for {path}")
    kind = "patch" if method == "PATCH" else "delete"
    if method == "PATCH":
        old = {k: snapshot.get(k) for k in data}
        fallback = ("PATCH", path, old)
    else:
        fallback = ("PUT", "/".join(path.split("/")[:-1]), {k: v for k, v in snapshot.items() if k not in READONLY_ITEM_FIELDS and not k.startswith(".")})

    SAFE_OPS[token] = {"method": method, "path": path, "data": data, "window": window, "rollback": "pending"}

    mechanism: str | None = None
    if method != "PUT":
        # arm the rollback BEFORE mutating so a failed/hung apply still reverts
        mechanism = await register_rollback(token, menu, kind, item_id, snapshot, data if method == "PATCH" else None, window, fallback)
        mark_deadline(token, window)

    try:
        result = await run_request(method, path, data if method == "PATCH" else None)
    except RouterOSError as exc:
        msg = str(exc)
        if msg.startswith("HTTP 4"):
            # definite server-side refusal — the mutation did not happen, safe to disarm
            await handle_commit_safe({"pending_id": token})
        else:
            # transport/ambiguous failure: rollback stays armed — the mutation may have landed
            raise RouterOSError(
                f"apply outcome unknown ({exc}); rollback remains armed for {window}s"
            )

    SAFE_OPS[token]["applied"] = True
    return one_text(
        success_payload(
            method,
            path,
            result,
            safe_apply=True,
            rollback_guarantee="best-effort recreate" if method == "DELETE" else "exact",
            pending_id=token,
            rollback_via=mechanism,
            window_seconds=window,
            how_to_commit=f"Call commit_safe with pending_id={token} within {window}s or the change auto-rolls back.",
        )
    )


async def handle_commit_safe(arguments: dict[str, Any]) -> list[TextContent]:
    token = str(arguments["pending_id"])
    op = SAFE_OPS.get(token)
    if op is None:
        return one_text({"ok": False, "error": f"unknown or expired pending_id: {token}"})
    cancelled = []
    disarm_error = None
    if op.get("rollback") == "router-scheduler":
        try:
            await run_request("POST", "/rest/system/scheduler/remove", {"numbers": f"mcp-rb-{token}"})
            cancelled.append("router-scheduler")
        except RouterOSError:
            # may have already fired or been removed; try by-name delete as fallback
            try:
                rows = await run_request("GET", "/rest/system/scheduler")
                match = [r[".id"] for r in rows if r.get("name") == f"mcp-rb-{token}"]
                for rid in match:
                    await run_request("DELETE", f"/rest/system/scheduler/{rid}")
                    cancelled.append("router-scheduler")
            except RouterOSError as exc:
                disarm_error = str(exc)
    task = op.pop("task", None)
    if task is not None:
        task.cancel()
        cancelled.append("process-timer")
    if disarm_error is not None:
        # keep the entry — commit can be retried; the armed rollback may still fire
        return one_text(
            {
                "ok": False,
                "pending_id": token,
                "error": f"rollback disarm failed: {disarm_error}; rollback may still fire at the armed deadline",
            }
        )
    SAFE_OPS.pop(token, None)
    return one_text({"ok": True, "pending_id": token, "cancelled_rollback": cancelled or "none"})


