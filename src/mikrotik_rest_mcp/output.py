from __future__ import annotations

import json
import re
from typing import Any
from collections.abc import Iterable

from mcp.types import TextContent

from .client import client


SENSITIVE_FIELD_RE = re.compile(
    r"(password|passphrase|secret|psk|private.?key|preshared.?key|token|api.?key|cak|pin|encryption.?key|shared.?key|ike.?key|sstp.?key)",
    re.IGNORECASE,
)


_SENSITIVE_TEXT_RE = re.compile(
    r'("(?:password|passphrase|secret|psk|private.?key|preshared.?key|token|api.?key|cak|pin|encryption.?key|shared.?key)"\s*:\s*")[^"]*(")',
    re.IGNORECASE,
)


def redact_secrets(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("***REDACTED***" if SENSITIVE_FIELD_RE.search(k) else redact_secrets(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_secrets(v) for v in obj]
    if isinstance(obj, str):
        # скраб вложенных JSON-фрагментов в текстовых полях (например тела ошибок RouterOS)
        return _SENSITIVE_TEXT_RE.sub(r"\1***REDACTED***\2", obj)
    return obj



def dump(data: Any) -> str:
    if client.redact:
        data = redact_secrets(data)
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)


def one_text(payload: Any) -> list[TextContent]:
    return [TextContent(type="text", text=dump(payload))]


def normalize_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def is_truthy_routeros(value: Any) -> bool:
    return normalize_scalar(value).lower() in {"true", "yes", "on", "enabled", "bound"}


def matches_exact(actual: Any, expected: Any) -> bool:
    if isinstance(expected, bool):
        return normalize_scalar(actual).lower() == normalize_scalar(expected)
    return actual == expected or normalize_scalar(actual) == normalize_scalar(expected)


def matches_contains(actual: Any, expected: Any) -> bool:
    return normalize_scalar(expected).lower() in normalize_scalar(actual).lower()


def matches_in(actual: Any, expected: Iterable[Any]) -> bool:
    return any(matches_exact(actual, item) for item in expected)


def matches_startswith(actual: Any, expected: Any) -> bool:
    return normalize_scalar(actual).lower().startswith(normalize_scalar(expected).lower())


def matches_endswith(actual: Any, expected: Any) -> bool:
    return normalize_scalar(actual).lower().endswith(normalize_scalar(expected).lower())


def parse_number_like(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    text = normalize_scalar(value).strip()
    if not text:
        return None
    try:
        if any(marker in text for marker in (".", "e", "E")):
            return float(text)
        return int(text)
    except ValueError:
        return None


def compare_values(actual: Any, expected: Any) -> int | None:
    if actual is None or expected is None:
        return None

    actual_number = parse_number_like(actual)
    expected_number = parse_number_like(expected)
    if actual_number is not None and expected_number is not None:
        if actual_number < expected_number:
            return -1
        if actual_number > expected_number:
            return 1
        return 0

    actual_text = normalize_scalar(actual).lower()
    expected_text = normalize_scalar(expected).lower()
    if actual_text < expected_text:
        return -1
    if actual_text > expected_text:
        return 1
    return 0


def matches_range(actual: Any, expected: Any, operator: str) -> bool:
    comparison = compare_values(actual, expected)
    if comparison is None:
        return False
    if operator == "gt":
        return comparison > 0
    if operator == "gte":
        return comparison >= 0
    if operator == "lt":
        return comparison < 0
    if operator == "lte":
        return comparison <= 0
    raise RouterOSError(f"unsupported range operator: {operator}")


def project_item(item: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    return {field: item.get(field) for field in fields}


def filter_items(items: list[dict[str, Any]], arguments: dict[str, Any]) -> list[dict[str, Any]]:
    where = arguments.get("where") or {}
    contains = arguments.get("contains")
    fields = arguments.get("fields") or []
    sort_by = arguments.get("sort_by")
    descending = bool(arguments.get("descending", False))
    limit = arguments.get("limit")

    filtered = items
    if where:
        next_items: list[dict[str, Any]] = []
        for item in filtered:
            keep = True
            for key, expected in where.items():
                if key.endswith("__contains"):
                    field = key[:-10]
                    keep = matches_contains(item.get(field), expected)
                elif key.endswith("__startswith"):
                    field = key[:-12]
                    keep = matches_startswith(item.get(field), expected)
                elif key.endswith("__endswith"):
                    field = key[:-10]
                    keep = matches_endswith(item.get(field), expected)
                elif key.endswith("__in"):
                    field = key[:-4]
                    if not isinstance(expected, list):
                        raise RouterOSError(f"filter {key} requires an array value")
                    keep = matches_in(item.get(field), expected)
                elif key.endswith("__not"):
                    field = key[:-5]
                    keep = not matches_exact(item.get(field), expected)
                elif key.endswith("__gte"):
                    field = key[:-5]
                    keep = matches_range(item.get(field), expected, "gte")
                elif key.endswith("__lte"):
                    field = key[:-5]
                    keep = matches_range(item.get(field), expected, "lte")
                elif key.endswith("__gt"):
                    field = key[:-4]
                    keep = matches_range(item.get(field), expected, "gt")
                elif key.endswith("__lt"):
                    field = key[:-4]
                    keep = matches_range(item.get(field), expected, "lt")
                else:
                    keep = matches_exact(item.get(key), expected)
                if not keep:
                    break
            if keep:
                next_items.append(item)
        filtered = next_items

    if contains:
        filtered = [item for item in filtered if matches_contains(item, contains)]

    if sort_by:
        filtered = sorted(
            filtered,
            key=lambda item: normalize_scalar(item.get(sort_by, "")),
            reverse=descending,
        )

    if isinstance(limit, int) and limit >= 0:
        filtered = filtered[:limit]

    if fields:
        filtered = [project_item(item, fields) for item in filtered]

    return filtered


def apply_view(payload: Any, arguments: dict[str, Any]) -> Any:
    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return filter_items(payload, arguments)
    return payload


    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return filter_items(payload, arguments)
    return payload


def success_payload(method: str, path: str, result: Any, **extra: Any) -> dict[str, Any]:
    payload = {
        "ok": True,
        "method": method,
        "path": path,
        "result": result,
    }
    payload.update(extra)
    return payload


def compact_text(payload: Any) -> list[TextContent]:
    if client.redact:
        payload = redact_secrets(payload)
    if isinstance(payload, list):
        lines = [json.dumps(item, separators=(",", ":"), ensure_ascii=False, default=str) for item in payload]
        return [TextContent(type="text", text="\n".join(lines))]
    return [TextContent(type="text", text=json.dumps(payload, separators=(",", ":"), ensure_ascii=False, default=str))]


def view_result(payload: Any, arguments: dict[str, Any]) -> list[TextContent]:
    viewed = apply_view(payload, arguments)
    if arguments.get("compact"):
        return compact_text(viewed)
    return one_text(viewed)


