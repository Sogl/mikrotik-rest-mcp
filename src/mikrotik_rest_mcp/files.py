from __future__ import annotations

from pathlib import Path
from typing import Any

from .client import client, run_request, RouterOSError
from .output import normalize_scalar

def routeros_bytes_from_string(value: Any) -> bytes:
    text = normalize_scalar(value)
    try:
        # response body was latin1-decoded (binary-safe path): codepoints == original bytes
        return text.encode("latin1")
    except UnicodeEncodeError:
        # response body was utf-8-decoded into real unicode: re-encode to get the file bytes
        return text.encode("utf-8")


MAX_CHUNK_SIZE = 32768


async def read_router_file_chunk(file_path: str, offset: int, chunk_size: int) -> bytes:
    result = await run_request(
        "POST",
        "/rest/file/read",
        {
            "file": file_path,
            "offset": str(offset),
            "chunk-size": str(chunk_size),
        },
    )
    if not isinstance(result, list) or not result:
        return b""
    first = result[0]
    if not isinstance(first, dict):
        return b""
    data = first.get("data", "")
    if not data:
        return b""
    return routeros_bytes_from_string(data)


async def read_router_file_all(file_path: str, chunk_size: int, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
        raise RouterOSError(f"chunk_size must be 1..{MAX_CHUNK_SIZE}")
    chunks: list[bytes] = []
    total = 0
    offset = 0
    while True:
        chunk = await read_router_file_chunk(file_path, offset, chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise RouterOSError(f"remote file exceeds size cap ({max_bytes} bytes)")
        chunks.append(chunk)
        offset += len(chunk)
        if len(chunk) < chunk_size:
            break
    return b"".join(chunks)


def ensure_router_file_text_payload(data: bytes) -> str:
    if len(data) > 60 * 1024:
        raise RouterOSError("RouterOS file contents edits are limited to about 60KB; larger uploads are not supported by this MCP yet")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RouterOSError("Only UTF-8 text uploads are supported for RouterOS file contents right now") from exc


def ensure_router_file_suffix(name: str, suffix: str) -> str:
    normalized = str(name).strip()
    if not normalized:
        raise RouterOSError("file name must not be empty")
    if normalized.lower().endswith(suffix.lower()):
        return normalized
    return f"{normalized}{suffix}"



MAX_LOCAL_FILE_BYTES = 8 * 1024 * 1024


def resolve_local_path(raw: str, *, must_exist: bool = True, overwrite: bool = False) -> Path:
    if not client.enable_local_files:
        raise RouterOSError("local filesystem access is disabled (set MIKROTIK_ENABLE_LOCAL_FILES=1)")
    if client.local_root is None:
        raise RouterOSError("MIKROTIK_LOCAL_ROOT is not set — required when local file access is enabled")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = client.local_root / candidate
    resolved = candidate.resolve()
    root = client.local_root
    if resolved != root and root not in resolved.parents:
        raise RouterOSError(f"local path escapes MIKROTIK_LOCAL_ROOT: {resolved}")
    if must_exist and not resolved.exists():
        raise RouterOSError(f"local file not found: {resolved}")
    if not must_exist and resolved.exists() and not overwrite:
        raise RouterOSError(f"local file exists; pass overwrite=true to replace: {resolved}")
    return resolved


