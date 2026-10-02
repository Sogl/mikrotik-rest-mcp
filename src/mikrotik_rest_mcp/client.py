from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .catalog import READ_ENDPOINTS

class RouterOSError(RuntimeError):
    pass


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")



class RouterOSClient:
    def __init__(self) -> None:
        self.base = os.environ.get("MIKROTIK_BASE", "").rstrip("/")
        self.username = os.environ.get("MIKROTIK_USERNAME", "")
        if not self.base or not self.username:
            raise RouterOSError("MIKROTIK_BASE and MIKROTIK_USERNAME must be set explicitly")
        self.enable_container_shell = _env_flag("MIKROTIK_ENABLE_CONTAINER_SHELL")
        self.enable_local_files = _env_flag("MIKROTIK_ENABLE_LOCAL_FILES")
        self.redact = os.environ.get("MIKROTIK_REDACT", "1").strip().lower() not in ("0", "no", "false")
        root = os.environ.get("MIKROTIK_LOCAL_ROOT", "").strip()
        self.local_root = Path(root).expanduser().resolve() if root else None
        password_file = os.environ.get("MIKROTIK_PASSWORD_FILE", "")
        if password_file:
            self.password = Path(password_file).expanduser().read_text(encoding="utf-8").strip()
        else:
            self.password = os.environ.get("MIKROTIK_PASSWORD", "")
        self.timeout = float(os.environ.get("MIKROTIK_TIMEOUT", "10"))
        if not self.password:
            raise RouterOSError("MIKROTIK_PASSWORD or MIKROTIK_PASSWORD_FILE is not set")
        self.mode = os.environ.get("MIKROTIK_MODE", "careful").strip().lower()
        if self.mode not in ("careful", "readonly", "yolo"):
            raise RouterOSError(f"unknown MIKROTIK_MODE: {self.mode}")
        if self.mode == "yolo":
            yolo_user = os.environ.get("MIKROTIK_YOLO_USERNAME", "")
            yolo_pw_file = os.environ.get("MIKROTIK_YOLO_PASSWORD_FILE", "")
            if yolo_user and yolo_pw_file:
                self.username = yolo_user
                self.password = Path(yolo_pw_file).expanduser().read_text(encoding="utf-8").strip()

    def _url(self, path: str) -> str:
        if not path.startswith("/rest/"):
            raise RouterOSError(f"path must start with /rest/: {path}")
        return f"{self.base}{path}"

    def _headers(self, json_body: bool = False) -> dict[str, str]:
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        headers = {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    def request(self, method: str, path: str, data: Any | None = None) -> Any:
        url = self._url(path)
        body = None
        headers = self._headers(json_body=data is not None)
        if data is not None:
            body = json.dumps(data).encode("utf-8")
        request = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
        context = None
        if urllib.parse.urlparse(url).scheme == "https":
            if os.environ.get("MIKROTIK_VERIFY_SSL", "yes").strip().lower() in ("no", "false", "0"):
                context = ssl._create_unverified_context()
            else:
                context = ssl.create_default_context()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                raw = response.read()
                if not raw:
                    return {"ok": True, "status": response.status}
                charset = response.headers.get_content_charset() or "utf-8"
                try:
                    text = raw.decode(charset)
                except UnicodeDecodeError:
                    # Some RouterOS endpoints, notably /file/read for binary chunks,
                    # return JSON bodies containing raw byte values. latin1 preserves
                    # those bytes 1:1 so callers can reconstruct the original file.
                    text = raw.decode("latin1")
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return {"ok": True, "status": response.status, "text": text}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise RouterOSError(f"HTTP {exc.code} for {path}: {raw}") from exc
        except urllib.error.URLError as exc:
            raise RouterOSError(f"Request failed for {path}: {exc.reason}") from exc


client = RouterOSClient()


async def run_request(method: str, path: str, data: Any | None = None) -> Any:
    return await asyncio.to_thread(client.request, method, path, data)


async def resolve_container_id(container: str) -> tuple[str, str]:
    if container.startswith("*"):
        return container, container
    containers = await run_request("GET", READ_ENDPOINTS["containers"])
    if not isinstance(containers, list):
        raise RouterOSError("unexpected container list response")
    for item in containers:
        if item.get("name") == container:
            return item[".id"], container
    raise RouterOSError(f"container not found: {container}")


