from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import urllib.parse
from pathlib import Path
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import mcp.server.stdio
from mcp.server import Server
from mcp.types import Resource, ResourceTemplate, TextContent, Tool, ToolAnnotations

from .catalog import (
    DESTRUCTIVE_TOOLS,
    LISTED_GET_TOOLS,
    PATCHABLE_COLLECTIONS,
    READ_ENDPOINTS,
    READONLY_TOOLS,
)
from .client import RouterOSError, client, run_request, resolve_container_id
from .files import (
    MAX_LOCAL_FILE_BYTES,
    ensure_router_file_suffix,
    ensure_router_file_text_payload,
    read_router_file_all,
    resolve_local_path,
)
from .output import (
    apply_view,
    compact_text,
    dump,
    matches_contains,
    normalize_scalar,
    one_text,
    success_payload,
    view_result,
)
from .policy import (
    gate_confirmation,
    is_mutation_path_allowed,
    pending_confirmation,
    requires_confirmation,
)
from .safe_apply import handle_apply_safe, handle_commit_safe

server = Server("mikrotik-rest")

RESOURCE_STATUS_URI = "routeros://status"
RESOURCE_REST_TEMPLATE = "routeros://rest/{path}"
RESOURCE_CONTAINERS_STATUS_URI = "routeros://containers/status"
RESOURCE_DEFAULT_ROUTES_URI = "routeros://routes/default"
RESOURCE_WIFI_CLIENTS_URI = "routeros://wifi/clients"
RESOURCE_DHCP_ACTIVE_URI = "routeros://dhcp/active"
RESOURCE_DNS_STATUS_URI = "routeros://dns/status"


@dataclass(frozen=True)
class ReadResourceItem:
    content: str | bytes
    mime_type: str = "application/json"
    meta: dict[str, Any] | None = None


def normalize_router_uri(uri: str) -> str:
    return str(uri).rstrip("/")


def template_path_to_rest(path_value: str) -> str:
    normalized = path_value.lstrip("/")
    if normalized.startswith("rest/"):
        normalized = normalized[5:]
    return f"/rest/{normalized}"


def base_query_schema(description: str) -> Tool:
    raise RuntimeError("base_query_schema() should not be called directly")


def query_properties() -> dict[str, Any]:
    return {
        "proplist": {
            "oneOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}},
            ],
            "description": "Optional RouterOS .proplist for server-side property selection on POST .../print.",
        },
        "query_words": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional RouterOS .query stack for server-side filtering on POST .../print.",
        },
        "contains": {
            "type": "string",
            "description": "Case-insensitive substring search across the rendered item.",
        },
        "where": {
            "type": "object",
            "description": "Client-side filters applied after any RouterOS .query/.proplist request. Exact match by field, or use suffixes __contains / __in / __not / __startswith / __endswith / __gt / __gte / __lt / __lte.",
        },
        "fields": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Client-side field projection applied after any RouterOS .proplist request.",
        },
        "sort_by": {
            "type": "string",
            "description": "Sort by a field name after filtering.",
        },
        "descending": {
            "type": "boolean",
            "description": "Reverse sort order when sort_by is set.",
        },
        "limit": {
            "type": "integer",
            "minimum": 0,
            "description": "Limit returned items after filtering and sorting.",
        },
        "compact": {
            "type": "boolean",
            "description": "Emit compact single-line JSON per item instead of pretty-printed output.",
        },
    }


def query_tool(name: str, description: str) -> Tool:
    return Tool(
        name=name,
        description=description,
        inputSchema={"type": "object", "properties": query_properties()},
    )


def compact_payload(payload: Any, max_chars: int = 4000) -> Any:
    if isinstance(payload, list):
        return [compact_payload(item, max_chars=max_chars) for item in payload]
    if isinstance(payload, dict):
        compacted: dict[str, Any] = {}
        for key, value in payload.items():
            if isinstance(value, str) and len(value) > max_chars:
                compacted[key] = value[:max_chars] + "...(truncated)"
            else:
                compacted[key] = compact_payload(value, max_chars=max_chars)
        return compacted
    return payload


def get_routeros_proplist(arguments: dict[str, Any]) -> str | list[str] | None:
    value = arguments.get("proplist", arguments.get(".proplist"))
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    if isinstance(value, list):
        normalized_items = [str(item).strip() for item in value if str(item).strip()]
        return normalized_items or None
    raise RouterOSError("proplist must be a string or array of strings")


def get_routeros_query_words(arguments: dict[str, Any]) -> list[str] | None:
    value = arguments.get("query_words", arguments.get(".query"))
    if value is None:
        return None
    if not isinstance(value, list):
        raise RouterOSError("query_words must be an array of strings")
    normalized_items = [str(item).strip() for item in value if str(item).strip()]
    return normalized_items or None


def canonicalize_rest_path(path: str) -> str:
    """Reject traversal/encoding tricks; keep only clean /rest/ paths."""
    normalized = urllib.parse.unquote(str(path)).strip()
    if (
        not normalized.startswith("/rest/")
        or ".." in normalized
        or "//" in normalized
        or "?" in normalized
        or "#" in normalized
        or " " in normalized
    ):
        raise RouterOSError(f"invalid REST path: {path!r}")
    return normalized


def build_routeros_read_request(path: str, arguments: dict[str, Any]) -> tuple[str, str, Any | None]:
    proplist = get_routeros_proplist(arguments)
    query_words = get_routeros_query_words(arguments)
    if proplist is None and query_words is None:
        return "GET", canonicalize_rest_path(path), None

    normalized_path = canonicalize_rest_path(path.rstrip("/"))
    if normalized_path.endswith("/print"):
        print_path = normalized_path
    else:
        print_path = f"{normalized_path}/print"

    payload: dict[str, Any] = {}
    if proplist is not None:
        payload[".proplist"] = proplist
    if query_words is not None:
        payload[".query"] = query_words
    return "POST", print_path, payload


def build_routeros_command_payload(arguments: dict[str, Any], field_map: dict[str, str]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for source_key, target_key in field_map.items():
        value = arguments.get(source_key)
        if value is None:
            continue
        payload[target_key] = normalize_scalar(value)
    return payload


def catalog_search_tool() -> Tool:
    return Tool(
        name="catalog_search",
        description="Search the RouterOS endpoint catalog by substring; returns callable get_<name> aliases and their /rest paths.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Substring matched against catalog names and paths (e.g. 'wireguard', 'route')."}
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
    )


def safe_status_tool() -> Tool:
    return Tool(
        name="safe_status",
        description="List pending apply_safe operations and their rollback state.",
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )


@server.list_tools()
async def list_tools() -> list[Tool]:
    tools = [
        query_tool("get_containers", "List RouterOS containers with optional client-side filters."),
        query_tool("get_queue_simple", "List simple queues with optional client-side filters."),
        query_tool("get_queue_tree", "List queue tree entries with optional client-side filters."),
        query_tool("get_queue_types", "List queue types with optional client-side filters."),
        query_tool("get_ppp_secrets", "List PPP secrets with optional client-side filters."),
        query_tool("get_ppp_active", "List active PPP sessions with optional client-side filters."),
        query_tool("get_ppp_profiles", "List PPP profiles with optional client-side filters."),
        query_tool("get_dhcp_leases", "List DHCP leases with optional client-side filters."),
        query_tool("get_dhcp_servers", "List DHCP servers with optional client-side filters."),
        query_tool("get_dhcp_networks", "List DHCP server network definitions with optional client-side filters."),
        query_tool("get_ip_pools", "List IP pools with optional client-side filters."),
        query_tool("get_vrf", "List VRF definitions with optional client-side filters."),
        query_tool("get_files", "List RouterOS files and directories with optional client-side filters."),
        query_tool("get_ipsec_policies", "List IPsec policies with optional client-side filters."),
        query_tool("get_ipsec_peers", "List IPsec peers with optional client-side filters."),
        query_tool("get_ipsec_identities", "List IPsec identities with optional client-side filters."),
        query_tool("get_hotspot_servers", "List Hotspot servers with optional client-side filters."),
        query_tool("get_hotspot_users", "List Hotspot users with optional client-side filters."),
        query_tool("get_hotspot_active", "List active Hotspot sessions with optional client-side filters."),
        query_tool("get_hotspot_profiles", "List Hotspot server profiles with optional client-side filters."),
        query_tool("get_hotspot_user_profiles", "List Hotspot user profiles with optional client-side filters."),
        query_tool("get_firewall_connections", "List firewall connections with optional client-side filters."),
        query_tool("get_filter_rules", "List firewall filter rules with optional client-side filters."),
        query_tool("get_raw_rules", "List firewall raw rules with optional client-side filters."),
        query_tool("get_nat_rules", "List NAT rules with optional client-side filters."),
        query_tool("get_mangle_rules", "List mangle rules with optional client-side filters."),
        query_tool("get_routes", "List routes with optional client-side filters."),
        query_tool("get_routing_rules", "List routing rules with optional client-side filters."),
        query_tool("get_routing_tables", "List routing tables with optional client-side filters."),
        query_tool("get_interfaces", "List interfaces with optional client-side filters."),
        query_tool("get_interface_lists", "List interface lists with optional client-side filters."),
        query_tool("get_bridges", "List bridge interfaces with optional client-side filters."),
        query_tool("get_bridge_ports", "List bridge ports with optional client-side filters."),
        query_tool("get_vlan_interfaces", "List VLAN interfaces with optional client-side filters."),
        query_tool("get_veth_interfaces", "List veth interfaces with optional client-side filters."),
        query_tool("get_wifi_interfaces", "List Wi-Fi interfaces with optional client-side filters."),
        query_tool("get_wifi_registrations", "List Wi-Fi registration table entries with optional client-side filters."),
        query_tool("get_ip_addresses", "List IP addresses with optional client-side filters."),
        query_tool("get_arp", "List ARP entries with optional client-side filters."),
        query_tool("get_neighbors", "List neighbor entries with optional client-side filters."),
        query_tool("get_dns_cache", "List DNS cache entries with optional client-side filters."),
        query_tool("get_dns_static", "List static DNS records with optional client-side filters."),
        query_tool("get_address_lists", "List firewall address-list entries with optional client-side filters."),
        query_tool("get_wireguard_interfaces", "List WireGuard interfaces with optional client-side filters."),
        query_tool("get_netwatch", "List netwatch entries with optional client-side filters."),
        query_tool("get_scripts", "List system scripts with optional client-side filters."),
        query_tool("get_schedulers", "List schedulers with optional client-side filters."),
        query_tool("get_wireguard_peers", "List WireGuard peers with optional client-side filters."),
        Tool(
            name="get_dns",
            description="Get RouterOS DNS configuration.",
            inputSchema={"type": "object", "properties": {}},
        ),
        query_tool("get_ip_services", "List RouterOS IP services with optional client-side filters."),
        Tool(
            name="get_system_identity",
            description="Get RouterOS system identity.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="get_system_clock",
            description="Get RouterOS system clock settings.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="get_system_ntp_client",
            description="Get RouterOS NTP client state.",
            inputSchema={"type": "object", "properties": {}},
        ),
        query_tool("get_system_package", "List RouterOS installed and available packages with optional client-side filters."),
        Tool(
            name="get_system_routerboard",
            description="Get RouterBOARD metadata and firmware versions.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="get_system_health",
            description="Get RouterOS system health summary.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="get_system_logging",
            description="List RouterOS system logging rules with optional client-side filters.",
            inputSchema={"type": "object", "properties": query_properties()},
        ),
        Tool(
            name="get_system_resource",
            description="Get RouterOS system resource summary.",
            inputSchema={"type": "object", "properties": {}},
        ),
        query_tool("get_users", "List RouterOS users with optional client-side filters."),
        query_tool("get_user_groups", "List RouterOS user groups with optional client-side filters."),
        Tool(
            name="get_logs",
            description="List router log entries. Supports limit, contains, fields, sort_by plus log-oriented filters.",
            inputSchema={
                "type": "object",
                "properties": {
                    **query_properties(),
                    "since": {
                        "type": "string",
                        "description": "Keep log entries with time >= this RouterOS timestamp string.",
                    },
                    "topics": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Keep entries whose topics string contains all of these fragments.",
                    },
                },
            },
        ),
        Tool(
            name="run_ping",
            description="Run a bounded RouterOS ping diagnostic via POST /rest/ping.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "count": {"type": "integer", "minimum": 1},
                    "interface": {"type": "string"},
                    "src_address": {"type": "string"},
                    "vrf": {"type": "string"},
                },
                "required": ["address"],
            },
        ),
        Tool(
            name="run_traceroute",
            description="Run a bounded RouterOS traceroute diagnostic via POST /rest/tool/traceroute.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "count": {"type": "integer", "minimum": 1},
                    "interface": {"type": "string"},
                    "src_address": {"type": "string"},
                    "use_dns": {"type": "boolean"},
                    "vrf": {"type": "string"},
                    "max_hops": {"type": "integer", "minimum": 1},
                },
                "required": ["address"],
            },
        ),
        Tool(
            name="run_fetch",
            description="Run a bounded RouterOS fetch diagnostic with as-value output and no file writes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "http_method": {"type": "string", "enum": ["GET", "HEAD"]},
                    "output": {"type": "string", "enum": ["user", "user-with-headers"]},
                    "address": {"type": "string"},
                    "host": {"type": "string"},
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="run_wifi_monitor",
            description="Run a one-shot RouterOS Wi-Fi monitor for an interface via POST /rest/interface/wifi/monitor.",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string"},
                },
                "required": ["interface"],
            },
        ),
        Tool(
            name="read_file",
            description="Read a RouterOS file chunk via /rest/file/read and return base64 plus text preview when possible.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "chunk_size": {"type": "integer", "minimum": 1},
                },
                "required": ["file"],
            },
        ),
        Tool(
            name="download_file",
            description="Download a RouterOS file to a local path on this computer using repeated /rest/file/read chunks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "local_path": {"type": "string"},
                    "chunk_size": {"type": "integer", "minimum": 1, "maximum": 32768},
                    "overwrite": {"type": "boolean", "description": "Replace an existing local file (default: refuse)."},
                },
                "required": ["file", "local_path"],
            },
        ),
        Tool(
            name="create_file",
            description="Create a small RouterOS text file via PUT /rest/file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "contents": {"type": "string"},
                },
                "required": ["name", "contents"],
            },
        ),
        Tool(
            name="update_file",
            description="Update contents of a small RouterOS text file via POST /rest/file/set.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "contents": {"type": "string"},
                },
                "required": ["name", "contents"],
            },
        ),
        Tool(
            name="rename_file",
            description="Rename a RouterOS file or directory via POST /rest/file/set.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "new_name": {"type": "string"},
                },
                "required": ["name", "new_name"],
            },
        ),
        Tool(
            name="delete_file",
            description="Delete a RouterOS file or directory via POST /rest/file/remove.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "confirm": {
                        "type": "boolean",
                        "description": "Set true only after the user explicitly approves this deletion.",
                    },
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="upload_file",
            description="Upload a small local UTF-8 text file to RouterOS via PUT /rest/file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "local_path": {"type": "string"},
                    "remote_name": {"type": "string"},
                },
                "required": ["local_path", "remote_name"],
            },
        ),
        Tool(
            name="save_backup",
            description="Create a RouterOS binary backup file on the router via POST /rest/system/backup/save.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "password": {"type": "string"},
                    "dont_encrypt": {"type": "boolean"},
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="save_export",
            description="Create a RouterOS text export file on the router via POST /rest/export.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "compact": {"type": "boolean"},
                    "terse": {"type": "boolean"},
                    "verbose": {"type": "boolean"},
                    "show_sensitive": {"type": "boolean"},
                },
                "required": ["file"],
            },
        ),
        Tool(
            name="routeros_get",
            description="GET a RouterOS REST path starting with /rest/, then optionally filter the result.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    **query_properties(),
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="routeros_write",
            description="Mutate a whitelisted RouterOS REST path using POST, PUT, PATCH or DELETE.",
            inputSchema={
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "enum": ["POST", "PUT", "PATCH", "DELETE"],
                    },
                    "path": {"type": "string"},
                    "data": {"type": ["object", "array", "string", "number", "boolean", "null"]},
                    "confirm": {
                        "type": "boolean",
                        "description": "Set true only after the user explicitly approves a destructive/disruptive operation.",
                    },
                },
                "required": ["method", "path"],
            },
        ),
        Tool(
            name="patch_resource_by_id",
            description="PATCH a whitelisted RouterOS collection item by .id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "collection_path": {"type": "string"},
                    "item_id": {"type": "string"},
                    "data": {"type": "object"},
                    "confirm": {
                        "type": "boolean",
                        "description": "Set true only after the user explicitly approves a destructive/disruptive operation.",
                    },
                },
                "required": ["collection_path", "item_id", "data"],
            },
        ),
        Tool(
            name="flush_dns_cache",
            description="Flush MikroTik DNS cache.",
            inputSchema={
                "type": "object",
                "properties": {
                    "confirm": {
                        "type": "boolean",
                        "description": "Set true only after the user explicitly approves this operation.",
                    }
                },
            },
        ),
        Tool(
            name="run_script",
            description="Run RouterOS system script by name using /rest/system/script/run.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "confirm": {
                        "type": "boolean",
                        "description": "Set true only after the user explicitly approves running this script.",
                    },
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="container_shell",
            description="Execute a shell command inside a RouterOS container by .id or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "container": {"type": "string", "description": "Container name or .id"},
                    "cmd": {"type": "string"},
                },
                "required": ["container", "cmd"],
            },
        ),
        Tool(
            name="apply_safe",
            description="Apply a whitelisted mutation with automatic timed rollback. Snapshots the target, applies the change, and auto-reverts after window_seconds unless commit_safe is called. Rollback runs via an on-router scheduler when possible, else an in-process timer.",
            inputSchema={
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["PUT", "PATCH", "DELETE"]},
                    "path": {"type": "string", "description": "Item path for PATCH/DELETE (/rest/<coll>/<.id>), collection path for PUT"},
                    "data": {"type": "object"},
                    "window_seconds": {"type": "integer", "minimum": 10, "default": 60},
                },
                "required": ["method", "path"],
            },
        ),
        Tool(
            name="routeros_batch",
            description="Run up to 16 RouterOS GETs in parallel. Each request accepts the same filters as routeros_get (where/fields/limit/compact).",
            inputSchema={
                "type": "object",
                "properties": {
                    "requests": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}, **query_properties()},
                            "required": ["path"],
                        },
                        "maxItems": 16,
                    }
                },
                "required": ["requests"],
            },
        ),
        Tool(
            name="describe_path",
            description="Introspect a REST path: fetch up to N items and report their field names plus a sample. Useful before writing filters.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "sample": {"type": "integer", "minimum": 0, "maximum": 5, "default": 1},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="interface_traffic",
            description="Measure live rx/tx bitrate and packet rate of an interface over a short sampling window (0.5-10s).",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "seconds": {"type": "number", "minimum": 0.5, "maximum": 10, "default": 2},
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="routeros_watch",
            description="Sample a REST path N times with an interval; optionally report per-item deltas of numeric fields (diff=true). Useful for watching counters, traffic, registrations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "count": {"type": "integer", "minimum": 2, "maximum": 10, "default": 3},
                    "interval": {"type": "number", "minimum": 0.5, "maximum": 30, "default": 2},
                    "diff": {"type": "boolean", "description": "Report field deltas between first and last sample instead of raw samples."},
                    **query_properties(),
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="run_script_inline",
            description="Create a temporary RouterOS script, execute it, and remove it. Requires a policy-capable user (yolo mode); always asks for confirmation in careful mode.",
            inputSchema={
                "type": "object",
                "properties": {
                    "script": {"type": "string"},
                    "confirm": {"type": "boolean", "description": "Set true only after the user explicitly approves executing this script."},
                },
                "required": ["script"],
            },
        ),
        Tool(
            name="commit_safe",
            description="Commit a change made via apply_safe, cancelling its automatic rollback.",
            inputSchema={
                "type": "object",
                "properties": {"pending_id": {"type": "string"}},
                "required": ["pending_id"],
            },
        ),
    ]
    # Hide rarely-used get_* tools from the schema to save context tokens; they remain
    # callable (call_tool falls back to READ_ENDPOINTS) and reachable via routeros_get.
    tools.append(catalog_search_tool())
    tools.append(safe_status_tool())
    tools = [t for t in tools if not t.name.startswith("get_") or t.name in LISTED_GET_TOOLS]
    for tool in tools:
        tool.annotations = annotate_tool(tool.name)
    if client.mode == "readonly":
        tools = [t for t in tools if t.annotations and t.annotations.readOnlyHint]
    return tools


def annotate_tool(name: str) -> ToolAnnotations:
    if name in READONLY_TOOLS or name.startswith("get_"):
        return ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    destructive = name in DESTRUCTIVE_TOOLS
    return ToolAnnotations(readOnlyHint=False, destructiveHint=destructive, idempotentHint=False, openWorldHint=True)


@server.list_resources()
async def list_resources() -> list[Resource]:
    resources = [
        Resource(
            name="router_status",
            title="Router Status",
            uri=RESOURCE_STATUS_URI,
            description="Compact system summary: identity, version, uptime, load, containers.",
            mimeType="application/json",
        ),
        Resource(
            name="router_containers_status",
            title="Router Containers Status",
            uri=RESOURCE_CONTAINERS_STATUS_URI,
            description="Compact status summary for RouterOS containers.",
            mimeType="application/json",
        ),
        Resource(
            name="router_default_routes",
            title="Router Default Routes",
            uri=RESOURCE_DEFAULT_ROUTES_URI,
            description="Read-only view of active default routes.",
            mimeType="application/json",
        ),
        Resource(
            name="router_wifi_clients",
            title="Router Wi-Fi Clients",
            uri=RESOURCE_WIFI_CLIENTS_URI,
            description="High-level snapshot of currently authorized Wi-Fi clients.",
            mimeType="application/json",
        ),
        Resource(
            name="router_dhcp_active",
            title="Router DHCP Active Leases",
            uri=RESOURCE_DHCP_ACTIVE_URI,
            description="High-level snapshot of currently active DHCP leases.",
            mimeType="application/json",
        ),
        Resource(
            name="router_dns_status",
            title="Router DNS Status",
            uri=RESOURCE_DNS_STATUS_URI,
            description="DNS configuration and cache/static summary for quick health checks.",
            mimeType="application/json",
        ),
    ]
    return resources


@server.list_resource_templates()
async def list_resource_templates() -> list[ResourceTemplate]:
    return [
        ResourceTemplate(
            name="router_rest_path",
            title="Router REST Path",
            uriTemplate=RESOURCE_REST_TEMPLATE,
            description="Read any RouterOS REST path by template, for example routeros://rest/ip/firewall/mangle.",
            mimeType="application/json",
        ),
    ]


async def build_status_resource() -> dict[str, Any]:
    resource = await run_request("GET", "/rest/system/resource")
    routerboard = await run_request("GET", "/rest/system/routerboard")
    identity = await run_request("GET", "/rest/system/identity")
    try:
        containers_raw = await run_request("GET", READ_ENDPOINTS["containers"])
    except RouterOSError:
        containers_raw = None
    containers = containers_raw if isinstance(containers_raw, list) else []
    return {
        "identity": identity.get("name"),
        "version": resource.get("version"),
        "board": routerboard.get("model"),
        "uptime": resource.get("uptime"),
        "cpu-load": resource.get("cpu-load"),
        "free-memory": resource.get("free-memory"),
        "free-hdd-space": resource.get("free-hdd-space"),
        "containers": (
            [
                {"name": c.get("name"), "running": c.get("running"), "interface": c.get("interface")}
                for c in containers
            ]
            if containers_raw is not None
            else None
        ),
    }


async def build_containers_status_resource() -> list[dict[str, Any]]:
    containers_raw = await run_request("GET", READ_ENDPOINTS["containers"])
    containers = containers_raw if isinstance(containers_raw, list) else []
    items: list[dict[str, Any]] = []
    for item in containers:
        items.append(
            {
                ".id": item.get(".id"),
                "name": item.get("name"),
                "running": item.get("running"),
                "start-on-boot": item.get("start-on-boot"),
                "interface": item.get("interface"),
                "memory-current": item.get("memory-current"),
            }
        )
    return sorted(items, key=lambda item: normalize_scalar(item.get("name", "")))


async def build_default_routes_resource() -> list[dict[str, Any]]:
    routes_raw = await run_request("GET", READ_ENDPOINTS["routes"])
    routes = routes_raw if isinstance(routes_raw, list) else []
    filtered = [
        item
        for item in routes
        if normalize_scalar(item.get("dst-address", "")) in {"0.0.0.0/0", "::/0"}
    ]
    items: list[dict[str, Any]] = []
    for item in filtered:
        items.append(
            {
                ".id": item.get(".id"),
                "dst-address": item.get("dst-address"),
                "routing-table": item.get("routing-table"),
                "gateway": item.get("gateway"),
                "active": item.get("active"),
                "distance": item.get("distance"),
                "comment": item.get("comment"),
                "dynamic": item.get("dynamic"),
            }
        )
    return sorted(
        items,
        key=lambda item: (
            normalize_scalar(item.get("routing-table", "")),
            normalize_scalar(item.get("distance", "")),
        ),
    )


async def build_wifi_clients_resource() -> dict[str, Any]:
    registrations_raw = await run_request("GET", READ_ENDPOINTS["wifi_registrations"])
    registrations = registrations_raw if isinstance(registrations_raw, list) else []
    clients: list[dict[str, Any]] = []
    for item in registrations:
        if not is_truthy_routeros(item.get("authorized")):
            continue
        clients.append(
            {
                "interface": item.get("interface"),
                "ssid": item.get("ssid"),
                "mac-address": item.get("mac-address"),
                "signal": item.get("signal"),
                "uptime": item.get("uptime"),
                "last-activity": item.get("last-activity"),
                "rx-rate": item.get("rx-rate"),
                "tx-rate": item.get("tx-rate"),
            }
        )
    clients = sorted(
        clients,
        key=lambda item: (
            normalize_scalar(item.get("interface", "")),
            normalize_scalar(item.get("mac-address", "")),
        ),
    )
    return {
        "count": len(clients),
        "clients": clients,
    }


async def build_dhcp_active_resource() -> dict[str, Any]:
    leases_raw = await run_request("GET", READ_ENDPOINTS["dhcp_leases"])
    leases = leases_raw if isinstance(leases_raw, list) else []
    active: list[dict[str, Any]] = []
    for item in leases:
        if normalize_scalar(item.get("status", "")).lower() != "bound":
            continue
        active.append(
            {
                "address": item.get("active-address") or item.get("address"),
                "host-name": item.get("host-name"),
                "mac-address": item.get("active-mac-address") or item.get("mac-address"),
                "server": item.get("active-server") or item.get("server"),
                "expires-after": item.get("expires-after"),
                "last-seen": item.get("last-seen"),
            }
        )
    active = sorted(active, key=lambda item: normalize_scalar(item.get("address", "")))
    return {
        "count": len(active),
        "leases": active,
    }


async def build_dns_status_resource() -> dict[str, Any]:
    dns_raw = await run_request("GET", READ_ENDPOINTS["dns"])
    cache_raw = await run_request("GET", READ_ENDPOINTS["dns_cache"])
    static_raw = await run_request("GET", READ_ENDPOINTS["dns_static"])

    dns = dns_raw if isinstance(dns_raw, dict) else {}
    cache = cache_raw if isinstance(cache_raw, list) else []
    static = static_raw if isinstance(static_raw, list) else []
    static_names = sorted(
        [normalize_scalar(item.get("name", "")) for item in static if item.get("name")],
    )
    return {
        "config": {
            "servers": dns.get("servers"),
            "dynamic-servers": dns.get("dynamic-servers"),
            "allow-remote-requests": dns.get("allow-remote-requests"),
            "use-doh-server": dns.get("use-doh-server"),
            "verify-doh-cert": dns.get("verify-doh-cert"),
            "cache-size": dns.get("cache-size"),
            "cache-used": dns.get("cache-used"),
            "vrf": dns.get("vrf"),
        },
        "summary": {
            "cache-entry-count": len(cache),
            "static-entry-count": len(static),
        },
        "static-names": static_names[:10],
    }


@server.read_resource()
async def read_resource(uri: Any) -> Iterable[ReadResourceItem]:
    normalized = normalize_router_uri(str(uri))
    if normalized == RESOURCE_STATUS_URI:
        payload = await build_status_resource()
        return [ReadResourceItem(content=dump(payload))]
    if normalized == RESOURCE_CONTAINERS_STATUS_URI:
        payload = await build_containers_status_resource()
        return [ReadResourceItem(content=dump(payload))]
    if normalized == RESOURCE_DEFAULT_ROUTES_URI:
        payload = await build_default_routes_resource()
        return [ReadResourceItem(content=dump(payload))]
    if normalized == RESOURCE_WIFI_CLIENTS_URI:
        payload = await build_wifi_clients_resource()
        return [ReadResourceItem(content=dump(payload))]
    if normalized == RESOURCE_DHCP_ACTIVE_URI:
        payload = await build_dhcp_active_resource()
        return [ReadResourceItem(content=dump(payload))]
    if normalized == RESOURCE_DNS_STATUS_URI:
        payload = await build_dns_status_resource()
        return [ReadResourceItem(content=dump(payload))]
    if normalized.startswith("routeros://rest/"):
        path_value = normalized[len("routeros://rest/") :]
        rest_path = template_path_to_rest(path_value)
        payload = await run_request("GET", rest_path)
        meta = {"rest_path": rest_path}
        return [ReadResourceItem(content=dump(payload), meta=meta)]

    raise RouterOSError(f"unsupported resource uri: {uri}")


async def handle_read(path: str, arguments: dict[str, Any]) -> list[TextContent]:
    method, request_path, data = build_routeros_read_request(path, arguments)
    payload = await run_request(method, request_path, data)
    return view_result(payload, arguments)


async def handle_batch(arguments: dict[str, Any]) -> list[TextContent]:
    requests = arguments.get("requests") or []
    if not requests:
        raise RouterOSError("requests array is required")
    if len(requests) > 16:
        raise RouterOSError("too many requests in one batch (max 16)")

    async def run_one(request: dict[str, Any]) -> Any:
        path = str(request["path"])
        method, request_path, data = build_routeros_read_request(path, request)
        payload = await run_request(method, request_path, data)
        return apply_view(payload, request)

    results = await asyncio.gather(*[run_one(r) for r in requests], return_exceptions=True)
    rendered = []
    for request, result in zip(requests, results):
        if isinstance(result, Exception):
            rendered.append({"path": request.get("path"), "ok": False, "error": str(result)})
        else:
            rendered.append({"path": request["path"], "ok": True, "result": result})
    return view_result(rendered, arguments)


async def handle_describe_path(arguments: dict[str, Any]) -> list[TextContent]:
    path = arguments["path"]
    sample_args = {"limit": int(arguments.get("sample", 1))}
    method, request_path, data = build_routeros_read_request(path, sample_args)
    payload = await run_request(method, request_path, data)
    items = payload if isinstance(payload, list) else [payload]
    fields = sorted({key for item in items if isinstance(item, dict) for key in item})
    return one_text(
        {
            "path": path,
            "item_count_in_sample": len(items),
            "fields": fields,
            "sample": items[: int(arguments.get("sample", 1))],
        }
    )


async def handle_interface_traffic(arguments: dict[str, Any]) -> list[TextContent]:
    name = str(arguments["name"])
    seconds = float(arguments.get("seconds", 2))
    seconds = max(0.5, min(seconds, 10))

    rows = await run_request("GET", "/rest/interface")
    match = [r for r in rows if r.get("name") == name]
    if not match:
        raise RouterOSError(f"interface not found: {name}")
    first = match[0]
    rx0 = int(first.get("rx-byte", 0) or 0)
    tx0 = int(first.get("tx-byte", 0) or 0)
    rxp0 = int(first.get("rx-packet", 0) or 0)
    txp0 = int(first.get("tx-packet", 0) or 0)

    await asyncio.sleep(seconds)

    rows = await run_request("GET", "/rest/interface")
    second = [r for r in rows if r.get("name") == name][0]
    rx1 = int(second.get("rx-byte", 0) or 0)
    tx1 = int(second.get("tx-byte", 0) or 0)
    rxp1 = int(second.get("rx-packet", 0) or 0)
    txp1 = int(second.get("tx-packet", 0) or 0)

    return one_text(
        {
            "interface": name,
            "seconds": seconds,
            "rx_bps": int((rx1 - rx0) * 8 / seconds),
            "tx_bps": int((tx1 - tx0) * 8 / seconds),
            "rx_pps": int((rxp1 - rxp0) / seconds),
            "tx_pps": int((txp1 - txp0) / seconds),
            "running": second.get("running"),
            "disabled": second.get("disabled"),
        }
    )


async def handle_run_script_inline(arguments: dict[str, Any]) -> list[TextContent]:
    """Create a temp RouterOS script, run it, remove it. Requires policy-capable creds."""
    script = str(arguments["script"])
    if not arguments.get("confirm"):
        gated = await gate_confirmation(
            "POST",
            "/rest/system/script",
            {"run_inline": script},
            "run_script_inline",
            arguments,
        )
        if gated is not None:
            return gated
    name = f"mcp-inline-{secrets.token_hex(4)}"
    created = await run_request("PUT", "/rest/system/script", {"name": name, "source": script, "owner": client.username})
    script_id = created.get(".id") if isinstance(created, dict) else None
    try:
        result = await run_request("POST", "/rest/system/script/run", {"number": name})
        return one_text(success_payload("POST", "/rest/system/script/run", result, script=name, inline=True))
    finally:
        if script_id:
            try:
                await run_request("DELETE", f"/rest/system/script/{script_id}")
            except RouterOSError:
                pass


async def handle_watch(arguments: dict[str, Any]) -> list[TextContent]:
    path = str(arguments["path"])
    samples = int(arguments.get("count", 3))
    interval = float(arguments.get("interval", 2))
    samples = max(2, min(samples, 10))
    interval = max(0.5, min(interval, 30))
    want_diff = bool(arguments.get("diff", False))

    series: list[Any] = []
    for i in range(samples):
        method, request_path, data = build_routeros_read_request(path, arguments)
        payload = await run_request(method, request_path, data)
        series.append(apply_view(payload, arguments))
        if i + 1 < samples:
            await asyncio.sleep(interval)

    if not want_diff:
        return view_result({"samples": series, "interval_seconds": interval}, arguments)

    def index_items(items: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(items, list):
            return {}
        out: dict[str, dict[str, Any]] = {}
        for pos, item in enumerate(items):
            key = item.get(".id") or item.get("name") or f"#{pos}"
            out[key] = item
        return out

    first, last = index_items(series[0]), index_items(series[-1])
    deltas = []
    for key, end in last.items():
        start = first.get(key)
        if start is None:
            deltas.append({"key": key, "new": True})
            continue
        numeric_delta = {}
        for field, val in end.items():
            a, b = start.get(field), val
            try:
                fa, fb = float(a), float(b)
            except (TypeError, ValueError):
                if a != b:
                    numeric_delta[field] = {"from": a, "to": b}
                continue
            if fb != fa:
                numeric_delta[field] = fb - fa
        if numeric_delta:
            deltas.append({"key": key, "delta": numeric_delta})
    return view_result({"diff_between_first_and_last": deltas, "elapsed_seconds": interval * (samples - 1)}, arguments)


async def handle_logs(arguments: dict[str, Any]) -> list[TextContent]:
    method, request_path, data = build_routeros_read_request(READ_ENDPOINTS["logs"], arguments)
    payload = await run_request(method, request_path, data)
    if not isinstance(payload, list):
        return one_text(payload)

    since = arguments.get("since")
    topics = arguments.get("topics") or []
    filtered = payload
    if since:
        filtered = [item for item in filtered if normalize_scalar(item.get("time", "")) >= normalize_scalar(since)]
    if topics:
        lowered_topics = [str(topic).lower() for topic in topics]
        filtered = [
            item
            for item in filtered
            if all(topic in normalize_scalar(item.get("topics", "")).lower() for topic in lowered_topics)
        ]

    return view_result(filtered, arguments)


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
    arguments = arguments or {}
    if name == "catalog_search":
        query = str(arguments.get("query", "")).lower()
        hits = sorted(
            f"{n} ({p})"
            for n, p in READ_ENDPOINTS.items()
            if query in n.lower() or query in p.lower()
        )
        return one_text({"query": query, "matches": hits[:40], "callable_as": "get_<name>"})
    if name == "safe_status":
        from .safe_apply import SAFE_OPS
        import time as _t
        now = _t.monotonic()
        # записи с armed_dealine в прошлом — откат уже сработал или отменён
        stale = [t for t, op in SAFE_OPS.items() if op.get("deadline") and now > op["deadline"]]
        for t in stale:
            SAFE_OPS.pop(t, None)
        view = {
            token: {k: v for k, v in op.items() if k != "task" and not callable(v)}
            for token, op in SAFE_OPS.items()
        }
        return one_text({"mode": client.mode, "pending": view})
    try:
        if client.mode == "readonly" and not (
            name in READONLY_TOOLS
            or name.startswith("get_")
            or name in ("routeros_get", "routeros_batch", "describe_path", "routeros_watch", "interface_traffic", "catalog_search", "safe_status")
        ):
            raise RouterOSError(f"tool '{name}' is not available in readonly mode")
        if name == "get_containers":
            return await handle_read(READ_ENDPOINTS["containers"], arguments)
        if name == "get_queue_simple":
            return await handle_read(READ_ENDPOINTS["queue_simple"], arguments)
        if name == "get_queue_tree":
            return await handle_read(READ_ENDPOINTS["queue_tree"], arguments)
        if name == "get_queue_types":
            return await handle_read(READ_ENDPOINTS["queue_type"], arguments)
        if name == "get_ppp_secrets":
            return await handle_read(READ_ENDPOINTS["ppp_secrets"], arguments)
        if name == "get_ppp_active":
            return await handle_read(READ_ENDPOINTS["ppp_active"], arguments)
        if name == "get_ppp_profiles":
            return await handle_read(READ_ENDPOINTS["ppp_profiles"], arguments)
        if name == "get_dhcp_leases":
            return await handle_read(READ_ENDPOINTS["dhcp_leases"], arguments)
        if name == "get_dhcp_servers":
            return await handle_read(READ_ENDPOINTS["dhcp_servers"], arguments)
        if name == "get_dhcp_networks":
            return await handle_read(READ_ENDPOINTS["dhcp_networks"], arguments)
        if name == "get_ip_pools":
            return await handle_read(READ_ENDPOINTS["ip_pools"], arguments)
        if name == "get_vrf":
            return await handle_read(READ_ENDPOINTS["vrf"], arguments)
        if name == "get_files":
            return await handle_read(READ_ENDPOINTS["files"], arguments)
        if name == "get_ipsec_policies":
            return await handle_read(READ_ENDPOINTS["ipsec_policies"], arguments)
        if name == "get_ipsec_peers":
            return await handle_read(READ_ENDPOINTS["ipsec_peers"], arguments)
        if name == "get_ipsec_identities":
            return await handle_read(READ_ENDPOINTS["ipsec_identities"], arguments)
        if name == "get_hotspot_servers":
            return await handle_read(READ_ENDPOINTS["hotspot_servers"], arguments)
        if name == "get_hotspot_users":
            return await handle_read(READ_ENDPOINTS["hotspot_users"], arguments)
        if name == "get_hotspot_active":
            return await handle_read(READ_ENDPOINTS["hotspot_active"], arguments)
        if name == "get_hotspot_profiles":
            return await handle_read(READ_ENDPOINTS["hotspot_profiles"], arguments)
        if name == "get_hotspot_user_profiles":
            return await handle_read(READ_ENDPOINTS["hotspot_user_profiles"], arguments)
        if name == "get_firewall_connections":
            return await handle_read(READ_ENDPOINTS["firewall_connections"], arguments)
        if name == "get_filter_rules":
            return await handle_read(READ_ENDPOINTS["filter_rules"], arguments)
        if name == "get_raw_rules":
            return await handle_read(READ_ENDPOINTS["raw_rules"], arguments)
        if name == "get_nat_rules":
            return await handle_read(READ_ENDPOINTS["nat_rules"], arguments)
        if name == "get_mangle_rules":
            return await handle_read(READ_ENDPOINTS["mangle_rules"], arguments)
        if name == "get_routes":
            return await handle_read(READ_ENDPOINTS["routes"], arguments)
        if name == "get_routing_rules":
            return await handle_read(READ_ENDPOINTS["routing_rules"], arguments)
        if name == "get_routing_tables":
            return await handle_read(READ_ENDPOINTS["routing_tables"], arguments)
        if name == "get_interfaces":
            return await handle_read(READ_ENDPOINTS["interfaces"], arguments)
        if name == "get_interface_lists":
            return await handle_read(READ_ENDPOINTS["interface_lists"], arguments)
        if name == "get_bridges":
            return await handle_read(READ_ENDPOINTS["bridges"], arguments)
        if name == "get_bridge_ports":
            return await handle_read(READ_ENDPOINTS["bridge_ports"], arguments)
        if name == "get_vlan_interfaces":
            return await handle_read(READ_ENDPOINTS["vlan_interfaces"], arguments)
        if name == "get_veth_interfaces":
            return await handle_read(READ_ENDPOINTS["veth_interfaces"], arguments)
        if name == "get_wifi_interfaces":
            return await handle_read(READ_ENDPOINTS["wifi_interfaces"], arguments)
        if name == "get_wifi_registrations":
            return await handle_read(READ_ENDPOINTS["wifi_registrations"], arguments)
        if name == "get_ip_addresses":
            return await handle_read(READ_ENDPOINTS["ip_addresses"], arguments)
        if name == "get_arp":
            return await handle_read(READ_ENDPOINTS["arp"], arguments)
        if name == "get_neighbors":
            return await handle_read(READ_ENDPOINTS["neighbors"], arguments)
        if name == "get_dns_cache":
            return await handle_read(READ_ENDPOINTS["dns_cache"], arguments)
        if name == "get_dns_static":
            return await handle_read(READ_ENDPOINTS["dns_static"], arguments)
        if name == "get_address_lists":
            return await handle_read(READ_ENDPOINTS["address_lists"], arguments)
        if name == "get_wireguard_interfaces":
            return await handle_read(READ_ENDPOINTS["wireguard_interfaces"], arguments)
        if name == "get_netwatch":
            return await handle_read(READ_ENDPOINTS["netwatch"], arguments)
        if name == "get_scripts":
            return await handle_read(READ_ENDPOINTS["scripts"], arguments)
        if name == "get_schedulers":
            return await handle_read(READ_ENDPOINTS["schedulers"], arguments)
        if name == "get_wireguard_peers":
            return await handle_read(READ_ENDPOINTS["wireguard_peers"], arguments)
        if name == "get_dns":
            return one_text(await run_request("GET", READ_ENDPOINTS["dns"]))
        if name == "get_ip_services":
            return await handle_read(READ_ENDPOINTS["ip_services"], arguments)
        if name == "get_system_identity":
            return one_text(await run_request("GET", READ_ENDPOINTS["system_identity"]))
        if name == "get_system_clock":
            return one_text(await run_request("GET", READ_ENDPOINTS["system_clock"]))
        if name == "get_system_ntp_client":
            return one_text(await run_request("GET", READ_ENDPOINTS["system_ntp_client"]))
        if name == "get_system_package":
            return await handle_read(READ_ENDPOINTS["system_package"], arguments)
        if name == "get_system_routerboard":
            return one_text(await run_request("GET", READ_ENDPOINTS["system_routerboard"]))
        if name == "get_system_health":
            return one_text(await run_request("GET", READ_ENDPOINTS["system_health"]))
        if name == "get_system_logging":
            return await handle_read(READ_ENDPOINTS["system_logging"], arguments)
        if name == "get_system_resource":
            return one_text(await run_request("GET", READ_ENDPOINTS["system_resource"]))
        if name == "get_users":
            return await handle_read(READ_ENDPOINTS["users"], arguments)
        if name == "get_user_groups":
            return await handle_read(READ_ENDPOINTS["user_groups"], arguments)
        if name == "get_logs":
            return await handle_logs(arguments)
        if name == "run_ping":
            path = "/rest/ping"
            payload = build_routeros_command_payload(
                arguments,
                {
                    "address": "address",
                    "count": "count",
                    "interface": "interface",
                    "src_address": "src-address",
                    "vrf": "vrf",
                },
            )
            result = await run_request("POST", path, payload)
            return one_text(success_payload("POST", path, result, command=payload))
        if name == "run_traceroute":
            path = "/rest/tool/traceroute"
            payload = build_routeros_command_payload(
                arguments,
                {
                    "address": "address",
                    "count": "count",
                    "interface": "interface",
                    "src_address": "src-address",
                    "vrf": "vrf",
                    "use_dns": "use-dns",
                    "max_hops": "max-hops",
                },
            )
            result = await run_request("POST", path, payload)
            return one_text(success_payload("POST", path, result, command=payload))
        if name == "run_fetch":
            path = "/rest/tool/fetch"
            payload = {
                "url": arguments["url"],
                "http-method": str(arguments.get("http_method", "GET")).lower(),
                "output": arguments.get("output", "user"),
                "as-value": "",
            }
            if arguments.get("address") is not None:
                payload["address"] = arguments["address"]
            if arguments.get("host") is not None:
                payload["host"] = arguments["host"]
            result = await run_request("POST", path, payload)
            compacted = compact_payload(result)
            return one_text(success_payload("POST", path, compacted, command=payload))
        if name == "run_wifi_monitor":
            path = "/rest/interface/wifi/monitor"
            payload = {
                "numbers": arguments["interface"],
                "once": "",
            }
            result = await run_request("POST", path, payload)
            return one_text(success_payload("POST", path, result, command=payload))
        if name == "read_file":
            file_path = arguments["file"]
            offset = int(arguments.get("offset", 0))
            chunk_size = int(arguments.get("chunk_size", 32768))
            data = await read_router_file_chunk(file_path, offset, chunk_size)
            text_preview = None
            try:
                text_preview = data.decode("utf-8")
            except UnicodeDecodeError:
                pass
            return one_text(
                success_payload(
                    "POST",
                    "/rest/file/read",
                    {
                        "file": file_path,
                        "offset": offset,
                        "chunk-size": chunk_size,
                        "bytes": len(data),
                        "data_base64": base64.b64encode(data).decode("ascii"),
                        "text": text_preview,
                    },
                )
            )
        if name == "download_file":
            file_path = arguments["file"]
            chunk_size = int(arguments.get("chunk_size", 32768))
            destination = resolve_local_path(arguments["local_path"], must_exist=False, overwrite=bool(arguments.get("overwrite")))
            data = await read_router_file_all(file_path, chunk_size)
            if len(data) > MAX_LOCAL_FILE_BYTES:
                raise RouterOSError("downloaded payload exceeds local size cap")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            return one_text(
                success_payload(
                    "POST",
                    "/rest/file/read",
                    {
                        "file": file_path,
                        "local_path": str(destination),
                        "bytes": len(data),
                    },
                )
            )
        if name == "create_file":
            path = "/rest/file"
            payload = {
                "name": arguments["name"],
                "type": "file",
                "contents": arguments["contents"],
            }
            result = await run_request("PUT", path, payload)
            return one_text(success_payload("PUT", path, result, command=payload))
        if name == "update_file":
            path = "/rest/file/set"
            payload = {
                "numbers": arguments["name"],
                "contents": arguments["contents"],
            }
            result = await run_request("POST", path, payload)
            return one_text(success_payload("POST", path, result, command=payload))
        if name == "rename_file":
            path = "/rest/file/set"
            payload = {
                "numbers": arguments["name"],
                "name": arguments["new_name"],
            }
            result = await run_request("POST", path, payload)
            return one_text(success_payload("POST", path, result, command=payload))
        if name == "delete_file":
            path = "/rest/file/remove"
            gated = await gate_confirmation("POST", path, {"numbers": arguments["name"]}, name, arguments)
            if gated is not None:
                return gated
            payload = {
                "numbers": arguments["name"],
            }
            result = await run_request("POST", path, payload)
            return one_text(success_payload("POST", path, result, command=payload))
        if name == "upload_file":
            local_path = resolve_local_path(arguments["local_path"], must_exist=True)
            data = local_path.read_bytes()
            if len(data) > MAX_LOCAL_FILE_BYTES:
                raise RouterOSError("local file exceeds size cap (8 MiB)")
            contents = ensure_router_file_text_payload(data)
            path = "/rest/file"
            payload = {
                "name": arguments["remote_name"],
                "type": "file",
                "contents": contents,
            }
            result = await run_request("PUT", path, payload)
            return one_text(
                success_payload(
                    "PUT",
                    path,
                    result,
                    command={"name": arguments["remote_name"], "type": "file"},
                    local_path=str(local_path),
                    bytes=len(data),
                )
            )
        if name == "save_backup":
            path = "/rest/system/backup/save"
            payload = {"name": arguments["name"]}
            if arguments.get("password") is not None:
                payload["password"] = arguments["password"]
            if arguments.get("dont_encrypt"):
                payload["dont-encrypt"] = "yes"
            result = await run_request("POST", path, payload)
            return one_text(
                success_payload(
                    "POST",
                    path,
                    result,
                    command={"name": arguments["name"], "password_set": arguments.get("password") is not None, "dont_encrypt": bool(arguments.get("dont_encrypt"))},
                    file=ensure_router_file_suffix(arguments["name"], ".backup"),
                )
            )
        if name == "save_export":
            path = "/rest/export"
            payload = {"file": arguments["file"]}
            for option, target in (
                ("compact", "compact"),
                ("terse", "terse"),
                ("verbose", "verbose"),
                ("show_sensitive", "show-sensitive"),
            ):
                if arguments.get(option):
                    payload[target] = ""
            result = await run_request("POST", path, payload)
            return one_text(
                success_payload(
                    "POST",
                    path,
                    result,
                    command=payload,
                    file=ensure_router_file_suffix(arguments["file"], ".rsc"),
                )
            )
        if name == "routeros_get":
            return await handle_read(arguments["path"], arguments)
        if name == "routeros_write":
            method = str(arguments["method"]).upper()
            path = arguments["path"]
            if not is_mutation_path_allowed(method, path):
                raise RouterOSError(f"path is not whitelisted for mutation: {path}")
            gated = await gate_confirmation(method, path, arguments.get("data"), name, arguments)
            if gated is not None:
                return gated
            result = await run_request(method, path, arguments.get("data"))
            return one_text(success_payload(method, path, result))
        if name == "patch_resource_by_id":
            collection_path = arguments["collection_path"].rstrip("/")
            if collection_path not in PATCHABLE_COLLECTIONS:
                raise RouterOSError(f"collection is not patchable: {collection_path}")
            path = f"{collection_path}/{arguments['item_id']}"
            gated = await gate_confirmation("PATCH", path, arguments["data"], name, arguments)
            if gated is not None:
                return gated
            result = await run_request("PATCH", path, arguments["data"])
            return one_text(success_payload("PATCH", path, result))
        if name == "flush_dns_cache":
            path = "/rest/ip/dns/cache/flush"
            gated = await gate_confirmation("POST", path, {}, name, arguments)
            if gated is not None:
                return gated
            result = await run_request("POST", path, {})
            return one_text(success_payload("POST", path, result))
        if name == "run_script":
            path = "/rest/system/script/run"
            gated = await gate_confirmation("POST", path, {"number": arguments["name"]}, name, arguments)
            if gated is not None:
                return gated
            result = await run_request("POST", path, {"number": arguments["name"]})
            return one_text(success_payload("POST", path, result, script=arguments["name"]))
        if name == "container_shell":
            if not client.enable_container_shell:
                raise RouterOSError("container shell is disabled (set MIKROTIK_ENABLE_CONTAINER_SHELL=1)")
            gated = await gate_confirmation("POST", "/rest/container/shell", {"cmd": arguments.get("cmd")}, name, arguments)
            if gated is not None:
                return gated
            container_id, container_name = await resolve_container_id(arguments["container"])
            path = "/rest/container/shell"
            result = await run_request("POST", path, {".id": container_id, "cmd": arguments["cmd"]})
            note = None
            if result == []:
                note = "RouterOS returned an empty container-shell payload; verify via a follow-up read when stdout matters."
            return one_text(
                success_payload(
                    "POST",
                    path,
                    result,
                    container=container_name,
                    container_id=container_id,
                    cmd=arguments["cmd"],
                    note=note,
                )
            )
        if name == "apply_safe":
            return await handle_apply_safe(arguments)
        if name == "commit_safe":
            return await handle_commit_safe(arguments)
        if name == "routeros_batch":
            return await handle_batch(arguments)
        if name == "routeros_watch":
            return await handle_watch(arguments)
        if name == "run_script_inline":
            return await handle_run_script_inline(arguments)
        if name == "describe_path":
            return await handle_describe_path(arguments)
        if name == "interface_traffic":
            return await handle_interface_traffic(arguments)
        if name.startswith("get_") and name[4:] in READ_ENDPOINTS:
            return await handle_read(READ_ENDPOINTS[name[4:]], arguments)
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except RouterOSError as exc:
        return [TextContent(type="text", text=f"RouterOS error: {exc}")]
    except Exception as exc:
        return [TextContent(type="text", text=f"Unexpected error: {exc}")]


async def run_server() -> None:
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
