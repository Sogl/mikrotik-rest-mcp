from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch


SRC_DIR = Path(__file__).resolve().parents[1] / "src"


def load_server_module():
    os.environ.setdefault("MIKROTIK_PASSWORD", "test-password")
    os.environ.setdefault("MIKROTIK_BASE", "https://router.test")
    os.environ.setdefault("MIKROTIK_USERNAME", "tester")
    module_name = "mikrotik_rest_server_test"
    if module_name in sys.modules:
        return sys.modules[module_name]

    sys.path.insert(0, str(SRC_DIR))
    import types
    import mikrotik_rest_mcp.server as _server
    import mikrotik_rest_mcp.output as _output
    import mikrotik_rest_mcp.files as _files
    import mikrotik_rest_mcp.policy as _policy
    import mikrotik_rest_mcp.catalog as _catalog
    import mikrotik_rest_mcp.client as _client

    class _Merged(types.ModuleType):
        def __init__(self):
            super().__init__("mikrotik_rest_server_test")
            self.__dict__.update(_server.__dict__)
            self._real = _server
            self._sources = (_server, _output, _files, _policy, _catalog, _client)

        def __getattr__(self, name):
            for mod in self._sources:
                if hasattr(mod, name):
                    return getattr(mod, name)
            raise AttributeError(name)

    return _Merged()


server = load_server_module()


class QueryHelpersTest(unittest.TestCase):
    def test_read_endpoints_include_new_routeros_sections(self) -> None:
        self.assertEqual(server.READ_ENDPOINTS["queue_simple"], "/rest/queue/simple")
        self.assertEqual(server.READ_ENDPOINTS["queue_tree"], "/rest/queue/tree")
        self.assertEqual(server.READ_ENDPOINTS["queue_type"], "/rest/queue/type")
        self.assertEqual(server.READ_ENDPOINTS["ppp_secrets"], "/rest/ppp/secret")
        self.assertEqual(server.READ_ENDPOINTS["ppp_active"], "/rest/ppp/active")
        self.assertEqual(server.READ_ENDPOINTS["ppp_profiles"], "/rest/ppp/profile")
        self.assertEqual(server.READ_ENDPOINTS["vrf"], "/rest/ip/vrf")
        self.assertEqual(server.READ_ENDPOINTS["ipsec_policies"], "/rest/ip/ipsec/policy")
        self.assertEqual(server.READ_ENDPOINTS["ipsec_peers"], "/rest/ip/ipsec/peer")
        self.assertEqual(server.READ_ENDPOINTS["ipsec_identities"], "/rest/ip/ipsec/identity")
        self.assertEqual(server.READ_ENDPOINTS["hotspot_servers"], "/rest/ip/hotspot")
        self.assertEqual(server.READ_ENDPOINTS["hotspot_users"], "/rest/ip/hotspot/user")
        self.assertEqual(server.READ_ENDPOINTS["hotspot_active"], "/rest/ip/hotspot/active")
        self.assertEqual(server.READ_ENDPOINTS["hotspot_profiles"], "/rest/ip/hotspot/profile")
        self.assertEqual(server.READ_ENDPOINTS["hotspot_user_profiles"], "/rest/ip/hotspot/user/profile")
        self.assertEqual(server.READ_ENDPOINTS["users"], "/rest/user")
        self.assertEqual(server.READ_ENDPOINTS["user_groups"], "/rest/user/group")

    def test_get_routeros_proplist_accepts_string_and_array(self) -> None:
        self.assertEqual(server.get_routeros_proplist({"proplist": "name,type"}), "name,type")
        self.assertEqual(
            server.get_routeros_proplist({"proplist": ["name", " type ", "", "comment"]}),
            ["name", "type", "comment"],
        )

    def test_get_routeros_query_words_normalizes_items(self) -> None:
        self.assertEqual(
            server.get_routeros_query_words({"query_words": ["type=ether", " #| ", ""]}),
            ["type=ether", "#|"],
        )

    def test_build_routeros_read_request_defaults_to_plain_get(self) -> None:
        self.assertEqual(
            server.build_routeros_read_request("/rest/interface", {}),
            ("GET", "/rest/interface", None),
        )

    def test_build_routeros_read_request_uses_print_with_server_side_options(self) -> None:
        self.assertEqual(
            server.build_routeros_read_request(
                "/rest/interface",
                {
                    "proplist": ["name", "type"],
                    "query_words": ["type=ether", "type=vlan", "#|"],
                },
            ),
            (
                "POST",
                "/rest/interface/print",
                {
                    ".proplist": ["name", "type"],
                    ".query": ["type=ether", "type=vlan", "#|"],
                },
            ),
        )


class FilterItemsTest(unittest.TestCase):
    def test_filter_items_supports_extended_operators(self) -> None:
        items = [
            {"name": "router.lan", "status": "bound", "packets": "10"},
            {"name": "test-device.lan", "status": "waiting", "packets": "200"},
            {"name": "other.example", "status": "bound", "packets": "5"},
        ]

        filtered = server.filter_items(
            items,
            {
                "where": {
                    "name__endswith": ".lan",
                    "status__not": "waiting",
                    "packets__gt": 9,
                }
            },
        )

        self.assertEqual(filtered, [{"name": "router.lan", "status": "bound", "packets": "10"}])

    def test_filter_items_applies_contains_sort_and_limit(self) -> None:
        items = [
            {"name": "ether3", "type": "ether"},
            {"name": "vlan10", "type": "vlan"},
            {"name": "ether1", "type": "ether"},
        ]

        filtered = server.filter_items(
            items,
            {
                "contains": "ether",
                "sort_by": "name",
                "limit": 1,
            },
        )

        self.assertEqual(filtered, [{"name": "ether1", "type": "ether"}])


class FileHelpersTest(unittest.TestCase):
    def test_ensure_router_file_text_payload_rejects_large_or_binary_data(self) -> None:
        with self.assertRaises(server.RouterOSError):
            server.ensure_router_file_text_payload(b"x" * (60 * 1024 + 1))
        with self.assertRaises(server.RouterOSError):
            server.ensure_router_file_text_payload(b"\xff\xfe\x00")

    def test_ensure_router_file_suffix_appends_only_when_missing(self) -> None:
        self.assertEqual(server.ensure_router_file_suffix("backup-name", ".backup"), "backup-name.backup")
        self.assertEqual(server.ensure_router_file_suffix("backup-name.backup", ".backup"), "backup-name.backup")


class AsyncHandlersTest(unittest.IsolatedAsyncioTestCase):
    async def test_call_tool_new_read_sections_dispatch_to_handle_read(self) -> None:
        fake_handle_read = AsyncMock(return_value=[server.TextContent(type="text", text="[]")])
        with patch.object(server._real, "handle_read", fake_handle_read):
            await server.call_tool("get_queue_simple", {"limit": 1})
            await server.call_tool("get_ppp_secrets", {"limit": 1})
            await server.call_tool("get_vrf", {"limit": 1})
            await server.call_tool("get_ipsec_policies", {"limit": 1})
            await server.call_tool("get_hotspot_users", {"limit": 1})
            await server.call_tool("get_users", {"limit": 1})
            await server.call_tool("get_user_groups", {"limit": 1})

        fake_handle_read.assert_any_await(server.READ_ENDPOINTS["queue_simple"], {"limit": 1})
        fake_handle_read.assert_any_await(server.READ_ENDPOINTS["ppp_secrets"], {"limit": 1})
        fake_handle_read.assert_any_await(server.READ_ENDPOINTS["vrf"], {"limit": 1})
        fake_handle_read.assert_any_await(server.READ_ENDPOINTS["ipsec_policies"], {"limit": 1})
        fake_handle_read.assert_any_await(server.READ_ENDPOINTS["hotspot_users"], {"limit": 1})
        fake_handle_read.assert_any_await(server.READ_ENDPOINTS["users"], {"limit": 1})
        fake_handle_read.assert_any_await(server.READ_ENDPOINTS["user_groups"], {"limit": 1})

    async def test_handle_read_uses_post_print_when_query_words_present(self) -> None:
        fake_run_request = AsyncMock(return_value=[{"name": "ether1", "type": "ether"}])
        with patch.object(server._real, "run_request", fake_run_request):
            response = await server.handle_read(
                "/rest/interface",
                {
                    "proplist": ["name", "type"],
                    "query_words": ["type=ether"],
                },
            )

        fake_run_request.assert_awaited_once_with(
            "POST",
            "/rest/interface/print",
            {
                ".proplist": ["name", "type"],
                ".query": ["type=ether"],
            },
        )
        self.assertIn('"name": "ether1"', response[0].text)

    async def test_call_tool_save_backup_wraps_rest_command(self) -> None:
        fake_run_request = AsyncMock(return_value=[])
        with patch.object(server._real, "run_request", fake_run_request):
            response = await server.call_tool(
                "save_backup",
                {"name": "test-backup", "dont_encrypt": True},
            )

        fake_run_request.assert_awaited_once_with(
            "POST",
            "/rest/system/backup/save",
            {"name": "test-backup", "dont-encrypt": "yes"},
        )
        self.assertIn('"file": "test-backup.backup"', response[0].text)

    async def test_call_tool_save_export_wraps_rest_command(self) -> None:
        fake_run_request = AsyncMock(return_value=[])
        with patch.object(server._real, "run_request", fake_run_request):
            response = await server.call_tool(
                "save_export",
                {"file": "test-export", "compact": True, "show_sensitive": True},
            )

        fake_run_request.assert_awaited_once_with(
            "POST",
            "/rest/export",
            {"file": "test-export", "compact": "", "show-sensitive": ""},
        )
        self.assertIn('"file": "test-export.rsc"', response[0].text)


if __name__ == "__main__":
    unittest.main()


class SecurityBoundaryTest(unittest.TestCase):
    """Regression tests for the publication-hardening changes."""

    def test_post_action_bypass_denied(self) -> None:
        # POST /rest/<collection>/<action> must not ride the collection allowlist
        self.assertFalse(server.is_mutation_path_allowed("POST", "/rest/ip/firewall/filter/disable"))
        self.assertFalse(server.is_mutation_path_allowed("POST", "/rest/tool/e-mail/send"))

    def test_post_allowed_actions_only(self) -> None:
        self.assertTrue(server.is_mutation_path_allowed("POST", "/rest/ip/dns/cache/flush"))
        self.assertTrue(server.is_mutation_path_allowed("POST", "/rest/system/script/run"))
        self.assertTrue(server.is_mutation_path_allowed("POST", "/rest/ping"))

    def test_container_shell_flag_gated(self) -> None:
        # generic writer cannot reach container/shell unless the capability flag is on
        self.assertFalse(server.is_mutation_path_allowed("POST", "/rest/container/shell"))

    def test_patch_delete_require_item_id(self) -> None:
        self.assertTrue(server.is_mutation_path_allowed("PATCH", "/rest/ip/route/*1"))
        self.assertTrue(server.is_mutation_path_allowed("DELETE", "/rest/ip/route/*A9F"))
        # bare collection PATCH/DELETE is not allowed
        self.assertFalse(server.is_mutation_path_allowed("PATCH", "/rest/ip/route"))
        self.assertFalse(server.is_mutation_path_allowed("DELETE", "/rest/ip/route"))

    def test_put_only_on_collections(self) -> None:
        self.assertTrue(server.is_mutation_path_allowed("PUT", "/rest/ip/route"))
        self.assertFalse(server.is_mutation_path_allowed("PUT", "/rest/ip/route/*1"))

    def test_path_canonicalization(self) -> None:
        for bad in (
            "/rest/../etc/passwd",
            "/rest//ip/route",
            "/rest/ip/route?x=1",
            "/rest/ip%2Froute",
            "not-rest/path",
        ):
            try:
                allowed = server.is_mutation_path_allowed("PATCH", bad)
            except server.RouterOSError:
                allowed = False
            self.assertFalse(allowed, bad)

    def test_redact_routeros_sensitive_fields(self) -> None:
        from mikrotik_rest_mcp.output import redact_secrets
        payload = {
            "preshared-key": "abc",
            "name": "ok",
            "nested": {"encryption-key": "k", "cak": "c"},
            "items": [{"password": "p"}, {"comment": "visible"}],
        }
        out = redact_secrets(payload)
        self.assertEqual(out["preshared-key"], "***REDACTED***")
        self.assertEqual(out["nested"]["encryption-key"], "***REDACTED***")
        self.assertEqual(out["items"][0]["password"], "***REDACTED***")
        self.assertEqual(out["name"], "ok")
        self.assertEqual(out["items"][1]["comment"], "visible")

    def test_redact_embedded_json_in_error_text(self) -> None:
        from mikrotik_rest_mcp.output import redact_secrets
        text = 'HTTP 400: {"detail":"x","password":"Secret123"}'
        out = redact_secrets(text)
        self.assertNotIn("Secret123", out)
        self.assertIn("***REDACTED***", out)


class SafeApplyPolicyTest(unittest.TestCase):
    async def test_apply_safe_rejects_put(self) -> None:
        resp = await server.call_tool(
            "apply_safe",
            {
                "method": "PUT",
                "path": "/rest/ip/firewall/address-list",
                "data": {"list": "x", "address": "1.2.3.4"},
                "confirm": True,
            },
        )
        self.assertIn("PATCH/DELETE", resp[0].text)

    async def test_apply_safe_requires_item_path(self) -> None:
        resp = await server.call_tool(
            "apply_safe",
            {
                "method": "PATCH",
                "path": "/rest/ip/route",
                "data": {"comment": "x"},
                "confirm": True,
            },
        )
        self.assertIn("item path", resp[0].text)


class FileEncodingTest(unittest.TestCase):
    def test_routeros_bytes_from_string_utf8(self) -> None:
        from mikrotik_rest_mcp.files import routeros_bytes_from_string
        # latin1-safe text → latin1 encode (legacy RouterOS binary-safe path)
        self.assertEqual(routeros_bytes_from_string("abc"), b"abc")
        # unicode text (utf-8 path) → utf-8 encode, кириллица не падает
        self.assertEqual(routeros_bytes_from_string("тест"), "тест".encode("utf-8"))


class SafeApplyMechanismTest(unittest.IsolatedAsyncioTestCase):
    """Rollback machinery with a mocked REST layer — no router needed."""

    def setUp(self) -> None:
        import mikrotik_rest_mcp.safe_apply as sa
        self.sa = sa
        sa.SAFE_OPS.clear()
        self.calls: list[tuple[str, str, Any]] = []
        async def fake(method, path, data=None):
            self.calls.append((method, path, data))
            if path == "/rest/system/clock":
                return {"date": "2026-10-02", "time": "20:00:00"}
            if path == "/rest/system/scheduler" and method == "GET":
                return [{"name": "mcp-rb-tok42", ".id": "*9"}]
            if method == "DELETE":
                return {"ok": True}
            return {}
        self._patcher = patch.object(sa, "run_request", fake)
        self._patcher.start()

    def tearDown(self) -> None:
        self._patcher.stop()
        self.sa.SAFE_OPS.clear()

    async def test_register_rollback_uses_scheduler_when_writable(self) -> None:
        self.sa.SAFE_OPS["tok42"] = {"rollback": "pending"}
        mech = await self.sa.register_rollback("tok42", "/ip route", "patch", "*1", {"dst-address": "0.0.0.0/0"}, {"comment": "x"}, 60, ("PATCH", "/rest/ip/route/*1", {}))
        self.assertEqual(mech, "router-scheduler")
        sched_put = next(c for c in self.calls if c[1] == "/rest/system/scheduler")
        self.assertIn("start-date", sched_put[2])
        self.assertIn("start-time", sched_put[2])
        self.assertIn("on-event", sched_put[2])
        self.assertEqual(self.sa.SAFE_OPS["tok42"]["rollback"], "router-scheduler")

    async def test_register_rollback_falls_back_to_process_timer(self) -> None:
        async def boom(method, path, data=None):
            if "scheduler" in path:
                raise server.RouterOSError("denied")
            if path == "/rest/system/clock":
                return {"date": "2026-10-02", "time": "20:00:00"}
            return {}
        with patch.object(self.sa, "run_request", boom):
            self.sa.SAFE_OPS["tok99"] = {"rollback": "pending"}
            mech = await self.sa.register_rollback("tok99", "/ip route", "patch", "*1", {}, {"comment": "x"}, 999, ("PATCH", "/rest/ip/route/*1", {}))
        self.assertEqual(mech, "process-timer")
        task = self.sa.SAFE_OPS["tok99"].get("task")
        self.assertIsNotNone(task)
        task.cancel()

    async def test_commit_safe_removes_scheduler_and_pops(self) -> None:
        self.sa.SAFE_OPS["tok42"] = {"rollback": "router-scheduler"}
        resp = await self.sa.handle_commit_safe({"pending_id": "tok42"})
        self.assertIn('"ok": true', resp[0].text)
        self.assertNotIn("tok42", self.sa.SAFE_OPS)
        self.assertTrue(any("scheduler" in c[1] and c[0] in ("POST", "DELETE") for c in self.calls))

    async def test_commit_safe_unknown_token(self) -> None:
        resp = await self.sa.handle_commit_safe({"pending_id": "nope"})
        self.assertIn('"ok": false', resp[0].text)
        self.assertIn("unknown or expired", resp[0].text)

    async def test_commit_safe_keeps_entry_on_disarm_failure(self) -> None:
        async def fail_delete(method, path, data=None):
            if method in ("DELETE", "POST"):
                raise server.RouterOSError("HTTP 500 boom")
            if path == "/rest/system/scheduler":
                return [{"name": "mcp-rb-tok77", ".id": "*9"}]
            return {}
        with patch.object(self.sa, "run_request", fail_delete):
            self.sa.SAFE_OPS["tok77"] = {"rollback": "router-scheduler"}
            resp = await self.sa.handle_commit_safe({"pending_id": "tok77"})
        self.assertIn('"ok": false', resp[0].text)
        self.assertIn("may still fire", resp[0].text)
        self.assertIn("tok77", self.sa.SAFE_OPS)  # entry retained for retry

    async def test_apply_safe_ambiguous_transport_keeps_rollback(self) -> None:
        import json as _j
        async def flaky(method, path, data=None):
            if path == "/rest/system/clock":
                return {"date": "2026-10-02", "time": "20:00:00"}
            if method == "PATCH":
                raise server.RouterOSError("Request failed: timeout")  # не HTTP 4xx → неизвестный исход
            return {}
        with patch.object(self.sa, "run_request", flaky):
            resp = await server.call_tool("apply_safe", {
                "method": "PATCH",
                "path": "/rest/ip/route/*1",
                "data": {"comment": "x"},
                "window_seconds": 60,
                "confirm": True,
            })
        self.assertIn("rollback remains armed", resp[0].text)
        self.assertTrue(self.sa.SAFE_OPS)  # запись осталась


class ClockAndScriptTest(unittest.TestCase):
    def test_parse_router_clock_iso(self) -> None:
        from mikrotik_rest_mcp.safe_apply import parse_router_clock
        self.assertEqual(parse_router_clock({"date": "2026-10-02", "time": "20:00:00"}).year, 2026)

    def test_parse_router_clock_ros_format(self) -> None:
        from mikrotik_rest_mcp.safe_apply import parse_router_clock
        dt = parse_router_clock({"date": "oct/02/2026", "time": "20:00:00"})
        self.assertEqual((dt.year, dt.month, dt.day), (2026, 10, 2))

    def test_parse_router_clock_garbage_fails(self) -> None:
        from mikrotik_rest_mcp.safe_apply import parse_router_clock
        with self.assertRaises(server.RouterOSError):
            parse_router_clock({"date": "nonsense", "time": "xx"})

    def test_cli_value_escapes_injection(self) -> None:
        from mikrotik_rest_mcp.safe_apply import cli_value
        self.assertEqual(cli_value("a;b"), '"a;b"')
        self.assertEqual(cli_value('say "hi"'), '"say \\"hi\\""')
        self.assertEqual(cli_value("$var"), '"\\$var"')
        self.assertEqual(cli_value("line\nbreak"), '"line\\nbreak"')
        self.assertEqual(cli_value(True), "yes")
        self.assertEqual(cli_value("false"), "no")
        self.assertEqual(cli_value("42"), "42")

    def test_build_rollback_script_patch_only_changed(self) -> None:
        from mikrotik_rest_mcp.safe_apply import build_rollback_script
        script = build_rollback_script("/ip route", "patch", "*1", {"comment": "old", "disabled": "no"}, {"comment": "new"}, "mcp-rb-x")
        self.assertIn("/ip route set *1", script)
        self.assertIn('comment="old"', script)
        self.assertNotIn("disabled", script)  # только изменённые поля
        self.assertIn('scheduler remove [find name="mcp-rb-x"]', script)

    def test_build_rollback_script_delete_recreates(self) -> None:
        from mikrotik_rest_mcp.safe_apply import build_rollback_script
        script = build_rollback_script("/ip firewall address-list", "delete", "*1", {"list": "x", "address": "1.2.3.4", ".id": "*1", "dynamic": "true"}, None, "mcp-rb-x")
        self.assertIn("/ip firewall address-list add", script)
        self.assertIn('list="x"', script)
        self.assertNotIn(".id", script)
        self.assertNotIn("dynamic", script)
