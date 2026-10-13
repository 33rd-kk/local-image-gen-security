"""profilecheck against fake servers on this computer and fake model folders."""

from __future__ import annotations

import json
import struct
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from profilecheck import __main__ as cli
from profilecheck.models import model_checks
from profilecheck.results import FAIL, PASS, WARN
from profilecheck.transport import RefusedRequest, Transport

# A second loopback address stands in for "this computer's LAN address": a
# server bound to 127.0.0.1 does not answer on it, one bound to 0.0.0.0 does.
# macOS has only 127.0.0.1 on its loopback interface.
OTHER_ADDRESS = "127.0.0.2"
needs_second_loopback = pytest.mark.skipif(sys.platform == "darwin", reason="macOS has no 127.0.0.2")


def make_handler(kind: str, *, cors: bool = False, check_host: bool = False, pairing: bool = False, manager: bool = False):
    class Handler(BaseHTTPRequestHandler):
        seen: ClassVar[list[tuple[str, str, str]]] = []

        def log_message(self, *args) -> None:
            pass

        def _send(self, status: int, body: object, headers: dict[str, str] | None = None) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if cors:
                self.send_header("Access-Control-Allow-Origin", "*")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def _answer(self) -> None:
            Handler.seen.append((self.command, self.path, self.headers.get("Host", "")))
            host = self.headers.get("Host", "").split(":")[0]
            if check_host and host not in ("127.0.0.1", "localhost", OTHER_ADDRESS):
                return self._send(403, {"error": "Forbidden host"})
            if kind == "comfyui" and self.path == "/system_stats":
                return self._send(200, {"system": {"comfyui_version": "0.39.2", "argv": ["main.py", "--secret-flag"]}, "devices": []})
            if kind == "comfyui" and self.path == "/extensions":
                return self._send(200, ["/extensions/core/a.js", "/extensions/core/b.js", "/extensions/private-pack/x.js", "/extensions/other-pack/y.js"])
            if kind == "comfyui" and manager and self.path == "/v2/manager/version":
                return self._send(200, "V4.2.2")
            if kind == "latentry" and self.path == "/api/pair":
                local = self.client_address[0] == "127.0.0.1" and host == "127.0.0.1"
                return self._send(200, {"local": True} if local or not pairing else {"paired": False})
            if self.path == "/":
                return self._send(200, {"page": True}, {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin"})
            return self._send(404, {"error": "not found"})

        do_GET = _answer
        do_HEAD = _answer
        do_OPTIONS = _answer

        def do_POST(self) -> None:  # the checker must never get here
            Handler.seen.append(("POST", self.path, ""))
            self._send(500, {"error": "POST"})

    return Handler


@contextmanager
def server(kind: str, bind: str = "127.0.0.1", **options):
    handler = make_handler(kind, **options)
    httpd = ThreadingHTTPServer((bind, 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", handler
    finally:
        httpd.shutdown()
        httpd.server_close()


def by_id(target, requirement: str):
    return [r for r in target.results if r.id == requirement]


# ── The transport's rules ────────────────────────────────────────────────


def test_only_read_only_methods_to_named_hosts() -> None:
    transport = Transport({"127.0.0.1"})
    with pytest.raises(RefusedRequest):
        transport.request("POST", "http://127.0.0.1:1/")
    with pytest.raises(RefusedRequest):
        transport.request("GET", "http://example.com/")
    with pytest.raises(RefusedRequest):
        transport.request("GET", "file:///etc/passwd")
    assert transport.sent == []


def test_a_full_check_sends_only_read_only_requests_to_named_hosts() -> None:
    with server("comfyui", cors=True) as (url, handler):
        transport = Transport()
        cli.check_server(transport, url, [OTHER_ADDRESS])
    assert transport.sent, "it sent something"
    assert {method for method, _ in transport.sent} <= {"GET", "HEAD", "OPTIONS"}
    assert all(sent_url.startswith(("http://127.0.0.1:", f"http://{OTHER_ADDRESS}:")) for _, sent_url in transport.sent)
    assert all(method != "POST" for method, _, _ in handler.seen)


# ── Servers ──────────────────────────────────────────────────────────────


def test_comfyui_is_identified_and_its_command_line_is_not_kept() -> None:
    with server("comfyui") as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert (target.kind, target.version) == ("comfyui", "0.39.2")
    assert "--secret-flag" not in json.dumps(target.to_json())


def test_a_server_on_loopback_only_passes_net_1() -> None:
    with server("comfyui", bind="127.0.0.1") as (url, _):
        target = cli.check_server(Transport(), url, [OTHER_ADDRESS])
    assert by_id(target, "NET-1")[0].status == PASS
    assert by_id(target, "NET-2")[0].status == PASS


@needs_second_loopback
def test_a_server_open_to_the_network_without_login_fails_net_1_and_net_2() -> None:
    with server("comfyui", bind="0.0.0.0") as (url, _):
        target = cli.check_server(Transport(), url, [OTHER_ADDRESS])
    assert by_id(target, "NET-1")[0].status == FAIL
    assert by_id(target, "NET-2")[0].status == FAIL
    assert "--listen" in by_id(target, "NET-1")[0].fix


@needs_second_loopback
def test_a_hub_that_asks_for_pairing_from_the_network_only_warns() -> None:
    with server("latentry", bind="0.0.0.0", pairing=True, check_host=True) as (url, _):
        target = cli.check_server(Transport(), url, [OTHER_ADDRESS])
    assert target.kind == "latentry"
    assert by_id(target, "NET-1")[0].status == WARN
    assert by_id(target, "NET-2")[0].status == PASS


def test_cors_for_any_site_fails_web_1() -> None:
    with server("comfyui", cors=True) as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert by_id(target, "WEB-1")[0].status == FAIL
    with server("comfyui") as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert by_id(target, "WEB-1")[0].status == PASS


def test_any_host_name_warns_web_2_and_a_host_check_passes() -> None:
    with server("comfyui") as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert by_id(target, "WEB-2")[0].status == WARN
    with server("comfyui", check_host=True) as (url, handler):
        target = cli.check_server(Transport(), url, [])
    assert by_id(target, "WEB-2")[0].status == PASS
    assert any(host == "rebind.example.invalid" for _, _, host in handler.seen)


def test_a_server_that_is_not_there_is_unknown() -> None:
    target = cli.check_server(Transport(), "http://127.0.0.1:9", [])
    assert [r.status for r in target.results] == ["unknown"]


# ── Model folders ────────────────────────────────────────────────────────


def safetensors(path: Path, good: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = json.dumps({"w": {"dtype": "F16", "shape": [1], "data_offsets": [0, 2]}}).encode()
    path.write_bytes(struct.pack("<Q", len(header) if good else 10**9) + header + b"\0\0")


def test_pickle_files_alone_fail_and_beside_safetensors_warn(tmp_path: Path) -> None:
    safetensors(tmp_path / "good.safetensors")
    (tmp_path / "old").mkdir()
    (tmp_path / "old" / "model.ckpt").write_bytes(b"x")
    safetensors(tmp_path / "vae" / "diffusion_pytorch_model.safetensors")
    (tmp_path / "vae" / "diffusion_pytorch_model.bin").write_bytes(b"x")
    results = model_checks(tmp_path)
    fails = [r for r in results if r.status == FAIL]
    warns = [r for r in results if r.status == WARN]
    assert fails and fails[0].evidence == ["old/model.ckpt"]
    assert warns and warns[0].evidence == ["vae/diffusion_pytorch_model.bin"]


def test_clean_folder_passes_and_a_broken_header_warns(tmp_path: Path) -> None:
    safetensors(tmp_path / "a.safetensors")
    assert [r.status for r in model_checks(tmp_path)] == [PASS]
    safetensors(tmp_path / "b.safetensors", good=False)
    results = model_checks(tmp_path)
    assert [r.status for r in results] == [PASS, WARN]
    assert results[1].evidence == ["b.safetensors"]


# ── The command ──────────────────────────────────────────────────────────


def test_no_target_is_a_usage_error(capsys) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main(["check"])
    assert stopped.value.code == 2
    assert "8188" in capsys.readouterr().err


def test_exit_code_and_redacted_json(tmp_path: Path, capsys) -> None:
    (tmp_path / "x.pt").write_bytes(b"x")
    with server("comfyui") as (url, _):
        port = url.rsplit(":", 1)[1]
        code = cli.main(["check", url, "--models", str(tmp_path), "--json", "-", "--redact"])
    out = capsys.readouterr().out
    assert code == 1  # the pickle file fails MOD-1
    data = json.loads(out)
    assert data["summary"]["fail"] >= 1
    assert str(tmp_path) not in out and str(tmp_path).replace("\\", "\\\\") not in out
    assert f":{port}" not in out


# ── Extensions and addresses ─────────────────────────────────────────────


def test_comfyui_manager_warns_and_names_of_node_packs_are_not_kept() -> None:
    with server("comfyui", manager=True) as (url, _):
        target = cli.check_server(Transport(), url, [])
    ext = by_id(target, "EXT-1")[0]
    assert ext.status == WARN
    assert "at least 2 custom node pack(s) with a web part" in ext.evidence
    assert any("4.2.2" in item for item in ext.evidence)
    assert "private-pack" not in json.dumps(target.to_json())
    with server("comfyui") as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert by_id(target, "EXT-1")[0].status == PASS


@needs_second_loopback
def test_comfyui_manager_reachable_from_the_network_fails() -> None:
    with server("comfyui", bind="0.0.0.0", manager=True) as (url, _):
        target = cli.check_server(Transport(), url, [OTHER_ADDRESS])
    assert by_id(target, "EXT-1")[0].status == FAIL


def test_ipv6_addresses_are_put_in_brackets() -> None:
    from profilecheck.net import with_host

    assert with_host("http://127.0.0.1:8188/system_stats", "fd00::5") == "http://[fd00::5]:8188/system_stats"
    assert with_host("http://127.0.0.1:8188/x", "192.168.1.5") == "http://192.168.1.5:8188/x"


def test_own_addresses_are_never_loopback_or_link_local() -> None:
    import ipaddress

    from profilecheck.net import own_lan_addresses

    for address in own_lan_addresses():
        ip = ipaddress.ip_address(address)
        assert not (ip.is_loopback or ip.is_link_local or ip.is_unspecified)
