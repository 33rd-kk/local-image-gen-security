"""ligsp against fake servers on this computer and fake model folders."""

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

from ligsp import __main__ as cli
from ligsp.models import model_checks
from ligsp.results import FAIL, PASS, WARN
from ligsp.transport import RefusedRequest, Transport

# A second loopback address stands in for "this computer's LAN address": a
# server bound to 127.0.0.1 does not answer on it, one bound to 0.0.0.0 does.
# macOS has only 127.0.0.1 on its loopback interface.
OTHER_ADDRESS = "127.0.0.2"
needs_second_loopback = pytest.mark.skipif(sys.platform == "darwin", reason="macOS has no 127.0.0.2")


def make_handler(kind: str, *, cors: bool = False, check_host: bool = False, pairing: bool = False, manager: bool = False,
                 version: str = "0.39.2", manager_version: str = "V4.2.2", settings: object = None,
                 multiuser: bool = False, setup_required: bool = False, token: bool = True):
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
                return self._send(200, {"system": {"comfyui_version": version, "argv": ["main.py", "--secret-flag"]}, "devices": []})
            if kind == "comfyui" and self.path == "/extensions":
                return self._send(200, ["/extensions/core/a.js", "/extensions/core/b.js", "/extensions/private-pack/x.js", "/extensions/other-pack/y.js"])
            if kind == "comfyui" and manager and self.path == "/v2/manager/version":
                return self._send(200, manager_version)
            if kind == "latentry" and self.path == "/api/settings" and settings is not None:
                return self._send(200, settings)
            if kind == "latentry" and self.path == "/api/pair":
                local = self.client_address[0] == "127.0.0.1" and host == "127.0.0.1"
                return self._send(200, {"local": True} if local or not pairing else {"paired": False})
            if kind == "invokeai" and self.path == "/api/v1/app/version":
                return self._send(200, {"version": "6.14.2"})
            if kind == "invokeai" and self.path == "/api/v2/custom_nodes/":
                if multiuser:
                    return self._send(401, {"detail": "Authentication required"})
                return self._send(200, {"node_packs": [{"name": "pack", "path": "C:/Users/someone/nodes/pack"}], "custom_nodes_path": "C:/Users/someone/nodes"})
            if kind == "invokeai" and self.path == "/api/v1/auth/status":
                return self._send(200, {"setup_required": setup_required, "multiuser_enabled": multiuser, "strict_password_checking": False,
                                        "admin_email": "owner@example.invalid" if setup_required else None})
            if kind in ("engine", "diffusers") and self.path == "/api/health":
                return self._send(200, {"status": "ok", **({"engine": "latentry", "version": "0.6.1"} if kind == "engine" else {})})
            if kind == "engine" and self.path == "/api/models":
                if token:
                    return self._send(401, {"detail": "token"})
                return self._send(200, {"models_dir": "C:/Users/someone/models-folder", "models": []})
            if kind == "swarmui" and self.path == "/Text2Image":
                if multiuser:  # accounts on: off to the login page
                    self.send_response(302)
                    self.send_header("Location", "/Login")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                page = b"<html><head><title>Generate - SwarmUI - Local</title></head></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return None
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
    from ligsp.net import with_host

    assert with_host("http://127.0.0.1:8188/system_stats", "fd00::5") == "http://[fd00::5]:8188/system_stats"
    assert with_host("http://127.0.0.1:8188/x", "192.168.1.5") == "http://192.168.1.5:8188/x"


def test_own_addresses_are_never_loopback_or_link_local() -> None:
    import ipaddress

    from ligsp.net import own_lan_addresses

    for address in own_lan_addresses():
        ip = ipaddress.ip_address(address)
        assert not (ip.is_loopback or ip.is_link_local or ip.is_unspecified)


# ── Private files ────────────────────────────────────────────────────────

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows access lists")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")


def test_a_folder_is_searched_for_known_private_files(tmp_path: Path) -> None:
    from ligsp.files import file_checks, private_files

    (tmp_path / "latentry.settings.json").write_text("{}")
    (tmp_path / "notes.txt").write_text("not private")
    assert [p.name for p in private_files(tmp_path)] == ["latentry.settings.json"]
    assert [r.status for r in file_checks(tmp_path / "empty-folder-that-is-not-there")] == ["unknown"]


@posix_only
def test_posix_modes(tmp_path: Path) -> None:
    from ligsp.files import file_checks

    secret = tmp_path / "latentry.pairing-key"
    secret.write_text("k")
    secret.chmod(0o600)
    assert [r.status for r in file_checks(secret)] == [PASS]
    secret.chmod(0o644)
    result = file_checks(secret)[0]
    assert result.status == FAIL and "every user" in result.evidence[0]


@windows_only
def test_windows_access_lists(tmp_path: Path) -> None:
    import os
    import subprocess

    from ligsp import winacl
    from ligsp.files import file_checks

    icacls = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
    me = winacl.current_user_sid()
    assert me and me.startswith("S-1-5-")
    secret = tmp_path / "latentry.pairing-key"
    secret.write_text("k")
    # By SID, so the test does not depend on the system's language or the computer's name.
    subprocess.run([icacls, str(secret), "/inheritance:r", "/grant:r", f"*{me}:F", "*S-1-5-18:F"], check=True, capture_output=True)
    first = file_checks(secret)
    assert [r.status for r in first] == [PASS], [(r.status, r.evidence) for r in first]
    assert {sid for sid, _ in winacl.readers(str(secret))} <= {me, winacl.SYSTEM, winacl.ADMINISTRATORS}
    # OWNER RIGHTS lets in whoever owns the file: here that is this account (or, elevated, Administrators).
    subprocess.run([icacls, str(secret), "/grant", "*S-1-3-4:R"], check=True, capture_output=True)
    assert winacl.OWNER_RIGHTS not in {sid for sid, _ in winacl.readers(str(secret))}
    assert [r.status for r in file_checks(secret)] == [PASS]
    subprocess.run([icacls, str(secret), "/grant", "*S-1-5-32-545:R"], check=True, capture_output=True)  # BUILTIN\Users
    assert "S-1-5-32-545" in {sid for sid, _ in winacl.readers(str(secret))}
    result = file_checks(secret)[0]
    assert result.status == FAIL, (result.status, result.evidence)
    assert result.evidence[0].startswith("latentry.pairing-key: also readable by ")


# ── Round 4: fixed endpoints, disguised pickles, plain HTTP on the network ──


def test_only_the_known_read_only_endpoints_are_asked() -> None:
    transport = Transport()
    transport.allow_url("http://127.0.0.1:8188/comfy/")
    # A GET that acts (ComfyUI-Manager has some) is refused like a POST.
    for path in ("/snapshot/remove", "/comfy/snapshot/remove", "/comfy/system_stats?x=1", "/system_stats/../snapshot/remove"):
        with pytest.raises(RefusedRequest):
            transport.request("GET", "http://127.0.0.1:8188" + path)
    assert transport.sent == []
    # Under the named path, and at the root, the known endpoints are asked
    # (port 9 is closed, so nothing answers, but nothing is refused either).
    for path in ("/comfy/system_stats", "/system_stats", "/comfy/", "/"):
        assert transport.request("GET", "http://127.0.0.1:9" + path, timeout=0.5) is None
    assert len(transport.sent) == 4


def test_a_pickle_named_safetensors_fails(tmp_path: Path) -> None:
    (tmp_path / "zip.safetensors").write_bytes(b"PK\x03\x04" + b"\0" * 60)
    (tmp_path / "bare.safetensors").write_bytes(b"\x80\x04" + b"\0" * 60)
    results = model_checks(tmp_path)
    assert results[0].status == FAIL
    assert sorted(results[0].evidence) == ["bare.safetensors", "zip.safetensors"]


def test_a_real_header_whose_length_starts_like_a_pickle_is_ok(tmp_path: Path) -> None:
    # A header of 0x0280 bytes: its length starts with 0x80 0x02, as a protocol 2 pickle does.
    body = json.dumps({"w": {"dtype": "F16", "shape": [1], "data_offsets": [0, 2]}, "__metadata__": {"pad": "x" * 560}}).encode()
    body = body + b" " * (0x0280 - len(body))
    (tmp_path / "real.safetensors").write_bytes(struct.pack("<Q", len(body)) + body + b"\0\0")
    assert [r.status for r in model_checks(tmp_path)] == [PASS]


@needs_second_loopback
def test_plain_http_on_the_network_is_said() -> None:
    with server("latentry", bind="0.0.0.0", pairing=True, check_host=True) as (url, _):
        target = cli.check_server(Transport(), url, [OTHER_ADDRESS])
    assert any("unencrypted" in item for item in by_id(target, "NET-1")[0].evidence)
    assert not any("unencrypted" in item for item in by_id(target, "NET-2")[0].evidence)  # said once, under NET-1


# ── The repository itself ────────────────────────────────────────────────


def test_no_control_characters_in_the_repository() -> None:
    """A NUL written by a scripted edit once broke a merge in a sister project."""
    root = Path(__file__).resolve().parents[2]
    bad = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in (".git", ".ruff_cache", "__pycache__", "private") or part.endswith(".egg-info") for part in path.parts):
            continue
        if path.suffix.lower() not in (".py", ".md", ".toml", ".yml", ".yaml", ".txt", ""):
            continue
        data = path.read_bytes()
        if any(b < 32 and b not in (9, 10, 13) for b in data):
            bad.append(path.relative_to(root).as_posix())
    assert bad == []


# ── OPS-3: published advisories ─────────────────────────────────────────


def test_version_ranges_in_both_comma_styles() -> None:
    from ligsp.advisories import affects, parse_version

    assert parse_version("V4.2.2") == (4, 2, 2) and parse_version("0.39.2") == (0, 39, 2) and parse_version("found") is None
    assert affects("< 0.28.0", (0, 27, 9)) and not affects("< 0.28.0", (0, 28)) and not affects("< 0.28.0", (0, 39, 2))
    assert affects(">= 1.0, < 2.0", (1, 5)) and not affects(">= 1.0, < 2.0", (2, 0))  # comma: both
    either = "< 3.39.2, 4.0.0 - 4.0.4"  # comma: one or the other
    assert affects(either, (3, 39, 1)) and affects(either, (4, 0, 3))
    assert not affects(either, (3, 39, 2)) and not affects(either, (4, 0, 5)) and not affects(either, (4, 2, 2))
    assert affects("not a range", (1,)) is None


def test_an_old_comfyui_and_manager_fail_ops_3_with_their_advisories() -> None:
    with server("comfyui", manager=True, version="0.27.0", manager_version="V4.0.3") as (url, _):
        target = cli.check_server(Transport(), url, [])
    ops = by_id(target, "OPS-3")
    comfy = next(r for r in ops if r.title.startswith("ComfyUI 0.27.0"))
    manager = next(r for r in ops if r.title.startswith("ComfyUI-Manager 4.0.3"))
    assert comfy.status == FAIL and sum("GHSA-" in item for item in comfy.evidence) == 4
    assert manager.status == FAIL and any("GHSA-562r-8445-54r2" in item for item in manager.evidence)
    assert any(item.startswith("advisories as of ") for item in comfy.evidence)
    assert any("frontend" in item for item in comfy.evidence) and not any("frontend" in item for item in manager.evidence)


def test_current_versions_pass_ops_3_and_say_how_old_the_table_is() -> None:
    from ligsp.advisory_data import DATA_AS_OF

    with server("comfyui", manager=True) as (url, _):
        target = cli.check_server(Transport(), url, [])
    ops = by_id(target, "OPS-3")
    assert [r.status for r in ops] == [PASS, PASS]
    assert all(DATA_AS_OF in r.title and "checker's data" in r.title for r in ops)
    comfy = next(r for r in ops if r.title.startswith("ComfyUI 0."))
    assert comfy.evidence == ["Covers ComfyUI core only: its frontend package is versioned separately, and its advisories are not checked"]


def test_the_checker_fetches_no_advisories() -> None:
    source = (Path(__file__).resolve().parents[1] / "src" / "ligsp" / "advisories.py").read_text(encoding="utf-8")
    assert "urllib" not in source and "http" not in source.replace("https://", "")


# ── --follow ─────────────────────────────────────────────────────────────


def test_follow_checks_a_hubs_backends_and_keeps_only_their_urls() -> None:
    with server("comfyui") as (comfy_url, comfy_handler):
        settings = {
            "editable": True,
            "backends": [
                {"id": "comfy", "kind": "comfyui", "url": comfy_url, "workflowsDir": "C:/Users/someone/secret-workflows", "token": "settings"},
                {"id": "odd", "url": "file:///etc/passwd"},
            ],
            "gallery": {"dirs": ["C:/Users/someone/private-pictures"]},
        }
        with server("latentry", settings=settings) as (hub_url, _):
            transport = Transport()
            found: list[str] = []
            hub = cli.check_server(transport, hub_url, [], found)
            assert found == [comfy_url]  # the file: URL is dropped
            backend = cli.check_server(transport, found[0], [], None, hub_url)
    assert hub.kind == "latentry" and backend.kind == "comfyui" and backend.via == hub_url
    text = json.dumps([hub.to_json(), backend.to_json()])
    assert "secret-workflows" not in text and "private-pictures" not in text
    assert {method for method, _ in transport.sent} <= {"GET", "HEAD", "OPTIONS"}
    assert any(path == "/system_stats" for _, path, _ in comfy_handler.seen)


def test_follow_from_the_command_line_checks_the_backend_once(capsys) -> None:
    with server("comfyui") as (comfy_url, _):
        settings = {"backends": [{"url": comfy_url}, {"url": comfy_url + "/"}]}
        with server("latentry", settings=settings) as (hub_url, _):
            cli.main(["check", hub_url, comfy_url, "--follow", "--json", "-"])
    data = json.loads(capsys.readouterr().out)
    assert [t["kind"] for t in data["targets"]] == ["latentry", "comfyui"]  # named and followed: checked once


def test_a_hub_that_will_not_show_its_backends_is_unknown() -> None:
    with server("latentry", settings={"editable": False, "reason": "Only from this computer"}) as (hub_url, _):
        found: list[str] = []
        hub = cli.check_server(Transport(), hub_url, [], found)
    assert found == []
    assert [r.status for r in by_id(hub, "FOLLOW")] == ["unknown"]
    assert "Only from this computer" in by_id(hub, "FOLLOW")[0].title


def test_without_follow_the_settings_are_never_asked() -> None:
    with server("latentry", settings={"backends": []}) as (hub_url, handler):
        cli.check_server(Transport(), hub_url, [])
    assert not any(path == "/api/settings" for _, path, _ in handler.seen)


# ── More servers: InvokeAI, SwarmUI, diffusers servers, Latentry's engine ──


@needs_second_loopback
def test_invokeai_in_single_user_mode_on_the_network_fails_net_2() -> None:
    with server("invokeai", bind="0.0.0.0") as (url, _):
        target = cli.check_server(Transport(), url, [OTHER_ADDRESS])
    assert (target.kind, target.version) == ("invokeai", "6.14.2")
    assert by_id(target, "NET-2")[0].status == FAIL
    assert "invokeai.yaml" in by_id(target, "NET-1")[0].fix


@needs_second_loopback
def test_invokeai_with_accounts_passes_net_2() -> None:
    with server("invokeai", bind="0.0.0.0", multiuser=True) as (url, _):
        target = cli.check_server(Transport(), url, [OTHER_ADDRESS])
    assert by_id(target, "NET-2")[0].status == PASS
    assert by_id(target, "AUTH-1") == []


def test_invokeai_accounts_with_no_administrator_yet_are_flagged_and_the_email_is_not_kept() -> None:
    with server("invokeai", multiuser=True, setup_required=True) as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert by_id(target, "AUTH-1")[0].status == WARN
    assert "owner@example.invalid" not in json.dumps(target.to_json())


def test_latentrys_engine_needs_its_token() -> None:
    with server("engine") as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert (target.kind, target.version) == ("latentry-engine", "0.6.1")
    assert by_id(target, "BE-2")[0].status == PASS
    with server("engine", token=False) as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert by_id(target, "BE-2")[0].status == WARN
    assert "models-folder" not in json.dumps(target.to_json())
    assert by_id(target, "WEB-3") == []  # an API-only server has no page to check


@needs_second_loopback
def test_a_diffusers_server_on_the_network_is_not_judged_by_its_open_health_endpoint() -> None:
    with server("diffusers", bind="0.0.0.0") as (url, _):
        target = cli.check_server(Transport(), url, [OTHER_ADDRESS])
    assert target.kind == "diffusers"
    assert by_id(target, "NET-1")[0].status == WARN
    assert by_id(target, "NET-2")[0].status == "unknown"


def test_swarmui_is_recognised_with_and_without_accounts() -> None:
    from ligsp.net import needs_login

    with server("swarmui") as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert target.kind == "swarmui"
    with server("swarmui", multiuser=True) as (url, _):
        transport = Transport()
        transport.allow_url(url)
        from ligsp.targets import identify

        found = identify(transport, url)
    assert found.kind == "swarmui" and needs_login(found.answer)


def test_invokeais_node_pack_installer_is_ext_1_and_its_folders_are_not_kept() -> None:
    with server("invokeai") as (url, _):
        target = cli.check_server(Transport(), url, [])
    ext = by_id(target, "EXT-1")[0]
    assert ext.status == WARN and ext.evidence == ["1 node pack(s) installed"]
    assert "someone" not in json.dumps(target.to_json())
    with server("invokeai", multiuser=True) as (url, _):
        target = cli.check_server(Transport(), url, [])
    assert by_id(target, "EXT-1")[0].status == PASS
