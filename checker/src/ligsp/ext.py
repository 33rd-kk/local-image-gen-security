"""Extensions (EXT-1): what runs other people's code on the server, from read-only endpoints.

ComfyUI lists the browser scripts of its custom nodes at /extensions, one
folder per node pack that has a web part (so the count is a lower bound);
ComfyUI-Manager answers its version at /v2/manager/version (or the older
/manager/version). A1111 / Forge list their extensions at
/sdapi/v1/extensions. Only counts and the Manager's version are kept, never
the names.
"""

from __future__ import annotations

import json

from . import fixes
from .results import FAIL, PASS, WARN, Result
from .targets import Identified
from .transport import Transport

MANAGER_PATHS = ("/v2/manager/version", "/manager/version")


def _json(answer) -> object:
    if answer is None or answer.status != 200:
        return None
    try:
        return json.loads(answer.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def extension_checks(transport: Transport, base: str, found: Identified, reachable_from_network: bool, any_host: bool,
                     versions: dict[str, str | None] | None = None) -> list[Result]:
    """`any_host`: it answers for any host name (WEB-2), so a web page could reach it too.
    `versions` gets the version of each extension installer found (for OPS-3)."""
    base = base.rstrip("/")
    if found.kind == "comfyui":
        return _comfyui(transport, base, reachable_from_network, any_host, versions if versions is not None else {})
    if found.kind == "a1111":
        return _a1111(transport, base)
    if found.kind == "invokeai":
        return _invokeai(transport, base, reachable_from_network)
    return []


def _comfyui(transport: Transport, base: str, reachable_from_network: bool, any_host: bool, versions: dict[str, str | None]) -> list[Result]:
    results: list[Result] = []
    listed = _json(transport.request("GET", base + "/extensions"))
    packs = None
    if isinstance(listed, list):
        packs = len({item.split("/")[2] for item in listed if isinstance(item, str) and item.startswith("/extensions/") and item.count("/") >= 3} - {"core"})

    manager = None
    for path in MANAGER_PATHS:
        answer = transport.request("GET", base + path)
        if answer is not None and answer.status == 200 and len(answer.body) < 64:
            manager = answer.body.decode("utf-8", "replace").strip().strip('"') or "found"
            break

    evidence = []
    if packs is not None:
        evidence.append(f"at least {packs} custom node pack(s) with a web part")
    if manager:
        versions["comfyui-manager"] = manager
        evidence.append(f"ComfyUI-Manager {manager}")
        if reachable_from_network:
            status, title = FAIL, "An extension installer (ComfyUI-Manager) can be used from the network"
        elif any_host:
            status, title = WARN, "An extension installer (ComfyUI-Manager) is on a server that answers any host name"
        else:
            status, title = WARN, "An extension installer (ComfyUI-Manager) is part of this server"
        results.append(Result("EXT-1", status, title, evidence, fixes.WHY["EXT-1"], fixes.fix("EXT-1", "comfyui")))
    else:
        results.append(Result("EXT-1", PASS, "No extension installer answered", evidence))
    return results


def _a1111(transport: Transport, base: str) -> list[Result]:
    listed = _json(transport.request("GET", base + "/sdapi/v1/extensions"))
    if not isinstance(listed, list):
        return []
    enabled = sum(1 for item in listed if isinstance(item, dict) and item.get("enabled"))
    return [Result("EXT-1", PASS if enabled == 0 else WARN, f"{enabled} extension(s) enabled", [f"{len(listed)} installed, {enabled} enabled"],
                   fixes.WHY["EXT-1"], fixes.fix("EXT-1", "a1111"))]


def _invokeai(transport: Transport, base: str, reachable_from_network: bool) -> list[Result]:
    """InvokeAI 6 installs node packs from a git URL through its API, for its administrator.

    In single-user mode everyone is the administrator. GET /api/v2/custom_nodes/
    lists the installed packs: only how many is kept (the answer also holds
    their folders). A 401 or 403 means it asks for an administrator; a 404, a
    version without the installer.
    """
    answer = transport.request("GET", base + "/api/v2/custom_nodes/")
    if answer is None:
        return []
    if answer.status in (401, 403):
        return [Result("EXT-1", PASS, "Its node-pack installer needs an administrator's login", [f"/api/v2/custom_nodes/: {answer.status}"])]
    listed = _json(answer)
    if answer.status == 404 or not isinstance(listed, dict):
        return [Result("EXT-1", PASS, "No extension installer answered")]
    packs = listed.get("node_packs")
    evidence = [f"{len(packs)} node pack(s) installed" if isinstance(packs, list) else "an installer that installs node packs from a git URL"]
    status = FAIL if reachable_from_network else WARN
    title = "Its node-pack installer can be used " + ("from the network" if reachable_from_network else "without logging in")
    return [Result("EXT-1", status, title, evidence, fixes.WHY["EXT-1"], fixes.fix("EXT-1", "invokeai"))]
