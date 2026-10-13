"""Telling what kind of server a URL is, from endpoints that change nothing.

Only the fields named here are read from an answer; everything else in it
(ComfyUI's /system_stats also lists the server's command line, for example)
is dropped unread.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .transport import Answer, Transport

KIND_NAMES = {
    "comfyui": "ComfyUI",
    "a1111": "AUTOMATIC1111 / Forge",
    "latentry": "Latentry",
    "http": "Web server",
}


@dataclass
class Identified:
    kind: str
    version: str | None
    probe_path: str  # the read-only endpoint the other checks use
    answer: Answer | None  # its answer from the URL as given


def _json(answer: Answer | None) -> object:
    if answer is None or answer.status != 200:
        return None
    try:
        return json.loads(answer.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def identify(transport: Transport, base: str) -> Identified:
    base = base.rstrip("/")

    answer = transport.request("GET", base + "/system_stats")
    data = _json(answer)
    if isinstance(data, dict) and isinstance(data.get("system"), dict) and "comfyui_version" in data["system"]:
        version = data["system"]["comfyui_version"]
        return Identified("comfyui", version if isinstance(version, str) else None, "/system_stats", answer)

    answer = transport.request("GET", base + "/sdapi/v1/samplers")
    data = _json(answer)
    if isinstance(data, list) or (answer is not None and answer.status == 401 and "basic" in (answer.header("www-authenticate") or "").lower()):
        return Identified("a1111", None, "/sdapi/v1/samplers", answer)

    answer = transport.request("GET", base + "/api/pair")
    data = _json(answer)
    if isinstance(data, dict) and ("local" in data or "paired" in data):
        return Identified("latentry", None, "/api/pair", answer)

    return Identified("http", None, "/", transport.request("GET", base + "/"))
