"""Telling what kind of server a URL is, from endpoints that change nothing.

Only the fields named here are read from an answer; everything else in it
is dropped unread (ComfyUI's /system_stats also lists the server's command
line, InvokeAI's auth status can name its administrator, Latentry's engine
lists its models folder).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .transport import Answer, Transport

KIND_NAMES = {
    "comfyui": "ComfyUI",
    "a1111": "AUTOMATIC1111 / Forge",
    "latentry": "Latentry",
    "latentry-engine": "Latentry's engine",
    "invokeai": "InvokeAI",
    "swarmui": "SwarmUI",
    "diffusers": "Diffusers server",
    "http": "Web server",
}


@dataclass
class Identified:
    kind: str
    version: str | None
    probe_path: str  # the read-only endpoint the other checks use
    answer: Answer | None  # its answer from the URL as given
    # What a kind says about logging in, e.g. InvokeAI's multi-user mode.
    extra: dict = field(default_factory=dict)


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

    answer = transport.request("GET", base + "/api/v1/app/version")
    data = _json(answer)
    if isinstance(data, dict) and isinstance(data.get("version"), str) and set(data) <= {"version", "highlights"}:
        status = _json(transport.request("GET", base + "/api/v1/auth/status"))
        extra = {}
        if isinstance(status, dict):
            # Only these two; admin_email is dropped unread.
            extra = {"multiuser": status.get("multiuser_enabled") is True, "setup_required": status.get("setup_required") is True}
        return Identified("invokeai", data["version"], "/api/v1/app/version", answer, extra)

    answer = transport.request("GET", base + "/api/health")
    data = _json(answer)
    if isinstance(data, dict) and data.get("status") == "ok":
        if data.get("engine") == "latentry":
            version = data.get("version")
            # The engine's model list needs its token: whether it does is BE-2.
            models = transport.request("GET", base + "/api/models")
            return Identified("latentry-engine", version if isinstance(version, str) else None, "/api/models", models)
        return Identified("diffusers", None, "/api/health", answer)

    answer = transport.request("GET", base + "/Text2Image")
    if answer is not None and (
        (answer.status == 200 and b"- SwarmUI -" in answer.body)
        # With user accounts on, its page sends you to its login page first.
        or (300 <= answer.status < 400 and (answer.header("location") or "").rstrip("/").lower().endswith("/login"))
    ):
        return Identified("swarmui", None, "/Text2Image", answer)

    return Identified("http", None, "/", transport.request("GET", base + "/"))
