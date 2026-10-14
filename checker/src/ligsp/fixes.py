"""Why each finding matters, and what to change, per requirement and per kind of server."""

from __future__ import annotations

WHY = {
    "NET-1": "Anyone on your network can reach it (T2). If your network is ever opened up, so can the internet (T3).",
    "NET-2": "Anyone who can reach it can use it, and on ComfyUI or A1111 that can mean running code on this computer through extensions (T2, T3).",
    "BE-1": "Prompts, pictures and any token travel unencrypted, so anyone who can watch the network can read them.",
    "WEB-1": "Any website you visit could read its answers, such as your pictures and settings, through your browser (T1).",
    "WEB-2": "A malicious site can make its own host name resolve to this computer (DNS rebinding); a server that does not check the Host header then answers the requests your browser sends for that site (T1).",
    "WEB-3": "Without these headers, other sites can frame its page, and browsers may guess file types (T1).",
    "EXT-1": "Extensions run with the server's rights, and an installer lets whoever can use the server add new code to this computer (T4, and T1-T3 when others can reach it).",
    "MOD-1": "Many files with these extensions use Python's pickle format, and loading an untrusted pickle can run any code in it (T4). The extension alone does not prove the format.",
    "BE-2": "A server without its token can be driven by any other program on this computer, and by web pages if it ever answers them (T1).",
    "AUTH-1": "Whoever reaches it first becomes its administrator, with every right over it (T2).",
    "OPS-3": "Published advisories describe how to attack these versions, so they are the first thing an attacker tries.",
    "DATA-4": "Other people who use this computer, or software running as them, can read settings, keys and tokens in these files (T6).",
}

FIXES: dict[tuple[str, str], str] = {
    ("NET-1", "comfyui"): "Start ComfyUI without --listen (or with --listen 127.0.0.1). In Comfy Desktop, set the listen address back to 127.0.0.1 in its server settings. To use it from other devices, put a hub that pairs devices, or an authenticating reverse proxy, in front of it.",
    ("NET-1", "a1111"): "Start the web UI without --listen (or remove it from COMMANDLINE_ARGS). If it must be on the network, add --api-auth and --gradio-auth, or put an authenticating reverse proxy in front.",
    ("NET-1", "latentry"): "It needs pairing from the network, which is how it is meant to work there. If you do not use it from other devices, remove LATENTRY_HOST from .env.local.",
    ("NET-1", "invokeai"): "Set host: 127.0.0.1 in invokeai.yaml (its default) and restart InvokeAI. To use it from other devices, turn on multiuser: true first, or put a hub or an authenticating reverse proxy in front.",
    ("NET-1", "swarmui"): "Set Server Configuration > Network > Host back to localhost (Data/Settings.fds) and restart SwarmUI. To use it from other devices, turn on UserAuthorization first.",
    ("NET-1", "diffusers"): "Bind the server to 127.0.0.1, and let the hub reach it there.",
    ("NET-1", "latentry-engine"): "Latentry starts its engine on 127.0.0.1; if you started it by hand with another host, start it from Latentry instead.",
    ("NET-1", "http"): "Make it listen on 127.0.0.1 only, or put an authenticating reverse proxy in front of it.",
    ("NET-2", "comfyui"): "ComfyUI has no login. Keep it on 127.0.0.1 (see NET-1), or put an authenticating reverse proxy in front of it.",
    ("NET-2", "a1111"): "Add --api-auth user:password (and --gradio-auth for the UI), or keep it on 127.0.0.1.",
    ("NET-2", "invokeai"): "Turn on multiuser: true in invokeai.yaml and create the administrator at once, or keep InvokeAI on 127.0.0.1.",
    ("NET-2", "swarmui"): "Turn on UserAuthorization > AuthorizationRequired (accounts), or set Network > RequiredAuthorization, or keep SwarmUI on localhost.",
    ("NET-2", "diffusers"): "Have the server require a token on everything but /api/health, and set the same token for it in the hub (GEN_TOKEN_<ID> in Latentry).",
    ("NET-2", "http"): "Add a login, or keep it on 127.0.0.1.",
    ("BE-1", "comfyui"): "Run it on the computer that uses it, or reach it over an encrypted tunnel or HTTPS proxy.",
    ("BE-1", "http"): "Use HTTPS, or an encrypted tunnel, to reach it.",
    ("WEB-1", "comfyui"): "Start ComfyUI without --enable-cors-header.",
    ("WEB-1", "a1111"): "Start the web UI without --cors-allow-origins (or with your own origin only).",
    ("WEB-1", "invokeai"): "Remove \"*\" (and any site you do not use) from allow_origins in invokeai.yaml.",
    ("WEB-1", "swarmui"): "Clear Server Configuration > Network > AccessControlAllowOrigin.",
    ("WEB-1", "http"): "Do not send Access-Control-Allow-Origin: * (or the requesting origin) on its API.",
    ("WEB-2", "comfyui"): "Keep it on 127.0.0.1 and put a hub in front that checks host names, or an authenticating reverse proxy that does.",
    ("WEB-2", "a1111"): "The web UI cannot check host names. Keep it on 127.0.0.1 and use it through a hub that does, or an authenticating reverse proxy that does.",
    ("WEB-2", "invokeai"): "InvokeAI does not check host names. Keep it on 127.0.0.1 and use it through a hub that does, or an authenticating reverse proxy.",
    ("WEB-2", "swarmui"): "SwarmUI does not check host names yet. Keep it on localhost and use it through a hub that does, or an authenticating reverse proxy.",
    ("WEB-2", "http"): "Check the Host header against the names it is meant to serve, and refuse others.",
    ("WEB-3", "comfyui"): "ComfyUI has no setting for these. Matters little while it stays on 127.0.0.1; a hub or reverse proxy in front of it can add them.",
    ("WEB-3", "a1111"): "The web UI has no setting for these. Matters little while it stays on 127.0.0.1; a reverse proxy in front of it can add them.",
    ("WEB-3", "invokeai"): "InvokeAI has no setting for these. Matters little while it stays on 127.0.0.1; a hub or reverse proxy in front of it can add them.",
    ("WEB-3", "swarmui"): "SwarmUI has no setting for these. Matters little while it stays on localhost; a hub or reverse proxy in front of it can add them.",
    ("WEB-3", "http"): "Send X-Frame-Options: DENY (or CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff and a Referrer-Policy.",
    ("EXT-1", "comfyui"): "Keep ComfyUI on 127.0.0.1 with nothing else able to reach it, and in ComfyUI-Manager's config.ini set security_level = strong so it cannot install from the browser. Remove node packs you do not use.",
    ("EXT-1", "invokeai"): "Turn on multiuser: true in invokeai.yaml so that only its administrator can install node packs, keep InvokeAI on 127.0.0.1, and remove packs you do not use.",
    ("EXT-1", "a1111"): "Remove extensions you do not use. Never start it with --enable-insecure-extension-access on the network.",
    ("BE-2", "latentry-engine"): "Start the engine from Latentry, which gives it a new random token each time, or set LATENTRY_ENGINE_TOKEN when you start it by hand.",
    ("AUTH-1", "invokeai"): "Open InvokeAI on this computer now and create the administrator account, before anyone else can reach it.",
    ("OPS-3", "comfyui"): "Update ComfyUI to the fixed version or later (Comfy Desktop: its update; a git install: git pull, then restart).",
    ("OPS-3", "comfyui-manager"): "Update ComfyUI-Manager to the fixed version or later from its own Update button, or with git pull in custom_nodes/ComfyUI-Manager.",
    ("DATA-4", "files"): "On Linux and macOS: chmod 600 on each file. On Windows: icacls <file> /inheritance:r /grant:r \"%USERNAME%:F\" \"*S-1-5-18:F\", or move the folder under your own profile. Latentry 0.8.1 and later does this itself the next time it starts.",
    ("MOD-1", "models"): "Replace each file with its .safetensors version from the same publisher, and delete the old one. If none exists, load it only if you trust where it came from.",
}


TOOL_NAMES = {
    "comfyui": "ComfyUI",
    "comfyui-manager": "ComfyUI-Manager",
    "a1111": "AUTOMATIC1111 / Forge",
    "latentry": "Latentry",
    "invokeai": "InvokeAI",
    "swarmui": "SwarmUI",
}


def fix(requirement: str, kind: str) -> str:
    return FIXES.get((requirement, kind)) or FIXES.get((requirement, "http"), "")
