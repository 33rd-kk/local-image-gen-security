"""--follow: the backends a hub is set up to use, so one command checks them too.

Latentry lists them at GET /api/settings, which answers only to the computer
it runs on and changes nothing. Of its answer only each backend's `url` is
kept; folders, model names and everything else are dropped unread. Tokens
are never in it.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from .results import UNKNOWN, Result
from .targets import Identified
from .transport import Transport


def backend_urls(transport: Transport, base: str, found: Identified) -> tuple[list[str], list[Result]]:
    """The http(s) URLs of the hub's backends, and a result when they cannot be read."""
    if found.kind != "latentry":
        return [], []
    answer = transport.request("GET", base.rstrip("/") + "/api/settings")
    if answer is None or answer.status != 200:
        status = answer.status if answer is not None else "no answer"
        return [], [Result("FOLLOW", UNKNOWN, f"Could not read the hub's backends ({status}); run the check on the computer the hub runs on")]
    try:
        data = json.loads(answer.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [], [Result("FOLLOW", UNKNOWN, "The hub's settings could not be read")]
    if not isinstance(data, dict) or not isinstance(data.get("backends"), list):
        reason = data.get("reason") if isinstance(data, dict) else None
        return [], [Result("FOLLOW", UNKNOWN, "The hub does not show its backends to this computer" + (f" ({reason})" if isinstance(reason, str) else ""))]
    urls: list[str] = []
    for backend in data["backends"]:
        url = backend.get("url") if isinstance(backend, dict) else None
        if isinstance(url, str) and urlsplit(url).scheme in ("http", "https") and urlsplit(url).hostname and url not in urls:
            urls.append(url)
    return urls, []
