"""Browser-facing checks (WEB-1, WEB-2, WEB-3), with read-only requests only."""

from __future__ import annotations

from . import fixes
from .results import FAIL, PASS, UNKNOWN, WARN, Result
from .targets import Identified
from .transport import Transport

FOREIGN_ORIGIN = "http://example.invalid"
FOREIGN_HOST = "rebind.example.invalid"
PAGE_TIMEOUT = 20.0
# Servers with no page of their own, only an API.
API_ONLY = ("latentry-engine", "diffusers")


def web_checks(transport: Transport, base: str, found: Identified, reachable_from_network: bool) -> list[Result]:
    kind = found.kind
    probe = base.rstrip("/") + found.probe_path
    results: list[Result] = []

    # WEB-1: does it let another website read its answers (CORS)?
    preflight = transport.request("OPTIONS", probe, {"Origin": FOREIGN_ORIGIN, "Access-Control-Request-Method": "POST"})
    plain = transport.request("GET", probe, {"Origin": FOREIGN_ORIGIN})
    allowed = [a.header("access-control-allow-origin") for a in (preflight, plain) if a is not None]
    if any(value in ("*", FOREIGN_ORIGIN) for value in allowed):
        results.append(
            Result("WEB-1", FAIL, "Other websites may read its answers (CORS allows them)", [f"Access-Control-Allow-Origin: {v}" for v in allowed if v],
                   fixes.WHY["WEB-1"], fixes.fix("WEB-1", kind))
        )
    elif preflight is None and plain is None:
        results.append(Result("WEB-1", UNKNOWN, "No answer to the cross-site checks"))
    else:
        results.append(Result("WEB-1", PASS, "Does not let other websites read its answers"))

    # WEB-2: does it answer for any host name (DNS rebinding)?
    rebound = transport.request("GET", probe, {"Host": FOREIGN_HOST})
    if rebound is None:
        results.append(Result("WEB-2", UNKNOWN, "No answer to the host-name check"))
    elif rebound.status in (400, 403, 421):
        results.append(Result("WEB-2", PASS, "Refuses host names it does not know", [f"{FOREIGN_HOST}: {rebound.status}"]))
    elif found.answer is not None and rebound.status == found.answer.status:
        status = FAIL if reachable_from_network else WARN
        results.append(
            Result("WEB-2", status, "Answers for any host name, so a web page could drive it through DNS rebinding", [f"{FOREIGN_HOST}: {rebound.status}"],
                   fixes.WHY["WEB-2"], fixes.fix("WEB-2", kind))
        )
    else:
        results.append(Result("WEB-2", PASS, "Answers differently for a host name it does not know", [f"{FOREIGN_HOST}: {rebound.status}"]))

    # WEB-3: headers on its page. Servers that only have an API (no page for a
    # browser to show or frame) are left out.
    if kind in API_ONLY:
        return results
    # A development server builds a page on its first request, which can take a while.
    page = transport.request("GET", base.rstrip("/") + "/", timeout=PAGE_TIMEOUT)
    if page is None:
        results.append(Result("WEB-3", UNKNOWN, f"Its page did not answer within {PAGE_TIMEOUT:.0f} s (run the check again)"))
    elif page.status >= 400:
        results.append(Result("WEB-3", UNKNOWN, f"No page to read headers from ({page.status})"))
    else:
        missing = []
        csp = (page.header("content-security-policy") or "").lower()
        if "frame-ancestors" not in csp and not page.header("x-frame-options"):
            missing.append("frame protection (X-Frame-Options or CSP frame-ancestors)")
        if (page.header("x-content-type-options") or "").lower() != "nosniff":
            missing.append("X-Content-Type-Options: nosniff")
        if not page.header("referrer-policy"):
            missing.append("Referrer-Policy")
        if missing:
            results.append(Result("WEB-3", WARN, "Its page is missing some protective headers", missing, fixes.WHY["WEB-3"], fixes.fix("WEB-3", kind)))
        else:
            results.append(Result("WEB-3", PASS, "Its page has the protective headers"))
    return results
