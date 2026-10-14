"""Checks that only some kinds of server have: Latentry's engine token (BE-2), InvokeAI's first administrator (AUTH-1)."""

from __future__ import annotations

from . import fixes
from .results import FAIL, PASS, UNKNOWN, WARN, Result
from .targets import Identified


def kind_checks(found: Identified, reachable_from_network: bool) -> list[Result]:
    results: list[Result] = []
    if found.kind == "latentry-engine" and found.answer is not None:
        # found.answer is GET /api/models without a token.
        if found.answer.status == 401:
            results.append(Result("BE-2", PASS, "Its model list needs the engine's token", ["/api/models without a token: 401"]))
        elif found.answer.status == 200:
            status = FAIL if reachable_from_network else WARN
            results.append(Result("BE-2", status, "It answers without a token, so other software on this computer can drive it", ["/api/models without a token: 200"],
                                  fixes.WHY["BE-2"], fixes.fix("BE-2", "latentry-engine")))
        else:
            results.append(Result("BE-2", UNKNOWN, f"Its model list answered {found.answer.status}"))
    if found.kind == "invokeai" and found.extra.get("multiuser") and found.extra.get("setup_required"):
        status = FAIL if reachable_from_network else WARN
        results.append(Result("AUTH-1", status, "Multi-user mode is on but has no administrator yet: whoever opens it first creates one", [],
                              fixes.WHY["AUTH-1"], fixes.fix("AUTH-1", "invokeai")))
    return results
