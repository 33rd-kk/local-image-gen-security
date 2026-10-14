"""OPS-3: whether the versions running have published security advisories.

Matched against the table in advisory_data.py, which ships with each release
of the checker and is never fetched at run time. A result says how old the
table is, so a pass is read as "none known as of then".

Version ranges are GitHub's: "< 0.28.0", ">= 1.0, < 2.0" (a comma joins two
conditions), and some advisories write "< 3.39.2, 4.0.0 - 4.0.4", where the
comma separates two alternatives. A list with a hyphen range, or with more
than one upper bound, is read that second way.
"""

from __future__ import annotations

import re

from . import fixes
from .advisory_data import ADVISORIES, DATA_AS_OF
from .results import FAIL, PASS, UNKNOWN, WARN, Result

SERIOUS = ("critical", "high")


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """(0, 39, 2) for "0.39.2" or "V4.2.2"; None when there is no number to read."""
    if not text:
        return None
    match = re.match(r"\s*[vV]?(\d+(?:\.\d+)*)", text)
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def _condition(part: str, version: tuple[int, ...]) -> bool | None:
    part = part.strip()
    hyphen = re.fullmatch(r"([\d.]+)\s+-\s+([\d.]+)", part)
    if hyphen:
        low, high = parse_version(hyphen.group(1)), parse_version(hyphen.group(2))
        return low is not None and high is not None and _cmp(version, low) >= 0 and _cmp(version, high) <= 0
    match = re.fullmatch(r"(<=|>=|<|>|=)?\s*([vV]?[\d.]+)", part)
    if not match:
        return None
    bound = parse_version(match.group(2))
    if bound is None:
        return None
    c = _cmp(version, bound)
    return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0, None: c == 0}[match.group(1)]


def affects(affected: str, version: tuple[int, ...]) -> bool | None:
    """Whether `version` is in `affected`; None when the range cannot be read."""
    parts = [part for part in affected.split(",") if part.strip()]
    if not parts:
        return None
    alternatives = any(" - " in part for part in parts) or sum(part.strip().startswith("<") for part in parts) > 1
    results = [_condition(part, version) for part in parts]
    if any(result is None for result in results):
        return None
    return any(results) if alternatives else all(results)


def advisory_checks(tool_versions: dict[str, str | None]) -> list[Result]:
    """One OPS-3 result per tool found on a server, e.g. {"comfyui": "0.39.2", "comfyui-manager": "V4.2.2"}."""
    results: list[Result] = []
    for tool, raw in tool_versions.items():
        name = fixes.TOOL_NAMES.get(tool, tool)
        known = [row for row in ADVISORIES if row["tool"] == tool]
        version = parse_version(raw)
        if version is None:
            if known:
                results.append(Result("OPS-3", UNKNOWN, f"{name}: its version could not be read, so advisories were not matched"))
            continue
        hits = []
        for row in known:
            matched = affects(row["affected"], version)
            if matched is None:
                results.append(Result("OPS-3", UNKNOWN, f"{name}: the range of {row['id']} could not be read", [row["affected"], row["url"]]))
            elif matched:
                hits.append(row)
        shown = ".".join(str(part) for part in version)
        if hits:
            serious = any(row["severity"] in SERIOUS for row in hits)
            evidence = [f"{row['id']} ({row['severity']}): {row['summary']}. Fixed in {row['fixed'] or 'no release yet'}. {row['url']}" for row in hits]
            evidence.append(f"advisories as of {DATA_AS_OF}")
            results.append(
                Result("OPS-3", FAIL if serious else WARN, f"{name} {shown} has {len(hits)} published security advisor{'y' if len(hits) == 1 else 'ies'}",
                       evidence, fixes.WHY["OPS-3"], fixes.fix("OPS-3", tool))
            )
        else:
            results.append(Result("OPS-3", PASS, f"{name} {shown}: no published advisory applies (as of {DATA_AS_OF})"))
    return results
