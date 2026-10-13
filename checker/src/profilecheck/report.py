"""The report: as text for people, as JSON for machines, optionally redacted."""

from __future__ import annotations

import json
import re
import textwrap

from . import PROFILE_VERSION, __version__
from .results import FAIL, PASS, UNKNOWN, WARN, Target
from .targets import KIND_NAMES

MARK = {PASS: "PASS", WARN: "WARN", FAIL: "FAIL", UNKNOWN: "  ? "}


class Redactor:
    """Replaces the given words (hosts, addresses, ports, paths) with stable placeholders."""

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.words: dict[str, str] = {}

    def add(self, word: str, placeholder: str) -> None:
        if not self.enabled or not word:
            return
        # As written, and as it appears inside JSON (backslashes doubled).
        for form in (word, json.dumps(word)[1:-1]):
            self.words.setdefault(form, placeholder)

    def __call__(self, text: str) -> str:
        if not self.enabled:
            return text
        # Longest first, so a path is replaced before a folder name inside it.
        for word in sorted(self.words, key=len, reverse=True):
            text = text.replace(word, self.words[word])
        # Any IPv4 address left over, except loopback, which says nothing about you.
        return re.sub(r"\b(?!127\.)(?:\d{1,3}\.){3}\d{1,3}\b", "<address>", text)


def summary(targets: list[Target]) -> dict[str, int]:
    counts = {FAIL: 0, WARN: 0, PASS: 0, UNKNOWN: 0}
    for target in targets:
        for result in target.results:
            counts[result.status] += 1
    return counts


def as_text(targets: list[Target], redact: Redactor) -> str:
    lines: list[str] = []
    for target in targets:
        name = {"models": "Models in", "files": "Private files in"}.get(target.kind) or KIND_NAMES.get(target.kind, target.kind)
        version = f" {target.version}" if target.version else ""
        lines.append(redact(f"{name}{version} {'' if target.kind in ('models', 'files') else 'at '}{target.label}".replace("  ", " ")))
        for result in sorted(target.results, key=lambda r: [FAIL, WARN, UNKNOWN, PASS].index(r.status)):
            lines.append(redact(f"  {MARK[result.status]}  {result.id:<6} {result.title}"))
            for item in result.evidence:
                lines.append(redact(f"               {item}"))
            if result.status in (FAIL, WARN):
                for label, text in (("Why", result.why), ("Fix", result.fix)):
                    if text:
                        wrapped = textwrap.wrap(f"{label}: {text}", 90)
                        lines.extend(redact("               " + line) for line in wrapped)
        lines.append("")
    counts = summary(targets)
    lines.append(f"Summary: {counts[FAIL]} failed, {counts[WARN]} warnings, {counts[PASS]} passed, {counts[UNKNOWN]} not checked")
    lines.append(f"Profile {PROFILE_VERSION}, profilecheck {__version__}. A pass means these checks found no problem, not that the setup is safe.")
    return "\n".join(lines)


def as_json(targets: list[Target], redact: Redactor) -> str:
    data = {"profile": PROFILE_VERSION, "checker": __version__, "summary": summary(targets), "targets": [t.to_json() for t in targets]}
    return redact(json.dumps(data, indent=2, ensure_ascii=False))
