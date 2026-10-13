"""What a check finds: one Result per requirement and target."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

PASS, WARN, FAIL, UNKNOWN = "pass", "warn", "fail", "unknown"


@dataclass
class Result:
    id: str  # the profile's requirement ID, e.g. "NET-1"
    status: str  # PASS, WARN, FAIL or UNKNOWN
    title: str  # one line, what was found
    evidence: list[str] = field(default_factory=list)  # what was seen (redactable)
    why: str = ""  # which threat, in plain words
    fix: str = ""  # what to change, for the tool that was found

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class Target:
    """A server or a models folder, with what was found about it."""

    label: str  # the URL or the folder, as given
    kind: str  # "comfyui", "a1111", "latentry", "http" or "models"
    version: str | None = None
    results: list[Result] = field(default_factory=list)

    def to_json(self) -> dict:
        return {"target": self.label, "kind": self.kind, "version": self.version, "results": [r.to_json() for r in self.results]}
