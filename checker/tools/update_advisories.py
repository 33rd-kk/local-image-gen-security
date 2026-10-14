"""Rebuilds checker/src/ligsp/advisory_data.py from GitHub's published security advisories.

For maintainers only: run by hand (python tools/update_advisories.py) or by
the scheduled workflow, which opens a pull request with the result. The
checker itself never fetches anything; it reads the table this writes.

Set GH_TOKEN (or GITHUB_TOKEN) to avoid the anonymous rate limit.
"""

from __future__ import annotations

import datetime
import json
import os
import pprint
import urllib.request
from pathlib import Path

# The repositories whose advisories the checker can match.
SOURCES = ("Comfy-Org/ComfyUI", "Comfy-Org/ComfyUI-Manager")
# The tool each advisory package belongs to: the "kind" the checker gives a
# server, or "comfyui-manager" for the Manager on a ComfyUI server.
PACKAGES = {
    "comfyui": "comfyui",
    "comfyui-manager": "comfyui-manager",
}
OUT = Path(__file__).resolve().parents[1] / "src" / "ligsp" / "advisory_data.py"


def fetch(repo: str) -> list[dict]:
    url = f"https://api.github.com/repos/{repo}/security-advisories?state=published&per_page=100"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "ligsp-advisory-update"})
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as answer:
        return json.load(answer)


def rows() -> list[dict]:
    found: dict[tuple[str, str], dict] = {}
    for repo in SOURCES:
        for advisory in fetch(repo):
            if advisory.get("withdrawn_at"):
                continue
            for vulnerability in advisory.get("vulnerabilities") or []:
                tool = PACKAGES.get(((vulnerability.get("package") or {}).get("name") or "").lower())
                if not tool or not vulnerability.get("vulnerable_version_range"):
                    continue
                found[(advisory["ghsa_id"], tool)] = {
                    "id": advisory["ghsa_id"],
                    "tool": tool,
                    "affected": vulnerability["vulnerable_version_range"],
                    "fixed": vulnerability.get("patched_versions") or "",
                    "severity": advisory.get("severity") or "unknown",
                    "summary": " ".join((advisory.get("summary") or "").split())[:120],
                    "url": advisory.get("html_url") or f"https://github.com/advisories/{advisory['ghsa_id']}",
                }
    return sorted(found.values(), key=lambda row: (row["tool"], row["id"]))


def main() -> None:
    data = rows()
    today = datetime.date.today().isoformat()
    text = (
        '"""Published security advisories for the tools the checker recognises.\n\n'
        "Written by tools/update_advisories.py from GitHub's advisory API; do not edit\n"
        "by hand. The checker reads this table and fetches nothing.\n"
        '"""\n\n'
        f'DATA_AS_OF = "{today}"\n\n'
        f"ADVISORIES = {pprint.pformat(data, width=120, sort_dicts=False)}\n"
    )
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"{len(data)} advisories as of {today} -> {OUT}")


if __name__ == "__main__":
    main()
