"""Model folders (MOD-1): weight files in a pickle format, and broken safetensors headers.

Nothing is loaded. Pickle-format files are only listed by name; of a
.safetensors file only the 8-byte length and the JSON header are read.
Links leading out of the folder are not followed.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

from . import fixes
from .results import FAIL, PASS, UNKNOWN, WARN, Result

PICKLE_SUFFIXES = (".ckpt", ".pt", ".pth", ".bin", ".pkl", ".pickle")
MAX_HEADER = 100_000_000
MAX_LISTED = 20


def _header_ok(path: Path) -> bool:
    try:
        size = path.stat().st_size
        with path.open("rb") as file:
            raw = file.read(8)
            if len(raw) != 8:
                return False
            (length,) = struct.unpack("<Q", raw)
            if length > MAX_HEADER or length + 8 > size:
                return False
            header = json.loads(file.read(length))
    except (OSError, ValueError, struct.error):
        return False
    return isinstance(header, dict)


def model_checks(folder: Path) -> list[Result]:
    if not folder.is_dir():
        return [Result("MOD-1", UNKNOWN, "Not a folder")]
    pickles_alone: list[str] = []
    pickles_beside: list[str] = []
    broken: list[str] = []
    safetensors = 0
    for root, dirs, files in os.walk(folder, followlinks=False):
        here = Path(root)
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        has_safetensors = any(name.lower().endswith(".safetensors") for name in files)
        for name in files:
            path = here / name
            if path.is_symlink():
                continue
            relative = path.relative_to(folder).as_posix()
            lower = name.lower()
            if lower.endswith(".safetensors"):
                safetensors += 1
                if not _header_ok(path):
                    broken.append(relative)
            elif lower.endswith(PICKLE_SUFFIXES):
                (pickles_beside if has_safetensors else pickles_alone).append(relative)

    results: list[Result] = []
    if pickles_alone:
        results.append(
            Result("MOD-1", FAIL, f"{len(pickles_alone)} weight file(s) only in a pickle format, which can run code when loaded",
                   _listed(pickles_alone), fixes.WHY["MOD-1"], fixes.fix("MOD-1", "models"))
        )
    if pickles_beside:
        results.append(
            Result("MOD-1", WARN, f"{len(pickles_beside)} pickle-format file(s) next to .safetensors files (most loaders read the .safetensors one)",
                   _listed(pickles_beside), fixes.WHY["MOD-1"], fixes.fix("MOD-1", "models"))
        )
    if not pickles_alone and not pickles_beside:
        results.append(Result("MOD-1", PASS, f"No pickle-format weight files ({safetensors} .safetensors files)"))
    if broken:
        results.append(Result("MOD-1", WARN, f"{len(broken)} .safetensors file(s) with a header that does not read", _listed(broken),
                              "A damaged or disguised file.", "Download it again from where it came from, and compare its SHA-256."))
    return results


def _listed(names: list[str]) -> list[str]:
    shown = names[:MAX_LISTED]
    return shown + ([f"... and {len(names) - MAX_LISTED} more"] if len(names) > MAX_LISTED else [])
