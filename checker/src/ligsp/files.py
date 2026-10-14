"""Private files (DATA-4, AUTH-5): settings, keys and tokens that only their owner may read.

A file is named with --private. A folder named there is searched (not
recursively) for the private files of the hubs the checker knows (Latentry's
settings file, pairing key, paired-device list and folder-name key). Only
the files' permissions are read, never their content.

On POSIX that is the mode. On Windows it is the access list, compared by
SID (see winacl.py), so it works in any system language. Entries for the
owner, SYSTEM and Administrators are fine; any other account or group
(Users, Everyone, Authenticated Users, another person) fails.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

from . import fixes, winacl
from .results import FAIL, PASS, UNKNOWN, Result

KNOWN_PRIVATE = ("latentry.settings.json", "latentry.pairing-key", "latentry.pairing-devices.json", "latentry.folder-names-key")


def private_files(path: Path) -> list[Path]:
    if path.is_dir():
        return [path / name for name in KNOWN_PRIVATE if (path / name).is_file()]
    return [path] if path.is_file() else []


def others_who_can_read(file: Path, platform: str = sys.platform) -> list[str] | None:
    """Who besides the owner (and Windows itself) can read `file`; None when unknown."""
    if platform == "win32":
        found = winacl.readers(str(file))
        me = winacl.current_user_sid()
        if found is None or me is None:
            return None
        fine = {me, winacl.SYSTEM, winacl.ADMINISTRATORS}
        return sorted({name for sid, name in found if sid not in fine})
    mode = file.stat().st_mode
    others = []
    if mode & stat.S_IRGRP:
        others.append("its group")
    if mode & stat.S_IROTH:
        others.append("every user")
    return others


def file_checks(path: Path) -> list[Result]:
    files = private_files(path)
    if not files:
        return [Result("DATA-4", UNKNOWN, "No private file found there" + (" (looked for: " + ", ".join(KNOWN_PRIVATE) + ")" if path.is_dir() else ""))]
    open_files: list[str] = []
    unknown: list[str] = []
    for file in files:
        others = others_who_can_read(file)
        if others is None:
            unknown.append(file.name)
        elif others:
            open_files.append(f"{file.name}: also readable by {', '.join(others)}")
    results = []
    if open_files:
        results.append(Result("DATA-4", FAIL, f"{len(open_files)} private file(s) can be read by others", open_files, fixes.WHY["DATA-4"], fixes.fix("DATA-4", "files")))
    readable = len(files) - len(open_files) - len(unknown)
    if readable:
        results.append(Result("DATA-4", PASS, f"{readable} private file(s) readable by their owner only", [f.name for f in files if f.name not in unknown and not any(o.startswith(f.name + ":") for o in open_files)]))
    if unknown:
        results.append(Result("DATA-4", UNKNOWN, "Could not read the permissions of some files", unknown))
    return results
