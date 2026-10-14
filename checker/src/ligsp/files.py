"""Private files (DATA-4, AUTH-5): settings, keys and tokens that only their owner may read.

A file is named with --private. A folder named there is searched (not
recursively) for the private files of the hubs the checker knows (Latentry's
settings file, pairing key, paired-device list and folder-name key). Only
the files' permissions are read, never their content.

On POSIX that is the mode. On Windows it is the access list, read with
icacls from Windows' own folder (no shell). Entries for the owner, SYSTEM
and Administrators are fine; any other account or group (Users, Everyone,
Authenticated Users, another person) fails.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

from . import fixes
from .results import FAIL, PASS, UNKNOWN, Result

KNOWN_PRIVATE = ("latentry.settings.json", "latentry.pairing-key", "latentry.pairing-devices.json", "latentry.folder-names-key")
WINDOWS_FINE = ("NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators")


def private_files(path: Path) -> list[Path]:
    if path.is_dir():
        return [path / name for name in KNOWN_PRIVATE if (path / name).is_file()]
    return [path] if path.is_file() else []


def _icacls(file: Path) -> list[str] | None:
    """The account names in a file's access list, or None when it cannot be read."""
    tool = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "icacls.exe"
    try:
        raw = subprocess.run([str(tool), str(file)], capture_output=True, timeout=10, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    # icacls writes in the console's OEM code page, whatever Python's own encoding is.
    out = raw.decode("oem", "replace")
    names = []
    for line in out.splitlines():
        line = line.replace(str(file), "", 1).strip()
        if ":(" in line:
            names.append(line.split(":(", 1)[0].strip())
    return names


def _current_user_names() -> set[str]:
    user = os.environ.get("USERNAME", "")
    names = {user.lower()}
    for domain in (os.environ.get("USERDOMAIN", ""), os.environ.get("COMPUTERNAME", "")):
        if domain:
            names.add(f"{domain}\\{user}".lower())
    return names


def others_who_can_read(file: Path, platform: str = sys.platform) -> list[str] | None:
    """Who besides the owner (and Windows itself) can read `file`; None when unknown."""
    if platform == "win32":
        names = _icacls(file)
        if names is None:
            return None
        mine = _current_user_names()
        return [n for n in names if n.lower() not in mine and n not in WINDOWS_FINE]
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
