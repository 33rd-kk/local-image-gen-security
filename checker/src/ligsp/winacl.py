"""Who may read a file on Windows, by security identifier (SID), through the Win32 API.

Account names depend on the system's language ("Administrators" is
"Administratoren" in German), so the access list is compared by SID:
GetNamedSecurityInfoW reads the file's DACL, and each allow entry that
applies to the file itself is turned into a SID string. Only the
permissions are read, never the file's content. Standard library only
(ctypes).
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x4
ACCESS_ALLOWED_ACE_TYPE = 0
INHERIT_ONLY_ACE = 0x08
# Rights that let an account read the content: read data, generic read or all, or full control.
READ_RIGHTS = 0x0001 | 0x80000000 | 0x10000000

SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"


class _AclHeader(ctypes.Structure):
    _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte), ("AclSize", wintypes.WORD), ("AceCount", wintypes.WORD), ("Sbz2", wintypes.WORD)]


class _AceHeader(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]


class _AllowedAce(ctypes.Structure):
    _fields_ = [("Header", _AceHeader), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]


def _api():
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_int),
    ]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return advapi32, kernel32


def _sid_string(advapi32, kernel32, sid: int) -> str | None:
    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        return None
    try:
        return text.value
    finally:
        kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _account_name(advapi32, sid: int) -> str | None:
    name_size, domain_size, use = wintypes.DWORD(256), wintypes.DWORD(256), ctypes.c_int()
    name, domain = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
    if not advapi32.LookupAccountSidW(None, sid, name, ctypes.byref(name_size), domain, ctypes.byref(domain_size), ctypes.byref(use)):
        return None
    return f"{domain.value}\\{name.value}" if domain.value else name.value


def current_user_sid() -> str | None:
    """The SID of the account this process runs as."""
    if sys.platform != "win32":
        return None
    advapi32, kernel32 = _api()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        return None
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))  # TokenUser: size first
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            return None
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]  # TOKEN_USER.User.Sid
        return _sid_string(advapi32, kernel32, sid)
    finally:
        kernel32.CloseHandle(token)


def readers(path: str) -> list[tuple[str, str]] | None:
    """(SID, account name) for every allow entry that lets an account read `path`.

    None when the access list cannot be read. A missing access list (a NULL
    DACL) lets everyone in, and is reported as Everyone.
    """
    if sys.platform != "win32":
        return None
    advapi32, kernel32 = _api()
    dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    status = advapi32.GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if status != 0:
        return None
    try:
        if not dacl.value:
            return [("S-1-1-0", "Everyone (the file has no access list)")]
        found: list[tuple[str, str]] = []
        count = ctypes.cast(dacl, ctypes.POINTER(_AclHeader)).contents.AceCount
        for index in range(count):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                return None
            header = ctypes.cast(ace, ctypes.POINTER(_AceHeader)).contents
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE or header.AceFlags & INHERIT_ONLY_ACE:
                continue
            allowed = ctypes.cast(ace, ctypes.POINTER(_AllowedAce)).contents
            if not allowed.Mask & READ_RIGHTS:
                continue
            sid = ace.value + _AllowedAce.SidStart.offset
            text = _sid_string(advapi32, kernel32, sid)
            if text:
                found.append((text, _account_name(advapi32, sid) or text))
        return found
    finally:
        kernel32.LocalFree(descriptor)
