"""This computer's own addresses, and the network checks (NET-1, NET-2, BE-1)."""

from __future__ import annotations

import ipaddress
import json
import socket
from urllib.parse import urlsplit, urlunsplit

from . import fixes
from .results import FAIL, PASS, UNKNOWN, WARN, Result
from .targets import Identified
from .transport import Answer, Transport

LAN_TIMEOUT = 2.0


def is_loopback(host: str) -> bool:
    host = host.lower().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def own_lan_addresses() -> list[str]:
    """This computer's IPv4 and IPv6 addresses other than loopback and link-local.

    From the host name's addresses, and from the address a UDP socket would
    send from (connect() on UDP sends no packet).
    """
    found: set[str] = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, family):
                found.add(str(info[4][0]).split("%")[0])
        except OSError:
            pass
    # Documentation addresses (TEST-NET-1, 2001:db8::): never reached, only routed.
    for family, target in ((socket.AF_INET, ("192.0.2.1", 9)), (socket.AF_INET6, ("2001:db8::1", 9))):
        try:
            probe = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            probe.connect(target)
            found.add(str(probe.getsockname()[0]).split("%")[0])
        except OSError:
            pass
        finally:
            probe.close()
    lan = []
    for address in sorted(found, key=lambda a: (":" in a, a)):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast):
            lan.append(address)
    return lan


def needs_login(answer: Answer) -> bool:
    """Whether an answer asks for credentials (or, on Latentry, pairing) instead of serving."""
    if answer.status in (401, 403):
        return True
    # A redirect to a login page (SwarmUI with user accounts, for one).
    if 300 <= answer.status < 400 and "login" in (answer.header("location") or "").lower():
        return True
    if answer.status != 200:
        return False
    try:
        data = json.loads(answer.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and data.get("paired") is False


def login_required(found: Identified, answer: Answer) -> bool | None:
    """Whether a server asks for a login, by what its kind tells; None when that cannot be known."""
    if found.kind == "invokeai" and answer.status not in (401, 403):
        # Its version endpoint is always open; its multi-user mode is what asks for a login.
        return bool(found.extra.get("multiuser")) and not found.extra.get("setup_required")
    if found.kind == "diffusers" and answer.status not in (401, 403):
        # The backend API keeps /api/health open by design, so it says nothing about generating.
        return None
    return needs_login(answer)


def with_host(url: str, host: str) -> str:
    parts = urlsplit(url)
    if ":" in host:
        host = f"[{host}]"
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


def network_checks(transport: Transport, base: str, found: Identified, lan: list[str]) -> tuple[list[Result], bool]:
    """NET-1, NET-2 and BE-1 for one server; also whether it is reachable from the network."""
    host = urlsplit(base).hostname or ""
    kind = found.kind
    results: list[Result] = []
    probe = base.rstrip("/") + found.probe_path

    if found.answer is None:
        return [Result("NET-1", UNKNOWN, "The server did not answer", why="Nothing to check.")], False

    from_network: list[tuple[str, Answer]] = []
    if is_loopback(host):
        for address in lan:
            transport.allow(address)
            answer = transport.request("GET", with_host(probe, address), timeout=LAN_TIMEOUT)
            if answer is not None:
                from_network.append((address, answer))
        if not lan:
            results.append(Result("NET-1", UNKNOWN, "No network address found on this computer to try from"))
        elif not from_network:
            results.append(Result("NET-1", PASS, "Not reachable from your network", [f"no answer on {a}" for a in lan]))
    else:
        from_network.append((host, found.answer))

    if from_network:
        judged = [(a, r, login_required(found, r)) for a, r in from_network]
        open_ones = [(a, r) for a, r, login in judged if login is False]
        unknown = [(a, r) for a, r, login in judged if login is None]
        words = {True: " and asked for a login or pairing", False: ", usable as is", None: ", and whether it needs a login cannot be read"}
        evidence = [f"{a} answered {r.status}{words[login]}" for a, r, login in judged]
        if is_loopback(host):
            status = FAIL if open_ones else WARN
            title = "Reachable from your network" + ("" if open_ones or unknown else ", but it asks for a login or pairing")
            net1_evidence = list(evidence)
            if urlsplit(base).scheme == "http":
                # The profile leaves TLS on the local network open (section 8); say what it means.
                net1_evidence.append("over plain HTTP: prompts, pictures and any login or pairing cookie cross the network unencrypted")
            results.append(Result("NET-1", status, title, net1_evidence, fixes.WHY["NET-1"], fixes.fix("NET-1", kind)))
        if open_ones:
            results.append(Result("NET-2", FAIL, "Usable from the network without logging in", evidence, fixes.WHY["NET-2"], fixes.fix("NET-2", kind)))
        elif unknown:
            results.append(Result("NET-2", UNKNOWN, "Reachable from the network; whether it needs a login to generate cannot be read safely", evidence,
                                  fixes.WHY["NET-2"], fixes.fix("NET-2", kind)))
        else:
            results.append(Result("NET-2", PASS, "From the network it asks for a login or pairing", evidence))
    else:
        results.append(Result("NET-2", PASS, "Only this computer can reach it, so no login is needed"))

    if not is_loopback(host):
        if urlsplit(base).scheme == "http":
            results.append(Result("BE-1", WARN, "Reached over plain HTTP on another computer", [base], fixes.WHY["BE-1"], fixes.fix("BE-1", kind)))
        else:
            results.append(Result("BE-1", PASS, "Reached over HTTPS, with its certificate checked"))
    return results, bool(from_network)
