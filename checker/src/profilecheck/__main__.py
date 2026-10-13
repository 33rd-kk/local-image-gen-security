"""profilecheck check URL ... [--models DIR ...] [--json FILE] [--redact]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .ext import extension_checks
from .files import file_checks
from .models import model_checks
from .net import network_checks, own_lan_addresses
from .report import Redactor, as_json, as_text, summary
from .results import FAIL, Target
from .targets import identify
from .transport import Transport
from .web import web_checks

DEFAULT_PORTS = "ComfyUI 8188, Comfy Desktop 8000, A1111 / Forge 7860, Latentry 3000, InvokeAI 9090, SwarmUI 7801"

DESCRIPTION = f"""\
Checks the image-generation servers and model folders you name against the
Secure Local Generation Profile. Read-only: it sends GET, HEAD and OPTIONS
only, to the URLs you give and to the same port on this computer's own
network addresses, and it reads only the headers of .safetensors files.
It tries no other ports. Common defaults: {DEFAULT_PORTS}.
"""


def check_server(transport: Transport, url: str, lan: list[str]) -> Target:
    transport.allow(urlsplit(url).hostname or "")
    found = identify(transport, url)
    target = Target(url, found.kind, found.version)
    results, reachable = network_checks(transport, url, found, lan)
    target.results.extend(results)
    if found.answer is not None:
        web = web_checks(transport, url, found, reachable)
        target.results.extend(web)
        any_host = any(r.id == "WEB-2" and r.status in ("warn", "fail") for r in web)
        target.results.extend(extension_checks(transport, url, found, reachable, any_host))
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="profilecheck", description=DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"profilecheck {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="check servers and model folders", description=DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter)
    check.add_argument("urls", nargs="*", metavar="URL", help="a server to check, e.g. http://127.0.0.1:8188")
    check.add_argument("--models", action="append", default=[], metavar="DIR", help="a model folder to check (may be repeated)")
    check.add_argument("--private", action="append", default=[], metavar="PATH",
                       help="a private file, or a folder with a hub's private files (Latentry's settings and keys), whose permissions to check")
    check.add_argument("--json", metavar="FILE", help="also write the report as JSON to FILE ('-' for standard output only)")
    check.add_argument("--redact", action="store_true", help="hide paths, host names, addresses and ports, to share the report")
    args = parser.parse_args(argv)

    for url in args.urls:
        if urlsplit(url).scheme not in ("http", "https") or not urlsplit(url).hostname:
            parser.error(f"not an http(s) URL: {url}")
    if not args.urls and not args.models and not args.private:
        parser.error(f"name at least one server URL, --models folder or --private path (common ports: {DEFAULT_PORTS})")

    redact = Redactor(args.redact)
    transport = Transport()
    lan = own_lan_addresses() if args.urls else []
    for address in lan:
        redact.add(address, "<this computer>")
    targets: list[Target] = []
    for index, url in enumerate(args.urls, 1):
        parts = urlsplit(url)
        if parts.hostname and parts.hostname not in ("127.0.0.1", "localhost", "::1"):
            redact.add(parts.hostname, f"<host{index}>")
        if parts.port:
            redact.add(f":{parts.port}", ":<port>")
        targets.append(check_server(transport, url, lan))
    for index, folder in enumerate(args.models, 1):
        path = Path(folder)
        redact.add(str(path.resolve()), f"<models{index}>")
        redact.add(folder, f"<models{index}>")
        target = Target(folder, "models")
        target.results.extend(model_checks(path))
        targets.append(target)
    for index, place in enumerate(args.private, 1):
        path = Path(place)
        redact.add(str(path.resolve()), f"<private{index}>")
        redact.add(place, f"<private{index}>")
        target = Target(place, "files")
        target.results.extend(file_checks(path))
        targets.append(target)
    redact.add(str(Path.home()), "<home>")

    if args.json != "-":
        print(as_text(targets, redact))
    if args.json:
        data = as_json(targets, redact)
        if args.json == "-":
            print(data)
        else:
            Path(args.json).write_text(data + "\n", encoding="utf-8")
    return 1 if summary(targets)[FAIL] else 0


if __name__ == "__main__":
    sys.exit(main())
