# Changelog

## Unreleased

- **OPS-3, published advisories** (profile, SHOULD): the owner can find out
  whether the version they run has published security advisories, and
  which version fixes them.
- **The checker matches versions against advisories**: the ComfyUI and
  ComfyUI-Manager versions it finds are matched against the advisories
  those projects publish on GitHub, from a table that ships with the
  checker (it fetches nothing). A high or critical advisory fails, and the
  report names each advisory, the fixed version and how old the table is.
  `tools/update_advisories.py` rebuilds the table, and a weekly workflow
  opens a pull request with the rebuilt table when it is out of date.
- A contributing guide, issue forms (a checker problem, a profile change)
  and a pull request template. The README lists the tools that claim
  conformance, starting with Latentry.

## 0.1.0 (2026-10-14)

The first public draft.

**The profile (LIGSP 0.1, draft)**

- The threats it covers: a website you visit, another device on your
  network, internet scanners, model files and extensions, swapped
  downloads, later users of the computer, and whoever receives a picture.
- Two levels: this computer only (1) and the local network (2).
- Requirements in ten groups, each with MUST or SHOULD, its reason and how
  to check it: network exposure, browser-facing HTTP, devices, hubs and
  servers, model files, extensions, the tool's own supply chain, data,
  metadata in pictures, and telling the owner.

**The checker (`ligsp` 0.1.0)**

- `ligsp check URL ... [--models DIR] [--private PATH] [--json FILE] [--redact]`
- It recognises ComfyUI, AUTOMATIC1111 / Forge and Latentry, and checks
  other web servers generically.
- It checks:
  - NET-1: reachable from the network (IPv4 and IPv6);
  - NET-2: usable without a login;
  - BE-1: plain HTTP to another computer;
  - WEB-1: CORS for other sites;
  - WEB-2: answering any host name (DNS rebinding);
  - WEB-3: protective headers;
  - EXT-1: an extension installer, and how many extensions run;
  - MOD-1: pickle-format weights, also when disguised as `.safetensors`;
  - DATA-4: who besides you can read a hub's private files, by SID on
    Windows.
- It only reads: GET, HEAD and OPTIONS, to a fixed list of endpoints known
  to change nothing, at the addresses you name and this computer's own. It
  sends no telemetry.
- Standard library only, Python 3.10 or newer, tested on Linux, Windows and
  macOS.
