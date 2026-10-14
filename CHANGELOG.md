# Changelog

## Unreleased

- **A correction**: the checker's README and notes said ComfyUI-Manager
  removes and restores snapshots on a GET. Its releases from 2024 did; its
  current ones use POST. The checker's rule (only fixed endpoints known to
  change nothing) is unchanged.

## 0.2.0 (2026-10-14)

**The profile (still 0.1: OPS-3 is a SHOULD, so no conformance claim changes)**

- **OPS-3, published advisories** (profile, SHOULD): the owner can find out
  whether the version they run has published security advisories, and
  which version fixes them.

**The checker (`ligsp` 0.2.0)**

- **The checker matches versions against advisories**: the ComfyUI and
  ComfyUI-Manager versions it finds are matched against the advisories
  those projects publish on GitHub, from a table that ships with the
  checker (it fetches nothing). A high or critical advisory fails, and the
  report names each advisory, the fixed version and how old the table is.
  `tools/update_advisories.py` rebuilds the table, and a weekly workflow
  opens a pull request with the rebuilt table when it is out of date.
- **`--follow`**: for a hub (Latentry), the checker also checks every
  backend it is set up to use, so one command covers the whole setup. It
  reads only the backends' URLs from the hub, on the computer the hub runs
  on, and does not follow further.
- **More servers recognised**: InvokeAI, SwarmUI, Latentry's engine, and
  other servers on Latentry's backend API, each with fixes in its own
  settings.
  - InvokeAI: login is judged by its multi-user mode. AUTH-1 flags
    accounts that are on but have no administrator yet. EXT-1 flags its
    node-pack installer (it installs from a git URL) when it can be used
    without logging in.
  - SwarmUI: also recognised when its page sends you to its login page.
  - Latentry's engine: BE-2 checks that it needs its token.
  - For other backend-API servers, whose `/api/health` is open by design,
    whether generating needs a login is reported as unknown rather than
    guessed.

**The repository**

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
