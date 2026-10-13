# Checker design (draft 0.1)

A command-line tool that checks one person's local image-generation setup
against the profile ([../profile.md](../profile.md)). It tells the owner
what is exposed and what to change. It is the profile's easiest entry
point, and it must also be useful to people who do not use Latentry.

## Goals

- Check the requirements that can be checked from outside the software: the
  network exposure, the HTTP behaviour and the model files.
- Run from one command, with no account, setup or configuration file.
- Give a result that a non-expert can act on: what was found, why it
  matters (the threat, T1–T7), and how to fix it, per tool.
- Give output that machines can read (JSON) for CI and for issue reports.

## Non-goals

- Fixing things automatically.
- Scanning: it checks only the servers and folders the owner names, never a
  range of ports or hosts.
- Reading other software's process command lines, logs or private files.
- Proving conformance: a pass means "no problem found by these checks".

## Rules the checker keeps

Since it is a security tool, it follows the profile itself:

1. **Read-only.** It sends only `GET`, `HEAD` and `OPTIONS`, and only to
   endpoints that change nothing. It never queues a job, uploads a file or
   changes a setting. Each check lists the requests it sends.
2. **Only where you point it.** It contacts the URLs given on the command
   line, plus the same port on this computer's own LAN addresses (to find
   out whether a server meant for this computer is reachable from the
   network). It contacts nothing else: no telemetry and no update check.
3. **Nothing left behind.** It writes nothing unless asked (`--json FILE`).
4. **Safe to share.** `--redact` replaces paths, host names, addresses and
   ports in the report, so it can be pasted into an issue.
5. **Small to trust.** Standard library only, no dependencies, one package,
   released with provenance.

## Usage

```
<name> check [URL ...] [--models DIR ...] [--json FILE|-] [--redact]

  <name> check http://127.0.0.1:8188                  # a ComfyUI
  <name> check http://127.0.0.1:7860 --models D:\models
  <name> check http://127.0.0.1:3000                  # Latentry or another hub
```

At least one URL or `--models` folder is required. It never tries ports
the owner did not name, not even the well-known defaults; the help text and
the report list the defaults of the known tools (ComfyUI 8188, Comfy
Desktop 8000, A1111 / Forge 7860, Latentry 3000, InvokeAI 9090, SwarmUI
7801) so the owner can name theirs.

Exit code: 0 when nothing failed, 1 when a MUST failed, and 2 for a usage
error.

## How it identifies a server

The kind is read from harmless endpoints:

- ComfyUI: `GET /system_stats`, which has `comfyui_version`. Only the
  version field is read; other fields (such as `argv`) are ignored and
  never stored.
- A1111 / Forge: `GET /sdapi/v1/samplers` (or a 401, with `--api-auth`).
- Latentry: `GET /api/gen/backends`, plus its response headers.
- Unknown: generic HTTP checks only.

## Checks (first version)

Each result has the requirement ID, `pass` / `warn` / `fail` / `unknown`,
the evidence (redactable), and a fix with steps for the tool it found.

| ID | Check | How (read-only) |
|---|---|---|
| NET-1 | Reachable from the network? | The URL is on 127.0.0.1: try the same port on each of this computer's LAN IPv4 addresses. An answer means it listens on all interfaces. A URL on another host is already on the network: then NET-2 decides. |
| NET-2 | Usable without logging in? | The identifying request without credentials. A 200 on a network-reachable server is a **fail** (ComfyUI: "anyone on the network can run code through custom nodes"). A 401 or 403 passes. |
| WEB-1 | Answers other websites? | `OPTIONS` and `GET` with `Origin: http://example.invalid`. `Access-Control-Allow-Origin: *`, or the origin echoed back, fails (ComfyUI `--enable-cors-header`). |
| WEB-2 | Answers any host name? | `GET` with `Host: rebind.example.invalid`. A normal answer means DNS rebinding can reach it: **warn** for a server on loopback (a web page can then drive it), **fail** together with NET-2. |
| WEB-3 | Security headers on its pages | `GET /`: `frame-ancestors` / `X-Frame-Options`, `nosniff`, `Referrer-Policy`. Warn only. |
| MOD-1 | Pickle-format model files | Walk the `--models` folders (no symlinks out). List `.ckpt`, `.pt`, `.pth`, `.bin` and `.pkl` files, and diffusers parts that have only those. Fail for a file; warn when a safetensors file sits next to it (then most loaders read that one). Nothing is opened except safetensors headers. |
| MOD-1b | Broken safetensors | Read each header (8 bytes and the JSON). A header that does not parse, or that claims more than the file size, is a warn. |
| BE-1 | Plain HTTP to another computer | A URL on another host over `http://`: warn (tokens and prompts unencrypted). |
| OPS | Version | Shown as found; no checks against advisories in v0.1. |

Not checked from outside (left to the hub's conformance table): AUTH-*,
DATA-*, META-*, SUP-*, EXT-*.

## Report

```
ComfyUI 0.39 at http://127.0.0.1:8188
  FAIL  NET-1  Reachable from your network (it answers on 192.168.x.x:8188)
               Why: anyone on your network can use it, and custom nodes run code (T2, T3).
               Fix: start ComfyUI without --listen, or with --listen 127.0.0.1.
                    Comfy Desktop: Settings > Server > Listen address.
  FAIL  NET-2  No login: it answered without credentials
  WARN  WEB-2  Answers any host name, so a web page could drive it (T1)
  PASS  WEB-1  Does not answer other websites
Models in D:\models
  FAIL  MOD-1  2 pickle-format files: old\model.ckpt, vae\x.pt
Summary: 3 failed, 1 warning, 1 passed
```

The JSON form uses the same structure: `{ "profile": "0.1", "checker": "x.y.z",
"targets": [{ "url", "kind", "version", "results": [{ "id", "status",
"evidence", "fix" }] }] }`.

## Decisions (2026-10-13)

1. **Python, standard library only**, run with `uvx` or `pipx run`, and
   published to PyPI with Trusted Publishing (poseorbit's recipe).
2. **In the profile's repository**, as `checker/`, so that a change to a
   requirement and to its check land together.
3. **Working name for now.** The profile and the checker get their names
   just before publishing; npm, PyPI and GitHub are checked then.
4. **Explicit URLs only.** No default ports are tried (see Usage).

## Layout

```
checker/
  pyproject.toml          no dependencies; requires-python >= 3.10
  src/<name>/
    __main__.py           argument parsing, exit codes
    targets.py            identifying a server (read-only requests)
    net.py                this computer's LAN addresses, the NET checks
    web.py                the WEB checks
    models.py             the MOD checks (safetensors headers only)
    report.py             text and JSON, --redact
    fixes.py              fix text per requirement and tool
  tests/                  pytest against local fake servers (http.server)
```

Every outgoing request goes through one function. That function refuses:

- any method other than GET, HEAD and OPTIONS;
- any path other than a fixed list of endpoints known to change nothing,
  under the path the named URL gives;
- any query string;
- any host that is neither named by the owner nor one of this computer's
  own addresses.

The tests assert all of these. The path list exists because a safe method
is not enough: ComfyUI-Manager, for one, removes and restores snapshots on
GET requests. ComfyUI-Manager's `security_level` cannot be read safely, so
EXT-1 says that the Manager is present, and how reachable the server is.

### Language (for the record)

| | Python, standard library only | Node, no dependencies | Go, one binary |
|---|---|---|---|
| Who already has it | Everyone with ComfyUI or A1111 (but often only inside their venv or Comfy Desktop) | Latentry users; few others | No one needs anything |
| Run it | `uvx <name>` or `pipx run <name>` | `npx <name>` | download, check, run |
| Supply chain | PyPI with Trusted Publishing, as poseorbit is | npm with provenance | GitHub release with attestations |
| Fits this repo's tools | poseorbit's recipe | Latentry's recipe | new toolchain |

Recommendation: **Python, standard library only**. It is what this
audience already runs. There is no dependency to trust. poseorbit's release
recipe can be reused. A Go binary can follow later if people without Python
want it.
