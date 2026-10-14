# ligsp: the LIGSP checker

Checks the image-generation servers and model folders you name against the
Local Image Generation Security Profile ([profile.md](https://github.com/33rd-kk/local-image-gen-security/blob/main/profile.md)). It is
read-only, and it contacts only the places you point it at.

```
ligsp check http://127.0.0.1:8188                      # a ComfyUI
ligsp check http://127.0.0.1:7860 --models D:\models   # A1111 / Forge and a model folder
ligsp check http://127.0.0.1:3000 --redact             # a report you can share
ligsp check --private C:\latentry                       # who can read Latentry's settings and keys
ligsp check http://127.0.0.1:3000 --follow              # Latentry, and every backend it is set up to use
```

Common default ports: ComfyUI 8188, Comfy Desktop 8000, A1111 / Forge 7860,
Latentry 3000, InvokeAI 9090, SwarmUI 7801. It tries no port you did not
name.

## What it recognises

ComfyUI (and ComfyUI-Manager), AUTOMATIC1111 / Forge, InvokeAI, SwarmUI,
Latentry and its engine, and other servers on Latentry's backend API. It
checks any other web server with the general checks.

## What it checks

| ID | What |
|---|---|
| NET-1 | Whether a server on 127.0.0.1 also answers on this computer's network addresses (IPv4 and IPv6) |
| NET-2 | Whether it can be used from the network without a login or pairing |
| BE-1 | A server on another computer reached over plain HTTP |
| WEB-1 | Whether other websites may read its answers (CORS) |
| WEB-2 | Whether it answers for any host name (DNS rebinding) |
| WEB-3 | Protective headers on its page |
| EXT-1 | An extension installer on the server (ComfyUI-Manager, InvokeAI's node-pack installer), and how many node packs or A1111 extensions it runs (counts only, never names or folders) |
| BE-2 | Whether Latentry's engine needs its token (its model list, asked without one) |
| AUTH-1 | InvokeAI with accounts turned on but no administrator yet, so whoever opens it first becomes one |
| OPS-3 | Whether the ComfyUI or ComfyUI-Manager version running has a published security advisory, from a table that ships with the checker (nothing is fetched); the report says how old the table is |
| DATA-4 | Who besides you can read a hub's private files (`--private FILE` or a folder; Latentry's settings and keys are found by name). Only permissions are read, never content. |
| MOD-1 | Weight files in a pickle format (`.ckpt`, `.pt`, `.pth`, `.bin`, `.pkl`), files named `.safetensors` that are really pickles, and safetensors headers that do not read |

Exit code 0 when nothing failed, 1 when something failed, 2 for a usage
error. `--json FILE` (or `-`) writes the same report as JSON.

## What it does not do

- It sends only GET, HEAD and OPTIONS, only to a fixed list of endpoints
  known to change nothing, with no query strings, to the URLs you give and
  to the same port on this computer's own addresses. One function sends
  every request, and it refuses anything else (`transport.py`). A safe
  method alone is not enough: some servers act on a GET (ComfyUI-Manager
  releases from 2024 removed and restored snapshots on one). It never queues a job, uploads a
  file or changes a setting.
- It reads only the fields it needs. ComfyUI's `/system_stats` also lists
  the server's command line; that is dropped unread.
- With `--follow` it reads a hub's backend list (Latentry's `/api/settings`,
  which answers only on the computer the hub runs on) and keeps only each
  backend's URL. Folders, model names and the rest are dropped unread, and
  the backends' own backends are not followed.
- In model folders it opens only `.safetensors` files, and only to read
  their header. It follows no links out of the folder.
- For private files it reads only their permissions: the mode, or on
  Windows the access list, through the Windows API and compared by account
  ID (SID), so it works in any system language.
- It sends no telemetry and checks for no updates, and it writes no file
  unless you ask (`--json FILE`).
- A pass means these checks found no problem, not that the setup is safe.

Standard library only (Python 3.10+). Tests: `pytest` in this folder, with
`src` on the path.
