# profilecheck (working name)

Checks the image-generation servers and model folders you name against the
Secure Local Generation Profile ([../profile.md](../profile.md)). It is
read-only, and it contacts only the places you point it at.

```
profilecheck check http://127.0.0.1:8188                      # a ComfyUI
profilecheck check http://127.0.0.1:7860 --models D:\models   # A1111 / Forge and a model folder
profilecheck check http://127.0.0.1:3000 --redact             # a report you can share
```

Common default ports: ComfyUI 8188, Comfy Desktop 8000, A1111 / Forge 7860,
Latentry 3000, InvokeAI 9090, SwarmUI 7801. It tries no port you did not
name.

## What it checks

| ID | What |
|---|---|
| NET-1 | Whether a server on 127.0.0.1 also answers on this computer's network addresses (IPv4 and IPv6) |
| NET-2 | Whether it can be used from the network without a login or pairing |
| BE-1 | A server on another computer reached over plain HTTP |
| WEB-1 | Whether other websites may read its answers (CORS) |
| WEB-2 | Whether it answers for any host name (DNS rebinding) |
| WEB-3 | Protective headers on its page |
| EXT-1 | An extension installer on the server (ComfyUI-Manager), and how many node packs or A1111 extensions it runs (counts only, never names) |
| MOD-1 | Weight files in a pickle format (`.ckpt`, `.pt`, `.pth`, `.bin`, `.pkl`), and safetensors headers that do not read |

Exit code 0 when nothing failed, 1 when something failed, 2 for a usage
error. `--json FILE` (or `-`) writes the same report as JSON.

## What it does not do

- It sends only GET, HEAD and OPTIONS, to the URLs you give and to the same
  port on this computer's own addresses. One function sends every request,
  and it refuses anything else (`transport.py`). It never queues a job,
  uploads a file or changes a setting.
- It reads only the fields it needs. ComfyUI's `/system_stats` also lists
  the server's command line; that is dropped unread.
- In model folders it opens only `.safetensors` files, and only to read
  their header. It follows no links out of the folder.
- It sends no telemetry and checks for no updates, and it writes no file
  unless you ask (`--json FILE`).
- A pass means these checks found no problem, not that the setup is safe.

Standard library only (Python 3.10+). Tests: `pytest` in this folder, with
`src` on the path.
