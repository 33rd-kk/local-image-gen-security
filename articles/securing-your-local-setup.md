# Securing your local image generation setup

*October 2026, by [33rd-kk](https://github.com/33rd-kk)*

## Why I built this

Running image generation locally gives you control over your models, workflows, and images. But the tools most of us use, such as ComfyUI, AUTOMATIC1111 / Forge, InvokeAI, and SwarmUI, were built primarily for single-user setups. Security is often left to whoever installs them, and many setup guides focus on getting the software running rather than securing it.

I wanted local image generation to be secure by default: safe as installed, and still safe when you turn on what you want, such as using it from your phone. So I wrote down what that should mean as a short security profile, the **Local Image Generation Security Profile (LIGSP)**, and built a read-only checker that tests a setup against it. I built both with an AI coding agent. A later section explains how I used it and what I had to verify myself.

## The problem

A local image generation server is much easier to secure when only your own computer can reach it. ComfyUI and the others were built for one person on one machine: most run without a login by default, and their extensions and custom nodes run code on your computer.

Bound to 127.0.0.1, that is mostly fine, though not risk-free: a web page in your browser can still reach the server, as the table below explains. The risk grows when the server listens on a network other devices can reach: a `--listen` flag, a published Docker port, a guide that says "use 0.0.0.0 to reach it from your phone". Depending on the authentication settings, enabled features, and firewall rules, someone on that network, or an internet user if the port is forwarded and reachable, may be able to queue jobs, access generated outputs, or install code through an exposed extension manager.

Configuration and exposure issues can exist even without a software vulnerability. Published vulnerabilities can add to the risk.

### Seven common issues

Seven issues account for much of the risk, covering configuration, files, extensions, and software versions. Many can be checked automatically, and some are quick to fix.

| Issue | What it means | Where it shows up |
| --- | --- | --- |
| Listening on the network | Other devices can reach the server, not only this computer | `--listen` (ComfyUI, A1111 / Forge), `host: 0.0.0.0` (InvokeAI), Network > Host (SwarmUI) |
| Authentication disabled or unavailable | An unauthenticated user may be able to use exposed functions | ComfyUI has no login of its own; A1111 / Forge, InvokeAI and SwarmUI have one, off by default |
| No host name check | A malicious site can use DNS rebinding: an attacker-controlled host name is made to resolve to your computer, so your browser sends that site's requests to the local server. A server that does not check the `Host` header answers them | ComfyUI, A1111 / Forge, InvokeAI and SwarmUI, also on 127.0.0.1 |
| CORS open to every site | The server tells browsers that any website may read its answers, so a page you visit can read your outputs and settings | `--enable-cors-header` (ComfyUI), `--cors-allow-origins` (A1111 / Forge), `allow_origins` (InvokeAI) |
| Pickle-based model files | Many `.ckpt`, `.pt`, `.pth` and `.bin` files use Python's pickle format, and loading an untrusted pickle can run any code in it. The name alone does not prove the format | Old downloads, and model folders with no `.safetensors` version |
| An extension installer you can reach | Anyone who can use the server can install code | ComfyUI-Manager (what it may install depends on its `security_level` and its separate `allow_git_url_install` / `allow_pip_install` switches); InvokeAI's node-pack installer, open to everyone in its default single-user mode |
| An old version with published advisories | Attackers try what the advisories describe first | ComfyUI before 0.28.0 is affected by four high-severity advisories published on July 15, 2026 (path traversal, stored XSS); see [its advisories](https://github.com/Comfy-Org/ComfyUI/security/advisories). The separately versioned ComfyUI frontend has [its own](https://github.com/Comfy-Org/ComfyUI_frontend/security/advisories): three high-severity XSS advisories published on August 18, 2026 (one affects cloud deployments only); comfyui-frontend-package 1.50.6 or later on PyPI includes all three fixes |

## What I built

LIGSP has three parts, each usable on its own:

1. **[The profile](../profile.md)**: the requirements. It covers seven threats: a website you visit, another device on your network, internet scanners, model files and extensions, swapped downloads, someone using the computer later, and whoever receives a picture you share. There are two levels: this computer only (1), and the local network (2). Each requirement says MUST or SHOULD, why, and how to check it.
2. **[The checker](../checker/)**, `ligsp`: checks the servers and folders you specify against the subset of requirements it can verify automatically.
3. **Conformance tables**: a tool may claim a level only when its default configuration meets every MUST at that level, and it publishes a table that shows how, requirement by requirement. The rule is the profile's; whether a tool meets it is shown by its table, not by its claim.

[Latentry](https://github.com/33rd-kk/latentry), my self-hosted hub over ComfyUI, A1111 / Forge and its own engine, is the reference implementation. It claims level 2 and publishes [its table](https://33rd-kk.github.io/latentry/reference/ligsp/). I used Latentry as a test case for the profile. Whenever it fell short of a requirement, I investigated whether the implementation needed a change or the requirement needed clarification. That feedback loop helped me refine both, rather than treating the profile as a checklist to pass.

## Check your setup in one command

`ligsp` is a small checker for these issues. It runs on Python 3.10 or newer. With [uv](https://docs.astral.sh/uv/) installed, one command fetches and runs it:

```bash
uvx local-image-gen-security check http://127.0.0.1:8188
```

Name each server you run (ComfyUI 8188, Comfy Desktop 8000, A1111 / Forge 7860, InvokeAI 9090, SwarmUI 7801 by default), and optionally a model folder:

```bash
uvx local-image-gen-security check http://127.0.0.1:8188 http://127.0.0.1:7860 --models D:\models
```

With [pipx](https://pipx.pypa.io/) instead, `pipx run local-image-gen-security check ...` does the same. In PowerShell, put a path with spaces in quotes (`--models "D:\AI models"`). Here is an example report from a ComfyUI with ComfyUI-Manager, running with its default settings:

```text
ComfyUI 0.39.2 at http://127.0.0.1:8188
  WARN  WEB-2  Does not check host names, so a web page may reach it through DNS rebinding
               Fix: Keep it on 127.0.0.1 and put a hub in front that checks host names, or an
                    authenticating reverse proxy that does.
  WARN  WEB-3  Its page is missing some protective headers
  WARN  EXT-1  An extension installer (ComfyUI-Manager) is on a server that answers any host name
               Fix: In ComfyUI-Manager's config.ini set security_level = strong, and remove node
                    packs you do not use.
  PASS  NET-1  Not reachable from your network
  PASS  NET-2  Only this computer can reach it, so no login is needed
  PASS  WEB-1  Does not let other websites read its answers
  PASS  OPS-3  ComfyUI 0.39.2: no advisory in the checker's data matches (as of 2026-10-14)
               Covers ComfyUI core only: its frontend package is versioned separately, and its advisories are not checked

Summary: 0 failed, 3 warnings, 4 passed, 0 not checked
```

Read this one from the bottom up. No other device can reach the server (NET-1, NET-2), and CORS is closed (WEB-1). OPS-3 passes because no advisory in the checker's bundled data matches ComfyUI core 0.39.2; that is narrower than "no known vulnerabilities" (see the limitations below). The warnings are all about your own browser: the server does not check host names (WEB-2), so a malicious page could reach it through DNS rebinding, and ComfyUI-Manager sits on that same server (EXT-1). WEB-3 is minor while the server stays local.

That is the point of keeping the checks separate. Reaching the server from other devices and reaching it through your browser are different paths, and a server closed to the first can still be open to the second.

Each finding names its requirement, says what was found and why it matters, and suggests a fix for that tool. A failure makes the command exit with 1, so it can run in a script. Use the URL and port of the server you actually run.

## What the checker will not do

A security tool you run on your own machine should be easy to trust, so the checker keeps these rules in code, and its tests hold it to them:

- **It is designed to be read-only.** It sends only GET, HEAD and OPTIONS requests, but the method alone is not enough: ComfyUI-Manager releases from 2024 removed and restored snapshots on a GET. So it asks only an explicit allowlist of endpoints, each reviewed in that tool's source to confirm that the checker's requests are not designed to change server state, and its tests verify that nothing else is sent.
- **It goes only where you point it.** It contacts the URLs you name and the same port on this computer's own network addresses, to see whether a server meant for 127.0.0.1 also answers there. It scans no ports and no hosts.
- **It keeps only what it needs.** Some answers carry more than a check needs: ComfyUI's command line, InvokeAI's administrator email, extension names. The checker discards the command line and the email, and where a check needs only a number, such as how many extensions are installed, it keeps the count rather than the names. In model folders it reads `.safetensors` headers only, and for private files it reads permissions, never content.
- **It sends nothing anywhere.** There is no telemetry and no update check. The advisory table ships with each release.
- **It is small.** Python's standard library only, no dependencies, published to PyPI with Trusted Publishing and provenance.

To share a report, for example in an issue, add `--redact`: addresses, ports, paths and host names are replaced by placeholders.

A clean report is not proof that a setup is secure. The checker looks for a defined set of configuration and exposure issues, plus published advisories for the versions it can read. It is not a penetration test, and flaws outside that scope, such as a malicious extension you already installed, can still be there.

## Fixes, tool by tool

The first fix is the same everywhere: keep the server on 127.0.0.1. To use it from your phone, put an authenticating gateway or reverse proxy in front of it rather than exposing the server itself, limit who can reach that gateway, and use HTTPS where you can.

The settings below were checked against each project's source in October 2026 (ComfyUI, ComfyUI-Manager, AUTOMATIC1111, Forge Neo, InvokeAI 6.14, SwarmUI). Names and defaults change between versions, so check them against the version you run.

| Tool | Keep it local | If it must be on the network | Extensions | CORS |
| --- | --- | --- | --- | --- |
| ComfyUI | Start without `--listen` (its default is 127.0.0.1); in Comfy Desktop, set the listen address to 127.0.0.1 | It has no login of its own: use a hub that pairs devices, or an authenticating reverse proxy | In ComfyUI-Manager's `config.ini`, set `security_level = strong` and keep `allow_git_url_install` and `allow_pip_install` off (their default); remove unused node packs | Start without `--enable-cors-header` |
| AUTOMATIC1111 / Forge | Start without `--listen` | `--api-auth` protects the API and `--gradio-auth` the web UI: set both | Remove unused extensions; never add `--enable-insecure-extension-access` on the network | Leave out `--cors-allow-origins`, or list only your own origin |
| InvokeAI | `host: 127.0.0.1` in `invokeai.yaml` (the default) | `multiuser: true`, and create the administrator at once | `multiuser: true` also limits the node-pack installer to the administrator | Remove `"*"` from `allow_origins` |
| SwarmUI | Network > Host = `localhost` (the default) | Turn on UserAuthorization > AuthorizationRequired, or set Network > RequiredAuthorization | Remove unused extensions | Leave Network > AccessControlAllowOrigin empty |

None of these four checks the `Host` header, so none has a setting against DNS rebinding. A hub or proxy in front that refuses unknown host names closes it; until then, keep the server on 127.0.0.1 and stop it when you are not using it.

For model files, prefer `.safetensors` weights from trusted publishers over pickle-based checkpoints, and keep each tool updated past its published advisories.

## How I built it

I built LIGSP, and most of Latentry, with an AI coding agent (Claude Code). The split of work was clear. I decided what to build and the rules it had to keep: privacy first, read-only, no scanning, standard library only, the name and the licences. The agent wrote the code, the tests and most of the text. Nothing reached the main branch without a pull request I read and approved.

The agent was fast at code and tests. What took me was checking that what it wrote was true:

- **Every endpoint was read in the tool's source** before the checker was allowed to ask it.
- **Tests run against fake servers**, and CI runs them on Linux, Windows and macOS.
- **I ran it on my own setup**: ComfyUI, Forge Neo, InvokeAI in single-user and multi-user mode, SwarmUI, Latentry and its engine.
- **A second AI reviewed this article**, and found claims worded more strongly than the facts.

That checking found real mistakes, which is why I trust the result more than I would have trusted the first draft:

- The Windows permission check passed on my computer and failed on a CI runner. Windows tools print account names in the system's language, and the computer name in the environment is cut to 15 characters. It now compares account IDs (SIDs) through the Windows API.
- The checker's notes said ComfyUI-Manager changes state on a GET. That was true of its 2024 releases, not its current ones, and is now said that way.
- Real servers revealed gaps that tests had missed. I added a dedicated check for InvokeAI's node-pack installer because it was available to everyone in single-user mode. I also increased a timeout after a development server's initial response took longer than four seconds.
- Writing the profile next to Latentry found gaps in Latentry too, such as a model folder that could still load pickle weights. Each was fixed and released before the profile was published.

An agent writes a confident sentence as easily as a correct one. The parts that needed me were deciding the rules, checking claims against sources, and running it on real machines.

## Limitations and next steps

LIGSP is an early draft (version 0.1), and the checker covers only what it can verify automatically:

- It cannot tell whether an extension you already installed is malicious, or read ComfyUI-Manager's `security_level` (no endpoint shows it safely).
- Its DNS rebinding check looks at how a server answers an unknown host name; it does not run an attack.
- It matches advisories for ComfyUI core and ComfyUI-Manager only. It does not yet check the separately versioned ComfyUI frontend package, which has its own published advisories, or perform advisory matching for AUTOMATIC1111 / Forge, InvokeAI, or SwarmUI. ComfyUI reports only the frontend version it requires, not the one installed, so the checker cannot yet read it.

A PASS for OPS-3 means that no matching advisory was found in the checker's bundled data for the component and version it recognizes. It does not mean that every component in the installation is free of known vulnerabilities.

Open questions for the next version of the profile include whether level 2 should require HTTPS on the local network, what a generation server alone (without a hub) can meet, and a machine-readable form of the conformance table.

If a requirement is missing, too strict or wrong for the tool you use, please [open an issue](https://github.com/33rd-kk/local-image-gen-security/issues). The profile is licensed under CC BY 4.0 and the checker under Apache-2.0. A tool that publishes its own conformance table is very welcome in the list.

## Links

- [LIGSP: the profile, the checker and how to contribute](https://github.com/33rd-kk/local-image-gen-security)
- [The checker on PyPI](https://pypi.org/project/local-image-gen-security/)
- [Latentry's conformance table](https://33rd-kk.github.io/latentry/reference/ligsp/)
- [ComfyUI's security advisories](https://github.com/Comfy-Org/ComfyUI/security/advisories)
- [The ComfyUI frontend's security advisories](https://github.com/Comfy-Org/ComfyUI_frontend/security/advisories)
