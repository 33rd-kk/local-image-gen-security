# Local Image Generation Security Profile (LIGSP)

Image generation runs on people's own computers: a web UI or hub drives a
generation server (ComfyUI, AUTOMATIC1111 / Forge, a diffusers server),
loads model files from the internet and runs extensions written by others.
Most of these tools were made for one person on one machine. Many have no
login, and can run downloaded code. Once one of them can be reached from a
network, it can be taken over.

LIGSP says what such a setup must do to be **secure by default**: safe as
installed, and still safe when you turn on what you want, such as using it
from your phone. It has three parts:

- **[The profile](profile.md)**: the requirements. There are two levels:
  this computer only, and the local network. Each requirement has its
  reason and a way to check it.
- **[The checker](checker/)** (`ligsp`): checks the servers and folders you
  name against the profile. It only reads, and only where you point it.
- **Conformance tables**: how a tool meets each requirement.
  [Latentry](https://github.com/33rd-kk/latentry) is the reference
  implementation (see below).

Status: **0.1 draft**. Requirements may still change, and feedback is
welcome (see Contributing).

## Check your setup

```
uvx local-image-gen-security check http://127.0.0.1:8188
pipx run local-image-gen-security check http://127.0.0.1:7860 --models D:\models
```

Once installed, the shorter `ligsp` works too. Name each server you run,
and optionally your model folders (`--models`) and a hub's settings folder
(`--private`). It tries no other addresses or ports. See [checker/README.md](checker/README.md) for what it checks, and
what it never does.

## Claiming conformance

A tool may say it conforms to "LIGSP 0.1, level 1 (or 2)" when, in its
**default configuration**, it meets every MUST at that level, and it
publishes a conformance table: for each requirement, its state (met, partly
met, not met) and where it is done, or why it is not.

## Tools that claim conformance

| Tool | Claim | Table |
|---|---|---|
| [Latentry](https://github.com/33rd-kk/latentry) (a hub over ComfyUI, A1111 / Forge and its own engine) | LIGSP 0.1, level 2 | [conformance table](https://33rd-kk.github.io/latentry/reference/ligsp/) |

To add a tool, open a pull request with a link to its published table.

## The name

"Local Image Generation Security Profile" and "LIGSP" name this profile
only. A changed version of the profile is welcome under its licence, but
give it another name, and do not call it LIGSP. Do not say a tool conforms
to LIGSP unless it meets the rule above.

## Using the text

The profile is under [CC BY 4.0](LICENSE-CC-BY-4.0): you may copy,
translate and adapt it, also commercially, if you give credit. Credit it
like this, and say whether you changed it:

> "Local Image Generation Security Profile 0.1" by 33rd-kk,
> https://github.com/33rd-kk/local-image-gen-security, licensed under
> CC BY 4.0.

The checker is under the [Apache License 2.0](checker/LICENSE). See
[NOTICE](NOTICE).

## Contributing and security

Issues and pull requests are welcome; [CONTRIBUTING.md](CONTRIBUTING.md)
says how changes to the profile and the checker work. Please do not post
your own addresses, ports, folder names or pictures; `ligsp check --redact`
makes a report you can paste. Report a security problem in the checker privately,
through GitHub's "Report a vulnerability" (see [SECURITY.md](SECURITY.md)).
