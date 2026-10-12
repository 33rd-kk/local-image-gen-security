# Secure Local Generation Profile

**Version:** 0.1 draft (not published)
**Status:** working draft, every requirement is open to change

## 1. Purpose

Image generation runs on people's own computers. Typically a web UI or hub
drives a generation server (ComfyUI, an A1111-style web UI, a diffusers
server), loads model files from the internet, and runs extensions written by
strangers. Most of these tools were built for one person on one machine.
Many have no login and run downloaded code. Once one of them is reached from
a network, it can be taken over.

This profile states what a setup must do to be **secure by default**. That
means it is safe as installed, with no hardening steps, and it stays safe
when the owner turns on the features they want, such as using it from a
phone. It is written so that:

- a **hub** (a front end that drives one or more generation servers) can
  claim conformance and so protect the servers behind it;
- a **generation server** can adopt the parts that apply to it;
- an **owner** can check their own setup against it.

## 2. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as
described in RFC 2119 and RFC 8174 when, and only when, they appear in
capitals.

Terms:

- **Host**: the computer the software runs on.
- **Owner**: the person who installed it and controls the host.
- **Device**: any other computer or phone that reaches the software over a
  network.
- **Hub**: software that serves a user interface and sends work to one or
  more generation servers.
- **Generation server** (or **backend**): software that runs models and
  returns pictures.
- **Component**: a hub or a generation server.

## 3. Scope

**In scope:**

- components running on the owner's host;
- use from devices on the owner's local network;
- the model files, workflows and dependencies that these components load.

**Out of scope:**

- serving the internet or several mutually untrusted users. A component that
  conforms MAY be put behind an authenticating reverse proxy for that, but
  this profile does not cover the proxy;
- the content of generated pictures;
- isolating GPU drivers or the operating system;
- an attacker who already runs code as the owner.

## 4. Threats

| ID | Who | What they try |
|---|---|---|
| T1 | A website the owner visits | Drive the local server from the owner's browser (CSRF), or read its answers after DNS rebinding |
| T2 | Another device on the local network | Use the server, read pictures and prompts, change settings |
| T3 | An internet scanner | Find a server that was exposed by accident, and run code through it |
| T4 | A model file, workflow or extension | Run code when it is loaded |
| T5 | The supply chain | Swap a downloaded model or package for a malicious one |
| T6 | Someone who uses the host or browser later | Find prompts, pictures or tokens that were left behind |
| T7 | Whoever receives a shared picture | Read the prompt, local paths or device data embedded in it |

## 5. Levels

- **Level 1, Local:** only the host uses the component. Every requirement
  marked L1 applies.
- **Level 2, Network:** devices on the local network use it as well. Every
  requirement applies.

A component claims a level only when it meets every MUST at that level in
its **default configuration**. A requirement that is met only after the
owner changes a setting does not count.

## 6. Requirements

Each requirement gives its level, the rule, why it exists, and how to check
it.

### 6.1 Network exposure (NET)

**NET-1 (L1, MUST)** A component listens on loopback addresses only, unless
the owner explicitly asks for more.
*Why:* T3. Most exposed servers were opened by a default or by a guide.
*Check:* start it with a fresh configuration and list its listening sockets.

**NET-2 (L2, MUST)** When it listens beyond loopback, the component answers
requests from other addresses only after the device is authenticated
(AUTH-1). It MUST NOT offer an unauthenticated network mode.
*Why:* T2 and T3.
*Check:* from a second device, every route other than enrolment is refused.

**NET-3 (L1, MUST)** A hub that sends work to a generation server with no
authentication of its own MUST warn the owner when that server is set at a
non-loopback address without credentials.
*Why:* T3. The hub cannot protect a server that others can reach directly.
*Check:* configure such a server at a LAN address and look for the warning.

**NET-4 (L2, MUST)** Decisions about "this host" versus "a device" use the
address of the TCP peer. A forwarded-for header is believed only when it
comes from a proxy on loopback.
*Why:* T2. A header that anyone can set must not unlock local-only
functions.
*Check:* send a request from a device with `X-Forwarded-For: 127.0.0.1`.

**NET-5 (L1, MUST)** The component connects out only to destinations the
owner configured, or to fixed download sources the owner started a download
from. It sends no telemetry (DATA-1).
*Why:* T6 and T7. It also keeps the owner in control of what leaves the
host.
*Check:* watch outbound connections through a normal session.

### 6.2 Browser-facing HTTP (WEB)

**WEB-1 (L1, MUST)** The component refuses state-changing requests that come
from another site: it checks `Sec-Fetch-Site` or `Origin`. It accepts request
bodies only with a content type that needs a CORS preflight (for example
`application/json`).
*Why:* T1. Any site can send a "simple" POST to `http://localhost`.
*Check:* send a cross-site POST, and a `text/plain` POST.

**WEB-2 (L1, MUST)** The component answers only for the `Host` names it
expects: `localhost`, IP literals, and names the owner adds.
*Why:* T1. DNS rebinding makes an attacker's page same-origin with the
component.
*Check:* send a request with `Host: attacker.example`.

**WEB-3 (L1, SHOULD)** Pages are sent with these headers:

- `frame-ancestors 'none'` (or `X-Frame-Options: DENY`);
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: same-origin`;
- a `Permissions-Policy` that turns off features the component does not use;
- `Cache-Control: no-store` on pages and answers that show prompts or
  pictures.

*Why:* T1 and T6.
*Check:* read the response headers.

**WEB-4 (L2, SHOULD)** Request bodies are limited in size. Requests are
limited per peer, and expensive work (GPU jobs) per peer and in total.
*Why:* T2. A device must not be able to exhaust the host.
*Check:* send an oversized body, then a burst of requests.

**WEB-5 (L2, SHOULD)** Controlling a running job (stopping it, reading its
result) needs an identifier that cannot be guessed. Only the client that
started the job holds it.
*Why:* T2. One device must not stop or read another's job.
*Check:* job identifiers have at least 122 bits of randomness.

### 6.3 Devices (AUTH)

**AUTH-1 (L2, MUST)** A device is enrolled by an action on the host. For
example, the host shows a code and the device enters it. The code is
single-use and expires within minutes.
*Why:* T2. Anyone on the network can reach the enrolment page, but only the
owner can see the host's screen.
*Check:* the code does not work twice, or after it has expired.

**AUTH-2 (L2, MUST)** A device credential:

- is signed or random, with at least 128 bits;
- is kept where page scripts cannot read it (an `HttpOnly`, `SameSite`
  cookie or equivalent);
- expires;
- can be revoked one device at a time, or for all devices at once.

*Why:* T2 and T6.
*Check:* inspect the cookie, then revoke a device and retry from it.

**AUTH-3 (L2, MUST)** By default, administration is available only from the
host. That covers settings, installing or updating software, and choosing
folders and servers.
*Why:* T2. A lost or shared phone must not be able to reconfigure the host.
*Check:* from an enrolled device, every administrative route is refused.

**AUTH-4 (L2, SHOULD)** Enrolled devices are not shown the host's file
paths, folder names or user name. That includes error messages.
*Why:* T2 and T7.
*Check:* trigger errors from a device and read the answers.

**AUTH-5 (L2, MUST)** Enrolment secrets and device lists are stored with
owner-only file permissions. The component SHOULD support keeping the
signing key in the operating system's keychain.
*Why:* T6.
*Check:* read the file modes.

### 6.4 Hub and generation servers (BE)

**BE-1 (L1, MUST)** A credential set up for a generation server is sent only
to that server's origin. It is not sent again after a redirect to another
origin, and it never reaches the browser.
*Why:* T1 and T2.
*Check:* point a server entry at a redirect, and read the settings answers.

**BE-2 (L1, SHOULD)** A generation server that the hub starts itself listens
on loopback and needs a fresh random token, which only the hub holds.
*Why:* T1 and T3. Other local software and web pages must not drive it.
*Check:* call it without the token.

**BE-3 (L1, MUST)** The graphs, workflows and scripts that a server executes
come only from the owner, for example from a folder on the host. They MUST
NOT come from an enrolled device, from a downloaded picture's metadata, or
from a web page.
*Why:* T2 and T4. A workflow can call any installed node, and nodes run code.
*Check:* try to submit a workflow from a device, and try to load one
embedded in a picture.

**BE-4 (L1, SHOULD)** Inputs that the hub uploads to a server (source
pictures, masks, pose images) are overwritten rather than allowed to pile
up. The private mode (DATA-3) removes them, together with the server's
history of the run.
*Why:* T6.
*Check:* run in private mode, then list the server's input folder and
history.

### 6.5 Model files (MOD)

**MOD-1 (L1, MUST)** Weights are loaded only from formats that cannot run
code when loaded, such as safetensors, GGUF or ONNX. Formats based on Python
pickle (`.ckpt`, `.pt`, `.pth`, `.bin`) are refused. The component MAY load
them only with an explicit opt-in from the owner for each file.
*Why:* T4. Loading a pickle runs code.
*Check:* put a pickle-only model where models are found, and try to use it.

**MOD-2 (L1, MUST)** A model that the component downloads by itself comes
from a fixed revision, not a moving branch. Its SHA-256 is checked before it
is used.
*Why:* T5.
*Check:* change a byte in a downloaded file. The component must download it
again or refuse it.

**MOD-3 (L1, SHOULD)** Loading a model does not fetch anything from the
network implicitly. Downloads happen only when the owner asks for one.
*Why:* T5 and NET-5.
*Check:* load models with the network cut off.

**MOD-4 (L1, SHOULD)** To list models and read their metadata, the component
reads only the file headers. It does not load the weights.
*Why:* T4. Files are listed before anyone chooses them.

### 6.6 Extensions (EXT)

**EXT-1 (L1, MUST NOT)** A hub MUST NOT install, update or enable extensions
or custom nodes for a generation server, and it MUST NOT offer a way for an
enrolled device to do so.
*Why:* T4 and T2. Installing an extension is running a stranger's code.

**EXT-2 (L1, SHOULD)** If a component has its own plugin system, it is off by
default. A plugin is enabled from the host only, and plugins cannot weaken
the WEB and AUTH requirements.
*Why:* T4.

### 6.7 The component's own supply chain (SUP)

**SUP-1 (L1, MUST)** The component's dependencies are installed from a lock
that carries a hash for every file, and the installer checks those hashes.
*Why:* T5.
*Check:* the lock files, and the install command it documents.

**SUP-2 (L1, SHOULD)** Releases are built in CI and carry provenance (for
example artifact attestations or Sigstore signatures). The documented install
does not pipe a downloaded script into a shell.
*Why:* T5.

**SUP-3 (L1, SHOULD)** Dependencies are audited automatically for known
vulnerabilities, and the code is analysed statically in CI.
*Why:* T5.

**SUP-4 (L1, MUST)** There is a private way to report vulnerabilities. It is
named in `SECURITY.md`.
*Why:* so problems can be fixed before they are published.

### 6.8 Data (DATA)

**DATA-1 (L1, MUST)** The component sends no telemetry or usage reports. It
turns off those of the frameworks it is built on.
*Why:* T7 and the owner's control over their own data.

**DATA-2 (L1, MUST)** Prompts, pictures, settings and tokens stay on the
host. The one exception is a destination the owner set, such as a generation
server on another computer.

**DATA-3 (L1, SHOULD)** The component leaves nothing behind that it does not
need:

- no pictures in browser storage;
- no prompts in logs;
- prompts kept in browser storage only as the form the owner sees, so they
  can find and clear it;
- an optional private mode that saves nothing (no browser storage of what is
  typed, no saved pictures) and removes what it sent to servers (BE-4).

*Why:* T6.

**DATA-4 (L1, MUST)** Files that hold tokens or settings are written with
owner-only permissions.
*Why:* T6.

### 6.9 Metadata in output files (META)

**META-1 (L1, SHOULD)** Generation metadata embedded in a saved picture
never contains local paths or device data. The private mode embeds none.
*Why:* T7.

**META-2 (L1, SHOULD)** When the component reads metadata from other tools'
pictures, it reads only the header text it needs. It ignores location and
camera data.
*Why:* T7, and to reduce what a malformed file can reach.

### 6.10 Telling the owner (OPS)

**OPS-1 (L1, MUST)** The documentation says what the component protects
against and what it does not, in terms of the threats in section 4.

**OPS-2 (L1, SHOULD)** When a setting lowers protection, the component says
so where the setting is made. Examples: listening beyond loopback, turning
enrolment off, a server reachable without credentials.

## 7. Claiming conformance

A component that claims this profile publishes a conformance table. For each
requirement, the table lists the level, "met", "partly met" or "not met",
and where it is done or why it is not. A claim names the profile version.

## 8. Open questions for 0.2

- Should Level 2 require TLS on the local network, or keep it a SHOULD with
  a documented risk?
- Requirements for generation servers alone, without a hub: which NET and
  WEB rules they can meet themselves.
- A machine-readable form of the conformance table, so a checker tool can
  read it.
- Whether EXT-1 is too strict for hubs that want to offer curated
  extensions.
