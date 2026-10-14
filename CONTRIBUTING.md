# Contributing

Thank you for helping. There are two kinds of change here, and they work a
little differently.

## Changing the profile

The profile is a draft (0.1), so its requirements can still change. Open an
issue with the **Profile change** form first, before you write a pull
request. It asks for:

- the requirement (an existing ID such as NET-2, or "new");
- the threat it is about (T1 to T7 in section 4 of the profile), or a new one;
- what a setup should do, and why. Real tools or incidents help: link
  public sources, never your own setup;
- how someone would check it, from outside the tool if possible.

A requirement must be checkable, and it must not ask for anything that
sends data off the user's computer. A MUST is for what every conforming
tool can do; anything that costs some tools real effort is a SHOULD.

Changes are recorded in [CHANGELOG.md](CHANGELOG.md). A version that
changes what a MUST asks for gets a new minor number (0.2), so that
conformance claims name what they were checked against.

## Changing the checker

The checker (`checker/`) is a Python package with no dependencies. To work
on it:

```
cd checker
pip install -e . pytest ruff==0.17.0
ruff check .
pytest -q
```

It keeps a few rules, and a pull request that breaks one will not be merged:

- **Read-only.** Every request goes through `transport.py`, which allows only
  GET, HEAD and OPTIONS to the fixed endpoints in `SAFE_PATHS`. A new
  endpoint needs a note on why it changes nothing on every version of the
  server, since some servers act on a GET.
- **Only where you point it.** No scanning, no default ports, no requests to
  anything but the named URLs and this computer's own addresses.
- **Nothing kept that is not needed.** Read only the fields a check uses.
  Never keep names of extensions, models or files beyond what the report
  shows, and never read a file's content when its permissions are enough.
- **Standard library only**, Python 3.10 or newer, working on Linux,
  Windows and macOS. CI runs all three.
- **Tests with fake servers**, never against real ones, and nothing fetched
  from the network.

## Reports and privacy

Please do not post your own addresses, ports, folder names, user name or
pictures in an issue. `ligsp check --redact` makes a report you can paste
as it is.

Security problems in the checker go through private reporting, not issues:
see [SECURITY.md](SECURITY.md).

By contributing you agree that your contribution is licensed like the
part it changes: the profile under CC BY 4.0, the checker under the
Apache License 2.0.
