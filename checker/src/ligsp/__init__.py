"""Checks a local image-generation setup against the Local Image Generation Security Profile.

Read-only: it sends GET, HEAD and OPTIONS only, to the servers you name and
to this computer's own addresses, and opens model files only to read
safetensors headers. See checker/DESIGN.md.
"""

__version__ = "0.2.2"
PROFILE_VERSION = "0.1"
