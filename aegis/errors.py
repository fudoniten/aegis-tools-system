"""Aegis error types.

The CLI layer is the only place that should raise ``typer.Exit``.  Library
code raises :class:`AegisError` instead, so that callers can catch it and
decide whether to skip an item or abort.

This matters: ``typer.Exit`` derives from ``RuntimeError``, *not* from
``SystemExit``, so ``except SystemExit`` around a call that raises
``typer.Exit`` never fires.  Guarding per-host loops that way silently turned
"skip this host" into "abort the whole build".
"""


class AegisError(Exception):
    """Base class for all recoverable aegis failures."""


class MissingHostKeyError(AegisError):
    """A host has no age public key configured."""

    def __init__(self, hostname: str):
        self.hostname = hostname
        super().__init__(
            f"No age key configured for {hostname}. "
            f"Set it with: aegis set-master-key {hostname} --public-key 'age1...'"
        )


class AdminKeyError(AegisError):
    """The admin key set is missing, unreadable, or does not match the repo."""


class RealmError(AegisError):
    """A Kerberos realm operation failed."""
