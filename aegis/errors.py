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
    """Base class for all recoverable aegis failures.

    Kept free of any CLI framework so library code stays importable on its
    own.  :func:`aegis.cli.main` turns it into a one-line message and a
    non-zero exit; the Typer app disables pretty tracebacks so that handler
    is reached before anything is printed.
    """


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


class ConfigError(AegisError):
    """A file under src/ does not say what it appears to say.

    Raised rather than defaulted around: a host whose status is misspelled
    would otherwise read as "active" and quietly start receiving secrets
    again.
    """
