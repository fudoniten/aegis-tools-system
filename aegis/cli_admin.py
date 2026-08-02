"""``aegis admin`` — manage the admin recipient set."""

from pathlib import Path
from typing import Optional

import typer

from . import admin, config, crypto
from .errors import AegisError

admin_app = typer.Typer(
    name="admin",
    help="Manage the admin keys every secret is encrypted for.",
    no_args_is_help=True,
)


def _repo(secrets_path: Optional[Path]) -> config.SecretsRepo:
    from .cli import get_secrets_repo
    return get_secrets_repo(secrets_path)


@admin_app.command("list-keys")
def list_keys(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Show the admin keys this repo encrypts for."""
    repo = _repo(secrets_path)

    try:
        keys = admin.recipients(repo)
    except AegisError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)

    try:
        local = admin.local_public_key()
    except AegisError:
        local = None

    typer.echo(f"Admin keys ({len(keys)}):")
    for path in admin.recipient_files(repo):
        key = admin._parse_pubkey_file(path)
        marker = "  <- this machine" if key and key == local else ""
        typer.echo(f"  {path.name:<24} {key}{marker}")

    if local and local not in keys:
        typer.secho(
            f"\nThis machine's key is NOT registered: {local}\n"
            f"Anything you encrypt would be unreadable by the other admins.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if len(keys) == 1:
        typer.secho(
            "\nOnly one admin key is registered. Losing it makes every role key,\n"
            "user key and Kerberos realm permanently unrecoverable -- hosts keep\n"
            "running, but no host can ever be added to a realm or role again.\n"
            "Register an offline backup: aegis admin add-key --name backup --public-key age1...",
            fg=typer.colors.YELLOW,
        )


@admin_app.command("add-key")
def add_key(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    name: str = typer.Option(..., "--name", "-n", help="Short label, e.g. 'laptop' or 'backup'"),
    public_key: Optional[str] = typer.Option(None, "--public-key", "-k", help="age public key (default: this machine's)"),
):
    """Register an admin public key.

    New secrets are encrypted for every registered key.  Existing secrets are
    unchanged until you run 'aegis reencrypt', which extends the new key's
    reach without touching key material.
    """
    repo = _repo(secrets_path)
    repo.ensure_structure()

    if public_key is None:
        public_key = admin.local_public_key()
        typer.echo(f"Using this machine's admin key: {public_key}")

    out = admin.add_key(repo, public_key, name)

    typer.secho(f"Registered admin key '{name}'", fg=typer.colors.GREEN)
    typer.echo(f"  {out}")
    typer.echo("")
    typer.echo("Existing secrets are still encrypted for the old set. To extend")
    typer.echo("this key's reach to them:  aegis reencrypt")


@admin_app.command("remove-key")
def remove_key(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    name: str = typer.Option(..., "--name", "-n", help="Label of the key to remove"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Unregister an admin public key."""
    repo = _repo(secrets_path)

    path = repo.admin_keys_path() / f"{name}.pub"
    if not path.exists():
        typer.echo(f"Error: No admin key named '{name}' at {path}", err=True)
        raise typer.Exit(1)

    remaining = [p for p in admin.recipient_files(repo) if p != path]
    if not remaining:
        typer.echo(
            "Error: refusing to remove the last admin key -- every secret in "
            "the repo would become unrecoverable.",
            err=True,
        )
        raise typer.Exit(1)

    if not yes:
        typer.secho(
            "Existing secrets stay encrypted for this key until 'aegis reencrypt' "
            "rewrites them, and git history keeps the old ciphertext regardless.",
            fg=typer.colors.YELLOW,
        )
        if not typer.confirm(f"Unregister admin key '{name}'?"):
            raise typer.Abort()

    path.unlink()
    typer.secho(f"Unregistered '{name}'", fg=typer.colors.GREEN)
    typer.echo("Run 'aegis reencrypt' to rewrite existing secrets without it.")


@admin_app.command("migrate")
def migrate(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Convert a legacy keys/admin.pub into the keys/admin/ directory form."""
    repo = _repo(secrets_path)

    out = admin.migrate_legacy(repo)
    if out is None:
        typer.echo("Nothing to migrate: no keys/admin.pub present.")
        return

    typer.secho(f"Migrated admin key to {out}", fg=typer.colors.GREEN)
    typer.echo("Add a second, offline key with: aegis admin add-key --name backup")


@admin_app.command("init")
def init(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    name: str = typer.Option("primary", "--name", "-n"),
):
    """Generate an admin key for this machine if absent, and register it."""
    repo = _repo(secrets_path)
    repo.ensure_structure()

    key_path = crypto.default_admin_key_path()
    if key_path.exists():
        typer.echo(f"Admin key already exists at {key_path}")
    else:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        keypair = crypto.generate_age_keypair()
        key_path.write_text(keypair.private_key + "\n")
        key_path.chmod(0o600)
        typer.secho(f"Generated admin key at {key_path}", fg=typer.colors.GREEN)
        typer.secho(
            "Back this up now. Without it you cannot decrypt anything in the repo.",
            fg=typer.colors.YELLOW,
        )

    public_key = crypto.get_admin_public_key()

    try:
        existing = admin.recipients(repo)
    except AegisError:
        existing = []

    if public_key in existing:
        typer.echo(f"Already registered: {public_key}")
        return

    out = admin.add_key(repo, public_key, name)
    typer.secho(f"Registered as '{name}'", fg=typer.colors.GREEN)
    typer.echo(f"  {out}")
