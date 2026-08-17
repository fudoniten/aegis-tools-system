"""Shared presentation for every ``aegis <thing> delete``.

One renderer for all of them, so a deletion reads the same whatever it is
deleting: what goes, what changes, what still points at it, and what to run
afterwards.  The planners in :mod:`aegis.removal` decide; this only shows and
confirms.
"""

import typer

from .removal import Removal, apply


def _age_note(path) -> str:
    if not path.is_dir():
        return ""
    count = len(list(path.rglob("*.age")))
    return f"  ({count} encrypted file(s))" if count else ""


def run_removal(
    removal: Removal,
    *,
    force: bool = False,
    yes: bool = False,
    dry_run: bool = False,
) -> None:
    """Show a planned removal, refuse or confirm it, then carry it out."""
    if removal.is_empty and not removal.blockers:
        typer.echo(
            f"Nothing to remove: no {removal.kind} '{removal.name}' "
            f"in this repository."
        )
        raise typer.Exit(1)

    typer.echo(f"\nDeleting {removal.kind} '{removal.name}' would remove:")

    if removal.paths:
        for path in removal.paths:
            kind = "dir " if path.is_dir() else "file"
            typer.echo(f"  {kind}  {path}{_age_note(path)}")
    if removal.edits:
        for edit in removal.edits:
            typer.echo(f"  edit  {edit.description}")

    for warning in removal.warnings:
        typer.secho(f"\n  {warning}", fg=typer.colors.YELLOW)

    if removal.blockers:
        count = len(removal.blockers)
        typer.secho(
            f"\nSomething still refers to this {removal.kind}:" if count == 1
            else f"\n{count} things still refer to this {removal.kind}:",
            fg=typer.colors.RED,
        )
        for blocker in removal.blockers:
            typer.echo(f"  - {blocker}")

        if not force:
            typer.secho(
                "\nRefusing to delete. Remove the references first, or pass "
                "--force to delete anyway and clean up after.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)

        typer.secho(
            "\n--force given: deleting despite the above.", fg=typer.colors.YELLOW
        )

    if dry_run:
        typer.echo("\n[dry-run] Nothing was removed.")
        return

    if not yes and not typer.confirm(f"\nDelete {removal.kind} '{removal.name}'?"):
        raise typer.Abort()

    apply(removal)

    typer.secho(f"\nDeleted {removal.kind} '{removal.name}'.", fg=typer.colors.GREEN)
    for step in removal.follow_up:
        typer.echo(f"  Next: {step}")
