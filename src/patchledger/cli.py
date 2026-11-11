"""PatchLedger command line interface (skeleton — full CLI lands in a later milestone)."""

from __future__ import annotations

import typer

from patchledger import __version__

app = typer.Typer(
    help="Evidence-first security finding and remediation verification.",
    no_args_is_help=True,
)


@app.callback()
def _callback() -> None:
    """Find it. Understand it. Fix it. Prove it."""


@app.command()
def version() -> None:
    """Show the PatchLedger version."""
    typer.echo(f"patchledger {__version__}")


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
