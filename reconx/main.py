"""Main entrypoint for RECON-X CLI."""

import typer

from reconx.cli.commands import register_commands

app = typer.Typer(
    name="recon-x",
    help="RECON-X: Lightweight, CLI-only, modular reconnaissance framework.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

register_commands(app)

if __name__ == "__main__":
    app()
