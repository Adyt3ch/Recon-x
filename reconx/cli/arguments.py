"""Common CLI argument options and helpers."""

import typer

ProfileOption = typer.Option(
    "cautious",
    "--profile",
    "-p",
    help="Scan profile: cautious | normal | program-custom",
)

ScopeOption = typer.Option(
    "config/scope.yaml",
    "--scope",
    "-s",
    help="Path to scope.yaml file",
)

RateOption = typer.Option(
    None,
    "--rate",
    "-r",
    help="Requests per second limit override (raising requires --confirm-rate)",
)

ConcurrencyOption = typer.Option(
    None,
    "--concurrency",
    "-c",
    help="Concurrency limit override (raising requires --confirm-rate)",
)

MaxRequestsOption = typer.Option(
    None,
    "--max-requests",
    "-m",
    help="Hard request budget for the scan",
)

ConfirmRateOption = typer.Option(
    False,
    "--confirm-rate",
    help="Explicitly confirm raising rate or concurrency above profile defaults",
)

DryRunOption = typer.Option(
    False,
    "--dry-run",
    help="Estimate request count and print planned tasks without sending requests",
)
