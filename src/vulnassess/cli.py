"""Command-line entry points for the staged VulnAssess pipeline."""

from typing import NoReturn

import typer

app = typer.Typer(
    name="vulnassess",
    help="Local-first vulnerability prioritisation for authorised lab targets only.",
    no_args_is_help=True,
)


def _not_implemented() -> NoReturn:
    typer.echo("not implemented")
    raise typer.Exit(code=2)


@app.command()
def scan() -> None:
    """Collect evidence from authorised lab targets."""
    _not_implemented()


@app.command()
def enrich() -> None:
    """Enrich findings with locally cached intelligence."""
    _not_implemented()


@app.command()
def context() -> None:
    """Infer bounded deployment context from evidence."""
    _not_implemented()


@app.command()
def rank() -> None:
    """Rank findings with the documented scoring formula."""
    _not_implemented()


@app.command()
def explain() -> None:
    """Write plain-English rationales without changing scores."""
    _not_implemented()


@app.command()
def report() -> None:
    """Render an offline report."""
    _not_implemented()


@app.command()
def eval() -> None:
    """Compare rankings with expert judgments."""
    _not_implemented()


@app.command()
def intel() -> None:
    """Manage the local intelligence cache."""
    _not_implemented()


if __name__ == "__main__":
    app()
