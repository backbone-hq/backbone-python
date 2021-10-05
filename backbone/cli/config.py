from typing import Dict

import typer
from halo import Halo

from backbone.cli.utilities import Configuration, read_configuration, write_configuration

config_cli = typer.Typer()


@config_cli.command("list")
def config_list():
    config: Dict[Configuration, str] = read_configuration()

    for key, value in config.items():
        typer.echo(f"{key.value}: {value}")


@config_cli.command("get")
def config_get(key: str):
    config: Dict[Configuration, str] = read_configuration()

    try:
        key = Configuration(key)
    except ValueError:
        typer.echo(f"Invalid key: {key.value}")
        raise typer.Abort()

    typer.echo(config.get(key))


@config_cli.command("set")
def config_set(key: str, value: str):
    config: Dict[Configuration, str] = read_configuration()

    try:
        key = Configuration(key)
    except ValueError:
        typer.echo(f"Invalid key: {key.value}")
        raise typer.Abort()

    config[key] = value
    write_configuration(config)


@config_cli.command("reset")
def config_reset():
    write_configuration({})
