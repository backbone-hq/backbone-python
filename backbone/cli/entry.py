from typing import List, Optional

import typer

from backbone.cli.utilities import client_from_config, read_configuration
from backbone.models import GrantAccess

entry_cli = typer.Typer()


@entry_cli.command("list")
def entry_list(prefix: str = typer.Argument("")):
    """List entries with a given prefix"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        for entry in client.entry.search(prefix):
            typer.echo(entry)


@entry_cli.command("set")
def entry_set(key: str, value: str, access: List[GrantAccess] = (), duration: Optional[int] = None):
    """Sets an entry"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.entry.set(key, value, access=access, duration=duration)
        typer.echo(f"{key}: {value}")


@entry_cli.command("get")
def entry_get(key: str):
    """Obtains an entry's value"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        typer.echo(client.entry.get(key))


@entry_cli.command("remove")
def entry_remove(key: str):
    """Delete an entry"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.entry.delete(key)


@entry_cli.command("grant")
def entry_share(key: str, username: str, access: List[GrantAccess] = ()):
    """Share an entry with a user"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        typer.echo(client.entry.grant(key, username, access=access))


@entry_cli.command("revoke")
def entry_revoke(key: str, username: str):
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        typer.echo(client.entry.revoke(key, username))
