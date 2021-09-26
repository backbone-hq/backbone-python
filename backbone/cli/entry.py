from typing import List, Optional

import typer
from halo import Halo

from backbone.cli.utilities import client_from_config, read_configuration
from backbone.exceptions import BackboneException
from backbone.models import GrantAccess

entry_cli = typer.Typer()


@entry_cli.command("list")
def entry_list(prefix: str = typer.Argument("")):
    """List entries with a given prefix"""
    configuration = read_configuration()

    try:
        with Halo("Listing entries"), client_from_config(configuration) as client:
            entries = list(client.namespace.get_child_entries(prefix))

        for entry in entries:
            typer.echo(entry["key"])
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@entry_cli.command("set")
def entry_set(key: str, value: str, access: List[GrantAccess] = (), duration: Optional[int] = None):
    """Set or overwrite an entry to hold a value"""
    configuration = read_configuration()

    try:
        with Halo(f"Setting entry {key} to {value}"), client_from_config(configuration) as client:
            client.entry.set(key, value, access=access, duration=duration)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@entry_cli.command("get")
def entry_get(key: str):
    """Get the value held in the entry"""
    configuration = read_configuration()

    try:
        with Halo(f"Reading entry {key}"), client_from_config(configuration) as client:
            value = client.entry.get(key)

        typer.echo(value)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@entry_cli.command("delete")
def entry_delete(key: str):
    """Delete an entry"""
    configuration = read_configuration()

    try:
        with Halo(f"Deleting entry {key}"), client_from_config(configuration) as client:
            client.entry.delete(key)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@entry_cli.command("grant")
def entry_grant(key: str, username: str, access: List[GrantAccess] = ()):
    """Grant or modify a user's access to an entry"""
    configuration = read_configuration()

    try:
        with Halo(f"Grant entry {key} to {username}"), client_from_config(configuration) as client:
            client.entry.grant(key, username, access=access)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@entry_cli.command("revoke")
def entry_revoke(key: str, username: str):
    """Revoke a user's access to an entry"""
    configuration = read_configuration()

    try:
        with Halo(f"Revoking entry {key} from {username}"), client_from_config(configuration) as client:
            client.entry.revoke(key, username)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()
