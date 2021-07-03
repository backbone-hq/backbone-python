from typing import List

import typer
from nacl import encoding
from nacl.public import PublicKey

from backbone.cli.utilities import client_from_config, read_configuration
from backbone.models import GrantAccess

entry_cli = typer.Typer()


@entry_cli.command("search")
def entry_search(prefix: str):
    """Searches for entries with a given prefix"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        for entry in client.entry.search(prefix):
            typer.echo(entry)


@entry_cli.command("set")
def entry_set(key: str, value: str, access: List[GrantAccess] = ()):
    """Sets an entry"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.entry.set(key, value, access=access)
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
        username = client.user.search(username=username)
        public_key = PublicKey(username["public_key"], encoder=encoding.URLSafeBase64Encoder)
        typer.echo(client.entry.grant(key, public_key, access=access))


@entry_cli.command("revoke")
def entry_revoke(key: str, username: str):
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        username = client.user.search(username=username)
        public_key = PublicKey(username["public_key"], encoder=encoding.URLSafeBase64Encoder)
        typer.echo(client.entry.revoke(key, public_key))
