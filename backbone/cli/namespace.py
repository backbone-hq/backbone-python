from typing import List

import typer
from nacl import encoding
from nacl.public import PublicKey

from backbone.cli.utilities import client_from_config, read_configuration
from backbone.sync import GrantAccess

namespace_cli = typer.Typer()


@namespace_cli.command("search")
def namespace_search(prefix: str):
    """Searches for entries with a given prefix"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        for namespace in client.namespace.search(prefix):
            typer.echo(namespace)


@namespace_cli.command("set")
def namespace_create(key: str, access: List[GrantAccess] = (), isolated: bool = False):
    """Creates an namespace"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.namespace.create(key, access=access, isolated=isolated)
        typer.echo(f"{key}")


@namespace_cli.command("get")
def namespace_get(key: str):
    """Obtains an namespace"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        typer.echo(client.namespace.get(key))


@namespace_cli.command("remove")
def namespace_remove(key: str):
    """Delete an namespace"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.namespace.delete(key)


@namespace_cli.command("grant")
def namespace_share(key: str, username: str, access: List[GrantAccess] = ()):
    """Share an namespace with a user"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        username = client.user.search(username=username)
        public_key = PublicKey(username["public_key"], encoder=encoding.URLSafeBase64Encoder)
        typer.echo(client.namespace.grant(key, public_key, access=access))


@namespace_cli.command("revoke")
def namespace_revoke(key: str, username: str):
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        username = client.user.search(username=username)
        public_key = PublicKey(username["public_key"], encoder=encoding.URLSafeBase64Encoder)
        typer.echo(client.namespace.revoke(key, public_key))