from typing import List

import typer

from backbone.cli.utilities import client_from_config, read_configuration
from backbone.models import GrantAccess

namespace_cli = typer.Typer()


@namespace_cli.command("list")
def namespace_list(prefix: str = typer.Argument("")):
    """List namespaces with a given prefix"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        for namespace in client.namespace.get_child_namespaces(prefix):
            typer.echo(namespace["key"])


@namespace_cli.command("create")
def namespace_create(key: str, access: List[GrantAccess] = (), isolated: bool = False):
    """Create a namespace"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.namespace.create(key, access=access, isolated=isolated)
        typer.echo(key)


@namespace_cli.command("delete")
def namespace_delete(key: str):
    """Delete a namespace"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.namespace.delete(key)


@namespace_cli.command("grant")
def namespace_share(key: str, username: str, access: List[GrantAccess] = ()):
    """Share an namespace with a user"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        typer.echo(client.namespace.grant(key, username, access=access))


@namespace_cli.command("revoke")
def namespace_revoke(key: str, username: str):
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        typer.echo(client.namespace.revoke(key, username))
