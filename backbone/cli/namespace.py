from typing import List

import typer
from halo import Halo

from backbone.cli.utilities import client_from_config, read_configuration
from backbone.exceptions import BackboneException
from backbone.models import GrantAccess

namespace_cli = typer.Typer()


@namespace_cli.command("list")
def namespace_list(prefix: str = typer.Argument("")):
    """List namespaces with a given prefix"""
    configuration = read_configuration()

    try:
        with Halo("Listing namespaces"), client_from_config(configuration) as client:
            namespaces = list(client.namespace.get_child_namespaces(prefix))

        for namespace in namespaces:
            typer.echo(namespace["key"])
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@namespace_cli.command("create")
def namespace_create(key: str, access: List[GrantAccess] = (), isolated: bool = False):
    """Create a namespace"""
    configuration = read_configuration()

    try:
        with Halo(f"Creating namespace {key}"), client_from_config(configuration) as client:
            client.namespace.create(key, access=access, isolated=isolated)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@namespace_cli.command("delete")
def namespace_delete(key: str):
    """Delete a namespace"""
    configuration = read_configuration()

    try:
        with Halo(f"Deleting namespace {key}"), client_from_config(configuration) as client:
            client.namespace.delete(key)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@namespace_cli.command("grant")
def namespace_grant(key: str, username: str, access: List[GrantAccess] = ()):
    """Grant or modify a user's access to a namespace"""
    configuration = read_configuration()

    try:
        with Halo(f"Granting namespace {key} to {username}"), client_from_config(configuration) as client:
            client.namespace.grant(key, username, access=access)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@namespace_cli.command("revoke")
def namespace_revoke(key: str, username: str):
    """Revoke a user's access to an entry"""
    configuration = read_configuration()

    try:
        with Halo(f"Revoking namespace {key} from {username}"), client_from_config(configuration) as client:
            client.namespace.revoke(key, username)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()
