from typing import List

import typer
from halo import Halo

from backbone.cli.utilities import client_from_config, read_configuration
from backbone.exceptions import BackboneException
from backbone.models import GrantAccess

namespace_cli = typer.Typer()


@namespace_cli.command("tree")
def namespace_tree(key: str = typer.Argument(""), depth: int = 3):
    """Visually display the store starting from a particular prefix"""
    configuration = read_configuration()
    _whitespace = "   "

    def print_layer(client, namespace: str, level: int = 1, indent: str = ""):
        if level > depth:
            return

        # Identify all children and namespaces of a parent namespace
        resources = [
            (False, e) for e in client.namespace.get_child_entries(namespace)
        ] + [
            (True, n) for n in client.namespace.get_child_namespaces(namespace)
        ]

        for index, (is_namespace, resource) in enumerate(resources):
            key: str = resource["key"]
            # Decide whether to use a corner or continuation character
            is_last: bool = index == len(resources) - 1
            wire: str = "└──" if is_last else "├──"
            bulb: str = "●" if is_namespace else "○"

            # Display resource
            typer.echo(f"{indent}{wire}{bulb} {key}")

            # Continue searching for resources in namespaces depth-first
            if is_namespace:
                next_indent = indent + (_whitespace if is_last else f"│{_whitespace[:-1]}")

                # If this is the last level, denote unexplored namespaces
                if level == depth:
                    typer.echo(f"{next_indent}└── ...")

                print_layer(client, key, level=level + 1, indent=next_indent)

    try:
        with client_from_config(configuration) as client:
            print_layer(client, key)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()


@namespace_cli.command("list")
def namespace_list(key: str = typer.Argument("")):
    """List namespaces with a given prefix"""
    configuration = read_configuration()

    try:
        with Halo("Listing namespaces"), client_from_config(configuration) as client:
            namespaces = list(client.namespace.get_child_namespaces(key))

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
