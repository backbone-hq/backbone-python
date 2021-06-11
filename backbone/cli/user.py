from typing import Optional

import typer

from backbone import crypto
from backbone.cli.utilities import client_from_config, read_configuration
from backbone.sync import PrivateKey, encoding

user_cli = typer.Typer()


@user_cli.command("list")
def user_list():
    """Lists all users in the current workspace"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        for user in client.user.get_all():
            typer.echo(user)


@user_cli.command("search")
def user_search(username: str):
    """Search for a particular user's details"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        typer.echo(client.user.search(username))


@user_cli.command("get")
def user_get():
    """View the current user's details"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        typer.echo(client.user.get())


@user_cli.command("create")
def user_create(
    username: str,
    email_address: Optional[str] = None,
    password: bool = False,
):
    """Create a new user account in the current workspace"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        secret = typer.prompt(f"Please enter a {'password' if password else 'key'}", hide_input=True)
        secret_key: PrivateKey = (
            PrivateKey(crypto.derive_password_key(identity=username, password=secret))
            if password
            else PrivateKey(secret, encoder=encoding.URLSafeBase64Encoder)
        )
        typer.echo(client.user.create(username=username, secret_key=secret_key, email_address=email_address))


@user_cli.command("delete")
def user_delete(force: bool = False):
    """Delete the current user account"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.user.delete(force_delete=force)
