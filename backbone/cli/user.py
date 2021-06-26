from typing import Optional, List

import typer

from backbone import crypto
from backbone.cli.utilities import client_from_config, read_configuration
from backbone.sync import PrivateKey, PublicKey, Permission, encoding

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
    username: str, public_key: str, email_address: Optional[str] = None, permissions: List[Permission] = ()
):
    """Create a new user account in the current workspace"""
    configuration = read_configuration()

    try:
        public_key: PublicKey = PublicKey(public_key, encoder=encoding.URLSafeBase64Encoder)
    except ValueError:
        typer.echo(f"Invalid public key: {public_key}")
        raise typer.Abort()

    with client_from_config(configuration) as client:
        client.user.create(username, public_key, email_address, permissions)


@user_cli.command("generate")
def user_generate_credential(username: str, password: bool = False):
    """Generate the user's credential pair"""

    if password:
        password = typer.prompt("Please enter your password", hide_input=True)
        secret_key: PrivateKey = PrivateKey(crypto.derive_password_key(identity=username, password=password))
    else:
        secret_key: PrivateKey = PrivateKey.generate()

    typer.echo(
        f"Public Key: {secret_key.public_key.encode(encoding.URLSafeBase64Encoder).decode()}", color=typer.colors.GREEN
    )
    typer.echo(f"Private Key: {secret_key.encode(encoding.URLSafeBase64Encoder).decode()}", color=typer.colors.RED)


@user_cli.command("delete")
def user_delete(force: bool = False):
    """Delete the current user account"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.user.delete(force_delete=force)
