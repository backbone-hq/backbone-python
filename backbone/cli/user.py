import secrets
from typing import List, Optional, Tuple

import cbor2
import typer

from backbone import crypto
from backbone.cli.utilities import client_from_config, get_secret, read_configuration
from backbone.crypto import encoding
from backbone.models import User
from backbone.sync import Permission, PrivateKey, PublicKey

user_cli = typer.Typer()


def _encode_user_spec(username: str, public_key: PublicKey) -> str:
    payload: bytes = cbor2.dumps((str(username), bytes(public_key)))
    payload = payload + crypto.digest_bytes(payload)
    return encoding.URLSafeBase64Encoder.encode(payload).decode()


def _decode_user_spec(payload: str) -> Tuple[str, PublicKey]:
    payload: bytes = encoding.URLSafeBase64Encoder.decode(payload.encode())

    payload, digest = payload[:-32], payload[-32:]
    if not secrets.compare_digest(digest, crypto.digest_bytes(payload)):
        raise ValueError

    username, public_key = cbor2.loads(payload)
    public_key = PublicKey(public_key)
    return username, public_key


def serialize(user: User):
    typer.echo(f"{user.name} : {user.public_key} : {user.permissions}")


@user_cli.command("list")
def user_list():
    """Lists all users in the current workspace"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        for user in client.user.list():
            serialize(user)


@user_cli.command("get")
def user_get(username: str):
    """View a particular user's details"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        for user in client.user.get(username):
            serialize(user)


@user_cli.command("self")
def user_get_self():
    """View the current user's details"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        user = client.user.self()
        serialize(user)


@user_cli.command("create")
def user_create(
    username: str,
    permissions: List[Permission] = (),
    password: bool = typer.Option(False, "--password"),
):
    """Create a new user account in the current workspace"""
    configuration = read_configuration()
    secret_key: PrivateKey = get_secret(username=username, password=password)
    public_key = secret_key.public_key

    with client_from_config(configuration) as client:
        user = client.user.create(username, public_key, permissions)
        serialize(user)
        typer.echo(f"Private Key: {secret_key.encode(encoding.URLSafeBase64Encoder).decode()}", color=typer.colors.RED)


@user_cli.command("import")
def user_import(payload: str, permissions: List[Permission] = ()):
    """Import a user account based on a payload from the generate utility"""
    configuration = read_configuration()

    try:
        username, public_key = _decode_user_spec(payload)
    except ValueError:
        typer.echo(f"Invalid payload: {payload}")
        raise typer.Abort()

    typer.confirm(f"Import the user `{username}`?", abort=True)

    with client_from_config(configuration) as client:
        user = client.user.create(username=username, public_key=public_key, permissions=permissions)
        serialize(user)


@user_cli.command("generate")
def user_generate(username: str, password: bool = typer.Option(False, "--password")):
    """Generate a user payload to import"""

    if password:
        password = typer.prompt("Please enter your password", hide_input=True)
        secret_key: PrivateKey = PrivateKey(crypto.derive_password_key(identity=username, password=password))
    else:
        secret_key: PrivateKey = PrivateKey.generate()

    payload = _encode_user_spec(username, secret_key.public_key)
    typer.echo(f"Preparing to create the user {username}")
    typer.echo(f"Payload: {payload}", color=typer.colors.GREEN)
    typer.echo(
        f"Public Key: {secret_key.public_key.encode(encoding.URLSafeBase64Encoder).decode()}", color=typer.colors.GREEN
    )
    typer.echo(f"Private Key: {secret_key.encode(encoding.URLSafeBase64Encoder).decode()}", color=typer.colors.RED)


@user_cli.command("modify")
def user_modify(username: str, permissions: List[Permission] = ()):
    """Modify an account's permissions"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.user.modify(username=username, permissions=permissions)


@user_cli.command("delete")
def user_delete(username: str, force: bool = False):
    """Delete the current user account"""
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.user.delete(username=username, force=force)
