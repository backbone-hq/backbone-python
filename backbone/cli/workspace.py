import typer

from backbone.cli.utilities import (
    Configuration,
    client_from_config,
    get_secret,
    read_configuration,
    write_configuration,
)
from backbone.crypto import encoding

workspace_cli = typer.Typer()


@workspace_cli.command("create")
def workspace_create(workspace_name: str, display_name: str, username: str, email_address: str, password: bool = False):
    """Create a new workspace and its associated admin account"""
    configuration = read_configuration()

    secret_key = get_secret(username=username, password=password)
    configuration[Configuration.KEY] = secret_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
    configuration[Configuration.WORKSPACE] = workspace_name
    configuration[Configuration.USERNAME] = username

    with client_from_config(configuration) as client:
        workspace = client.workspace.create(display_name, email_address)
        typer.echo(f"{workspace.name}: {workspace.display_name}")

    write_configuration(configuration)
