import typer
from halo import Halo

from backbone.cli.utilities import (
    Configuration,
    client_from_config,
    get_secret,
    read_configuration,
    write_configuration,
)
from backbone.crypto import encoding
from backbone.exceptions import BackboneException

workspace_cli = typer.Typer()


@workspace_cli.command("create")
def workspace_create(
    workspace_name: str,
    display_name: str,
    username: str,
    password: bool = typer.Option(False, "--password"),
):
    """Create a new workspace and its associated admin account"""
    configuration = read_configuration()

    secret_key = get_secret(username=username, password=password)
    configuration[Configuration.KEY] = secret_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
    configuration[Configuration.WORKSPACE] = workspace_name
    configuration[Configuration.USERNAME] = username

    try:
        with Halo(f"Creating workspace {workspace_name}"), client_from_config(configuration) as client:
            client.workspace.create(display_name)
            token = client.token.authenticate(permissions=None)

            configuration[Configuration.TOKEN] = token
            write_configuration(configuration)
    except BackboneException as exc:
        typer.echo(exc)
        raise typer.Abort()
