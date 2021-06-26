from typing import Optional

import typer
from nacl.utils import encoding

from backbone.cli.config import config_cli
from backbone.cli.entry import entry_cli
from backbone.cli.namespace import namespace_cli
from backbone.cli.user import user_cli
from backbone.cli.utilities import (
    Configuration,
    client_from_config,
    get_secret,
    read_configuration,
    resolve_configuration,
    write_configuration,
)

# Specify CLI structure
backbone_cli = typer.Typer()
backbone_cli.add_typer(config_cli, name="config")
backbone_cli.add_typer(entry_cli, name="entry")
backbone_cli.add_typer(namespace_cli, name="namespace")
backbone_cli.add_typer(user_cli, name="user")


@backbone_cli.command("authenticate")
def authenticate(username: str, workspace: Optional[str] = None, duration: int = 86_400, password: bool = False):
    configuration = resolve_configuration(workspace=workspace, username=username,)

    if configuration[Configuration.WORKSPACE] is None:
        configuration[Configuration.WORKSPACE] = typer.prompt("Please enter your workspace")

    secret_key = get_secret(username=username, password=password)
    configuration[Configuration.KEY] = secret_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()

    with client_from_config(configuration) as client:
        # Always request maximum permissions in the CLI
        token = client.token.authenticate(permissions=None, duration=duration)

    configuration[Configuration.TOKEN] = token
    write_configuration(configuration)


@backbone_cli.command("deauthenticate")
def deauthenticate():
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.deauthenticate()
