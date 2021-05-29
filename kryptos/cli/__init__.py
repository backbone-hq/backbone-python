from typing import Optional

import typer
from nacl.utils import encoding

from kryptos.cli.config import config_cli
from kryptos.cli.entry import entry_cli
from kryptos.cli.namespace import namespace_cli
from kryptos.cli.user import user_cli

from kryptos.cli.utilities import (
    resolve_configuration,
    client_from_config,
    get_secret,
    Configuration,
    write_configuration,
    read_configuration,
)

# Specify CLI structure
kryptos_cli = typer.Typer()
kryptos_cli.add_typer(config_cli, name="config")
kryptos_cli.add_typer(entry_cli, name="entry")
kryptos_cli.add_typer(namespace_cli, name="namespace")
kryptos_cli.add_typer(user_cli, name="user")


@kryptos_cli.command("authenticate")
def authenticate(username: str, workspace: Optional[str] = None, duration: int = 86_400, password: bool = False):
    configuration = resolve_configuration(
        workspace=workspace,
        username=username,
    )

    if configuration[Configuration.WORKSPACE] is None:
        configuration[Configuration.WORKSPACE] = typer.prompt("Please enter your workspace")

    secret_key = get_secret(username=username, password=password)
    configuration[Configuration.KEY] = secret_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()

    with client_from_config(configuration) as client:
        # Always request maximum permissions in the CLI
        token = client.token.authenticate(permissions=None, duration=duration)

    configuration[Configuration.TOKEN] = token
    write_configuration(configuration)


@kryptos_cli.command("deauthenticate")
def deauthenticate():
    configuration = read_configuration()

    with client_from_config(configuration) as client:
        client.deauthenticate()
