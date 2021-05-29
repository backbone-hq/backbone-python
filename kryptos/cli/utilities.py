import json
from kryptos.sync import KryptosClient
from kryptos import crypto
from pathlib import Path
from typing import Dict, Optional
from enum import Enum
from nacl.public import PrivateKey
from nacl import encoding

import typer

KRYPTOS_ROOT = Path(__file__).parent
KRYPTOS_CONFIG = KRYPTOS_ROOT / "kryptos.json"


class Configuration(Enum):
    WORKSPACE = "workspace"
    USERNAME = "username"
    TOKEN = "token"
    KEY = "key"


def _get_or_config(key: Configuration, value: Optional[str]) -> str:
    if value:
        return value

    configuration = read_configuration()
    value = configuration.get(key.value)
    if not value:
        typer.echo(f"No {key.value} found")
        raise typer.Abort()

    return value


def resolve_configuration(
    token: Optional[str] = None,
    workspace: Optional[str] = None,
    username: Optional[str] = None,
    key: Optional[str] = None,
) -> Dict[Configuration, str]:
    configuration = read_configuration()

    return {
        Configuration.WORKSPACE: workspace or configuration.get(Configuration.WORKSPACE),
        Configuration.USERNAME: username or configuration.get(Configuration.USERNAME),
        Configuration.TOKEN: token or configuration.get(Configuration.TOKEN),
        Configuration.KEY: key or configuration.get(Configuration.TOKEN),
    }


def client_from_config(configuration: Dict[Configuration, str]):
    client = KryptosClient(
        workspace=configuration[Configuration.WORKSPACE],
        username=configuration[Configuration.USERNAME],
        secret_key=PrivateKey(configuration[Configuration.KEY], encoder=encoding.URLSafeBase64Encoder),
    )

    token = configuration[Configuration.TOKEN]
    if token:
        client.load_token(token)

    return client


def get_secret(username: str, password: bool) -> PrivateKey:
    secret = typer.prompt(f"Please enter a {'password' if password else 'key'}", hide_input=True)

    return (
        PrivateKey(crypto.derive_password_key(identity=username, password=secret))
        if password
        else PrivateKey(secret, encoder=encoding.URLSafeBase64Encoder)
    )


def read_configuration() -> Dict[Configuration, str]:
    try:
        with open(KRYPTOS_CONFIG) as configuration_file:
            configuration = json.load(configuration_file)
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        return {}

    result = {}
    for key, value in configuration.items():
        try:
            result[Configuration(key)] = str(value)
        except ValueError:
            pass

    return result


def write_configuration(configuration: Dict[Configuration, str]) -> None:
    with open(KRYPTOS_CONFIG, "w") as config_file:
        json.dump({key.value: value for key, value in configuration.items()}, config_file)
