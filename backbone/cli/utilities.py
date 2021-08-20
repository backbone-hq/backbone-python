import json
from enum import Enum
from pathlib import Path
from typing import Dict, Optional

import typer
import nacl.exceptions
from nacl import encoding
from nacl.public import PrivateKey

from backbone import crypto
from backbone.sync import BackboneClient
from nacl.pwhash import argon2id
from nacl.hash import blake2b
from nacl.secret import SecretBox
from nacl.utils import encoding, random
import getmac
import functools

# Define the configuration file location
BACKBONE_ROOT: Path = Path(typer.get_app_dir("backbone"))
BACKBONE_CONFIG: Path = BACKBONE_ROOT / "config.json"


class Configuration(Enum):
    WORKSPACE = "workspace"
    USERNAME = "username"
    TOKEN = "token"
    KEY = "key"


@functools.lru_cache()
def _get_config_secret():
    salt = blake2b(b"NOVUS ORDO SECLORUM", digest_size=16, encoder=encoding.RawEncoder)
    return argon2id.kdf(size=32, password=get_mac_address(), salt=salt, memlimit=argon2id.MEMLIMIT_MIN, opslimit=argon2id.OPSLIMIT_MIN)


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
    client = BackboneClient(
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


def get_mac_address():
    return bytes.fromhex(getmac.get_mac_address().replace(":", ""))


def encrypt_configuration(configuration):
    secret = _get_config_secret()
    data = json.dumps(configuration).encode()
    return SecretBox(secret).encrypt(data, encoder=encoding.RawEncoder)


def decrypt_configuration(data):
    secret = _get_config_secret()

    try:
        data = SecretBox(secret).encrypt(data, encoder=encoding.RawEncoder)
    except nacl.exceptions.CryptoError:
        return {}

    try:
        return json.loads(data.decode())
    except (UnicodeDecodeError, json.decoder.JSONDecodeError):
        return {}


def read_configuration() -> Dict[Configuration, str]:
    try:
        with BACKBONE_CONFIG.open("rb") as configuration_file:
            configuration = decrypt_configuration(configuration_file.read())
    except FileNotFoundError:
        return {}

    result = {}
    for key, value in configuration.items():
        try:
            result[Configuration(key)] = str(value)
        except ValueError:
            pass

    return result


def write_configuration(configuration: Dict[Configuration, str]) -> None:
    if not BACKBONE_ROOT.is_dir():
        BACKBONE_ROOT.mkdir()

    with open(BACKBONE_CONFIG, "wb") as config_file:
        configuration = {key.value: value for key, value in configuration.items()}
        config_file.write(encrypt_configuration(configuration))
