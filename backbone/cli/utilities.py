import functools
from enum import Enum
from pathlib import Path
from typing import Dict, Optional

import cbor2
import getmac
import nacl.exceptions
import typer
from nacl import encoding
from nacl.hash import blake2b
from nacl.public import PrivateKey
from nacl.pwhash import argon2id
from nacl.secret import SecretBox
from nacl.utils import encoding, random

from backbone import crypto
from backbone.sync import BackboneClient

# Define the configuration file location
BACKBONE_ROOT: Path = Path(typer.get_app_dir("backbone"))
BACKBONE_CONFIG: Path = BACKBONE_ROOT / "config.json"


class Configuration(Enum):
    WORKSPACE = "workspace"
    USERNAME = "username"
    TOKEN = "token"
    KEY = "key"


@functools.lru_cache()
def _get_public_secret():
    salt = blake2b(b"NOVUS ORDO SECLORUM", digest_size=16, encoder=encoding.RawEncoder)
    return argon2id.kdf(
        size=32, password=get_mac_address(), salt=salt, memlimit=argon2id.MEMLIMIT_MIN, opslimit=argon2id.OPSLIMIT_MIN
    )


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

    if Configuration.TOKEN in configuration:
        client.load_token(configuration[Configuration.TOKEN])

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
    secret = _get_public_secret()
    data = cbor2.dumps(configuration)
    return SecretBox(secret).encrypt(data, encoder=encoding.RawEncoder)


def decrypt_configuration(data):
    secret = _get_public_secret()

    try:
        data = SecretBox(secret).decrypt(data, encoder=encoding.RawEncoder)
    except nacl.exceptions.CryptoError:
        return {}

    try:
        return cbor2.loads(data)
    except (UnicodeDecodeError, cbor2.CBORError):
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
