"""
Kryptos CLI

Usage:
    kryptos config list
    kryptos config get <key>
    kryptos config set <key> <value>
    kryptos config reset
    kryptos authenticate <name> <password> [--workspace=<workspace>]
    kryptos entry get <key> [options]
    kryptos entry set <key> <value> [options]
    kryptos entry remove <key> [options]
    kryptos namespace create <key> [options]
    kryptos namespace remove <key> [options]
    kryptos namespace rotate <key> [options]
    kryptos user create <name> <password> [<email>] [<permissions>...] [options]
    kryptos user delete <name> [options]
    kryptos allow <name> <key> [options]
    kryptos deny <name> <key> [options]
    kryptos --version
Options:
    -t, --token=<token>          Use TOKEN for authentication
"""

import kryptos
from pathlib import Path
import json
import sys
import os
import httpx

KRYPTOS_ROOT = Path(__file__).parent
KRYPTOS_CONFIG = KRYPTOS_ROOT / "config.json"

SUPPORTED_CONFIG_KEYS = {"token", "workspace"}


def panic(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)
    exit(os.EX_SOFTWARE)


def execute(arguments):
    pass

"""
if KRYPTOS_CONFIG.exists():
    with open(KRYPTOS_CONFIG) as config_file:
        kryptos_config = {k: str(v) for k, v in json.load(config_file).items() if k in SUPPORTED_CONFIG_KEYS}
else:
    kryptos_config = {}

if arguments["config"]:
    if arguments["list"]:
        for key, value in kryptos_config.items():
            if key not in SUPPORTED_CONFIG_KEYS:
                del kryptos_config[key]
                continue

            print(f"{key}: {value}")
    elif arguments["get"]:
        print(f"{arguments['<key>']}: {kryptos_config.get(arguments['<key>'])}")
    elif arguments["set"]:
        key = arguments["<key>"].lower()
        if key not in SUPPORTED_CONFIG_KEYS:
            panic(f"Unsupported config key: {key}")

        kryptos_config[key] = str(arguments["<value>"])
    elif arguments["reset"]:
        kryptos_config = {}
elif arguments["authenticate"]:
    workspace = arguments["--workspace"] or kryptos_config.get("workspace")
    if not workspace:
        panic("No workspace defined")

    try:
        token = kryptos.core.authenticate(
            workspace=workspace, username=arguments["<name>"], password=arguments["<password>"]
        )
    except httpx._exceptions.NetworkError:
        panic("Failed to establish connection with Kryptos")

    if not token:  # noqa
        panic("Authentication failed")

    kryptos_config["workspace"] = workspace
    kryptos_config["token"] = token
elif arguments["user"]:
    token = arguments["--token"] or kryptos_config.get("token")
    if not token:
        panic("No token defined")

    try:
        if arguments["create"]:
            kryptos.core.create_user(
                token=token,
                name=arguments["<name>"],
                password=arguments["<password>"],
                email_address=arguments["<email_address>"],
                permissions=arguments["<permission"],
            )
        elif arguments["delete"]:
            kryptos.core.delete_user(token=token)
    except httpx._exceptions.NetworkError:
        panic("Failed to establish connection with Kryptos")
elif arguments["entry"]:
    pass
elif arguments["namespace"]:
    pass
elif arguments["allow"]:
    pass
elif arguments["deny"]:
    pass

with open(KRYPTOS_CONFIG, "w") as config_file:
    json.dump(kryptos_config, config_file)
"""
