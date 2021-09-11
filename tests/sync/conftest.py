import asyncio
from typing import List, Tuple

import pytest
from nacl import encoding
from nacl.public import PrivateKey

from backbone.sync import BackboneClient, Permission
from tests.sync.utilities import random_lower

WORKSPACE_DISPLAY_NAME = "Backbone Testing Suite"
ADMIN_USERNAME = "admin"
ADMIN_SK = PrivateKey("CG1bq0tkf4FJlHhbXwgEv30eLj27xS4Cd8GgjBerDVg=", encoder=encoding.URLSafeBase64Encoder)


@pytest.fixture(scope="session")
def event_loop():
    return asyncio.get_event_loop()


@pytest.mark.sync
@pytest.fixture()
def client():
    with BackboneClient(workspace=random_lower(8), username=ADMIN_USERNAME, secret_key=ADMIN_SK) as client:
        # Create workspace
        client.workspace.create(display_name=WORKSPACE_DISPLAY_NAME)

        # Escalate to root privileges
        client.authenticate()

        yield client

        # Re-escalate to root privileges
        client.authenticate()

        # Delete workspace
        client.workspace.delete(safety_check=False)


@pytest.mark.sync
@pytest.fixture()
def create_user():
    users: List[Tuple[BackboneClient, str]] = []

    def _create_user(client: BackboneClient, username: str, permissions: List[Permission]):
        secret_key = PrivateKey.generate()

        # Create an account with the given client
        client.user.create(username=username, public_key=secret_key.public_key, permissions=permissions)

        # Add to user deletion queue
        users.append((client, username))

        # Authenticate and return
        with BackboneClient(
            workspace=client._workspace_name, username=username, secret_key=secret_key
        ) as user_client:
            user_client.authenticate()
            return user_client

    yield _create_user

    for client, username in users:
        client.authenticate()
        client.user.delete(username, force=True)
