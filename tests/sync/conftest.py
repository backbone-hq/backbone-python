import asyncio
from typing import List

import pytest
from nacl import encoding
from nacl.public import PrivateKey

from backbone.sync import BackboneClient, Permission

from .utilities import random_lower

WORKSPACE_NAME = random_lower(8)
WORKSPACE_DISPLAY_NAME = "Backbone Testing Workspace"

ADMIN_USERNAME = "admin"
ADMIN_EMAIL = "testing@backbone.dev"
ADMIN_SK = PrivateKey("CG1bq0tkf4FJlHhbXwgEv30eLj27xS4Cd8GgjBerDVg=", encoder=encoding.URLSafeBase64Encoder)


@pytest.fixture(scope="session")
def event_loop():
    return asyncio.get_event_loop()


@pytest.mark.sync
@pytest.fixture(scope="session")
def client():
    client = BackboneClient(workspace=WORKSPACE_NAME, username=ADMIN_USERNAME, secret_key=ADMIN_SK)

    # Create workspace
    client.workspace.create(display_name=WORKSPACE_DISPLAY_NAME, email_address=ADMIN_EMAIL)

    yield client

    # Authenticate
    client.authenticate(permissions=[Permission.ROOT])

    # Delete workspace
    client.workspace.delete(safety_check=False)

    # Close the client's session
    client.close()


@pytest.mark.sync
@pytest.fixture()
def create_user(client):
    user_clients = []

    @pytest.mark.asyncio
    def _create_user(username: str, permissions: List[Permission]):
        secret_key = PrivateKey.generate()

        # Create an account with the admin user client
        client.user.create(
            username=username, public_key=secret_key.public_key, email_address=None, permissions=permissions
        )

        return BackboneClient(workspace=WORKSPACE_NAME, username=username, secret_key=secret_key)

    yield _create_user

    for user_client in user_clients:
        user_client.close()
