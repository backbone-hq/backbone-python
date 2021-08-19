import asyncio
from typing import List

import pytest
from nacl import encoding
from nacl.public import PrivateKey

from backbone.core import BackboneClient, Permission

from .utilities import random_lower

WORKSPACE_NAME = random_lower(8)
WORKSPACE_DISPLAY_NAME = "Backbone Testing Workspace"

ADMIN = "admin"
ADMIN_EMAIL = "testing@backbone.dev"
ADMIN_SK = PrivateKey("CG1bq0tkf4FJlHhbXwgEv30eLj27xS4Cd8GgjBerDVg=", encoder=encoding.URLSafeBase64Encoder)


@pytest.fixture(scope="session")
def event_loop():
    return asyncio.get_event_loop()


@pytest.mark.asyncio
@pytest.fixture(scope="session")
async def client():
    client = BackboneClient(workspace=WORKSPACE_NAME, username=ADMIN, secret_key=ADMIN_SK)

    # Create workspace
    await client.workspace.create(display_name=WORKSPACE_DISPLAY_NAME, email_address=ADMIN_EMAIL)

    yield client

    # Authenticate
    await client.authenticate(permissions=[Permission.ROOT])

    # Delete workspace
    await client.workspace.delete(safety_check=False)

    # Close the client's session
    await client.close()


@pytest.mark.asyncio
@pytest.fixture()
async def create_user(client):
    user_clients = []

    @pytest.mark.asyncio
    async def _create_user(username: str, permissions: List[Permission]):
        secret_key = PrivateKey.generate()

        # Create an account with the admin user client
        await client.user.create(
            username=username, public_key=secret_key.public_key, email_address=None, permissions=permissions
        )

        return BackboneClient(workspace=WORKSPACE_NAME, username=username, secret_key=secret_key)

    yield _create_user

    for user_client in user_clients:
        await user_client.close()
