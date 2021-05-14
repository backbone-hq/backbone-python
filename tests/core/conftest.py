import pytest
from nacl import encoding
from nacl.public import PrivateKey
from typing import Optional, List
from kryptos.core import KryptosClient, Permission, GrantAccess

WORKSPACE_NAME = "kryptos"
WORKSPACE_DISPLAY_NAME = "kryptos-display"

ADMIN = "admin"
ADMIN_EMAIL = "root@kryptos.io"
ADMIN_SK = PrivateKey(b"CG1bq0tkf4FJlHhbXwgEv30eLj27xS4Cd8GgjBerDVg=", encoder=encoding.URLSafeBase64Encoder)


@pytest.mark.asyncio
@pytest.fixture()
async def client():
    client = KryptosClient(workspace=WORKSPACE_NAME, username=ADMIN, secret_key=ADMIN_SK)

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
    async def _create_user(username: str, permissions: List[Permission], email_address: Optional[str] = None):
        secret_key = PrivateKey.generate()

        # Create an account with the admin user client
        await client.user.create(
            username=username, secret_key=secret_key, email_address=email_address, permissions=permissions
        )

        return KryptosClient(workspace=WORKSPACE_NAME, username=username, secret_key=secret_key)

    yield _create_user

    for user_client in user_clients:
        await user_client.close()
