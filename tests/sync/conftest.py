import pytest
from nacl import encoding
from nacl.public import PrivateKey

from kryptos.sync import KryptosClient, Permission

WORKSPACE_NAME = "kryptos"
WORKSPACE_DISPLAY_NAME = "CIA Brothel"

ADMIN = "admin"
ADMIN_EMAIL = "root@kryptos.io"
ADMIN_SK = PrivateKey(b"CG1bq0tkf4FJlHhbXwgEv30eLj27xS4Cd8GgjBerDVg=", encoder=encoding.URLSafeBase64Encoder)



@pytest.fixture(scope="function")
def client():
    client = KryptosClient(workspace=WORKSPACE_NAME, username=ADMIN, secret_key=ADMIN_SK)

    # Create workspace
    client.workspace.create(display_name=WORKSPACE_DISPLAY_NAME, email_address=ADMIN_EMAIL)

    # Authenticate
    client.authenticate(permissions=[Permission.ROOT])

    yield client

    # Authenticate
    client.authenticate(permissions=[Permission.ROOT])

    # Delete workspace
    client.workspace.delete(safety_check=False)
