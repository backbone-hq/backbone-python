from nacl.public import PrivateKey

from backbone import crypto
from backbone.sync import BackboneClient, Permission

WORKSPACE_NAME = "backbone"
WORKSPACE_DISPLAY_NAME = "backbone-display"

ADMIN = "admin"
ADMIN_EMAIL = "root@backbone.io"
PASSWORD = "admin"
SECRET_KEY = PrivateKey(crypto.derive_password_key(ADMIN, PASSWORD))

TEST = "test"
TEST_EMAIL = "test@backbone.io"
TEST_PASSWORD = "test"
TEST_SECRET_KEY = PrivateKey(crypto.derive_password_key(TEST, TEST_PASSWORD))


if __name__ == "__main__":
    with BackboneClient(workspace=WORKSPACE_NAME, username=ADMIN, secret_key=SECRET_KEY) as client:
        # Create workspace and admin user
        client.workspace.create(display_name=WORKSPACE_DISPLAY_NAME, email_address=ADMIN_EMAIL)

        # Authenticate
        client.authenticate(permissions=[Permission.ROOT])

        # Create test user
        client.user.create(TEST, secret_key=TEST_SECRET_KEY, email_address=TEST_EMAIL)
