from kryptos import crypto
from kryptos.sync import KryptosClient, Permission
from nacl.public import PrivateKey

WORKSPACE_NAME = "kryptos"
WORKSPACE_DISPLAY_NAME = "kryptos-display"

ADMIN = "admin"
ADMIN_EMAIL = "root@kryptos.io"
PASSWORD = "admin"
SECRET_KEY = PrivateKey(crypto.derive_password_key(ADMIN, PASSWORD))

TEST = "test"
TEST_EMAIL = "test@kryptos.io"
TEST_PASSWORD = "test"
TEST_SECRET_KEY = PrivateKey(crypto.derive_password_key(TEST, TEST_PASSWORD))


if __name__ == "__main__":
    with KryptosClient(workspace=WORKSPACE_NAME, username=ADMIN, secret_key=SECRET_KEY) as client:
        # Create workspace and admin user
        client.workspace.create(display_name=WORKSPACE_DISPLAY_NAME, email_address=ADMIN_EMAIL)

        # Authenticate
        client.authenticate(permissions=[Permission.ROOT])

        # Create test user
        client.user.create(TEST, secret_key=TEST_SECRET_KEY, email_address=TEST_EMAIL)
