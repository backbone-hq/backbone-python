from kryptos.core import KryptosClient, Permission
from nacl.public import PrivateKey
from nacl import encoding

WORKSPACE_NAME = "kryptos"
WORKSPACE_DISPLAY_NAME = "CIA Brothel"

ADMIN = "admin"
ADMIN_EMAIL = "root@kryptos.io"
ADMIN_SK = PrivateKey(b"CG1bq0tkf4FJlHhbXwgEv30eLj27xS4Cd8GgjBerDVg=", encoder=encoding.URLSafeBase64Encoder)


if __name__ == "__main__":
    # Client creation
    client = KryptosClient(workspace=WORKSPACE_NAME, username=ADMIN, secret_key=ADMIN_SK)

    try:
        # Create workspace
        client.workspace.create(display_name=WORKSPACE_DISPLAY_NAME, email_address=ADMIN_EMAIL)

        # Authenticate
        client.authenticate(permissions=[Permission.ROOT])

        # Create entries
        client.entry.set("key-001", "value-001")

        # Read entry
        value = client.entry.get("key-001")
        print(f"Entry value: {value}")
    finally:
        # Authenticate
        client.authenticate(permissions=[Permission.ROOT])

        # Delete workspace
        client.workspace.delete(safety_check=False)
