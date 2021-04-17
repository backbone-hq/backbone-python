from kryptos.core import KryptosClient, Permission
from manual import WORKSPACE_NAME, USER_NAME, USER_SK
from nacl import encoding


if __name__ == "__main__":
    # Client creation
    client = KryptosClient(workspace=WORKSPACE_NAME, username=USER_NAME, secret_key=USER_SK)

    # Create workspace
    client.workspace.create(display_name="CIA Brothel", email_address="admin@kryptos.io")

    # Authentication
    client.authenticate(permissions=[Permission.ROOT])

    # Namespace creation
    client.namespace.create("project")

    # Entry creation
    client.entry.set("key", "value")

    # Entry read
    value = client.entry.get("key")
    print(f"Entry value: {value}")

    # Delete workspace
    client.workspace.delete(safety_check=False)
