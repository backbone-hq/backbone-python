from kryptos.core import KryptosClient, Permission
from main import create_workspace, delete_workspace, WORKSPACE_NAME, USER_NAME, USER_SK


if __name__ == "__main__":
    # Create workspace
    create_workspace()

    # Client creation
    client = KryptosClient(workspace=WORKSPACE_NAME, username=USER_NAME, secret_key=USER_SK)

    # Authentication
    client.authenticate(permissions=[Permission.ROOT])

    try:
        # Entry creation
        client.entry.set("example_key", "example_value")
        client.entry.set("potato", "other")

        # Entry read
        value = client.entry.get("example_key")
        print(value)
        value2 = client.entry.get("nonexistent")
        print(value2)
    finally:
        # Delete workspace
        delete_workspace(token=client.authenticator.token)
