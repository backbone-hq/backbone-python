from backbone.crypto import PrivateKey, encoding, encrypt_grant
from backbone.models import GrantAccess, Workspace


class WorkspaceClient:
    endpoint = "workspace"

    def __init__(self, client):
        self.backbone = client

    def get(self) -> Workspace:
        response = self.backbone.session.get(self.endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return Workspace.parse_obj(response.json())

    def create(self, display_name: str, email_address: str) -> Workspace:
        # Generate root namespace keypair
        namespace_key: PrivateKey = PrivateKey.generate()
        namespace_grant = encrypt_grant(self.backbone._secret_key.public_key, namespace_key)

        response = self.backbone.session.post(
            self.endpoint,
            json={
                "workspace": {"name": self.backbone._workspace_name, "display_name": display_name},
                "user": {
                    "name": self.backbone._username,
                    "email_address": email_address,
                    "public_key": self.backbone._secret_key.public_key.encode(
                        encoder=encoding.URLSafeBase64Encoder
                    ).decode(),
                    "permissions": [],  # Ignored by the server; the initial account must be root.
                },
                "namespace": {
                    "public_key": namespace_key.public_key.encode(encoding.URLSafeBase64Encoder).decode(),
                    "grants": [
                        {
                            "grantee_pk": self.backbone._secret_key.public_key.encode(
                                encoder=encoding.URLSafeBase64Encoder
                            ).decode(),
                            "access": list(map(lambda access: access.value, GrantAccess.__members__.values())),
                            "value": namespace_grant.decode(),
                        }
                    ],
                },
            },
            auth=self.backbone.authenticator,
        )

        response.raise_for_status()
        return Workspace.parse_obj(response.json())

    def delete(self, safety_check=True) -> None:
        if safety_check:
            print(f"WARNING: You're about to delete the workspace {self.backbone._workspace_name}")
            assert input("Please confirm by typing your workspace's name: ") == self.backbone._workspace_name

        response = self.backbone.session.delete(self.endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
