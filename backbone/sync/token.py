from typing import Optional, List
from backbone.models import Permission
from backbone.crypto import decrypt_hidden_token
from httpx import Response


class TokenClient:
    def __init__(self, client):
        self.backbone = client

    def get(self) -> dict:
        token_endpoint = self.backbone.endpoint("token")

        response = self.backbone.session.get(token_endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return response.json()

    def authenticate(self, permissions: Optional[List[Permission]] = None, duration: int = 86_400) -> str:
        token_endpoint = self.backbone.endpoint("token")

        response = self.backbone.session.post(
            token_endpoint,
            json={
                "workspace": self.backbone._workspace_name,
                "username": self.backbone._username,
                "permissions": None if permissions is None else [permission.value for permission in permissions],
                "duration": duration,
            },
        )
        response.raise_for_status()
        return self.__parse(response)

    def derive(self, permissions: Optional[List[Permission]] = None, duration: int = 86_400) -> str:
        token_endpoint = self.backbone.endpoint("token")
        response = self.backbone.session.patch(
            token_endpoint,
            json={
                "permissions": None if permissions is None else [permission.value for permission in permissions],
                "duration": duration,
            },
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
        return self.__parse(response)

    def revoke(self, throw: bool = True) -> None:
        token_endpoint = self.backbone.endpoint("token")
        response = self.backbone.session.delete(token_endpoint, auth=self.backbone.authenticator)

        if throw:
            response.raise_for_status()

    def __parse(self, response: Response) -> str:
        result = response.json()
        hidden_token = result["hidden_token"]
        return decrypt_hidden_token(self.backbone._secret_key, hidden_token.encode()).decode()
