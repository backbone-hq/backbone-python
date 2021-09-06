from typing import List, Optional

from httpx import Response

from backbone.crypto import decrypt_hidden_token
from backbone.models import Permission, Token, TokenAuthentication, TokenDerivation


class TokenClient:
    endpoint = "token"
    bulk_endpoint = "tokens"

    def __init__(self, client):
        self.backbone = client

    def get_all(self):
        for item in self.backbone.paginate(self.bulk_endpoint):
            yield Token.parse_obj(item)

    def get(self) -> Token:
        response = self.backbone.session.get(self.endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return Token.parse_obj(response.json())

    def authenticate(self, permissions: Optional[List[Permission]] = None, duration: int = 86_400) -> str:
        response = self.backbone.session.post(
            self.endpoint,
            content=TokenAuthentication(
                workspace=self.backbone._workspace_name,
                username=self.backbone._username,
                permissions=permissions,
                duration=duration,
            ).json(),
        )
        response.raise_for_status()
        return self.__decrypt_token_response(response)

    def derive(self, permissions: Optional[List[Permission]] = None, duration: int = 86_400) -> str:
        response = self.backbone.session.patch(
            self.endpoint,
            content=TokenDerivation(permissions=permissions, duration=duration).json(),
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
        return self.__decrypt_token_response(response)

    def revoke(self) -> None:
        response = self.backbone.session.delete(self.endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()

    def __decrypt_token_response(self, response: Response) -> str:
        token: Token = Token.parse_obj(response.json())
        hidden_token = token.hidden_token
        return decrypt_hidden_token(self.backbone._secret_key, hidden_token.encode()).decode()
