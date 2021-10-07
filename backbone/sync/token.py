from typing import List, Optional

from httpx import Response
from backbone.crypto import encrypt_token_challenge, decrypt_token
import base64

from backbone import models


class TokenClient:
    endpoint = "token"
    bulk_endpoint = "tokens"

    def __init__(self, client):
        self.backbone = client

    def _decrypt_token(self, response: Response) -> str:
        token: models.Token = models.Token.parse_obj(response.json())
        return decrypt_token(self.backbone._secret_key, token.encrypted_value.encode()).decode()

    def get_all(self):
        for item in self.backbone.paginate(self.bulk_endpoint):
            yield models.Token.parse_obj(item)

    def get(self) -> models.Token:
        response = self.backbone.session.get(self.endpoint, auth=self.backbone.authenticator)
        self.backbone.handle_exception(response)
        return models.Token.parse_obj(response.json())

    def authenticate(self, permissions: Optional[List[models.Permission]] = None, duration: int = 86_400) -> str:
        challenge_response = self.backbone.session.request(
            method="GET",
            url=f"{self.endpoint}/authenticate",
            content=models.TokenRequest(
                workspace=self.backbone._workspace_name,
                username=self.backbone._username,
                permissions=permissions,
                duration=duration,
            ).json(),
        )

        self.backbone.handle_exception(challenge_response)
        challenge: models.TokenChallenge = models.TokenChallenge.parse_obj(challenge_response.json())
        raw_challenge = base64.urlsafe_b64decode(challenge.challenge)
        proof = encrypt_token_challenge(self.backbone._secret_key, raw_challenge).decode()

        response = self.backbone.session.request(
            method="POST",
            url=f"{self.endpoint}/authenticate",
            content=models.TokenResponse(
                workspace=self.backbone._workspace_name,
                username=self.backbone._username,
                permissions=permissions,
                duration=duration,
                response=proof
            ).json(),
        )

        self.backbone.handle_exception(response)
        return self._decrypt_token(response)

    def derive(self, permissions: Optional[List[models.Permission]] = None, duration: int = 86_400) -> str:
        response = self.backbone.session.request(
            method="POST",
            url=f"{self.endpoint}/derive",
            content=models.TokenDerivation(permissions=permissions, duration=duration).json(),
            auth=self.backbone.authenticator,
        )
        self.backbone.handle_exception(response)
        return self._decrypt_token(response)

    def revoke(self) -> None:
        response = self.backbone.session.delete(self.endpoint, auth=self.backbone.authenticator)
        self.backbone.handle_exception(response)
