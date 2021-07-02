from typing import Tuple, Optional, List

from backbone.crypto import PublicKey, PrivateKey, encoding, derive_password_key
from backbone.models import Permission


class UserClient:
    def __init__(self, client):
        self.backbone = client

    async def get_all(self):
        endpoint = self.backbone.endpoint("users")
        async for item in self.backbone.paginate(endpoint):
            yield item

    async def search(self, usernames: Tuple[str]) -> dict:
        endpoint = self.backbone.endpoint("users")
        response = await self.backbone.session.post(endpoint, auth=self.backbone.authenticator, json=usernames)
        response.raise_for_status()
        return response.json()

    async def get(self) -> dict:
        endpoint = self.backbone.endpoint("user")
        response = await self.backbone.session.get(endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return response.json()

    async def create(
        self,
        username: str,
        public_key: PublicKey,
        email_address: Optional[str] = None,
        permissions: List[Permission] = (),
    ) -> dict:
        endpoint = self.backbone.endpoint("user")
        response = await self.backbone.session.post(
            endpoint,
            json={
                "name": username,
                "email_address": email_address,
                "public_key": public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                "permissions": [permission.value for permission in permissions],
            },
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
        return response.json()

    async def create_self(self, email_address: Optional[str] = None, permissions: List[Permission] = ()):
        return self.create(
            username=self.backbone._username,
            public_key=self.backbone._public_key,
            email_address=email_address,
            permissions=permissions,
        )

    async def create_from_credentials(
        self, username: str, password: str, email_address: Optional[str] = None, permissions: List[Permission] = ()
    ) -> dict:
        derived_public_key = PrivateKey(derive_password_key(identity=username, password=password)).public_key
        return await self.create(
            username=username,
            public_key=derived_public_key,
            email_address=email_address,
            permissions=permissions,
        )

    async def delete(self, force_delete: bool = False) -> None:
        endpoint = self.backbone.endpoint("user")
        response = await self.backbone.session.delete(
            endpoint, params={"force_delete": force_delete}, auth=self.backbone.authenticator
        )
        response.raise_for_status()
