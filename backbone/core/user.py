from typing import AsyncIterable, List, Optional, Tuple

from backbone.crypto import PrivateKey, PublicKey, derive_password_key, encoding
from backbone.models import Permission, User, UserPermissionModification


class UserClient:
    endpoint = "user"
    bulk_endpoint = "users"

    def __init__(self, client):
        self.backbone = client

    async def list(self) -> AsyncIterable[User]:
        async for user in self.backbone.paginate(self.bulk_endpoint):
            yield User.parse_obj(user)

    async def get(self, *usernames: str) -> Tuple[User]:
        response = await self.backbone.session.post(
            self.bulk_endpoint, auth=self.backbone.authenticator, json=usernames
        )
        response.raise_for_status()
        return tuple(map(User.parse_obj, response.json()))

    async def self(self) -> User:
        response = await self.backbone.session.get(self.endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return User.parse_obj(response.json())

    async def create(
        self,
        username: str,
        public_key: PublicKey,
        permissions: List[Permission] = (),
    ) -> User:
        response = await self.backbone.session.post(
            self.endpoint,
            content=User(
                name=username,
                public_key=public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                permissions=permissions,
            ).json(),
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
        return User.parse_obj(response.json())

    async def create_from_credentials(self, username: str, password: str, permissions: List[Permission] = ()) -> User:
        derived_public_key = PrivateKey(derive_password_key(identity=username, password=password)).public_key
        return await self.create(
            username=username,
            public_key=derived_public_key,
            permissions=permissions,
        )

    async def modify(self, username: str, permissions: List[Permission] = ()) -> User:
        response = await self.backbone.session.patch(
            self.endpoint,
            content=UserPermissionModification(name=username, permissions=permissions).json(),
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
        return User.parse_obj(response.json())

    async def delete(self, username: str, force: bool = False) -> None:
        response = await self.backbone.session.delete(
            self.endpoint, params={"username": username, "force": force}, auth=self.backbone.authenticator
        )
        response.raise_for_status()
