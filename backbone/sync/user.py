from typing import Iterable, List, Tuple

from backbone.crypto import PrivateKey, PublicKey, derive_password_key, encoding
from backbone.models import Permission, User, UserPermissionModification


class UserClient:
    endpoint = "user"
    bulk_endpoint = "users"

    def __init__(self, client):
        self.backbone = client

    def list(self) -> Iterable[User]:
        for user in self.backbone.paginate(self.bulk_endpoint):
            yield User.parse_obj(user)

    def get(self, *usernames: str) -> Tuple[User]:
        response = self.backbone.session.post(
            self.bulk_endpoint, auth=self.backbone.authenticator, json=usernames
        )
        self.backbone.handle_exception(response)
        return tuple(map(User.parse_obj, response.json()))

    def self(self) -> User:
        response = self.backbone.session.get(self.endpoint, auth=self.backbone.authenticator)
        self.backbone.handle_exception(response)
        return User.parse_obj(response.json())

    def create(
        self,
        username: str,
        public_key: PublicKey,
        permissions: List[Permission] = (),
    ) -> User:
        response = self.backbone.session.post(
            self.endpoint,
            content=User(
                name=username,
                public_key=public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                permissions=permissions,
            ).json(),
            auth=self.backbone.authenticator,
        )
        self.backbone.handle_exception(response)
        return User.parse_obj(response.json())

    def create_from_credentials(self, username: str, password: str, permissions: List[Permission] = ()) -> User:
        derived_public_key = PrivateKey(derive_password_key(identity=username, password=password)).public_key
        return self.create(
            username=username,
            public_key=derived_public_key,
            permissions=permissions,
        )

    def modify(self, username: str, permissions: List[Permission] = ()) -> User:
        response = self.backbone.session.patch(
            self.endpoint,
            content=UserPermissionModification(name=username, permissions=permissions).json(),
            auth=self.backbone.authenticator,
        )
        self.backbone.handle_exception(response)
        return User.parse_obj(response.json())

    def delete(self, username: str, force: bool = False) -> None:
        response = self.backbone.session.delete(
            self.endpoint, params={"username": username, "force": force}, auth=self.backbone.authenticator
        )
        self.backbone.handle_exception(response)
