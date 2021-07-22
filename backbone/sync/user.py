from typing import Iterable, List, Optional, Tuple

from backbone.crypto import PrivateKey, PublicKey, derive_password_key, encoding
from backbone.models import Permission, User


class UserClient:
    endpoint = "user"
    bulk_endpoint = "users"

    def __init__(self, client):
        self.backbone = client

    def get_all(self) -> Iterable[User]:
        for item in self.backbone.paginate(self.bulk_endpoint):
            yield User.parse_obj(item)

    def search(self, usernames: Tuple[str]) -> Tuple[User]:
        response = self.backbone.session.post(
            self.bulk_endpoint, auth=self.backbone.authenticator, json=usernames
        )
        response.raise_for_status()
        return tuple(User.parse_obj(user) for user in response.json())

    def get(self) -> User:
        response = self.backbone.session.get(self.endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return User.parse_obj(response.json())

    def create(
        self,
        username: str,
        public_key: PublicKey,
        email_address: Optional[str] = None,
        permissions: List[Permission] = (),
    ) -> User:
        response = self.backbone.session.post(
            self.endpoint,
            content=User(
                name=username,
                email_address=email_address,
                public_key=public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                permissions=permissions,
            ).json(),
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
        return User.parse_obj(response.json())

    def create_self(self, email_address: Optional[str] = None, permissions: List[Permission] = ()) -> User:
        return self.create(
            username=self.backbone._username,
            public_key=self.backbone._public_key,
            email_address=email_address,
            permissions=permissions,
        )

    def create_from_credentials(
        self, username: str, password: str, email_address: Optional[str] = None, permissions: List[Permission] = ()
    ) -> User:
        derived_public_key = PrivateKey(derive_password_key(identity=username, password=password)).public_key
        return self.create(
            username=username,
            public_key=derived_public_key,
            email_address=email_address,
            permissions=permissions,
        )

    def delete(self, force_delete: bool = False) -> None:
        response = self.backbone.session.delete(
            self.endpoint, params={"force_delete": force_delete}, auth=self.backbone.authenticator
        )
        response.raise_for_status()
