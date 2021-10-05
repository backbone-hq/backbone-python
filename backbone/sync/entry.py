from typing import List, Optional, Set, Tuple

from backbone import crypto
from backbone.crypto import PrivateKey, PublicKey, encoding
from backbone.models import GrantAccess


class EntryClient:
    endpoint = "entry"
    grant_endpoint = "grant/entry"

    def __init__(self, client):
        self.backbone = client

    def _unroll_chain(self, key: str) -> Tuple[str, dict, PrivateKey]:
        response = self.backbone.session.get(f"{self.endpoint}/{key}", auth=self.backbone.authenticator)
        self.backbone.handle_exception(response)
        result = response.json()

        # Decrypt the grant chain; obtain the nearest namespace's private key
        closest_namespace_sk = crypto.decrypt_namespace_grant_chain(self.backbone._secret_key, result["chain"])

        # Find the nearest namespace's grant
        current_namespace_pk = closest_namespace_sk.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
        grants = [grant for grant in result["grants"] if grant["grantee_pk"] == current_namespace_pk]

        if not grants:
            raise ValueError

        # The user should only have a single grant (with at least READ access)
        user_grant = grants[0]
        return result["value"], user_grant, closest_namespace_sk

    def get(self, key: str) -> str:
        """
        Obtains the value stored under a particular key
        :param key: the key to obtain
        :return: the value if the user has sufficient access
        """
        ciphertext, grant, grant_sk = self._unroll_chain(key)
        return crypto.decrypt_entry(ciphertext, grant["value"].encode(), grant_sk).decode()

    def set(self, key: str, value: str, access: List[GrantAccess] = (), duration: Optional[int] = None) -> dict:
        chain = self.backbone.namespace.get_chain(key)
        closest_namespace_grant = chain[-1]
        namespace_public_key = PublicKey(closest_namespace_grant["subject_pk"], encoder=encoding.URLSafeBase64Encoder)
        ciphertext, grants = crypto.encrypt_entry(value, namespace_public_key)

        response = self.backbone.session.post(
            f"{self.endpoint}/{key}",
            json={
                "value": ciphertext.decode(),
                "grants": [
                    {
                        "grantee_pk": public_key.decode(),
                        "value": value.decode(),
                        "access": [level.value for level in access] or closest_namespace_grant["access"],
                    }
                    for public_key, value in grants
                ],
                "duration": duration,
            },
            auth=self.backbone.authenticator,
            timeout=None,
        )

        self.backbone.handle_exception(response)
        return response.json()

    def delete(self, key: str) -> None:
        response = self.backbone.session.delete(f"{self.endpoint}/{key}", auth=self.backbone.authenticator)
        self.backbone.handle_exception(response)

    def grant_raw(self, key: str, *grants):
        response = self.backbone.session.post(
            f"{self.grant_endpoint}/{key}", json=grants, auth=self.backbone.authenticator
        )
        self.backbone.handle_exception(response)
        return response.json()

    def grant(self, key: str, *users: str, access: Set[GrantAccess] = None, strict: bool = True) -> dict:
        """
        Grant users a certain level of access to an entry
        :param key: The entry's key
        :param users: A collection of users to grant the level of access to
        :param access: The access package to grant. Grants equivalent access to the current user if `None`
        :param strict: Throw if one of the specified users does not exist
        """

        resolved_users = self.backbone.user.get(*users)
        if strict and len(resolved_users) != len(users):
            raise ValueError

        _, grant, grant_sk = self._unroll_chain(key)
        entry_key = crypto.decrypt_entry_encryption_key(grant["value"].encode(), grant_sk)
        access = [item.value for item in access] if access else grant["access"]

        grants = [
            {
                "grantee_pk": user.public_key,
                "value": crypto.create_entry_grant(
                    entry_key, PublicKey(user.public_key, encoder=encoding.URLSafeBase64Encoder)
                ).decode(),
                "access": access,
            }
            for user in resolved_users
        ]

        return self.grant_raw(key, *grants)

    def revoke(self, key: str, *users: str, strict: bool = True) -> None:
        """
        Revoke users access to an entry
        :param key: The entry's key
        :param users: A collection of users to revoke access from
        :param strict: Throw if one of the specified users does not exist
        """

        resolved_users = self.backbone.user.get(*users)
        if strict and len(resolved_users) != len(users):
            raise ValueError

        response = self.backbone.session.request(
            "DELETE",
            f"{self.grant_endpoint}/{key}",
            json=[user["public_key"] for user in resolved_users],
            auth=self.backbone.authenticator,
        )
        self.backbone.handle_exception(response)
