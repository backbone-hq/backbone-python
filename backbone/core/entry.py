from typing import AsyncIterable, List, Set, Tuple

from backbone import crypto
from backbone.crypto import PrivateKey, PublicKey, encoding
from backbone.models import GrantAccess


class EntryClient:
    endpoint = "entry"
    bulk_endpoint = "entries"
    chain_endpoint = "chain"
    grant_endpoint = "grant/entry"

    def __init__(self, client):
        self.backbone = client

    async def __unroll_chain(self, key: str) -> Tuple[str, dict, PrivateKey]:
        response = await self.backbone.session.get(f"{self.endpoint}/{key}", auth=self.backbone.authenticator)
        response.raise_for_status()
        result = response.json()

        # Decrypt the grant chain; obtain the nearest namespace's private key
        closest_namespace_sk = crypto.decrypt_namespace_grant_chain(self.backbone._secret_key, result["chain"])

        # Find the nearest namespace's grant
        current_namespace_pk = closest_namespace_sk.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
        grants = [grant for grant in result["grants"] if grant["grantee_pk"] == current_namespace_pk]

        # The user should only have a single grant (with at least READ access)
        user_grant = grants[0]
        return result["value"], user_grant, closest_namespace_sk

    async def get(self, key: str) -> str:
        """
        Obtains the value stored under a particular key
        :param key: the key to obtain
        :return: the value if the user has sufficient access
        """
        ciphertext, grant, grant_sk = await self.__unroll_chain(key)
        return crypto.decrypt_entry(ciphertext, grant["value"].encode(), grant_sk).decode()

    async def search(self, prefix: str) -> AsyncIterable[str]:
        async for item in self.backbone.paginate(f"{self.bulk_endpoint}/{prefix}"):
            yield item

    async def set(self, key: str, value: str, access: List[GrantAccess] = ()) -> dict:
        chain = await self.backbone.namespace.get_chain(key)
        closest_namespace_grant = chain[-1]
        namespace_public_key = PublicKey(closest_namespace_grant["subject_pk"], encoder=encoding.URLSafeBase64Encoder)
        ciphertext, grants = crypto.encrypt_entry(value, namespace_public_key)

        response = await self.backbone.session.post(
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
            },
            auth=self.backbone.authenticator,
        )

        response.raise_for_status()
        return response.json()

    async def delete(self, key: str) -> None:
        response = await self.backbone.session.delete(f"{self.endpoint}/{key}", auth=self.backbone.authenticator)
        response.raise_for_status()

    async def grant_raw(self, key: str, *grants):
        response = await self.backbone.session.post(
            f"{self.grant_endpoint}/{key}", json=grants, auth=self.backbone.authenticator
        )
        response.raise_for_status()
        return response.json()

    async def grant(self, key: str, *users: str, access: Set[GrantAccess] = None, strict: bool = True) -> dict:
        """
        Grant users a certain level of access to a namespace
        :param key: The namespace's key
        :param users: A collection of users to grant the level of access to
        :param access: The access package to grant. Grants equivalent access to the current user if `None`
        :param strict: Throw if one of the specified users does not exist
        """

        resolved_users = await self.backbone.user.search(users)
        if strict and len(resolved_users) != len(users):
            raise ValueError

        _, grant, grant_sk = self.__unroll_chain(key)
        entry_key = crypto.decrypt_entry_encryption_key(grant["value"].encode(), grant_sk)

        grants = [
            {
                "grantee_pk": user["public_key"],
                "value": crypto.create_entry_grant(
                    entry_key, PublicKey(user["public_key"], encoder=encoding.URLSafeBase64Encoder)
                ).decode(),
                "access": [level.value for level in access] or grant["access"],
            }
            for user in resolved_users
        ]

        return await self.grant_raw(key, *grants)

    async def revoke(self, key: str, *users: str, strict: bool = True) -> None:
        """
        Revoke users access to an entry
        :param key: The entry's key
        :param users: A collection of users to grant the level of access to
        :param strict: Throw if one of the specified users does not exist
        """

        resolved_users = await self.backbone.user.search(users)
        if strict and len(resolved_users) != len(users):
            raise ValueError

        response = await self.backbone.session.request(
            "DELETE",
            f"{self.grant_endpoint}/{key}",
            json=[user["public_key"] for user in resolved_users],
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
