from typing import AsyncIterable, List, Set, Tuple

from backbone import crypto
from backbone.crypto import PrivateKey, PublicKey, encoding
from backbone.models import GrantAccess


class NamespaceClient:
    endpoint = "namespace"
    bulk_endpoint = "namespaces"
    chain_endpoint = "chain"
    grant_endpoint = "grant/namespace"
    child_namespace_endpoint = "child/namespace"
    child_entry_endpoint = "child/entry"

    def __init__(self, client):
        self.backbone = client

    async def __unroll_chain(self, key: str) -> Tuple[PrivateKey, dict]:
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
        namespace_public_key = PublicKey(result["public_key"], encoder=encoding.URLSafeBase64Encoder)
        namespace_private_key = PrivateKey(
            crypto.decrypt_grant(namespace_public_key, closest_namespace_sk, user_grant["value"])
        )
        return namespace_private_key, user_grant

    async def get(self, key: str) -> PrivateKey:
        return (await self.__unroll_chain(key))[0]

    async def get_chain(self, key: str) -> List[dict]:
        response = await self.backbone.session.get(f"{self.chain_endpoint}/{key}", auth=self.backbone.authenticator)
        response.raise_for_status()
        return response.json().get("chain")

    async def get_child_namespaces(self, prefix: str) -> AsyncIterable[dict]:
        async for item in self.backbone.paginate(f"{self.child_namespace_endpoint}/{prefix}"):
            yield item

    async def get_child_entries(self, prefix: str) -> AsyncIterable[dict]:
        async for item in self.backbone.paginate(f"{self.child_entry_endpoint}/{prefix}"):
            yield item

    async def search(self, prefix: str) -> AsyncIterable[str]:
        async for item in self.backbone.paginate(f"{self.bulk_endpoint}/{prefix}"):
            yield item

    async def create(self, key: str, *, access: List[GrantAccess] = (), isolated: bool = False) -> dict:
        grant_access = [item.value for item in access or GrantAccess]

        # Generate new namespace keypair
        new_namespace_key: PrivateKey = PrivateKey.generate()

        if isolated:
            # Grant access to the user directly
            grant_pk = self.backbone._public_key
        else:
            # Find all relevant children of the namespace
            chain = await self.backbone.namespace.get_chain(key)

            closest_namespace_sk: PrivateKey = crypto.decrypt_namespace_grant_chain(self.backbone._secret_key, chain)
            grant_pk: PublicKey = closest_namespace_sk.public_key

            # Default grant access to the closest namespace's access
            grant_access = grant_access or chain[-1]["access"]
            encoded_closest_namespace_pk: str = grant_pk.encode(encoder=encoding.URLSafeBase64Encoder).decode()

            async for child_namespace in self.get_child_namespaces(key):
                # Find the closest namespace's grant
                child_public_key = PublicKey(child_namespace["public_key"], encoder=encoding.URLSafeBase64Encoder)

                grant = next(
                    (
                        grant
                        for grant in child_namespace["grants"]
                        if grant["grantee_pk"] == encoded_closest_namespace_pk
                    ),
                    None,
                )

                grantee_sk: PrivateKey = PrivateKey(
                    crypto.decrypt_grant(child_public_key, closest_namespace_sk, grant["value"])
                )

                prospective_grant = {
                    "grantee_pk": new_namespace_key.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                    "value": crypto.encrypt_grant(new_namespace_key.public_key, grantee_sk).decode(),
                    "access": grant["access"],
                    "active": False,
                }

                await self.backbone.namespace.grant_raw(child_namespace["key"], prospective_grant)

            async for child_entry in self.get_child_entries(key):
                # Find the closest namespace's grant
                grant = next(
                    (grant for grant in child_entry["grants"] if grant["grantee_pk"] == encoded_closest_namespace_pk),
                    None,
                )

                entry_key = crypto.decrypt_entry_encryption_key(grant["value"], closest_namespace_sk)

                prospective_grant = {
                    "grantee_pk": new_namespace_key.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                    "value": crypto.create_entry_grant(entry_key, new_namespace_key.public_key).decode(),
                    "access": grant["access"],
                    "active": False,
                }

                await self.backbone.entry.grant_raw(child_entry["key"], prospective_grant)

        # Grant access to the new namespace
        namespace_grant = crypto.encrypt_grant(grant_pk, new_namespace_key)
        response = await self.backbone.session.post(
            f"{self.endpoint}/{key}",
            json={
                "public_key": new_namespace_key.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                "grants": [
                    {
                        "grantee_pk": grant_pk.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                        "value": namespace_grant.decode(),
                        "access": grant_access,
                    }
                ],
            },
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
        return response.json()

    async def delete(self, key: str) -> None:
        child_namespaces = []
        async for child_namespace in self.get_child_namespaces(key):
            child_namespaces.append(child_namespace)

        child_entries = []
        async for child_entry in self.get_child_entries(key):
            child_entries.append(child_entry)

        # Grants must be overwritten if the namespace has children
        if child_namespaces or child_entries:
            chain = await self.backbone.namespace.get_chain(key)

            # If a chain exists, the namespace is not isolated
            if chain:
                # Split the chain into the new parent namespace and the current namespace (being deleted)
                chain_invariant, chain_extension = chain[:-1], chain[-1]
                new_parent_namespace_sk: PrivateKey = crypto.decrypt_namespace_grant_chain(
                    self.backbone._secret_key, chain_invariant
                )
                new_parent_namespace_pk: PublicKey = new_parent_namespace_sk.public_key
                new_parent_namespace_pk_encoded = new_parent_namespace_pk.encode(
                    encoder=encoding.URLSafeBase64Encoder
                ).decode()

                current_parent_namespace_sk: PrivateKey = crypto.decrypt_namespace_grant_chain_step(
                    new_parent_namespace_sk, chain_extension
                )
                current_parent_namespace_pk: PublicKey = current_parent_namespace_sk.public_key
                current_parent_namespace_pk_encoded: str = current_parent_namespace_pk.encode(
                    encoder=encoding.URLSafeBase64Encoder
                ).decode()

                for child_namespace in child_namespaces:
                    child_public_key = PublicKey(child_namespace["public_key"], encoder=encoding.URLSafeBase64Encoder)

                    grant = next(
                        (
                            grant
                            for grant in child_namespace["grants"]
                            if grant["grantee_pk"] == current_parent_namespace_pk_encoded
                        ),
                        None,
                    )

                    grantee_sk: PrivateKey = PrivateKey(
                        crypto.decrypt_grant(child_public_key, current_parent_namespace_sk, grant["value"])
                    )

                    prospective_grant = {
                        "grantee_pk": new_parent_namespace_pk_encoded,
                        "value": crypto.encrypt_grant(new_parent_namespace_pk, grantee_sk).decode(),
                        "access": grant["access"],
                        "active": False,
                    }

                    await self.backbone.namespace.grant_raw(child_namespace["key"], prospective_grant)

                for child_entry in child_entries:
                    # Find the closest namespace's grant
                    grant = next(
                        (
                            grant
                            for grant in child_entry["grants"]
                            if grant["grantee_pk"] == current_parent_namespace_pk_encoded
                        ),
                        None,
                    )

                    entry_key = crypto.decrypt_entry_encryption_key(grant["value"], current_parent_namespace_sk)

                    prospective_grant = {
                        "grantee_pk": new_parent_namespace_pk_encoded,
                        "value": crypto.create_entry_grant(entry_key, new_parent_namespace_pk).decode(),
                        "access": grant["access"],
                        "active": False,
                    }

                    await self.backbone.entry.grant_raw(child_entry["key"], prospective_grant)

        response = await self.backbone.session.delete(f"{self.endpoint}/{key}", auth=self.backbone.authenticator)
        response.raise_for_status()

    async def grant_raw(self, key: str, *grants):
        response = await self.backbone.session.post(
            f"{self.grant_endpoint}/{key}", json=grants, auth=self.backbone.authenticator
        )
        response.raise_for_status()
        return response.json()

    async def grant(self, key: str, *users: str, access: Set[GrantAccess] = None, strict: bool = True) -> None:
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

        namespace_secret_key, namespace_grant = await self.__unroll_chain(key)

        grants = [
            {
                "grantee_pk": user.public_key,
                "value": crypto.encrypt_grant(
                    PublicKey(user.public_key, encoder=encoding.URLSafeBase64Encoder), namespace_secret_key
                ).decode(),
                "access": [level.value for level in access] or namespace_grant["access"],
            }
            for user in resolved_users
        ]

        return await self.grant_raw(key, *grants)

    async def revoke(self, key: str, *users: str, strict: bool = True) -> None:
        """
        Revoke users access to a namespace
        :param key: The namespace's key
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
