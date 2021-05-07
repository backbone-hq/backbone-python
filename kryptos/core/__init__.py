import base64
from typing import Generator, List, Optional, Tuple

import httpx
from nacl import encoding
from nacl.public import PrivateKey, PublicKey

from kryptos import crypto
from kryptos.models import GrantAccess, Permission

__version__ = 0


class KryptosAuth(httpx.Auth):
    def __init__(self, client: "KryptosClient", permissions: Optional[List[Permission]], token: str):
        self.client = client
        self.permissions = permissions
        self.token = token

    async def async_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self.token}"
        response = yield request

        # Reauthenticate in the event of an invalid token
        if response.status_code == 401:
            await self.client.authenticate(self.permissions)


class KryptosClient:
    _base_url = f"http://localhost:8000/v{__version__}"

    def __init__(self, workspace: str, username: str, secret_key: PrivateKey):
        # Kryptos parameters
        self._secret_key: PrivateKey = secret_key
        self._public_key: PublicKey = secret_key.public_key
        self._username: str = username
        self._workspace_name: str = workspace

        # Endpoint Clients
        self.namespace: _NamespaceClient = _NamespaceClient(self)
        self.entry: _EntryClient = _EntryClient(self)
        self.token: _TokenClient = _TokenClient(self)
        self.workspace: _WorkspaceClient = _WorkspaceClient(self)
        self.user: _UserClient = _UserClient(self)

        # Properties
        self.__session: Optional[httpx.AsyncClient] = None
        self.authenticator: Optional[KryptosAuth] = None

    @property
    def session(self) -> httpx.AsyncClient:
        if not self.__session:
            self.__session = httpx.AsyncClient()

        return self.__session

    async def __aenter__(self):
        if not self.__session:
            self.__session = httpx.AsyncClient()

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        if self.__session:
            await self.__session.aclose()

        self.__session = None

    @classmethod
    def from_credentials(cls, workspace: str, username: str, password: str):
        derived_private_key = crypto.derive_password_key(identity=username, password=password)
        return cls(workspace=workspace, username=username, secret_key=PrivateKey(derived_private_key))

    @classmethod
    def endpoint(cls, *parts: str) -> str:
        return f"{cls._base_url}/{'/'.join(parts)}"

    async def authenticate(self, permissions: Optional[List[Permission]] = None):
        """Initialize the client with a scoped token"""
        if not self.authenticator:
            token: str = await self.token.authenticate(permissions=permissions)
            self.authenticator = KryptosAuth(client=self, permissions=permissions, token=token)

    async def deauthenticate(self):
        """Revoke the current token and remove the authenticator"""
        await self.token.revoke()
        self.authenticator = None

    async def paginate(self, endpoint):
        response = await self.session.get(endpoint, auth=self.authenticator)
        response.raise_for_status()
        result = response.json()

        for item in result["results"]:
            yield item

        while result["next"]:
            response = await self.session.get(endpoint, params=result["next"], auth=self.authenticator)
            response.raise_for_status()
            result = response.json()

            for item in result["results"]:
                yield item


class _TokenClient:
    def __init__(self, client: KryptosClient):
        self.kryptos = client

    async def authenticate(self, permissions: List[Permission]) -> str:
        token_endpoint = self.kryptos.endpoint("token")

        response = await self.kryptos.session.post(
            token_endpoint,
            json={
                "workspace": self.kryptos._workspace_name,
                "username": self.kryptos._username,
                "permissions": [permission.value for permission in permissions],
            },
        )
        response.raise_for_status()
        return self._parse(response)

    async def derive(self) -> str:
        token_endpoint = self.kryptos.endpoint("token")
        response = await self.kryptos.session.patch(token_endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()
        return self._parse(response)

    async def revoke(self) -> None:
        token_endpoint = self.kryptos.endpoint("token")
        response = await self.kryptos.session.delete(token_endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()

    def _parse(self, response: httpx.Response) -> str:
        result = response.json()
        hidden_token = result["hidden_token"]
        return crypto.decrypt_hidden_token(self.kryptos._secret_key, hidden_token.encode()).decode()


class _WorkspaceClient:
    def __init__(self, client: KryptosClient):
        self.kryptos = client

    async def get(self) -> dict:
        endpoint = self.kryptos.endpoint("workspace")
        response = await self.kryptos.session.get(endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()
        return response.json()

    async def create(self, display_name: str, email_address: str) -> dict:
        endpoint = self.kryptos.endpoint("workspace")

        # Generate root namespace keypair
        namespace_key: PrivateKey = PrivateKey.generate()
        namespace_grant = crypto.encrypt_grant(self.kryptos._secret_key.public_key, namespace_key)

        response = await self.kryptos.session.post(
            endpoint,
            json={
                "workspace": {"name": self.kryptos._workspace_name, "display_name": display_name},
                "user": {
                    "name": self.kryptos._username,
                    "email_address": email_address,
                    "public_key": self.kryptos._secret_key.public_key.encode(
                        encoder=encoding.URLSafeBase64Encoder
                    ).decode(),
                    "hidden_key": crypto.encrypt_with_secret(
                        secret=self.kryptos._secret_key.encode(), plaintext=self.kryptos._secret_key.encode()
                    ).decode(),
                    "permissions": [],  # Ignored by the server; the initial account must be root.
                },
                "namespace": {
                    "public_key": namespace_key.public_key.encode(encoding.URLSafeBase64Encoder).decode(),
                    "grants": [
                        {
                            "grantee_pk": self.kryptos._secret_key.public_key.encode(
                                encoder=encoding.URLSafeBase64Encoder
                            ).decode(),
                            "access": list(map(lambda access: access.value, GrantAccess.__members__.values())),
                            "value": namespace_grant.decode(),
                        }
                    ],
                },
            },
            auth=self.kryptos.authenticator,
        )

        response.raise_for_status()
        return response.json()

    async def delete(self, safety_check=True) -> None:
        if safety_check:
            print(f"WARNING: You're about to delete the workspace {self.kryptos._workspace_name}")
            assert input("Please confirm by typing your workspace's name: ") == self.kryptos._workspace_name

        endpoint = self.kryptos.endpoint("workspace")
        response = await self.kryptos.session.delete(endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()


class _UserClient:
    def __init__(self, client: KryptosClient):
        self.kryptos = client

    async def get_all(self):
        endpoint = self.kryptos.endpoint("users")
        async for item in self.kryptos.paginate(endpoint):
            yield item

    async def find(self, username: str) -> dict:
        endpoint = self.kryptos.endpoint("user", username)
        response = await self.kryptos.session.get(endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()
        return response.json()

    async def get(self) -> dict:
        endpoint = self.kryptos.endpoint("user")
        response = await self.kryptos.session.get(endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()
        return response.json()

    async def create(
        self,
        username: Optional[str] = None,
        secret_key: Optional[PrivateKey] = None,
        email_address: Optional[str] = None,
        permissions: List[Permission] = (),
    ) -> dict:
        username = username or self.kryptos._username
        secret_key = secret_key or self.kryptos._secret_key

        endpoint = self.kryptos.endpoint("user")
        response = await self.kryptos.session.post(
            endpoint,
            json={
                "name": username,
                "email_address": email_address,
                "public_key": secret_key.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                "hidden_key": crypto.encrypt_with_secret(
                    secret=self.kryptos._secret_key.encode(), plaintext=self.kryptos._secret_key.encode()
                ).decode(),
                "permissions": [permission.value for permission in permissions],
            },
            auth=self.kryptos.authenticator,
        )
        response.raise_for_status()
        return response.json()

    async def create_from_credentials(
        self, username: str, password: str, email_address: Optional[str] = None, permissions: List[Permission] = ()
    ) -> dict:
        derived_private_key = crypto.derive_password_key(identity=username, password=password)
        return await self.create(
            username=username,
            secret_key=PrivateKey(derived_private_key),
            email_address=email_address,
            permissions=permissions,
        )

    async def delete(self) -> None:
        endpoint = self.kryptos.endpoint("user")
        response = await self.kryptos.session.delete(endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()


class _NamespaceClient:
    def __init__(self, client: KryptosClient):
        self.kryptos = client

    async def __unroll_chain(self, key: str) -> Tuple[PrivateKey, dict]:
        endpoint = self.kryptos.endpoint("namespace", key)
        response = await self.kryptos.session.get(endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()
        result = response.json()

        # Follow and decrypt the namespace grant chain
        current_sk: PrivateKey = self.kryptos._secret_key
        for grant in result["chain"]:
            subject_pk = PublicKey(grant["subject_pk"], encoder=encoding.URLSafeBase64Encoder)
            current_sk: PrivateKey = PrivateKey(crypto.decrypt_grant(subject_pk, current_sk, grant["value"]))

        # Find the relevant entry grant
        current_pk = current_sk.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
        grants = [grant for grant in result["grants"] if grant["grantee_pk"] == current_pk]
        if not grants:
            # This shouldn't happen; the user must have at least 1 `READ` grant on the entry for the endpoint to return
            raise ValueError

        # Pick the first
        grant = grants[0]
        namespace_public_key = PublicKey(result["public_key"], encoder=encoding.URLSafeBase64Encoder)
        namespace_private_key = PrivateKey(crypto.decrypt_grant(namespace_public_key, current_sk, grant["value"]))
        return namespace_private_key, grant

    async def get(self, key: str) -> PrivateKey:
        return (await self.__unroll_chain(key))[0]

    async def get_chain(self, key: str) -> List[dict]:
        endpoint = self.kryptos.endpoint("chain", key)
        response = await self.kryptos.session.get(endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()
        return response.json().get("chain")

    async def search(self, key: str):
        endpoint = self.kryptos.endpoint("namespaces", key)
        async for item in self.kryptos.paginate(endpoint):
            yield item

    async def create(self, key: str, *, access: List[GrantAccess] = (), is_segregated: bool = False) -> dict:
        grant_access = [item.value for item in access or GrantAccess]

        if is_segregated:
            # Grant access to the user directly
            # TODO: Backend permissions
            grant_pk = self.kryptos._public_key
        else:
            # Find the closest namespace
            chain = await self.get_chain(key)
            parent_grant = chain[-1]

            grant_pk = PublicKey(base64.urlsafe_b64decode(parent_grant["subject_pk"]))
            grant_access = grant_access or parent_grant["access"]

        # Generate new namespace keypair
        namespace_key: PrivateKey = PrivateKey.generate()
        namespace_grant = crypto.encrypt_grant(grant_pk, namespace_key)

        endpoint = self.kryptos.endpoint("namespace", key)
        response = await self.kryptos.session.post(
            endpoint,
            json={
                "public_key": namespace_key.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                "grants": [
                    {
                        "grantee_pk": grant_pk.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                        "value": namespace_grant.decode(),
                        "access": grant_access,
                    }
                ],
            },
            auth=self.kryptos.authenticator,
        )

        response.raise_for_status()
        return response.json()

    async def delete(self, key: str) -> None:
        endpoint = self.kryptos.endpoint("namespace", key)
        response = await self.kryptos.session.delete(endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()

    async def grant(self, key: str, access: List[GrantAccess] = (), *users: PublicKey) -> None:
        namespace_secret_key, namespace_grant = self.__unroll_chain(key)

        grants = [
            (
                public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                crypto.encrypt_grant(public_key, namespace_secret_key),
            )
            for public_key in users
        ]

        endpoint = self.kryptos.endpoint("grant", "namespace", key)
        response = await self.kryptos.session.post(
            endpoint,
            json=[
                {
                    "grantee_pk": public_key.decode(),
                    "value": value.decode(),
                    "access": [level.value for level in access] or namespace_grant["access"],
                }
                for public_key, value in grants
            ],
            auth=self.kryptos.authenticator,
        )
        response.raise_for_status()

    async def revoke(self, key: str, *users: PublicKey) -> None:
        endpoint = self.kryptos.endpoint("grant", "namespace", key)

        response = await self.kryptos.session.post(
            endpoint,
            json=[public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode() for public_key in users],
            auth=self.kryptos.authenticator,
        )
        response.raise_for_status()


class _EntryClient:
    def __init__(self, client: KryptosClient):
        self.kryptos = client

    async def __unroll_chain(self, key: str) -> Tuple[str, str, PrivateKey]:
        endpoint = self.kryptos.endpoint("entry", key)
        response = await self.kryptos.session.get(endpoint, auth=self.kryptos.authenticator)
        response.raise_for_status()
        result = response.json()

        # Follow and decrypt the namespace grant chain
        current_sk: PrivateKey = self.kryptos._secret_key
        for grant in result["chain"]:
            subject_pk = PublicKey(grant["subject_pk"], encoder=encoding.URLSafeBase64Encoder)
            current_sk: PrivateKey = PrivateKey(crypto.decrypt_grant(subject_pk, current_sk, grant["value"]))

        # Find the relevant entry grant
        current_pk = current_sk.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
        grants = [grant for grant in result["grants"] if grant["grantee_pk"] == current_pk]
        if not grants:
            # This shouldn't happen; the user must have at least 1 `READ` grant on the entry for the endpoint to return
            raise ValueError

        # Pick the first
        current_grant = grants[0]
        return result["value"], current_grant["value"], current_sk

    async def get(self, key: str) -> str:
        """
        Obtains the value stored under a particular key
        :param key: the key to obtain
        :return: the value if the user has sufficient access
        """
        ciphertext, grant, grant_sk = await self.__unroll_chain(key)
        return crypto.decrypt_entry(ciphertext, grant.encode(), grant_sk).decode()

    async def search(self, key: str):
        endpoint = self.kryptos.endpoint("entries", key)
        async for item in self.kryptos.paginate(endpoint):
            yield item

    async def set(self, key: str, value: str, access: List[GrantAccess] = ()) -> dict:
        chain = await self.kryptos.namespace.get_chain(key)
        closest_namespace_grant = chain[-1]
        namespace_public_key = PublicKey(base64.urlsafe_b64decode(closest_namespace_grant["subject_pk"]))
        ciphertext, grants = crypto.encrypt_entry(value, namespace_public_key)

        endpoint = self.kryptos.endpoint("entry", key)
        response = await self.kryptos.session.post(
            endpoint,
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
            auth=self.kryptos.authenticator,
        )

        response.raise_for_status()
        return response.json()

    async def grant(self, key: str, access: List[GrantAccess], *users: PublicKey) -> dict:
        # Get the user's grant
        _, grant, grant_sk = self.__unroll_chain(key)
        entry_key = crypto.decrypt_entry_encryption_key(grant.encode(), grant_sk)

        grants = [
            (
                public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                crypto.create_entry_grant(entry_key, public_key),
            )
            for public_key in users
        ]

        endpoint = self.kryptos.endpoint("grant", "entry", key)
        response = await self.kryptos.session.post(
            endpoint,
            json=[
                {
                    "grantee_pk": public_key.decode(),
                    "value": value.decode(),
                    # TODO (dalmjali): Inherit grant access from the user's grant by default
                    "access": [level.value for level in access],
                }
                for public_key, value in grants
            ],
            auth=self.kryptos.authenticator,
        )
        response.raise_for_status()
        return response.json()

    async def revoke(self, key: str, *users: PublicKey) -> None:
        endpoint = self.kryptos.endpoint("grant", "entry", key)
        response = await self.kryptos.session.delete(
            endpoint,
            params=[public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode() for public_key in users],
            auth=self.kryptos.authenticator,
        )
        response.raise_for_status()
