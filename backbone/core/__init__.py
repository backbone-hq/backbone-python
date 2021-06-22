import base64
from typing import AsyncIterable, Generator, List, Optional, Tuple

import httpx
from nacl import encoding
from nacl.public import PrivateKey, PublicKey

from backbone import crypto
from backbone.models import GrantAccess, Permission

__version__ = 0


class BackboneAuth(httpx.Auth):
    def __init__(self, client: "BackboneClient", token: str, **kwargs):
        self.client = client
        self.token = token
        self.authentication_kwargs = kwargs

    async def async_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self.token}"
        response = yield request

        # Reauthenticate in the event of an invalid token
        if response.status_code == 401:
            self.client.authenticator = None  # Skip token revocation
            await self.client.authenticate(**self.authentication_kwargs)
            yield request


class BackboneClient:
    _base_url = f"http://localhost:8000/v{__version__}"
    # _base_url = f"https://backbone.dev/v{__version__}"

    def __init__(self, workspace: str, username: str, secret_key: PrivateKey):
        # Backbone parameters
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
        self.authenticator: Optional[BackboneAuth] = None

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
    def from_credentials(cls, workspace: str, username: str, password: str) -> "BackboneClient":
        derived_private_key = crypto.derive_password_key(identity=username, password=password)
        return cls(workspace=workspace, username=username, secret_key=PrivateKey(derived_private_key))

    @classmethod
    def endpoint(cls, *parts: str) -> str:
        return f"{cls._base_url}/{'/'.join(parts)}"

    async def load_token(self, token: str):
        if self.authenticator:
            await self.token.revoke(throw=False)

        self.authenticator = BackboneAuth(client=self, token=token, permissions=[], duration=None)

    async def authenticate(self, permissions: Optional[List[Permission]] = None, duration: int = 86_400):
        """Initialize the client with a scoped token"""
        if self.authenticator:
            await self.deauthenticate()

        token: str = await self.token.authenticate(permissions=permissions, duration=duration)
        self.authenticator = BackboneAuth(client=self, token=token, permissions=permissions, duration=duration)

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
    def __init__(self, client: BackboneClient):
        self.backbone = client

    async def get(self) -> dict:
        token_endpoint = self.backbone.endpoint("token")

        response = await self.backbone.session.get(token_endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return response.json()

    async def authenticate(self, permissions: Optional[List[Permission]] = None, duration: int = 86_400) -> str:
        token_endpoint = self.backbone.endpoint("token")

        response = await self.backbone.session.post(
            token_endpoint,
            json={
                "workspace": self.backbone._workspace_name,
                "username": self.backbone._username,
                "permissions": None if permissions is None else [permission.value for permission in permissions],
                "duration": duration,
            },
        )
        response.raise_for_status()
        return self._parse(response)

    async def derive(self, permissions: Optional[List[Permission]] = None, duration: int = 86_400) -> str:
        token_endpoint = self.backbone.endpoint("token")
        response = await self.backbone.session.patch(
            token_endpoint,
            json={
                "permissions": None if permissions is None else [permission.value for permission in permissions],
                "duration": duration,
            },
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
        return self._parse(response)

    async def revoke(self, throw: bool = True) -> None:
        token_endpoint = self.backbone.endpoint("token")
        response = await self.backbone.session.delete(token_endpoint, auth=self.backbone.authenticator)

        if throw:
            response.raise_for_status()

    def _parse(self, response: httpx.Response) -> str:
        result = response.json()
        hidden_token = result["hidden_token"]
        return crypto.decrypt_hidden_token(self.backbone._secret_key, hidden_token.encode()).decode()


class _WorkspaceClient:
    def __init__(self, client: BackboneClient):
        self.backbone = client

    async def get(self) -> dict:
        endpoint = self.backbone.endpoint("workspace")
        response = await self.backbone.session.get(endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return response.json()

    async def create(self, display_name: str, email_address: str) -> dict:
        endpoint = self.backbone.endpoint("workspace")

        # Generate root namespace keypair
        namespace_key: PrivateKey = PrivateKey.generate()
        namespace_grant = crypto.encrypt_grant(self.backbone._secret_key.public_key, namespace_key)

        response = await self.backbone.session.post(
            endpoint,
            json={
                "workspace": {"name": self.backbone._workspace_name, "display_name": display_name},
                "user": {
                    "name": self.backbone._username,
                    "email_address": email_address,
                    "public_key": self.backbone._secret_key.public_key.encode(
                        encoder=encoding.URLSafeBase64Encoder
                    ).decode(),
                    "permissions": [],  # Ignored by the server; the initial account must be root.
                },
                "namespace": {
                    "public_key": namespace_key.public_key.encode(encoding.URLSafeBase64Encoder).decode(),
                    "grants": [
                        {
                            "grantee_pk": self.backbone._secret_key.public_key.encode(
                                encoder=encoding.URLSafeBase64Encoder
                            ).decode(),
                            "access": list(map(lambda access: access.value, GrantAccess.__members__.values())),
                            "value": namespace_grant.decode(),
                        }
                    ],
                },
            },
            auth=self.backbone.authenticator,
        )

        response.raise_for_status()
        return response.json()

    async def delete(self, safety_check=True) -> None:
        if safety_check:
            print(f"WARNING: You're about to delete the workspace {self.backbone._workspace_name}")
            assert input("Please confirm by typing your workspace's name: ") == self.backbone._workspace_name

        endpoint = self.backbone.endpoint("workspace")
        response = await self.backbone.session.delete(endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()


class _UserClient:
    def __init__(self, client: BackboneClient):
        self.backbone = client

    async def get_all(self):
        endpoint = self.backbone.endpoint("users")
        async for item in self.backbone.paginate(endpoint):
            yield item

    async def search(self, username: str) -> dict:
        endpoint = self.backbone.endpoint("user", username)
        response = await self.backbone.session.get(endpoint, auth=self.backbone.authenticator)
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
            public_key=self.backbone._secret_key.public_key,
            email_address=email_address,
            permissions=permissions,
        )

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

    async def delete(self, force_delete: bool = False) -> None:
        endpoint = self.backbone.endpoint("user")
        response = await self.backbone.session.delete(
            endpoint, params={"force_delete": force_delete}, auth=self.backbone.authenticator
        )
        response.raise_for_status()


class _NamespaceClient:
    def __init__(self, client: BackboneClient):
        self.backbone = client

    async def __unroll_chain(self, key: str) -> Tuple[PrivateKey, dict]:
        endpoint = self.backbone.endpoint("namespace", key)
        response = await self.backbone.session.get(endpoint, auth=self.backbone.authenticator)
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
        endpoint = self.backbone.endpoint("chain", key)
        response = await self.backbone.session.get(endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return response.json().get("chain")

    """
    async def layer(self, prefix: str) -> dict:
        endpoint = self.backbone.endpoint("layer", prefix)
        response = await self.backbone.session.get(endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()
        return response.json()
    """

    async def search(self, prefix: str) -> AsyncIterable[str]:
        endpoint = self.backbone.endpoint("namespaces", prefix)
        async for item in self.backbone.paginate(endpoint):
            yield item

    async def create(self, key: str, *, access: List[GrantAccess] = (), isolated: bool = False) -> dict:
        grant_access = [item.value for item in access or GrantAccess]

        # Generate new namespace keypair
        new_namespace_key: PrivateKey = PrivateKey.generate()

        # Track any grant replacements
        namespace_grant_replacements = {}
        entry_grant_replacements = {}

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

            # TODO: Intermediate namespaces requires the layer API to exist
            """
            closest_namespace_pk: str = grant_pk.encode(encoder=encoding.URLSafeBase64Encoder).decode()

            # Replace child namespace grants
            for item in children["namespaces"]:
                # Find the closest namespace's grant
                child_public_key = PublicKey(item["public_key"], encoder=encoding.URLSafeBase64Encoder)
                grant = next((grant for grant in item["grants"] if grant["grantee_pk"] == closest_namespace_pk), None)
                grantee_sk: PrivateKey = PrivateKey(crypto.decrypt_grant(child_public_key, closest_namespace_sk, grant["value"]))

                key = item["key"]
                namespace_grant_replacements[key] = {
                    "grantee_pk": new_namespace_key.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                    "value": crypto.encrypt_grant(new_namespace_key.public_key, grantee_sk).decode()
                    "access": grant["access"]
                }

            # Replace child entry grants
            for item in children["entries"]:
                # Find the closest namespace's grant
                grant = next((grant for grant in item["grants"] if grant["grantee_pk"] == closest_namespace_pk), None)
                entry_key = crypto.decrypt_entry_encryption_key(grant["value"], closest_namespace_sk)

                key = item["key"]
                entry_grant_replacements[key] = {
                    "grantee_pk": new_namespace_key.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                    "value": crypto.create_entry_grant(entry_key, new_namespace_key.public_key).decode(),
                    "access": grant["access"],
                }
            """

        # Grant access to the new namespace
        namespace_grant = crypto.encrypt_grant(grant_pk, new_namespace_key)
        endpoint = self.backbone.endpoint("namespace", key)
        response = await self.backbone.session.post(
            endpoint,
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
        endpoint = self.backbone.endpoint("namespace", key)
        response = await self.backbone.session.delete(endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()

    async def grant(self, key: str, *users: PublicKey, access: List[GrantAccess] = ()) -> None:
        namespace_secret_key, namespace_grant = self.__unroll_chain(key)

        endpoint = self.backbone.endpoint("grant", "namespace", key)
        response = await self.backbone.session.post(
            endpoint,
            json=[
                {
                    "grantee_pk": public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                    "value": crypto.encrypt_grant(public_key, namespace_secret_key).decode(),
                    "access": [level.value for level in access] or namespace_grant["access"],
                }
                for public_key in users
            ],
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()

    async def revoke(self, key: str, *users: PublicKey) -> None:
        endpoint = self.backbone.endpoint("grant", "namespace", key)

        response = await self.backbone.session.request(
            "DELETE",
            endpoint,
            json=[public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode() for public_key in users],
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()


class _EntryClient:
    def __init__(self, client: BackboneClient):
        self.backbone = client

    async def __unroll_chain(self, key: str) -> Tuple[str, dict, PrivateKey]:
        endpoint = self.backbone.endpoint("entry", key)
        response = await self.backbone.session.get(endpoint, auth=self.backbone.authenticator)
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
        endpoint = self.backbone.endpoint("entries", prefix)
        async for item in self.backbone.paginate(endpoint):
            yield item

    async def set(self, key: str, value: str, access: List[GrantAccess] = ()) -> dict:
        chain = await self.backbone.namespace.get_chain(key)
        closest_namespace_grant = chain[-1]
        namespace_public_key = PublicKey(base64.urlsafe_b64decode(closest_namespace_grant["subject_pk"]))
        ciphertext, grants = crypto.encrypt_entry(value, namespace_public_key)

        endpoint = self.backbone.endpoint("entry", key)
        response = await self.backbone.session.post(
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
            auth=self.backbone.authenticator,
        )

        response.raise_for_status()
        return response.json()

    async def delete(self, key: str) -> None:
        endpoint = self.backbone.endpoint("entry", key)
        response = await self.backbone.session.delete(endpoint, auth=self.backbone.authenticator)
        response.raise_for_status()

    async def grant(self, key: str, *users: PublicKey, access: List[GrantAccess] = ()) -> dict:
        # Get the user's grant
        _, grant, grant_sk = self.__unroll_chain(key)
        entry_key = crypto.decrypt_entry_encryption_key(grant["value"].encode(), grant_sk)

        endpoint = self.backbone.endpoint("grant", "entry", key)
        response = await self.backbone.session.post(
            endpoint,
            json=[
                {
                    "grantee_pk": public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                    "value": crypto.create_entry_grant(entry_key, public_key).decode(),
                    "access": [level.value for level in access] or grant["access"],
                }
                for public_key in users
            ],
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
        return response.json()

    async def revoke(self, key: str, *users: PublicKey) -> None:
        endpoint = self.backbone.endpoint("grant", "entry", key)

        response = await self.backbone.session.request(
            "DELETE",
            endpoint,
            json=[public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode() for public_key in users],
            auth=self.backbone.authenticator,
        )
        response.raise_for_status()
