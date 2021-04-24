import base64

from nacl.public import PrivateKey, PublicKey
from typing import Optional, List, Generator, Tuple
import httpx
from kryptos import crypto
from kryptos.models import Permission, GrantAccess
from nacl import encoding

__version__ = 0


def paginate(endpoint, *, client):
    response = httpx.get(endpoint, auth=client.authenticator)
    response.raise_for_status()
    result = response.json()
    yield from result["results"]

    while result["next"]:
        response = httpx.get(endpoint, params=result["next"], auth=client.authenticator)
        response.raise_for_status()
        result = response.json()
        yield from result["results"]


class KryptosAuth(httpx.Auth):
    def __init__(self, client: "KryptosClient", permissions: List[Permission], token: str):
        self.client = client
        self.permissions = permissions
        self.token = token

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self.token}"
        response = yield request

        if response.status_code == 401:
            request.headers["Authorization"] = f"Bearer {self.token}"
            self.client.authenticate(self.permissions)
            yield request


class KryptosClient:
    _base_url = f"http://localhost:8000/v{__version__}"

    def __init__(self, workspace: str, username: str, secret_key: PrivateKey):
        self._secret_key: PrivateKey = secret_key
        self._username: str = username
        self._workspace: str = workspace

        self.namespace: _NamespaceClient = _NamespaceClient(self)
        self.entry: _EntryClient = _EntryClient(self)
        self.token: _TokenClient = _TokenClient(self)
        self.workspace: _WorkspaceClient = _WorkspaceClient(self)
        self.user: _UserClient = _UserClient(self)

        self.authenticator: Optional[KryptosAuth] = None

    @classmethod
    def from_credentials(cls, workspace: str, username: str, password: str):
        derived_private_key = crypto.derive_password_key(identity=username, password=password)
        return cls(workspace=workspace, username=username, secret_key=PrivateKey(derived_private_key))

    def authenticate(self, permissions: List[Permission]):
        """Initialize the client with a scoped token"""
        token: Optional[str] = self.token.authenticate(permissions=permissions)

        if token:
            self.authenticator = KryptosAuth(client=self, permissions=permissions, token=token)

    def endpoint(self, *parts: str) -> str:
        return f"{self._base_url}/{'/'.join(parts)}"


class _TokenClient:
    def __init__(self, client: KryptosClient):
        self.client = client

    def authenticate(self, permissions: List[Permission]) -> Optional[str]:
        token_endpoint = self.client.endpoint("token")
        response = httpx.post(
            token_endpoint,
            json={
                "workspace": self.client._workspace,
                "username": self.client._username,
                "permissions": [permission.value for permission in permissions],
            },
        )
        return self._parse(response)

    def derive(self) -> Optional[str]:
        token_endpoint = self.client.endpoint("token")
        response = httpx.patch(token_endpoint, auth=self.client.authenticator)
        return self._parse(response)

    def _parse(self, response: httpx.Response) -> Optional[str]:
        if response.is_error:
            raise Exception(response.json())

        result = response.json()
        hidden_token = result["hidden_token"]
        return crypto.decrypt_hidden_token(self.client._secret_key, hidden_token.encode()).decode()


class _WorkspaceClient:
    def __init__(self, client: KryptosClient):
        self.client = client

    def get(self):
        endpoint = self.client.endpoint("workspace")
        response = httpx.get(endpoint, auth=self.client.authenticator).json()
        response.raise_for_status()
        return response.json()

    def create(self, display_name: str, email_address: str):
        endpoint = self.client.endpoint("workspace")

        # Generate root namespace keypair
        namespace_key: PrivateKey = PrivateKey.generate()
        namespace_grant = crypto.encrypt_grant(self.client._secret_key.public_key, namespace_key)

        response = httpx.post(
            endpoint,
            json={
                "workspace": {"name": self.client._workspace, "display_name": display_name},
                "user": {
                    "name": self.client._username,
                    "email_address": email_address,
                    "public_key": self.client._secret_key.public_key.encode(
                        encoder=encoding.URLSafeBase64Encoder
                    ).decode(),
                    "hidden_key": crypto.encrypt_with_secret(
                        secret=self.client._secret_key.encode(), plaintext=self.client._secret_key.encode()
                    ).decode(),
                    "permissions": [],  # Ignored by the server; the initial account must be root.
                },
                "namespace": {
                    "public_key": namespace_key.public_key.encode(encoding.URLSafeBase64Encoder).decode(),
                    "grants": [
                        {
                            "grantee_pk": self.client._secret_key.public_key.encode(
                                encoder=encoding.URLSafeBase64Encoder
                            ).decode(),
                            "access": list(map(lambda access: access.value, GrantAccess.__members__.values())),
                            "value": namespace_grant.decode(),
                        }
                    ],
                },
            },
            auth=self.client.authenticator,
        )

        response.raise_for_status()
        return response.json()

    def delete(self, safety_check=True):
        if safety_check:
            print(f"WARNING: You're about to delete the workspace {self.client._workspace}")
            assert input("Please confirm by typing your workspace's name: ") == self.client._workspace

        endpoint = self.client.endpoint("workspace")
        response = httpx.delete(endpoint, auth=self.client.authenticator)
        response.raise_for_status()
        return response.json()


class _UserClient:
    def __init__(self, client: KryptosClient):
        self.client = client

    def get_all(self):
        endpoint = self.client.endpoint("users")
        yield from paginate(endpoint, client=self.client)

    def find(self, username: str):
        endpoint = self.client.endpoint("user", username)
        response = httpx.get(endpoint, auth=self.client.authenticator)
        response.raise_for_status()
        return response.json()

    def get(self):
        endpoint = self.client.endpoint("user")
        response = httpx.get(endpoint, auth=self.client.authenticator)
        response.raise_for_status()
        return response.json()

    def create(
        self,
        username: Optional[str] = None,
        secret_key: Optional[PrivateKey] = None,
        email_address: Optional[str] = None,
        permissions: List[Permission] = (),
    ):
        username = username or self.client._username
        secret_key = secret_key or self.client._secret_key

        endpoint = self.client.endpoint("user")
        response = httpx.post(
            endpoint,
            json={
                "name": username,
                "email_address": email_address,
                "public_key": secret_key.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                "hidden_key": crypto.encrypt_with_secret(
                    secret=self.client._secret_key.encode(), plaintext=self.client._secret_key.encode()
                ).decode(),
                "permissions": [permission.value for permission in permissions],
            },
            auth=self.client.authenticator,
        )
        response.raise_for_status()
        return response.json()

    def create_from_credentials(
        self, username: str, password: str, email_address: Optional[str] = None, permissions: List[Permission] = ()
    ):
        derived_private_key = crypto.derive_password_key(identity=username, password=password)
        return self.create(
            username=username,
            secret_key=PrivateKey(derived_private_key),
            email_address=email_address,
            permissions=permissions,
        )

    def delete(self):
        endpoint = self.client.endpoint("user")
        response = httpx.delete(endpoint, auth=self.client.authenticator)
        response.raise_for_status()
        return response.json()


class _NamespaceClient:
    def __init__(self, client: KryptosClient):
        self.client = client

    def get(self, key: str):  # TODO: Decide whether this method should exist; no clear use-case
        endpoint = self.client.endpoint("namespace", key)
        response = httpx.get(endpoint, auth=self.client.authenticator).json()
        response.raise_for_status()
        return response.json()

    def get_chain(self, key: str) -> List[dict]:
        endpoint = self.client.endpoint("chain", key)
        response = httpx.get(endpoint, auth=self.client.authenticator)
        response.raise_for_status()
        return response.json().get("chain")

    def search(self, key: str):
        endpoint = self.client.endpoint("namespaces", key)
        yield from paginate(endpoint, client=self.client)

    def create(self, key: str, access: List[GrantAccess] = ()):
        # Find the closest namespace
        chain = self.get_chain(key)
        parent_namespace_grant = chain[-1]
        parent_namespace_pk = PublicKey(base64.urlsafe_b64decode(parent_namespace_grant["subject_pk"]))

        # Generate new namespace keypair
        namespace_key: PrivateKey = PrivateKey.generate()
        namespace_grant = crypto.encrypt_grant(parent_namespace_pk, namespace_key)

        endpoint = self.client.endpoint("namespace", key)
        response = httpx.post(
            endpoint,
            json={
                "public_key": namespace_key.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                "grants": [
                    {
                        "grantee_pk": parent_namespace_pk.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                        "value": namespace_grant.decode(),
                        "access": parent_namespace_grant["access"],
                    }
                ],
            },
            auth=self.client.authenticator,
        )

        response.raise_for_status()
        return response.json()

    def delete(self, key):
        endpoint = self.client.endpoint("namespace", key)
        response = httpx.delete(endpoint, auth=self.client.authenticator)
        response.raise_for_status()
        return response.json()

    # TODO @david: implement namespace granting/revocation
    # def grant(self, key: str, access: List[GrantAccess] = (), *users: PublicKey):
    #     endpoint = self.client.endpoint("grant", "namespace", key)

    # def revoke(self, key: str, *users: PublicKey):
    #     endpoint = self.client.endpoint("grant", "namespace", key)


class _EntryClient:
    def __init__(self, client: KryptosClient):
        self.client = client

    def __get(self, key: str) -> Tuple[str, str]:
        """
        Unrolls the grant chain and returns the ciphertext and user's entry grant
        :param key: The entry's key
        :return: (value_ciphertext, grant_ciphertext)
        """
        endpoint = self.client.endpoint("entry", key)
        response = httpx.get(endpoint, auth=self.client.authenticator)
        response.raise_for_status()
        result = response.json()

        # Follow and decrypt the namespace grant chain
        current_sk: PrivateKey = self.client._secret_key
        for grant in result["chain"]:
            subject_pk = PublicKey(grant["subject_pk"], encoder=encoding.URLSafeBase64Encoder)
            current_sk: PrivateKey = PrivateKey(crypto.decrypt_grant(subject_pk, current_sk, grant["value"]))

        # Find the user's entry grant
        user_pk = current_sk.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
        grants = [grant for grant in result["grants"] if grant["grantee_pk"] == user_pk]
        if not grants:
            # This shouldn't happen; the user must have at least 1 `READ` grant on the entry for the endpoint to return
            raise ValueError

        # Pick the first
        user_grant = grants[0]
        return result["value"], user_grant["value"]

    def get(self, key: str) -> str:
        """
        Obtains the value stored under a particular key
        :param key: the key to obtain
        :return: the value if the user has sufficient access
        """
        ciphertext, user_grant = self.__get(key)
        return crypto.decrypt_entry(ciphertext, user_grant.encode(), self.client._secret_key).decode()

    def search(self, key: str):
        endpoint = self.client.endpoint("entries", key)
        yield from paginate(endpoint, client=self.client)

    def set(self, key: str, value: str, access: List[GrantAccess] = ()):
        chain = self.client.namespace.get_chain(key)
        closest_namespace_grant = chain[-1]
        namespace_public_key = PublicKey(base64.urlsafe_b64decode(closest_namespace_grant["subject_pk"]))
        ciphertext, grants = crypto.encrypt_entry(value, namespace_public_key)

        endpoint = self.client.endpoint("entry", key)
        response = httpx.post(
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
            auth=self.client.authenticator,
        )

        response.raise_for_status()
        return response.json()

    def grant(self, key: str, access: List[GrantAccess], *users: PublicKey):
        # Get the user's
        _, users_grant = self.__get(key)
        entry_key = crypto.decrypt_entry_encryption_key(users_grant, self.client._secret_key)

        grants = [
            (
                public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                crypto.create_entry_grant(entry_key, public_key),
            )
            for public_key in users
        ]

        endpoint = self.client.endpoint("grant", "entry", key)
        response = httpx.post(
            endpoint,
            json=[grants],
            auth=self.client.authenticator,
        )
        response.raise_for_status()

    def revoke(self, key: str, *users: PublicKey):
        endpoint = self.client.endpoint("grant", "entry", key)
        response = httpx.delete(
            endpoint,
            params=[public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode() for public_key in users],
            auth=self.client.authenticator,
        )
        response.raise_for_status()
