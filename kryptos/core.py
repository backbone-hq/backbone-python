import base64

from nacl.public import PrivateKey, PublicKey
from typing import Optional, List, Generator
import httpx
from kryptos import crypto
from kryptos.models import Permission, GrantAccess
from nacl import encoding

__version__ = 0


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

    # TODO: Username shouldn't be necessary for initialization (or authentication)
    def __init__(self, workspace: str, username: str, secret_key: PrivateKey):
        self._secret_key: PrivateKey = secret_key
        self._username: str = username
        self._workspace: str = workspace

        self.namespace: _NamespaceClient = _NamespaceClient(self)
        self.entry: _EntryClient = _EntryClient(self)
        self.token: _TokenClient = _TokenClient(self)

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
        if response.is_redirect or response.is_error:
            return None

        result = response.json()
        hidden_token = result["hidden_token"]
        return crypto.decrypt_hidden_token(self.client._secret_key, hidden_token.encode()).decode()


class _NamespaceClient:
    def __init__(self, client: KryptosClient):
        self.client = client

    # def get(self, key: str):
    #     endpoint = self.client.endpoint("entry", key)
    #     response = httpx.get(endpoint, auth=self.client.authenticator)

    def get_chain(self, key: str) -> List[dict]:
        endpoint = self.client.endpoint("chain", key)
        return httpx.get(endpoint, auth=self.client.authenticator).json().get("chain")

    # def delete(self, key):
    #     pass
    #
    # def share(self, public_key):
    #     pass


class _EntryClient:
    def __init__(self, client: KryptosClient):
        self.client = client

    def get(self, key: str) -> Optional[str]:
        endpoint = self.client.endpoint("entry", key)
        result = httpx.get(endpoint, auth=self.client.authenticator)

        if result.is_error:
            raise Exception(result.json())
        result = result.json()

        # Follow and decrypt the namespace grant chain
        current_sk: PrivateKey = self.client._secret_key
        for grant in result["chain"]:
            grantee_pk = PublicKey(grant["subject_pk"], encoder=encoding.URLSafeBase64Encoder)
            current_sk: PrivateKey = PrivateKey(crypto.decrypt_grant(grantee_pk, current_sk, grant["value"]))

        # Find an applicable entry grant
        applicable_grant_pk = base64.urlsafe_b64encode(current_sk.public_key.encode()).decode()
        grants = [grant for grant in result["grants"] if grant["grantee_pk"] == applicable_grant_pk]
        if not grants:
            return None

        grant = grants[0]
        return crypto.decrypt_entry(result["value"], grant["value"], current_sk).decode()

    def set(self, key: str, value: str, access: List[GrantAccess] = None):
        chain = self.client.namespace.get_chain(key)
        closest_namespace_grant = chain[0]
        namespace_public_key = PublicKey(base64.urlsafe_b64decode(closest_namespace_grant["subject_pk"]))
        ciphertext, grants = crypto.encrypt_entry(value, namespace_public_key)

        endpoint = self.client.endpoint("entry", key)
        response = httpx.post(
            endpoint,
            json={
                "value": ciphertext.decode(),
                "grants": [
                    {
                        "grantee_pk": public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                        "value": value.decode(),
                        "access": ["read", "write", "delete"],
                        # FIXME: Replace with `access` and instill sensible defaults
                        # TODO: Consider inheriting from namespace's access grants if `access` = None
                    }
                    for public_key, value in grants
                ],
            },
            auth=self.client.authenticator,
        )

        if response.is_error:
            raise Exception(response.json())
