from typing import Generator, List, Optional

import httpx
from nacl.public import PrivateKey, PublicKey

from backbone import crypto
from backbone.core.entry import EntryClient
from backbone.core.namespace import NamespaceClient
from backbone.core.token import TokenClient
from backbone.core.user import UserClient
from backbone.core.workspace import WorkspaceClient
from backbone.exceptions import deserialize_exception
from backbone.models import Permission
from backbone.constants import SERVICE_URL


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
    def __init__(self, workspace: str, username: str, secret_key: PrivateKey):
        # Backbone parameters
        self._secret_key: PrivateKey = secret_key
        self._public_key: PublicKey = self._secret_key.public_key

        self._username: str = username
        self._workspace_name: str = workspace

        # Endpoint Clients
        self.namespace: NamespaceClient = NamespaceClient(self)
        self.entry: EntryClient = EntryClient(self)
        self.token: TokenClient = TokenClient(self)
        self.workspace: WorkspaceClient = WorkspaceClient(self)
        self.user: UserClient = UserClient(self)

        # Properties
        self._session: Optional[httpx.AsyncClient] = None
        self.authenticator: Optional[BackboneAuth] = None

    def _init_session(self):
        if not self._session:
            self._session = httpx.AsyncClient(base_url=SERVICE_URL)

    @property
    def session(self) -> httpx.AsyncClient:
        self._init_session()
        return self._session

    async def __aenter__(self):
        self._init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        if self._session:
            await self._session.aclose()

        self._session = None

    @classmethod
    def from_credentials(cls, workspace: str, username: str, password: str) -> "BackboneClient":
        derived_private_key = crypto.derive_password_key(identity=username, password=password)
        return cls(workspace=workspace, username=username, secret_key=PrivateKey(derived_private_key))

    async def load_token(self, token: str):
        if self.authenticator:
            # Attempt to revoke the previous token on a best-effort basis
            try:
                await self.token.revoke()
            except httpx.HTTPError:
                pass

        self.authenticator = BackboneAuth(client=self, token=token, permissions=None, duration=86_400)

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
        self.handle_exception(response)
        result = response.json()

        for item in result["results"]:
            yield item

        while result["next"]:
            response = await self.session.get(endpoint, params=result["next"], auth=self.authenticator)
            response.raise_for_status()
            result = response.json()

            for item in result["results"]:
                yield item

    def handle_exception(self, response: httpx.Response):
        if httpx._status_codes.codes.is_error(response.status_code):
            deserialize_exception(response.json())
