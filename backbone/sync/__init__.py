from typing import Generator, List, Optional

import httpx
from nacl.public import PrivateKey, PublicKey

from backbone import crypto
from backbone.sync.entry import EntryClient
from backbone.sync.namespace import NamespaceClient
from backbone.sync.token import TokenClient
from backbone.sync.user import UserClient
from backbone.sync.workspace import WorkspaceClient
from backbone.models import Permission

__version__ = 0


class BackboneAuth(httpx.Auth):
    def __init__(self, client: "BackboneClient", token: str, **kwargs):
        self.client = client
        self.token = token
        self.authentication_kwargs = kwargs

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self.token}"
        response = yield request

        # Reauthenticate in the event of an invalid token
        if response.status_code == 401:
            self.client.authenticator = None  # Skip token revocation
            self.client.authenticate(**self.authentication_kwargs)
            yield request


class BackboneClient:
    _base_url = f"https://backbone.dev/v{__version__}/"

    def __init__(self, workspace: str, username: str, secret_key: PrivateKey):
        # Backbone parameters
        self._secret_key: PrivateKey = secret_key
        self._public_key: PublicKey = secret_key.public_key
        self._username: str = username
        self._workspace_name: str = workspace

        # Endpoint Clients
        self.namespace: NamespaceClient = NamespaceClient(self)
        self.entry: EntryClient = EntryClient(self)
        self.token: TokenClient = TokenClient(self)
        self.workspace: WorkspaceClient = WorkspaceClient(self)
        self.user: UserClient = UserClient(self)

        # Properties
        self.__session: Optional[httpx.Client] = None
        self.authenticator: Optional[BackboneAuth] = None

    def __init_session(self):
        if not self.__session:
            self.__session = httpx.Client(base_url=self._base_url)

    @property
    def session(self) -> httpx.Client:
        self.__init_session()
        return self.__session

    def __enter__(self):
        self.__init_session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self.__session:
            self.__session.close()

        self.__session = None

    @classmethod
    def from_credentials(cls, workspace: str, username: str, password: str) -> "BackboneClient":
        derived_private_key = crypto.derive_password_key(identity=username, password=password)
        return cls(workspace=workspace, username=username, secret_key=PrivateKey(derived_private_key))

    def load_token(self, token: str):
        if self.authenticator:
            # Attempt to revoke the previous token on a best-effort basis
            try:
                self.token.revoke()
            except httpx.HTTPError:
                pass

        self.authenticator = BackboneAuth(client=self, token=token, permissions=None, duration=86_400)

    def authenticate(self, permissions: Optional[List[Permission]] = None, duration: int = 86_400):
        """Initialize the client with a scoped token"""
        if self.authenticator:
            self.deauthenticate()

        token: str = self.token.authenticate(permissions=permissions, duration=duration)
        self.authenticator = BackboneAuth(client=self, token=token, permissions=permissions, duration=duration)

    def deauthenticate(self):
        """Revoke the current token and remove the authenticator"""
        self.token.revoke()
        self.authenticator = None

    def paginate(self, endpoint):
        response = self.session.get(endpoint, auth=self.authenticator)
        response.raise_for_status()
        result = response.json()

        for item in result["results"]:
            yield item

        while result["next"]:
            response = self.session.get(endpoint, params=result["next"], auth=self.authenticator)
            response.raise_for_status()
            result = response.json()

            for item in result["results"]:
                yield item
