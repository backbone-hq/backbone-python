import pydantic
import pytest
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey

from backbone.sync import BackboneClient, Permission
from backbone.exceptions import ExpiringTokenException, InvalidTokenException, UnauthorizedTokenException
from backbone.models import Token, User


@pytest.mark.sync
def test_fake_token(client):
    # Create a client for a nonexistent account
    fake_client = BackboneClient(workspace=client._workspace_name, username="fake", secret_key=PrivateKey.generate())

    # Token decryption fails
    with pytest.raises(CryptoError):
        fake_client.token.authenticate()


@pytest.mark.sync
def test_client_authentication_explicit_permissions(client):
    # Authenticate
    client.authenticate(permissions=[Permission.STORE_USE])

    # Get the existing token
    token: Token = client.token.get()

    # Validate that only the requested permissions exist on the token
    assert token.permissions == [Permission.STORE_USE]


@pytest.mark.sync
def test_client_authentication_minimally_scoped_token(client):
    client.authenticate(permissions=[])

    token = client.token.get()
    assert len(token.permissions) == 0


@pytest.mark.sync
def test_client_authentication_implicit_max_permissions(client):
    user: User = client.user.self()
    token: Token = client.token.get()
    assert token.permissions == user.permissions
    assert token.permissions == [Permission.ROOT]


@pytest.mark.sync
def test_client_authentication_zero_or_negative_token_duration_fails(client):
    with pytest.raises(pydantic.ValidationError):
        client.authenticate(duration=-1)

    with pytest.raises(pydantic.ValidationError):
        client.authenticate(duration=0)


@pytest.mark.sync
def test_token_deauthentication(client):
    client.deauthenticate()

    with pytest.raises(InvalidTokenException):
        client.token.get()


@pytest.mark.sync
def test_token_derivation_scope_reduction(client):
    # Authenticate for 300 seconds
    client.authenticate(duration=300)

    # Derive scoped token for 240 seconds
    store_read_token = client.token.derive(permissions=[Permission.STORE_USE], duration=240)
    assert len(store_read_token) == 24


@pytest.mark.sync
def test_token_derivation_privilege_escalation_fails(client):
    client.authenticate(permissions=[Permission.STORE_USE], duration=86_400)

    with pytest.raises(UnauthorizedTokenException):
        client.token.derive(permissions=[Permission.STORE_USE, Permission.STORE_SHARE], duration=86_300)


@pytest.mark.sync
def test_token_derivation_length_extension_fails(client):
    client.authenticate(permissions=[Permission.ROOT], duration=86_400)

    with pytest.raises(ExpiringTokenException):
        client.token.derive(permissions=[Permission.ROOT], duration=86_500)
