import pydantic
import pytest
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey

from backbone.core import BackboneClient, Permission
from backbone import exceptions
from backbone import models


@pytest.mark.asyncio
async def test_fake_token(client):
    # Create a client for a nonexistent account
    fake_client = BackboneClient(workspace=client._workspace_name, username="fake", secret_key=PrivateKey.generate())

    # Token decryption fails
    with pytest.raises(exceptions.InvalidTokenResponseException):
        await fake_client.token.authenticate()


@pytest.mark.asyncio
async def test_client_authentication_explicit_permissions(client):
    # Authenticate
    await client.authenticate(permissions=[Permission.STORE_USE])

    # Get the existing token
    token: models.Token = await client.token.get()

    # Validate that only the requested permissions exist on the token
    assert token.permissions == [Permission.STORE_USE]


@pytest.mark.asyncio
async def test_client_authentication_minimally_scoped_token(client):
    await client.authenticate(permissions=[])

    token = await client.token.get()
    assert len(token.permissions) == 0


@pytest.mark.asyncio
async def test_client_authentication_implicit_max_permissions(client):
    user: models.User = await client.user.self()
    token: models.Token = await client.token.get()
    assert token.permissions == user.permissions
    assert token.permissions == [Permission.ROOT]


@pytest.mark.asyncio
async def test_client_authentication_zero_or_negative_token_duration_fails(client):
    with pytest.raises(pydantic.ValidationError):
        await client.authenticate(duration=-1)

    with pytest.raises(pydantic.ValidationError):
        await client.authenticate(duration=0)


@pytest.mark.asyncio
async def test_token_deauthentication(client):
    await client.deauthenticate()

    with pytest.raises(exceptions.InvalidTokenException):
        await client.token.get()


@pytest.mark.asyncio
async def test_token_derivation_scope_reduction(client):
    # Authenticate for 300 seconds
    await client.authenticate(duration=300)

    # Derive scoped token for 240 seconds
    store_read_token = await client.token.derive(permissions=[Permission.STORE_USE], duration=240)
    assert len(store_read_token) == 24


@pytest.mark.asyncio
async def test_token_derivation_privilege_escalation_fails(client):
    await client.authenticate(permissions=[Permission.STORE_USE], duration=86_400)

    with pytest.raises(exceptions.UnauthorizedTokenException):
        await client.token.derive(permissions=[Permission.STORE_USE, Permission.STORE_SHARE], duration=86_300)


@pytest.mark.asyncio
async def test_token_derivation_length_extension_fails(client):
    await client.authenticate(permissions=[Permission.ROOT], duration=86_400)

    with pytest.raises(exceptions.ExpiringTokenException):
        await client.token.derive(permissions=[Permission.ROOT], duration=86_500)
