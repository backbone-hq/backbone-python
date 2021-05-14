import pytest
from kryptos.core import Permission, KryptosClient
from httpx import HTTPError
from datetime import datetime
from nacl.public import PrivateKey
from nacl.exceptions import CryptoError


@pytest.mark.asyncio
async def test_fake_token(client, create_user):
    await client.authenticate()

    # Create a client for a nonexistent account
    fake_client = KryptosClient(workspace=client._workspace_name, username="fake", secret_key=PrivateKey.generate())

    # Token decryption fails
    with pytest.raises(CryptoError) as _exception:
        await fake_client.token.authenticate()


@pytest.mark.asyncio
async def test_client_authentication_explicit_permissions(client):
    # Authenticate
    await client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])

    # Get the existing token
    token = await client.token.get()
    assert set(token.keys()) == {"hidden_key", "hidden_token", "creation", "expiration", "permissions"}

    # Check the lengths of ciphertexts
    assert len(token["hidden_key"]) == 96
    assert len(token["hidden_token"]) == 88

    # Check the formats of the timestamps; throws `ValueError` if not ISO8601 compliant
    assert datetime.fromisoformat(token["creation"])
    assert datetime.fromisoformat(token["expiration"])

    # Validate that the requested permissions exist on the token
    assert token["permissions"] == [Permission.STORE_READ.value, Permission.STORE_WRITE.value]


@pytest.mark.asyncio
async def test_client_authentication_minimally_scoped_token(client):
    await client.authenticate(permissions=[])

    token = await client.token.get()
    assert token["permissions"] == []


@pytest.mark.asyncio
async def test_client_authentication_implicit_max_permissions(client):
    await client.authenticate()

    user = await client.user.get()
    token = await client.token.get()
    assert token["permissions"] == user["permissions"] == [Permission.ROOT.value]


@pytest.mark.asyncio
async def test_client_authentication_zero_or_negative_token_duration_fails(client):
    with pytest.raises(HTTPError) as _exception:
        await client.authenticate(duration=-1)

    with pytest.raises(HTTPError) as _exception:
        await client.authenticate(duration=0)


@pytest.mark.asyncio
async def test_token_deauthentication(client):
    await client.authenticate()
    await client.deauthenticate()

    with pytest.raises(HTTPError) as _exception:
        await client.token.get()


@pytest.mark.asyncio
async def test_token_derivation_scope_reduction(client):
    # Authenticate for 86_400 seconds
    await client.authenticate(permissions=[Permission.ROOT], duration=86_400)

    # Derive scoped token for 86_300 seconds
    store_read_token = await client.token.derive(permissions=[Permission.STORE_READ], duration=86_300)
    assert len(store_read_token) == 24


@pytest.mark.asyncio
async def test_token_derivation_privilege_escalation_fails(client):
    await client.authenticate(permissions=[Permission.STORE_READ], duration=86_400)

    with pytest.raises(HTTPError) as _exception:
        await client.token.derive(permissions=[Permission.STORE_READ, Permission.STORE_WRITE], duration=86_300)


@pytest.mark.asyncio
async def test_token_derivation_length_extension_fails(client):
    await client.authenticate(permissions=[Permission.ROOT], duration=86_400)

    with pytest.raises(HTTPError) as _exception:
        await client.token.derive(permissions=[Permission.ROOT], duration=86_500)
