import pytest
from httpx import HTTPError

from backbone.core import Permission

# TODO: find_user endpoint
# TODO: user pagination endpoint


@pytest.mark.asyncio
async def test_user_read(client):
    # User read requires a valid token, but no specific permissions
    await client.authenticate(permissions=[])

    result = await client.user.get()
    assert set(result.keys()) == {"name", "email_address", "public_key", "permissions"}

    # Assert properties defined remain intact
    assert result["name"] == "admin"
    assert result["email_address"] == "root@backbone.io"
    assert result["public_key"] == "etHbHeOUNpTao_ACalJEpsBQc19QTlr68GzSzNPKWn4="
    assert result["permissions"] == [Permission.ROOT.value]


@pytest.mark.asyncio
async def test_user_creation_and_deletion(client, create_user):
    await client.authenticate(permissions=[Permission.USER_MANAGE, Permission.STORE_READ])

    test_client = await create_user(username="test", permissions=[])
    await test_client.authenticate()
    await test_client.user.delete(force_delete=True)


@pytest.mark.asyncio
async def test_user_creation_fails_without_user_manage_permission(client, create_user):
    # Authenticate the client
    await client.authenticate(permissions=[])

    with pytest.raises(HTTPError) as _exception:
        await create_user(username="test", permissions=[])
