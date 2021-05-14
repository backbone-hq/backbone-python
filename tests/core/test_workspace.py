import pytest
from httpx import HTTPError


# Testing workspace creation/deletion is implicitly done by the client setup and teardown


@pytest.mark.asyncio
async def test_workspace_read(client):
    # User read requires a valid token, but no specific permissions
    await client.authenticate(permissions=[])

    result = await client.workspace.get()
    assert set(result.keys()) == {"name", "display_name"}

    # Assert properties defined remain intact
    assert result["name"] == "kryptos"
    assert result["display_name"] == "kryptos-display"


@pytest.mark.asyncio
async def test_workspace_delete_fails_without_root(client):
    await client.authenticate(permissions=[])

    with pytest.raises(HTTPError) as _exception:
        await client.workspace.delete(safety_check=False)
