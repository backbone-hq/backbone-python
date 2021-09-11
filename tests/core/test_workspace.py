import pytest
from httpx import HTTPError

from backbone.models import Workspace
from tests.core.conftest import WORKSPACE_DISPLAY_NAME

# Testing workspace creation/deletion is implicitly done by the client setup and teardown


@pytest.mark.asyncio
async def test_workspace_read(client):
    # User read requires a valid token, but no specific permissions
    await client.authenticate(permissions=[])

    workspace: Workspace = await client.workspace.get()

    assert workspace.display_name == WORKSPACE_DISPLAY_NAME


@pytest.mark.asyncio
async def test_workspace_delete_fails_without_root(client):
    await client.authenticate(permissions=[])

    with pytest.raises(HTTPError) as _exception:
        await client.workspace.delete(safety_check=False)
