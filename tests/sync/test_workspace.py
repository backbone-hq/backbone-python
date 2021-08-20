import pytest
from httpx import HTTPError

from backbone.models import Workspace

from .conftest import WORKSPACE_DISPLAY_NAME, WORKSPACE_NAME

# Testing workspace creation/deletion is implicitly done by the client setup and teardown


@pytest.mark.sync
def test_workspace_read(client):
    # User read requires a valid token, but no specific permissions
    client.authenticate(permissions=[])

    workspace: Workspace = client.workspace.get()

    # Assert properties defined remain intact
    assert workspace.name == WORKSPACE_NAME
    assert workspace.display_name == WORKSPACE_DISPLAY_NAME


@pytest.mark.sync
def test_workspace_delete_fails_without_root(client):
    client.authenticate(permissions=[])

    with pytest.raises(HTTPError) as _exception:
        client.workspace.delete(safety_check=False)
