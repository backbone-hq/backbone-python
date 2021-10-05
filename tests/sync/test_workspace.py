import pytest

from backbone.exceptions import UnauthorizedTokenException
from backbone.models import Workspace
from tests.sync.conftest import WORKSPACE_DISPLAY_NAME

# Note: Testing workspace creation/deletion is implicitly done by the client setup and teardown


@pytest.mark.sync
def test_workspace_read(client):
    # User read requires a valid token, but no specific permissions
    client.authenticate(permissions=[])

    workspace: Workspace = client.workspace.get()

    assert workspace.display_name == WORKSPACE_DISPLAY_NAME


@pytest.mark.sync
def test_workspace_delete_fails_without_root(client):
    client.authenticate(permissions=[])

    with pytest.raises(UnauthorizedTokenException):
        client.workspace.delete(safety_check=False)
