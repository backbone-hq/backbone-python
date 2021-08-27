import pytest
from httpx import HTTPError
from nacl import encoding

from backbone.sync import Permission
from backbone.models import User

from .conftest import ADMIN_EMAIL, ADMIN_SK, ADMIN_USERNAME

# TODO: find_user endpoint
# TODO: user pagination endpoint


@pytest.mark.sync
def test_user_read_self(client):
    # User read requires a valid token, but no specific permissions
    client.authenticate(permissions=[])

    user: User = client.user.self()

    # Assert properties defined remain intact
    assert user.name == ADMIN_USERNAME
    assert user.email_address == ADMIN_EMAIL
    # TODO: Return a PublicKey object
    assert user.public_key == ADMIN_SK.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
    assert user.permissions == [Permission.ROOT]


@pytest.mark.sync
def test_user_creation_and_deletion(client, create_user):
    client.authenticate(permissions=[Permission.USER_MANAGE])

    test_client = create_user(username="test", permissions=[])
    test_client.authenticate()
    test_client.user.delete(force_delete=True)


@pytest.mark.sync
def test_user_creation_fails_without_user_manage_permission(client, create_user):
    # Authenticate the client
    client.authenticate(permissions=[])

    with pytest.raises(HTTPError) as _exception:
        create_user(username="test", permissions=[])
