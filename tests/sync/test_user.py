import pytest
from httpx import HTTPError
from nacl import encoding
from nacl.exceptions import CryptoError

from backbone.sync import Permission
from backbone.models import User
from tests.sync.conftest import ADMIN_SK, ADMIN_USERNAME
from tests.sync.utilities import random_lower


@pytest.mark.sync
def test_user_read(client, create_user):
    # Ensure test user querying itself is equivalent to other users querying the test user
    test_user = random_lower(8)
    test_client = create_user(client, test_user, permissions=[])

    assert (test_client.user.self()).name == (client.user.get(test_user))[0].name

    # User read requires a valid token, but no specific permissions
    client.authenticate(permissions=[])
    user: User = client.user.self()
    assert user.name == ADMIN_USERNAME
    assert user.public_key == ADMIN_SK.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
    assert user.permissions == [Permission.ROOT]


@pytest.mark.sync
def test_user_creation_and_deletion(client, create_user):
    test_user = random_lower(8)
    test_client = create_user(client, test_user, permissions=[])

    # Test user cannot delete themselves
    with pytest.raises(HTTPError):
        test_client.user.delete(username=test_user, force=True)

    # User with USER_MANAGE can delete the user
    client.user.delete(username=test_user, force=True)

    # Test user cannot authenticate
    with pytest.raises(CryptoError):
        test_client.authenticate()


@pytest.mark.sync
def test_user_permission_modification(client, create_user):
    test_user = random_lower(8)
    test_client = create_user(client, test_user, permissions=[Permission.STORE_USE])

    # Validate the test user's privileges
    user: User = test_client.user.self()
    assert user.permissions == [Permission.STORE_USE]

    # De-escalate the test user's privileges
    client.user.modify(test_user, permissions=[])
    user: User = test_client.user.self()
    assert user.permissions == []

    # Re-escalate the test user's privileges
    client.user.modify(test_user, permissions=[Permission.ROOT])
    user: User = test_client.user.self()
    assert user.permissions == [Permission.ROOT]


@pytest.mark.sync
def test_duplicate_user_creation(client, create_user):
    with pytest.raises(HTTPError):
        create_user(client, ADMIN_USERNAME, permissions=[Permission.STORE_USE])



@pytest.mark.sync
def test_user_get(client, create_user):
    test_user = random_lower(8)
    test_client = create_user(client, test_user, permissions=[Permission.STORE_USE])

    result = client.user.get(test_user)
    assert len(result) == 1
    user = result[0]
    assert user.name == test_user
    assert user.permissions == [Permission.STORE_USE]


@pytest.mark.sync
def test_user_list(client, create_user):
    users = [random_lower(8) for _ in range(1)]
    for user in users:
        create_user(client, user, permissions=[])

    result = [user for user in client.user.list()]
    assert {user.name for user in result} == {*users, ADMIN_USERNAME}


@pytest.mark.sync
def test_user_creation_fails_without_user_manage_permission(client, create_user):
    # Authenticate the client
    client.authenticate(permissions=[])

    with pytest.raises(HTTPError):
        create_user(client, "test", permissions=[])
