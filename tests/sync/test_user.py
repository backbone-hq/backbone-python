import pytest
from httpx import HTTPError
from nacl import encoding
from nacl.exceptions import CryptoError

from backbone.sync import Permission
from backbone.models import User
from tests.sync.conftest import ADMIN_EMAIL, ADMIN_SK, ADMIN_USERNAME
from tests.sync.utilities import random_lower


@pytest.mark.sync
def test_user_read(client, create_user):
    client.authenticate(permissions=[Permission.USER_MANAGE])

    # Ensure test user querying itself is equivalent to other users querying the test user
    test_user = random_lower(8)
    test_client = create_user(username=test_user, permissions=[])

    test_client.authenticate()
    assert (test_client.user.self()).name == (client.user.get(test_user))[0].name

    # User read requires a valid token, but no specific permissions
    client.authenticate(permissions=[])
    user: User = client.user.self()
    assert user.name == ADMIN_USERNAME
    assert user.email_address == ADMIN_EMAIL
    assert user.public_key == ADMIN_SK.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
    assert user.permissions == [Permission.ROOT]


@pytest.mark.sync
def test_user_creation_and_deletion(client, create_user):
    client.authenticate(permissions=[Permission.USER_MANAGE])

    test_user = random_lower(8)
    test_client = create_user(username=test_user, permissions=[])
    test_client.authenticate()

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
    client.authenticate()

    test_user = random_lower(8)
    test_client = create_user(username=test_user, permissions=[Permission.STORE_USE])
    test_client.authenticate()

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
def test_user_permission_modification_requires_at_least_one_root_user(client, create_user):
    client.authenticate()

    # Can't de-escalate permissions as the sole root user
    with pytest.raises(HTTPError):
        client.user.modify(ADMIN_USERNAME, permissions=[Permission.STORE_USE])

    test_user = random_lower(8)
    test_client = create_user(username=test_user, permissions=[Permission.ROOT])
    test_client.authenticate()

    client.user.modify(ADMIN_USERNAME, permissions=[Permission.STORE_USE])

    self = client.user.self()
    assert self.permissions == [Permission.STORE_USE]

    # Revert admin account's root permission
    test_client.user.modify(ADMIN_USERNAME, permissions=[Permission.ROOT])


@pytest.mark.sync
def test_user_get(client, create_user):
    client.authenticate()

    test_user = random_lower(8)
    create_user(username=test_user, permissions=[Permission.STORE_USE])

    result = client.user.get(test_user)
    assert len(result) == 1
    user = result[0]
    assert user.name == test_user
    assert user.permissions == [Permission.STORE_USE]
    assert user.email_address is None


@pytest.mark.sync
def test_user_list(client, create_user):
    client.authenticate()

    users = [random_lower(8) for _ in range(9)]
    for user in users:
        create_user(username=user, permissions=[])

    result = [user for user in client.user.list()]
    assert {user.name for user in result} == {*users, ADMIN_USERNAME}


@pytest.mark.sync
def test_user_creation_fails_without_user_manage_permission(client, create_user):
    # Authenticate the client
    client.authenticate(permissions=[])

    with pytest.raises(HTTPError) as _exception:
        create_user(username="test", permissions=[])
