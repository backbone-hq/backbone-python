import pytest
from httpx import HTTPError
from nacl import encoding
import random
import string

from backbone.models import Permission, GrantAccess


def r_str(length: int, *, prefix: str = '') -> str:
    return prefix + ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


@pytest.mark.sync
def test_entry_creation_read_deletion(client):
    """Entries can be created, read and deleted"""
    client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])
    key = r_str(8)
    value = r_str(16)

    # Set the entry
    result = client.entry.set(key, value)
    assert set(result.keys()) == {"key", "value", "chain", "grants"}

    assert result["key"] == key
    assert len(result["value"]) == 56 + ((len(value) * 4 / 3) // 4) * 4
    assert len(result["chain"]) == 1
    assert len(result["grants"]) == 1

    # Read the entry
    assert value == client.entry.get(key)

    # Delete the entry
    result = client.entry.delete(key)
    assert result is None

    # Fail to obtain the deleted entry
    with pytest.raises(HTTPError) as _exception:
        client.entry.get(key)


@pytest.mark.sync
def test_namespace_creation_read_deletion(client):
    """Namespaces can be created, read and deleted"""
    client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])
    key = r_str(8)

    # Create the namespace
    result = client.namespace.create(key)
    assert set(result.keys()) == {"key", "public_key", "chain", "grants"}

    assert result["key"] == key
    assert len(result["public_key"]) == 44
    assert len(result["chain"]) == 0
    assert len(result["grants"]) == 1

    # Read the created namespace
    namespace = client.namespace.get(key)
    assert namespace.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode() == result["public_key"]

    # Delete the namespace
    result = client.namespace.delete(key)
    assert result is None

    # Fail to obtain the deleted namespace
    with pytest.raises(HTTPError) as _exception:
        client.namespace.get(key)


@pytest.mark.sync
def test_entry_operations_in_isolated_namespace(client):
    """Entries can be created, read and deleted within an isolated namespace"""
    client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])

    namespace_key = r_str(8)
    entry_key = r_str(8, prefix=namespace_key)
    entry_value = r_str(16)

    client.namespace.create(namespace_key, isolated=True)
    client.entry.set(entry_key, entry_value)
    assert entry_value == client.entry.get(entry_key)
    client.entry.delete(entry_key)

    # Cleanup
    client.namespace.delete(namespace_key)


@pytest.mark.sync
def test_search(client):
    """Entries and Namespace searches return the correct results"""
    client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])

    common_prefix = r_str(8)
    namespace_keys = [r_str(8, prefix=common_prefix) for _ in range(3)]
    for key in namespace_keys:
        client.namespace.create(key)

    entry_keys = [f"{key}++" for key in namespace_keys]
    for key in entry_keys:
        client.entry.set(key, "dummy")

    namespace_results = [item for item in client.namespace.search(common_prefix)]
    assert namespace_results == namespace_keys

    entry_results = [item for item in client.entry.search(common_prefix)]
    assert entry_results == entry_keys


@pytest.mark.sync
def test_entry_read_grant_access(client, create_user):
    """READ grant access on an entry allows the entry to be read and decrypted"""
    client.authenticate()

    test_user = r_str(8)
    test_client = create_user(test_user, permissions=[Permission.STORE_READ])
    test_client.authenticate()

    key = r_str(8)
    value = r_str(16)

    # Create the entry
    client.entry.set(key, value)

    # Test account fails to find the entry
    with pytest.raises(HTTPError) as _exception:
        assert test_client.entry.get(key)

    # Granting the test account read access and reading works as expected
    client.entry.grant(key, test_user, access=[GrantAccess.READ])
    assert test_client.entry.get(key) == value


@pytest.mark.sync
def test_entry_write_grant_access(client, create_user):
    """WRITE grant access on an entry allows the entry to be overwritten"""
    client.authenticate()

    test_user = r_str(8)
    test_client = create_user(test_user, permissions=[Permission.STORE_READ, Permission.STORE_WRITE])
    test_client.authenticate()

    key = r_str(8)
    value = r_str(16)
    new_value = r_str(16)

    client.entry.set(key, value)

    with pytest.raises(HTTPError) as _exception:
        test_client.entry.set(key, new_value)

    # User must have read access to the namespace and write access to the entry
    client.entry.grant(key, test_user, access=[GrantAccess.WRITE])
    test_client.entry.set(key, new_value)

    # The original user should retain access after an overwrite
    # client.entry.set(key, new_value)


@pytest.mark.sync
def test_entry_delete_grant_access(client, create_user):
    """DELETE grant access on an entry allows the entry to be deleted"""
    client.authenticate()

    test_user = r_str(8)
    test_client = create_user(test_user, permissions=[Permission.STORE_READ, Permission.STORE_WRITE])
    test_client.authenticate()

    key = r_str(8)
    value = r_str(16)

    client.entry.set(key, value)

    with pytest.raises(HTTPError) as _exception:
        test_client.entry.delete(key)

    client.entry.grant(key, test_user, access=[GrantAccess.DELETE])
    test_client.entry.delete(key)


@pytest.mark.sync
def test_entry_union_access(client, create_user):
    """Multiple access types grant all of their respective access"""
    client.authenticate()

    test_client = create_user("test", permissions=[Permission.STORE_READ, Permission.STORE_WRITE])
    test_client.authenticate()

    client.entry.set("key", "value")
    client.entry.grant("key", "test", access=[GrantAccess.READ, GrantAccess.WRITE])

    # User should have read and write access
    assert test_client.entry.get("key") == "value"
    test_client.entry.set("key", "value")

    # User should not have delete access
    with pytest.raises(HTTPError) as _exception:
        test_client.entry.delete("key")
