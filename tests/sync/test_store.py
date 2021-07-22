import pytest
from httpx import HTTPError
from nacl import encoding

from backbone.models import Permission, GrantAccess


@pytest.mark.sync
def test_entry_creation_read_deletion(client):
    """Entries can be created, read and deleted"""
    client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])
    key = "entry-key"
    value = "entry-value"

    # Set the entry
    result = client.entry.set(key, value)
    assert set(result.keys()) == {"key", "value", "chain", "grants"}

    assert result["key"] == key
    assert len(result["value"]) == 68
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
    key = "namespace-key"

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

    namespace_key = "key"
    entry_key = "key-001"
    entry_value = "value"

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

    namespace_keys = ["key", "key-1", "key-2"]
    for key in namespace_keys:
        client.namespace.create(key)

    entry_keys = [f"{key}++" for key in namespace_keys]
    for key in entry_keys:
        client.entry.set(key, "dummy")

    namespace_results = [item for item in client.namespace.search("key")]
    assert namespace_results == namespace_keys

    entry_results = [item for item in client.entry.search("key")]
    assert entry_results == entry_keys


@pytest.mark.sync
def test_entry_read_grant_access(client, create_user):
    """READ grant access on an entry allows the entry to be read and decrypted"""
    client.authenticate()

    test_client = create_user("test", permissions=[Permission.STORE_READ])
    test_client.authenticate()

    client.entry.set("key", "value")

    with pytest.raises(ValueError) as _exception:
        assert test_client.entry.get("key")

    client.entry.grant("key", "test", access=[GrantAccess.READ])
    assert test_client.entry.get("key") == "value"


@pytest.mark.sync
def test_entry_write_grant_access(client, create_user):
    """WRITE grant access on an entry allows the entry to be overwritten"""
    client.authenticate()

    test_client = create_user("test", permissions=[Permission.STORE_READ, Permission.STORE_WRITE])
    test_client.authenticate()

    client.namespace.create("key")
    client.entry.set("key-001", "value")

    with pytest.raises(HTTPError) as _exception:
        assert test_client.entry.set("key-001", "new-value")

    # User must have read access to the namespace and write access to the entry
    client.namespace.grant("key", "test", access=[GrantAccess.READ])
    client.entry.grant("key-001", "test", access=[GrantAccess.WRITE])
    assert test_client.entry.set("key-001", "new-value")


@pytest.mark.sync
def test_entry_delete_grant_access(client, create_user):
    """DELETE grant access on an entry allows the entry to be deleted"""
    client.authenticate()

    test_client = create_user("test", permissions=[Permission.STORE_READ])
    test_client.authenticate()

    client.entry.set("key", "value")

    with pytest.raises(HTTPError) as _exception:
        assert test_client.entry.delete("key")

    client.entry.grant("key", "test", access=[GrantAccess.DELETE])
    assert test_client.entry.delete("key", "new")
