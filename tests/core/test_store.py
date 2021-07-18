import pytest
from httpx import HTTPError
from nacl import encoding

from backbone.core import Permission


@pytest.mark.asyncio
async def test_entry_creation_read_deletion(client):
    """Entries can be created, read and deleted"""
    await client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])
    key = "entry-key"
    value = "entry-value"

    # Set the entry
    result = await client.entry.set(key, value)
    assert set(result.keys()) == {"key", "value", "chain", "grants"}

    assert result["key"] == key
    assert len(result["value"]) == 68
    assert len(result["chain"]) == 1
    assert len(result["grants"]) == 1

    # Read the entry
    assert value == await client.entry.get(key)

    # Delete the entry
    result = await client.entry.delete(key)
    assert result is None

    # Fail to obtain the deleted entry
    with pytest.raises(HTTPError) as _exception:
        await client.entry.get(key)


@pytest.mark.asyncio
async def test_namespace_creation_read_deletion(client):
    """Namespaces can be created, read and deleted"""
    await client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])
    key = "namespace-key"

    # Create the namespace
    result = await client.namespace.create(key)
    assert set(result.keys()) == {"key", "public_key", "chain", "grants"}

    assert result["key"] == key
    assert len(result["public_key"]) == 44
    assert len(result["chain"]) == 0
    assert len(result["grants"]) == 1

    # Read the created namespace
    namespace = await client.namespace.get(key)
    assert namespace.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode() == result["public_key"]

    # Delete the namespace
    result = await client.namespace.delete(key)
    assert result is None

    # Fail to obtain the deleted namespace
    with pytest.raises(HTTPError) as _exception:
        await client.namespace.get(key)


@pytest.mark.asyncio
async def test_entry_operations_in_isolated_namespace(client):
    """Entries can be created, read and deleted within an isolated namespace"""
    await client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])

    namespace_key = "key"
    entry_key = "key-001"
    entry_value = "value"

    await client.namespace.create(namespace_key, isolated=True)
    await client.entry.set(entry_key, entry_value)
    assert entry_value == await client.entry.get(entry_key)
    await client.entry.delete(entry_key)

    # Cleanup
    await client.namespace.delete(namespace_key)


@pytest.mark.asyncio
async def test_search(client):
    """Entries and Namespace searches return the correct results"""
    await client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])

    namespace_keys = ["key", "key-1", "key-2"]
    for key in namespace_keys:
        await client.namespace.create(key)

    entry_keys = [f"{key}++" for key in namespace_keys]
    for key in entry_keys:
        await client.entry.set(key, "dummy")

    namespace_results = [item async for item in client.namespace.search("key")]
    assert namespace_results == namespace_keys

    entry_results = [item async for item in client.entry.search("key")]
    assert entry_results == entry_keys
