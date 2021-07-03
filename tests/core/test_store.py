import pytest
from httpx import HTTPError
from nacl import encoding

from backbone.core import Permission


@pytest.mark.asyncio
async def test_entry_creation_read_deletion(client):
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
async def test_entry_operations_in_segregated_namespace(client):
    await client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])

    namespace_key = "key"
    entry_key = "key-001"
    entry_value = "value"

    await client.namespace.create(namespace_key, isolated=True)
    await client.entry.set(entry_key, entry_value)
    assert entry_value == await client.entry.get(entry_key)
    await client.entry.delete(entry_key)

    with pytest.raises(HTTPError) as _exception:
        await client.namespace.get(entry_key)

    await client.namespace.delete(namespace_key)


@pytest.mark.asyncio
async def test_search(client):
    await client.authenticate(permissions=[Permission.STORE_READ, Permission.STORE_WRITE])

    await client.namespace.create("key")
    await client.namespace.create("key-1")
    await client.namespace.create("key-2", isolated=True)

    await client.entry.set("key-x", "dummy")
    await client.entry.set("key-1-1", "dummy")
    await client.entry.set("key-2-1", "dummy")

    namespace_results = [item async for item in client.namespace.search("key")]
    assert len(namespace_results) == 3

    entry_results = [item async for item in client.entry.search("key")]
    assert len(entry_results) == 3
