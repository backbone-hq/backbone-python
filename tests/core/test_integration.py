import pytest


@pytest.mark.asyncio
async def test_basic_setget(client):
    key = "key-001"
    value = "value-001"

    await client.entry.set(key, value)
    assert value == await client.entry.get(key)


@pytest.mark.asyncio
async def test_segregated_setget(client):
    prefix = "key"
    key = "key-001"
    value = "value-001"

    await client.namespace.create(prefix, is_segregated=True)
    await client.entry.set(key, value)
    assert value == await client.entry.get(key)


@pytest.mark.asyncio
async def test_search(client):
    await client.namespace.create("key")
    await client.namespace.create("key-1")
    await client.namespace.create("key-2", is_segregated=True)

    await client.entry.set("key-x", "dummy")
    await client.entry.set("key-1-1", "dummy")
    await client.entry.set("key-2-1", "dummy")

    namespace_results = [item async for item in client.namespace.search("key")]
    assert len(namespace_results) == 3

    entry_results = [item async for item in client.entry.search("key")]
    assert len(entry_results) == 3
