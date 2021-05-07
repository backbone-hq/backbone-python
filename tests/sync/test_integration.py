import pytest



def test_basic_setget(client):
    key = "key-001"
    value = "value-001"

    client.entry.set(key, value)
    assert value == client.entry.get(key)



def test_segregated_setget(client):
    prefix = "key"
    key = "key-001"
    value = "value-001"

    client.namespace.create(prefix, is_segregated=True)
    client.entry.set(key, value)
    assert value == client.entry.get(key)



def test_search(client):
    client.namespace.create("key")
    client.namespace.create("key-1")
    client.namespace.create("key-2", is_segregated=True)

    client.entry.set("key-x", "dummy")
    client.entry.set("key-1-1", "dummy")
    client.entry.set("key-2-1", "dummy")

    namespace_results = [item for item in client.namespace.search("key")]
    assert len(namespace_results) == 3

    entry_results = [item for item in client.entry.search("key")]
    assert len(entry_results) == 3
