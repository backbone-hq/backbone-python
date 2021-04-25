def test_basic_setget(client):
    key = "key-001"
    value = "value-001"

    entry = client.entry.set(key, value)
    assert value == client.entry.get(key)


def test_segregated_setget(client):
    prefix = "key"
    key = "key-001"
    value = "value-001"

    namespace = client.namespace.create(prefix, is_segregated=True)
    entry = client.entry.set(key, value)
    assert value == client.entry.get(key)
