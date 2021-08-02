import random
import string

import pytest
from httpx import HTTPError
from nacl import encoding

from backbone.models import GrantAccess, Permission


def r_str(length: int, *, prefix: str = "") -> str:
    return prefix + "".join(random.choice(string.ascii_lowercase) for _ in range(length))


@pytest.mark.asyncio
async def test_entry_creation_read_deletion(client):
    """Entries can be created, read and deleted"""
    await client.authenticate(permissions=[Permission.STORE_USE])
    key = r_str(8)
    value = r_str(16)

    # Set the entry
    result = await client.entry.set(key, value)
    assert set(result.keys()) == {"key", "value", "chain", "grants"}

    assert result["key"] == key
    assert len(result["value"]) == 56 + ((len(value) * 4 / 3) // 4) * 4
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
    await client.authenticate(permissions=[Permission.STORE_USE])
    key = r_str(8)

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
    await client.authenticate(permissions=[Permission.STORE_USE])

    namespace_key = r_str(8)
    entry_key = r_str(8, prefix=namespace_key)
    entry_value = r_str(16)

    await client.namespace.create(namespace_key, isolated=True)
    await client.entry.set(entry_key, entry_value)
    assert entry_value == await client.entry.get(entry_key)
    await client.entry.delete(entry_key)

    # Cleanup
    await client.namespace.delete(namespace_key)


@pytest.mark.asyncio
async def test_search(client):
    """Entries and Namespace searches return the correct results"""
    await client.authenticate(permissions=[Permission.STORE_USE])

    common_prefix = r_str(8)
    namespace_keys = [r_str(8, prefix=common_prefix) for _ in range(3)]
    for key in namespace_keys:
        await client.namespace.create(key)

    entry_keys = [f"{key}++" for key in namespace_keys]
    for key in entry_keys:
        await client.entry.set(key, "dummy")

    namespace_results = [item async for item in client.namespace.search(common_prefix)]
    assert namespace_results == namespace_keys

    entry_results = [item async for item in client.entry.search(common_prefix)]
    assert entry_results == entry_keys


@pytest.mark.asyncio
async def test_read_grant_access(client, create_user):
    """Direct READ grant access allows the entry/namespace to be read and decrypted"""
    await client.authenticate()

    # Create the test user
    test_user = r_str(8)
    test_client = await create_user(test_user, permissions=[Permission.STORE_USE])
    await test_client.authenticate()

    # Define the randomized variables
    namespace_key = r_str(8)
    direct_entry_key = r_str(8)
    indirect_entry_key = r_str(8, prefix=namespace_key)
    value = r_str(16)

    # Create the namespace & entry
    await client.namespace.create(namespace_key)
    await client.entry.set(direct_entry_key, value, access=[GrantAccess.READ])
    await client.entry.set(indirect_entry_key, value, access=[GrantAccess.READ])

    # Test account fails to find the namespace & entry
    with pytest.raises(HTTPError) as _exception:
        await test_client.namespace.get(namespace_key)

    with pytest.raises(HTTPError) as _exception:
        await test_client.entry.get(direct_entry_key)

    # Granting the test account read access and reading works as expected
    await client.namespace.grant(namespace_key, test_user, access=[GrantAccess.READ])
    await test_client.namespace.get(namespace_key)
    assert await test_client.entry.get(indirect_entry_key) == value

    await client.entry.grant(direct_entry_key, test_user, access=[GrantAccess.READ])
    assert await test_client.entry.get(direct_entry_key) == value


@pytest.mark.asyncio
async def test_entry_write_grant_access(client, create_user):
    """Direct WRITE grant access allows the entry/namespace to be overwritten"""
    await client.authenticate()

    # Create the test user
    test_user = r_str(8)
    test_client = await create_user(test_user, permissions=[Permission.STORE_USE])
    await test_client.authenticate()

    # Define the randomized variables
    namespace_key = r_str(8)
    direct_entry_key = r_str(8)
    indirect_entry_key = r_str(8, prefix=namespace_key)
    value = r_str(16)
    new_value = r_str(16)

    # Create the namespace & entry
    await client.namespace.create(namespace_key)
    await client.entry.set(direct_entry_key, value, access=[GrantAccess.WRITE])
    await client.entry.set(indirect_entry_key, value, access=[GrantAccess.WRITE])

    # Test account fails to overwrite the entry
    with pytest.raises(HTTPError) as _exception:
        await test_client.entry.set(direct_entry_key, new_value)

    # Test account can overwrite the entry when granted write access
    await client.namespace.grant(namespace_key, test_user, access=[GrantAccess.WRITE])
    await test_client.entry.set(indirect_entry_key, new_value)

    await client.entry.grant(direct_entry_key, test_user, access=[GrantAccess.WRITE])
    await test_client.entry.set(direct_entry_key, new_value)

    # The original user must retain access after the overwrite
    await client.entry.set(indirect_entry_key, new_value)
    await client.entry.set(direct_entry_key, new_value)


@pytest.mark.asyncio
async def test_entry_delete_grant_access(client, create_user):
    """DELETE grant access on an entry allows the entry to be deleted"""
    await client.authenticate()

    # Create the test user
    test_user = r_str(8)
    test_client = await create_user(test_user, permissions=[Permission.STORE_USE])
    await test_client.authenticate()

    # Define the randomized variables
    namespace_key = r_str(8)
    direct_entry_key = r_str(8)
    indirect_entry_key = r_str(8, prefix=namespace_key)
    value = r_str(16)

    # Create the namespace & entry
    await client.namespace.create(namespace_key)
    await client.entry.set(direct_entry_key, value, access=[GrantAccess.DELETE])
    await client.entry.set(indirect_entry_key, value, access=[GrantAccess.DELETE])

    # Test account fails to delete the namespace & entry
    with pytest.raises(HTTPError) as _exception:
        await test_client.namespace.delete(namespace_key)

    with pytest.raises(HTTPError) as _exception:
        await test_client.entry.delete(direct_entry_key)

    # Test account can delete the namespace & entry when granted delete access
    await client.namespace.grant(namespace_key, test_user, access=[GrantAccess.DELETE])
    await test_client.entry.delete(indirect_entry_key)
    await test_client.namespace.delete(namespace_key)

    await client.entry.grant(direct_entry_key, test_user, access=[GrantAccess.DELETE])
    await test_client.entry.delete(direct_entry_key)


@pytest.mark.asyncio
async def test_entry_union_access(client, create_user):
    """Multiple access types grant all of their respective access"""
    await client.authenticate()

    test_client = await create_user("test", permissions=[Permission.STORE_USE])
    await test_client.authenticate()

    await client.entry.set("key", "value")
    await client.entry.grant("key", "test", access=[GrantAccess.READ, GrantAccess.WRITE])

    # User should have read and write access
    assert await test_client.entry.get("key") == "value"
    await test_client.entry.set("key", "value")

    # User should not have delete access
    with pytest.raises(HTTPError) as _exception:
        await test_client.entry.delete("key")
