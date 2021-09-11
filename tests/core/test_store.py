import asyncio

import pytest
from httpx import HTTPError
from nacl import encoding

from backbone.models import GrantAccess, Permission
from tests.core.utilities import random_lower


@pytest.mark.asyncio
async def test_entry_creation_read_deletion(client):
    """Entries can be created, read and deleted"""
    key = random_lower(8)
    value = random_lower(16)

    # Set the entry
    result = await client.entry.set(key, value)
    assert set(result.keys()) == {"key", "value", "chain", "grants", "duration"}

    assert result["key"] == key
    assert len(result["value"]) == 56 + ((len(value.encode()) * 4 / 3) // 4) * 4
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
async def test_entry_expiration(client):
    """Expired entries cannot be queried after their expiration"""
    key = random_lower(8)
    value = random_lower(16)

    # Set the entry for 1 second
    await client.entry.set(key, value, duration=1)

    # Immediate call succeeds
    await client.entry.get(key)

    # Delayed call fails
    await asyncio.sleep(1)
    with pytest.raises(HTTPError) as _exception:
        await client.entry.get(key)


@pytest.mark.asyncio
async def test_namespace_creation_read_deletion(client):
    """Namespaces can be created, read and deleted"""
    key = random_lower(8)

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
async def test_intermediate_namespace_creation(client):
    """Creating a new namespace with children"""
    namespace_key = random_lower(8)
    entry_key = random_lower(8, prefix=namespace_key)
    value = random_lower(16)

    # Create the entry first
    await client.entry.set(entry_key, value)

    # Create the intermediate namespace
    await client.namespace.create(namespace_key)


@pytest.mark.asyncio
async def test_intermediate_namespace_deletion(client):
    """Deleting a namespace with children"""
    namespace_key = random_lower(8)
    child_namespace_key = random_lower(8, prefix=namespace_key)
    child_entry_key = random_lower(8, prefix=namespace_key)

    # Create the intermediate namespace
    await client.namespace.create(namespace_key)

    # Create the children
    await client.namespace.create(child_namespace_key)
    await client.entry.set(child_entry_key, random_lower(16))

    # Delete the intermediate namespace
    await client.namespace.delete(namespace_key)


@pytest.mark.asyncio
async def test_entry_operations_in_isolated_namespace(client):
    """Entries can be created, read and deleted within an isolated namespace"""
    namespace_key = random_lower(8)
    entry_key = random_lower(8, prefix=namespace_key)
    entry_value = random_lower(16)

    await client.namespace.create(namespace_key, isolated=True)
    await client.entry.set(entry_key, entry_value)
    assert entry_value == await client.entry.get(entry_key)
    await client.entry.delete(entry_key)

    # Cleanup
    await client.namespace.delete(namespace_key)


@pytest.mark.asyncio
async def test_read_grant_access(client, create_user):
    """Direct READ grant access allows the entry/namespace to be read and decrypted"""
    test_user = random_lower(8)
    test_client = await create_user(client, test_user, permissions=[Permission.STORE_USE])

    # Define the randomized variables
    namespace_key = random_lower(8)
    direct_entry_key = random_lower(8)
    indirect_entry_key = random_lower(8, prefix=namespace_key)
    value = random_lower(16)

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
async def test_write_grant_access(client, create_user):
    """Direct WRITE grant access allows the entry/namespace to be overwritten"""
    test_user = random_lower(8)
    test_client = await create_user(client, test_user, permissions=[Permission.STORE_USE])

    # Define the randomized variables
    namespace_key = random_lower(8)
    direct_entry_key = random_lower(8)
    indirect_entry_key = random_lower(8, prefix=namespace_key)
    value = random_lower(16)
    new_value = random_lower(16)

    # Create the namespace & entry
    await client.namespace.create(namespace_key)
    await client.entry.set(direct_entry_key, value, access=[GrantAccess.WRITE])
    await client.entry.set(indirect_entry_key, value, access=[GrantAccess.WRITE])

    # Test account fails to overwrite the entry
    with pytest.raises(HTTPError) as _exception:
        await test_client.entry.set(direct_entry_key, new_value)

    # Test account can overwrite the entry when granted write access
    await client.namespace.grant(namespace_key, test_user, access=[GrantAccess.WRITE, GrantAccess.READ])
    await test_client.entry.set(indirect_entry_key, new_value)

    await client.namespace.grant("", test_user, access=[GrantAccess.READ])
    await client.entry.grant(direct_entry_key, test_user, access=[GrantAccess.WRITE])
    await test_client.entry.set(direct_entry_key, new_value)

    # The original user must retain access after the overwrite
    await client.entry.set(indirect_entry_key, new_value)
    await client.entry.set(direct_entry_key, new_value)


@pytest.mark.asyncio
async def test_delete_grant_access(client, create_user):
    """DELETE grant access on an entry allows the entry to be deleted"""
    test_user = random_lower(8)
    test_client = await create_user(client, test_user, permissions=[Permission.STORE_USE])

    # Define the randomized variables
    namespace_key = random_lower(8)
    direct_entry_key = random_lower(8)
    indirect_entry_key = random_lower(8, prefix=namespace_key)
    value = random_lower(16)

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
async def test_union_grant_access(client, create_user):
    """A grant with multiple access types grant the union of each of their respective access"""
    test_user = random_lower(8)
    test_client = await create_user(client, test_user, permissions=[Permission.STORE_USE])

    # Define the randomized variables
    namespace_key = random_lower(8)
    direct_entry_key = random_lower(8)
    indirect_entry_key = random_lower(8, prefix=namespace_key)
    value = random_lower(16)

    # Create the namespace & entry
    await client.namespace.create(namespace_key)
    await client.entry.set(direct_entry_key, value)
    await client.entry.set(indirect_entry_key, value)

    # Grant READ/DELETE access to the namespace and entry
    await client.namespace.grant(namespace_key, test_user, access=[GrantAccess.READ, GrantAccess.DELETE])
    await client.entry.grant(direct_entry_key, test_user, access=[GrantAccess.READ, GrantAccess.DELETE])

    # User should not have WRITE access to either entry
    with pytest.raises(HTTPError) as _exception:
        await test_client.entry.set(direct_entry_key, random_lower(8))

    with pytest.raises(HTTPError) as _exception:
        await test_client.entry.set(indirect_entry_key, random_lower(8))

    # User should have READ and DELETE access
    assert await test_client.entry.get(direct_entry_key) == value
    assert await test_client.entry.get(indirect_entry_key) == value

    await test_client.entry.delete(direct_entry_key)
    await test_client.entry.delete(indirect_entry_key)


@pytest.mark.asyncio
async def test_grant_access_overwrite(client, create_user):
    """A grant can be overwritten to provide a different grant access without revoking it first"""
    test_user = random_lower(8)
    await create_user(client, test_user, permissions=[Permission.STORE_USE])

    # Define the randomized variables
    entry_key = random_lower(8)
    namespace_key = random_lower(8)
    value = random_lower(16)

    # Create the namespace & entry
    await client.namespace.create(namespace_key)
    await client.entry.set(entry_key, value)

    # Grant the namespace and entry
    await client.namespace.grant(namespace_key, test_user, access=[GrantAccess.READ])
    await client.entry.grant(entry_key, test_user, access=[GrantAccess.READ])

    # Overwrite the access
    await client.namespace.grant(namespace_key, test_user, access=[GrantAccess.WRITE])
    await client.entry.grant(entry_key, test_user, access=[GrantAccess.WRITE])


@pytest.mark.asyncio
async def test_grant_sharing(client, create_user):
    """A user can only grant a level of access that they already have"""

    # Create the test users
    test_user_a, test_user_b = random_lower(8), random_lower(8)
    test_client_a = await create_user(client, test_user_a, permissions=[Permission.STORE_USE, Permission.STORE_SHARE])
    await create_user(client, test_user_b, permissions=[Permission.STORE_USE])

    # Define the randomized variables
    entry_key = random_lower(8)
    namespace_key = random_lower(8)
    value = random_lower(16)

    # Create the namespace & entry
    await client.namespace.create(namespace_key)
    await client.entry.set(entry_key, value)

    # Grant READ access to user A
    await client.namespace.grant(namespace_key, test_user_a, access=[GrantAccess.READ])
    await client.entry.grant(entry_key, test_user_a, access=[GrantAccess.READ])

    # User A can grant READ access to user B
    await test_client_a.namespace.grant(namespace_key, test_user_b, access=[GrantAccess.READ])
    await test_client_a.entry.grant(entry_key, test_user_b, access=[GrantAccess.READ])

    # User A can NOT grant WRITE access to user B
    with pytest.raises(HTTPError) as _exception:
        await test_client_a.namespace.grant(namespace_key, test_user_b, access=[GrantAccess.WRITE])

    with pytest.raises(HTTPError) as _exception:
        await test_client_a.entry.grant(entry_key, test_user_b, access=[GrantAccess.WRITE])


@pytest.mark.asyncio
async def test_direct_access_does_not_impede_indirect_access(client, create_user):
    """A user's direct access will not override their indirect access to a resource"""
    test_user = random_lower(8)
    test_client = await create_user(client, test_user, permissions=[Permission.STORE_USE])

    # Define the randomized variables
    namespace_key = random_lower(8)
    entry_key = random_lower(8)
    value = random_lower(16)

    # Create the namespace & entry
    await client.namespace.create(namespace_key, access=[GrantAccess.READ, GrantAccess.WRITE])
    await client.entry.set(entry_key, value, access=[GrantAccess.READ, GrantAccess.WRITE])

    # Grant direct WRITE access to both
    await client.namespace.grant(namespace_key, test_user, access=[GrantAccess.WRITE])
    await client.entry.grant(entry_key, test_user, access=[GrantAccess.WRITE])

    # Grant indirect READ access to both
    await client.namespace.grant("", test_user, access=[GrantAccess.READ])

    assert await test_client.entry.get(entry_key) == value


@pytest.mark.asyncio
async def test_child_enumeration(client, create_user):
    """Enumerating child entries and namespaces works as expected"""
    test_user = random_lower(8)
    test_client = await create_user(client, test_user, permissions=[Permission.STORE_USE])

    # Define randomized variables
    parent_namespace_key = random_lower(8)
    namespace_keys = [random_lower(8, prefix=parent_namespace_key) for _ in range(3)]
    entry_keys = [random_lower(8, prefix=parent_namespace_key) for _ in range(3)]

    await client.namespace.create(parent_namespace_key)

    # Create the resources
    for key in namespace_keys:
        await client.namespace.create(key)

    for key in entry_keys:
        await client.entry.set(key, "dummy")

    # Querying children by prefix returns the original results
    assert [
        namespace["key"] async for namespace in client.namespace.get_child_namespaces(parent_namespace_key)
    ] == namespace_keys
    assert [entry["key"] async for entry in client.namespace.get_child_entries(parent_namespace_key)] == entry_keys

    # An unprivileged user querying throws a 404
    with pytest.raises(HTTPError) as _exception:
        async for _ in test_client.namespace.get_child_namespaces(parent_namespace_key):
            pass

    with pytest.raises(HTTPError) as _exception:
        async for _ in test_client.namespace.get_child_entries(parent_namespace_key):
            pass
