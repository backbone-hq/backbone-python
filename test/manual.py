import httpx
from nacl.public import PrivateKey, PublicKey
from nacl.utils import encoding
from kryptos.crypto import (
    encrypt_with_password,
    decrypt_with_password,
    encrypt_entry,
    decrypt_entry,
    encrypt_grant,
    decrypt_hidden_token,
)

WORKSPACE_NAME = "kryptos"
WORKSPACE_DISPLAY_NAME = "CIA Brothel"

USER_NAME = "admin"
USER_PASSWORD = "project_kryptos"

USER_SK = PrivateKey(b"CG1bq0tkf4FJlHhbXwgEv30eLj27xS4Cd8GgjBerDVg=", encoder=encoding.URLSafeBase64Encoder)
USER_PK = PublicKey(b"etHbHeOUNpTao_ACalJEpsBQc19QTlr68GzSzNPKWn4=", encoder=encoding.URLSafeBase64Encoder)

NAMESPACE_SK = PrivateKey(b"A6cgWzRiUyH9RaaVxWM_u_nzqSAJJKSxe_is4QzbfNM=", encoder=encoding.URLSafeBase64Encoder)
NAMESPACE_PK = PublicKey(b"X3U0wKsCk82-DECB63k1StpRYDOcGromY1LeveIKqH0=", encoder=encoding.URLSafeBase64Encoder)


def create_workspace():
    hidden_key = USER_SK.encode(encoding.RawEncoder)
    hidden_key = encrypt_with_password(USER_NAME, USER_PASSWORD, hidden_key)
    namespace_grant = encrypt_grant(USER_PK, NAMESPACE_SK)

    workspace_params = {"name": WORKSPACE_NAME, "display_name": WORKSPACE_DISPLAY_NAME}

    user_params = {
        "name": USER_NAME,
        "email_address": "admin@kryptos.io",
        "public_key": USER_PK.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
        "hidden_key": hidden_key.decode(),
        "permissions": ["root"],
    }

    namespace_params = {
        "public_key": NAMESPACE_PK.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
        "grants": [
            {
                "grantee_pk": USER_PK.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                "value": namespace_grant.decode(),
                "access": ["read", "write", "delete"],
            }
        ],
    }

    result = httpx.post(
        "http://127.0.0.1:8000/v0/workspace",
        json={"workspace": workspace_params, "user": user_params, "namespace": namespace_params},
    )

    return result.json()


def get_workspace(*, token):
    return httpx.get("http://127.0.0.1:8000/v0/workspace", headers={"Authorization": f"Bearer {token}"}).json()


def delete_workspace(*, token):
    return httpx.delete("http://127.0.0.1:8000/v0/workspace", headers={"Authorization": f"Bearer {token}"}).json()


def authenticate(workspace, username):
    result = httpx.post(
        f"http://127.0.0.1:8000/v0/token/",
        json={"workspace": workspace, "username": username, "permissions": ["root"]},
    )
    return result.json()


def store__create_entry(key, value, *, token):
    ciphertext, grants = encrypt_entry(value, NAMESPACE_PK)

    result = httpx.post(
        f"http://127.0.0.1:8000/v0/entry/{key}",
        json={
            "value": ciphertext.decode(),
            "grants": [
                {
                    "grantee_pk": public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                    "value": value.decode(),
                    "access": ["read", "write", "delete"],
                }
                for public_key, value in grants
            ],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    return result.json()


def store__fetch_namespace_chain(key, *, token):
    result = httpx.get(
        f"http://127.0.0.1:8000/v0/chain/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )

    result = result.json()
    return result


def store__fetch_entry(key, *, token):
    result = httpx.get(
        f"http://127.0.0.1:8000/v0/entry/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )

    result = result.json()
    namespace_pk = NAMESPACE_PK.encode(encoder=encoding.URLSafeBase64Encoder).decode()
    active_secret_kek = None

    # FIXME: This is a hack that doesn't account for the chain.
    # The grant on the entry is for the root namespace; the user's grant on the root namespace is included in the chain
    for grant in result["grants"]:
        if grant["grantee_pk"] != namespace_pk:
            continue

        active_secret_kek = grant["value"]
        break

    result = decrypt_entry(result["value"], active_secret_kek, NAMESPACE_SK)
    return result


def store__list_entries(key, *, token):
    result = httpx.get(
        f"http://127.0.0.1:8000/v0/entries/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )

    return result.json()


def store__delete_entry(key, *, token):
    result = httpx.delete(
        f"http://127.0.0.1:8000/v0/entry/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )

    return result.json()


if __name__ == "__main__":
    workspace_create = create_workspace()
    print("workspace", workspace_create)

    authenticate_res = authenticate(WORKSPACE_NAME, USER_NAME)
    print("auth", authenticate_res)

    user_sk = decrypt_with_password(USER_NAME, USER_PASSWORD, authenticate_res["hidden_key"].encode())
    user_sk = PrivateKey(user_sk)
    token = decrypt_hidden_token(user_sk, authenticate_res["hidden_token"].encode()).decode()
    print("token", token)

    workspace_read = get_workspace(token=token)
    print("workspace", workspace_read)

    store_create_entry_res = store__create_entry("fuck", "david", token=token)
    print("created", store_create_entry_res)
    store_list_entries_res = store__list_entries("fu", token=token)
    print("listed", store_list_entries_res)
    store_fetch_namespace_chain = store__fetch_namespace_chain("fuck", token=token)
    print("chained", store_fetch_namespace_chain)
    store_fetch_entry_res = store__fetch_entry("fuck", token=token)
    print("fetched", store_fetch_entry_res)
    store_delete_entry_res = store__delete_entry("fuck", token=token)
    print("deleted", store_delete_entry_res)

    # Delete all objects at the end of the scenario
    delete_workspace(token=token)
