import httpx
from nacl.public import PrivateKey, PublicKey
from nacl.utils import encoding
from kryptos.crypto import (
    encrypt_with_password,
    decrypt_with_password,
    encrypt_entry,
    decrypt_entry,
    encrypt_grant,
    decrypt_grant,
)

WORKSPACE_NAME = "kryptos"
WORKSPACE_DISPLAY_NAME = "CIA Brothel"

USER_NAME = "admin@kryptos.io"
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
        "name": "admin",
        "email_address": "test@example.com",
        "public_key": USER_PK.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
        "hidden_key": hidden_key.decode(),
        "permissions": ["root"],
    }

    namespace_params = {
        "public_key": NAMESPACE_PK.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
        "grants": [
            {
                "public_key": USER_PK.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
                "value": namespace_grant.decode(),
            }
        ],
    }

    result = httpx.post(
        "http://127.0.0.1:8000/v0/workspace",
        json={"workspace": workspace_params, "user": user_params, "namespace": namespace_params},
    )

    return result.json()


def authenticate():
    result = httpx.post(
        f"http://127.0.0.1:8000/v0/workspace/auth/{WORKSPACE_NAME}", json={"username": USER_NAME, "permissions": [""]}
    )
    return result.json()


def store__crate_entry(key, value, *, token):
    ciphertext, grants = encrypt_entry(value, NAMESPACE_PK)

    result = httpx.post(
        f"http://127.0.0.1:8000/v0/entry/{key}",
        json={
            "value": ciphertext.decode(),
            "grants": [
                {"public_key": public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode(), "value": value.decode()}
                for public_key, value in grants
            ],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    return result.json()

def store__fetch_entry(key, *, token):
    result = httpx.get(
        f"http://127.0.0.1:8000/v0/entry/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )

    result = result.json()
    decoded_pk = USER_PK.encode(encoder=encoding.URLSafeBase64Encoder).decode()

    active_sk = USER_SK
    active_secret_kek = None

    for grant in result["grants"]:
        if grant["public_key"] != decoded_pk:
            continue

        active_secret_kek = grant["value"]
        break

    result["value"] = decrypt_entry(result["value"], active_secret_kek, active_sk)
    return result

def store__list_entries(key, *, token):
    result = httpx.get(
        f"http://127.0.0.1:8000/v0/entries/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )

    return result.json()

if __name__ == "__main__":
    # temp_sk, temp_pk = generate_keypair()
    # print(temp_sk.encode(encoder=encoding.URLSafeBase64Encoder), temp_pk.encode(encoding.URLSafeBase64Encoder))

    workspace_res = create_workspace()
    authenticate_res = authenticate()

    user_sk = decrypt_with_password(USER_NAME, USER_PASSWORD, authenticate_res["hidden_key"].encode())
    user_sk = PrivateKey(user_sk)

    token = decrypt_grant(user_sk, authenticate_res["hidden_token"].encode()).decode()
    store_create_entry_res = store__crate_entry("fuck", "david", token=token)
    store_list_entries_res = store__list_entries("fu", token=token)
    store_fetch_entry_res = store__fetch_entry("fuck", token=token)

    print(store_create_entry_res)
    print(store_list_entries_res)
