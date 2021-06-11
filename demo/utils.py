import httpx
from halo import Halo
from nacl.public import PrivateKey, PublicKey
from nacl.utils import encoding

from backbone.crypto import (
    decrypt_entry,
    decrypt_grant,
    decrypt_hidden_token,
    decrypt_with_password,
    encrypt_entry,
    encrypt_grant,
    encrypt_with_password,
)


@Halo(text="Authenticating", spinner="dots")
def authenticate(workspace, username, password):
    result = httpx.post(
        f"http://127.0.0.1:8000/v0/token/",
        json={"workspace": workspace, "username": username, "permissions": ["root"]},
    )

    payload = result.json()
    user_sk = decrypt_with_password(username, password, payload["hidden_key"].encode())
    user_sk = PrivateKey(user_sk)

    token = decrypt_hidden_token(user_sk, payload["hidden_token"].encode()).decode()
    return token, user_sk


@Halo(text="Creating workspace", spinner="dots")
def create_workspace(name, display_name, admin_username, admin_password):
    user_sk = PrivateKey.generate()
    user_pk = user_sk.public_key

    namespace_sk = PrivateKey.generate()
    namespace_pk = namespace_sk.public_key

    hidden_key = user_sk.encode(encoding.RawEncoder)
    hidden_key = encrypt_with_password(admin_username, admin_password, hidden_key)
    namespace_grant = encrypt_grant(user_pk, namespace_sk)

    workspace_params = {"name": name, "display_name": display_name}

    user_params = {
        "name": admin_username,
        "email_address": "admin@backbone.io",
        "public_key": user_pk.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
        "hidden_key": hidden_key.decode(),
        "permissions": ["root"],
    }

    namespace_params = {
        "public_key": namespace_pk.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
        "grants": [
            {
                "grantee_pk": user_pk.encode(encoder=encoding.URLSafeBase64Encoder).decode(),
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
    response = httpx.delete("http://127.0.0.1:8000/v0/workspace", headers={"Authorization": f"Bearer {token}"})

    print(response.status_code, response.read())


def fetch_chain(key, *, token):
    result = httpx.get(
        f"http://127.0.0.1:8000/v0/chain/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )

    result = result.json()
    return result


@Halo(text="Creating entry", spinner="dots")
def create_entry(key, value, *, token):
    namespace_pk = fetch_chain(key, token=token)["chain"][-1]["subject_pk"]
    namespace_pk = PublicKey(namespace_pk, encoder=encoding.URLSafeBase64Encoder)
    ciphertext, grants = encrypt_entry(value, namespace_pk)

    result = httpx.post(
        f"http://127.0.0.1:8000/v0/entry/{key}",
        json={
            "value": ciphertext.decode(),
            "grants": [
                {
                    "grantee_pk": public_key.decode(),
                    "value": value.decode(),
                    "access": ["read", "write", "delete"],
                }
                for public_key, value in grants
            ],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    return result.json()


@Halo(text="Fetching entry", spinner="dots")
def fetch_entry(key, *, token, sk):
    result = httpx.get(
        f"http://127.0.0.1:8000/v0/entry/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )
    result = result.json()

    current_sk = sk

    for hop in result["chain"]:
        subject_pk = PublicKey(hop["subject_pk"], encoder=encoding.URLSafeBase64Encoder)
        current_sk = decrypt_grant(subject_pk, current_sk, hop["value"])
        current_sk = PrivateKey(current_sk, encoder=encoding.RawEncoder)

    current_pk_encoded = current_sk.public_key.encode(encoder=encoding.URLSafeBase64Encoder).decode()
    grant = next(iter([grant for grant in result["grants"] if grant["grantee_pk"] == current_pk_encoded]))
    return {**result, "value": decrypt_entry(result["value"], grant["value"], current_sk).decode()}


def list_entries(key, *, token):
    result = httpx.get(
        f"http://127.0.0.1:8000/v0/entries/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )

    return result.json()


def delete_entry(key, *, token):
    result = httpx.delete(
        f"http://127.0.0.1:8000/v0/entry/{key}",
        headers={"Authorization": f"Bearer {token}"},
    )

    return result.json()
