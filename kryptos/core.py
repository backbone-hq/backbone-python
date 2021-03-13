from nacl import exceptions, hash, pwhash, secret, public
import secrets
from typing import Optional, Set
import httpx
from base64 import urlsafe_b64decode, urlsafe_b64encode

__version__ = 0
KRYPTOS_V0 = f"http://localhost:8000/v{__version__}"
WORKSPACE_V0 = f"{KRYPTOS_V0}/workspace"
USER_V0 = f"{KRYPTOS_V0}/user"


def derive_symmetric_key(name: str, password: str) -> bytes:
    return pwhash.argon2id.kdf(
        size=32, password=password.encode(), salt=bytes.fromhex(hash.blake2b(name.encode(), 16).decode())
    )


def generate_keypair(name: str, password: str) -> (bytes, bytes):
    # Sensitive
    private_key: public.PrivateKey = public.PrivateKey.generate()
    symmetric_key: bytes = derive_symmetric_key(name, password)

    # Public
    hidden_key: bytes = secret.SecretBox(key=symmetric_key).encrypt(private_key.encode())
    public_key: bytes = private_key.public_key.encode()

    return public_key, hidden_key


def decrypt_hidden_key(hidden_key: bytes, username: str, password: str) -> Optional[public.PrivateKey]:
    symmetric_key: bytes = derive_symmetric_key(username, password)
    private_key: bytes = secret.SecretBox(key=symmetric_key).decrypt(hidden_key)

    try:
        return public.PrivateKey(private_key)
    except exceptions.CryptoError:
        return None


def decrypt_token(token: bytes, private_key: public.PrivateKey) -> str:
    return public.SealedBox(private_key).decrypt(token)


def create_grant(owner: public.PublicKey, value: bytes) -> (bytes, bytes):
    key = secrets.token_bytes(32)
    ciphertext = secret.SecretBox(key).encrypt(value)
    grant = public.SealedBox(key).encrypt(key)
    return ciphertext, grant


def authenticate(workspace: str, username: str, password: str) -> Optional[str]:
    result = httpx.post(f"{WORKSPACE_V0}/{workspace}/auth", json={"username": username}).json()

    if "hidden_key" not in result or "hidden_token" not in result:
        return None

    hidden_key: bytes = urlsafe_b64decode(result.get("hidden_key"))
    hidden_token: bytes = urlsafe_b64decode(result.get("hidden_token"))

    private_key: Optional[public.PrivateKey] = decrypt_hidden_key(hidden_key, username, password)
    if not private_key:
        return None

    return decrypt_token(hidden_token, private_key)


def create_user(token: str, name: str, password: str, email_address: Optional[str], permissions=Set[str]):
    public_key, hidden_key = generate_keypair(name, password)

    params = {
        "name": name,
        "public_key": urlsafe_b64encode(public_key),
        "hidden_key": urlsafe_b64encode(hidden_key),
        "permissions": permissions,
    }

    if email_address:
        params["email_address"] = email_address

    result = httpx.post(USER_V0, json=params, headers={"Authentication": f"Bearer {token}"})

    if not (200 <= result.status_code < 300):
        raise ValueError


def delete_user(token: str):
    result = httpx.post(USER_V0, headers={"Authentication": f"Bearer {token}"})

    if not (200 <= result.status_code < 300):
        raise ValueError
