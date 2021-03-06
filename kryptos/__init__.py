from typing import Optional
from nacl import exceptions, hash, pwhash, secret, public

import gc

__version__ = 0


def derive_symmetric_key(username: str, password: str) -> bytes:
    return pwhash.argon2i.kdf(size=32, password=password.encode(), salt=bytes.fromhex(hash.blake2b(username.encode(), 16).decode()))


def generate_user_keypair(username: str, password: str) -> (bytes, bytes):
    # Sensitive
    private: public.PrivateKey = public.PrivateKey.generate()
    symmetric_key: bytes = derive_symmetric_key(username, password)

    # Public
    hidden_key: bytes = secret.SecretBox(key=symmetric_key).encrypt(private.encode())
    public_key: bytes = private.public_key.encode()

    # Delete references to the private and symmetric keys and force garbage collection
    del symmetric_key, private
    gc.collect()

    return public_key, hidden_key


def decrypt_hidden_key(hidden_key: bytes, username: str, password: str) -> Optional[public.PrivateKey]:
    symmetric_key: bytes = derive_symmetric_key(username, password)
    private_key: bytes = secret.SecretBox(key=symmetric_key).decrypt(hidden_key)

    # Delete references to the symmetric key
    del symmetric_key
    gc.collect()

    try:
        return public.PrivateKey(private_key)
    except exceptions.CryptoError:
        return None
