from nacl.public import PrivateKey, PublicKey, Box, SealedBox
from nacl.utils import encoding, random
from nacl.pwhash import argon2id
from nacl.hash import blake2b
from nacl.secret import SecretBox
from typing import List, Tuple


def derive_password_key(identity: str, password: str) -> bytes:
    salt = blake2b(identity.encode(), digest_size=16, encoder=encoding.RawEncoder)
    return argon2id.kdf(size=32, password=password.encode(), salt=salt)


def encrypt_with_secret(secret: bytes, plaintext: bytes) -> bytes:
    return SecretBox(secret).encrypt(plaintext, encoder=encoding.URLSafeBase64Encoder)


def encrypt_with_password(identity, password, plaintext) -> bytes:
    password_key: bytes = derive_password_key(identity, password)
    return encrypt_with_secret(password_key, plaintext)


def decrypt_with_secret(secret: bytes, ciphertext: bytes) -> bytes:
    return SecretBox(secret).decrypt(ciphertext, encoder=encoding.URLSafeBase64Encoder)


def decrypt_with_password(identity, password, ciphertext) -> bytes:
    password_key: bytes = derive_password_key(identity, password)
    return decrypt_with_secret(password_key, ciphertext)


def encrypt_grant(public_key: PublicKey, secret_key: PrivateKey) -> bytes:
    plaintext = secret_key.encode(encoder=encoding.RawEncoder)
    return Box(secret_key, public_key).encrypt(plaintext, encoder=encoding.URLSafeBase64Encoder)


def decrypt_grant(public_key: PublicKey, secret_key: PrivateKey, ciphertext: bytes) -> bytes:
    return Box(secret_key, public_key).decrypt(ciphertext, encoder=encoding.URLSafeBase64Encoder)


def decrypt_hidden_token(secret_key: PrivateKey, ciphertext: bytes) -> bytes:
    auth_box_pk = PublicKey(b"etHbHeOUNpTao_ACalJEpsBQc19QTlr68GzSzNPKWn4=", encoder=encoding.URLSafeBase64Encoder)
    return Box(secret_key, auth_box_pk).decrypt(ciphertext, encoder=encoding.URLSafeBase64Encoder)


def encrypt_entry(plaintext: str, *public_keys: PublicKey) -> (bytes, List[Tuple[bytes, bytes]]):
    entry_key = random(SecretBox.KEY_SIZE)
    ciphertext = SecretBox(entry_key).encrypt(plaintext.encode(), encoder=encoding.URLSafeBase64Encoder)
    grants = []

    for public_key in public_keys:
        grants.append(
            (
                public_key.encode(encoder=encoding.URLSafeBase64Encoder),
                SealedBox(public_key).encrypt(entry_key, encoder=encoding.URLSafeBase64Encoder),
            )
        )

    return ciphertext, grants


def decrypt_entry(ciphertext: str, secret_kek: bytes, secret_key: PrivateKey) -> bytes:
    entry_key = SealedBox(secret_key).decrypt(secret_kek, encoder=encoding.URLSafeBase64Encoder)
    return SecretBox(entry_key).decrypt(ciphertext.encode(), encoder=encoding.URLSafeBase64Encoder)
