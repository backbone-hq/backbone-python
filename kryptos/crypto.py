import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box, SealedBox
from nacl.utils import encoding, random
from nacl.pwhash import argon2id
from nacl.hash import blake2b
from nacl.secret import SecretBox


def derive_password_key(identity: str, password: str):
    salt = blake2b(identity.encode(), 16, encoder=encoding.RawEncoder)
    return argon2id.kdf(size=32, password=password.encode(), salt=salt)


def generate_keypair() -> (PrivateKey, PublicKey):
    # Sensitive
    secret_key: PrivateKey = PrivateKey.generate()
    public_key: PublicKey = secret_key.public_key

    return secret_key, public_key


def encrypt_with_password(identity, password, plaintext) -> bytes:
    password_key: bytes = derive_password_key(identity, password)
    return SecretBox(password_key).encrypt(plaintext, encoder=encoding.URLSafeBase64Encoder)


def decrypt_with_password(identity, password, ciphertext) -> bytes:
    password_key: bytes = derive_password_key(identity, password)
    return SecretBox(password_key).decrypt(ciphertext, encoder=encoding.URLSafeBase64Encoder)


def encrypt_grant(public_key: PublicKey, plaintext: PrivateKey):
    plaintext = plaintext.encode(encoder=encoding.RawEncoder)
    return SealedBox(public_key).encrypt(plaintext, encoder=encoding.URLSafeBase64Encoder)


def decrypt_grant(secret_key: PrivateKey, ciphertext: bytes):
    return SealedBox(secret_key).decrypt(ciphertext, encoder=encoding.URLSafeBase64Encoder)


def encrypt_entry(plaintext, *public_keys):
    entry_key = random(SecretBox.KEY_SIZE)
    ciphertext = SecretBox(entry_key).encrypt(plaintext.encode(), encoder=encoding.URLSafeBase64Encoder)
    grants = []

    for public_key in public_keys:
        grants.append((public_key, SealedBox(public_key).encrypt(entry_key, encoder=encoding.URLSafeBase64Encoder)))

    return ciphertext, grants


def decrypt_entry(ciphertext, secret_kek, secret_key):
    entry_key = SealedBox(secret_key).decrypt(secret_kek, encoder=encoding.URLSafeBase64Encoder)
    return SecretBox(entry_key).decrypt(ciphertext.encode(), encoder=encoding.URLSafeBase64Encoder)
