import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import encoding
from nacl.pwhash import argon2id
from nacl.secret import SecretBox

ENDPOINT = "http://127.0.0.1:8000/v0/workspace"

WORKSPACE_SK = PrivateKey(b'JXQBOiVG7y_r_09buC2Tb3HlDkGx-DRYUvDP2ByNdI4=', encoder=encoding.URLSafeBase64Encoder)
WORKSPACE_PK = PublicKey(b'RKvVbTd3FXkLXKmC85fzbHuA-v1VlYq7OHW_ksoKIhY=', encoder=encoding.URLSafeBase64Encoder)

USER_NAME = "admin@kryptos.io"
USER_PASSWORD = "project_kryptos"

USER_SK = PrivateKey(b'CG1bq0tkf4FJlHhbXwgEv30eLj27xS4Cd8GgjBerDVg=', encoder=encoding.URLSafeBase64Encoder)
USER_PK = PublicKey(b'etHbHeOUNpTao_ACalJEpsBQc19QTlr68GzSzNPKWn4=', encoder=encoding.URLSafeBase64Encoder)
USER_HIDDEN_KEY = 'AlTIEdx-t1K7h41EHaynp-LjBIG6UwdFz_SqCYcsUJ6RSkbN7m9omdZClJquKAtPYxgX6UAmzgosn2EWmY3_4DtGAO79Rg3Q'


def encrypt_with_password(username, password, plaintext):
    box_key = argon2id.kdf(32, password.encode(), username.encode())
    return SecretBox(box_key).encrypt(plaintext, encoder=encoding.URLSafeBase64Encoder)


def decrypt_with_password(username, password, ciphertext):
    box_key = argon2id.kdf(32, password.encode(), username.encode())
    return SecretBox(box_key).decrypt(ciphertext, encoder=encoding.URLSafeBase64Encoder)


if __name__ == "__main__":
    original_plaintext = WORKSPACE_SK.encode(encoding.RawEncoder)
    ciphertext = encrypt_with_password(USER_NAME, USER_PASSWORD, original_plaintext)
    recovered_plaintext = decrypt_with_password(USER_NAME, USER_PASSWORD, ciphertext)
    assert original_plaintext == recovered_plaintext
    print(ciphertext)
