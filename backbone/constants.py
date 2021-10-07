import os
from nacl.public import PublicKey
from nacl import encoding

SERVICE_VERSION = 0
SERVICE_ROOT_PK = PublicKey(b"etHbHeOUNpTao_ACalJEpsBQc19QTlr68GzSzNPKWn4=", encoder=encoding.URLSafeBase64Encoder)

if os.environ.get("BACKBONE_DEV_LOCAL", "false").lower() in {"1", "true"}:
    SERVICE_URL = f"http://localhost:8000/v{SERVICE_VERSION}/"
else:
    SERVICE_URL = f"https://backbone.dev/v{SERVICE_VERSION}/"
