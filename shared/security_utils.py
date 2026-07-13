from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from cryptography.fernet import Fernet


SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)(authorization:\s*)([^\r\n]+)"),
    re.compile(r"(?i)(cookie:\s*)([^\r\n]+)"),
    re.compile(r"(?i)(password['\"]?\s*[:=]\s*['\"]?)([^'\"\s,}]+)"),
    re.compile(r"(?i)(token['\"]?\s*[:=]\s*['\"]?)([^'\"\s,}]+)"),
]


def _fernet() -> Fernet:
    raw = os.getenv("SECRET_KEY", "change_me").encode("utf-8")
    import base64

    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw).digest()))


def encrypt_json(payload: dict[str, Any] | None) -> dict[str, str] | None:
    if not payload:
        return None
    data = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return {"v": "fernet-v1", "data": _fernet().encrypt(data).decode("ascii")}


def decrypt_json(payload: dict[str, str] | None) -> dict[str, Any] | None:
    if not payload or not payload.get("data"):
        return None
    if payload.get("v") != "fernet-v1":
        raise ValueError("Unsupported credential encryption format")
    data = _fernet().decrypt(payload["data"].encode("ascii"))
    return json.loads(data.decode("utf-8"))


def redact_secret_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", redacted)
    return redacted


def redact_secrets(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secret_text(value)
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, dict):
        safe = {}
        for key, item in value.items():
            if key.lower() in {"password", "token", "bearer_token", "cookie", "authorization", "headers"}:
                safe[key] = "[REDACTED]"
            else:
                safe[key] = redact_secrets(item)
        return safe
    return value
