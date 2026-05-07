import base64
import hashlib
import hmac
from typing import Any, Mapping, Optional, Union


def _header_value(headers: Mapping[str, Any], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() != wanted:
            continue
        if isinstance(value, (list, tuple)):
            return str(value[0] if value else "")
        return str(value if value is not None else "")
    return ""


def verify_signature(
    provider_or_mode: str,
    *,
    secret: str,
    headers: Mapping[str, Any],
    body: Union[bytes, bytearray, memoryview],
) -> None:
    """
    Validate common provider webhook signatures using the raw, unmodified request body bytes.

    Supported providers/modes:
      - "stripe" / "stripe_hmac"
      - "github" / "github_hmac"
      - "shopify" / "shopify_hmac"
      - "gitlab" / "gitlab_token"
      - "custom_hmac_sha256"
    """
    mode = str(provider_or_mode or "").strip().lower()
    if not mode:
        raise ValueError("provider/signature mode is required")

    raw_body = bytes(body or b"")
    raw_secret = str(secret or "").encode("utf-8")

    if mode in ("stripe", "stripe_hmac"):
        header = _header_value(headers, "Stripe-Signature").strip()
        if not header:
            raise ValueError("missing Stripe-Signature header")
        timestamp: Optional[str] = None
        candidate: Optional[str] = None
        for part in header.split(","):
            part = part.strip()
            if part.startswith("t="):
                timestamp = part[2:].strip()
            if part.startswith("v1="):
                candidate = part[3:].strip()
        if not timestamp or not candidate:
            raise ValueError("invalid Stripe-Signature header format")
        expected = hmac.new(raw_secret, (timestamp + ".").encode("utf-8") + raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, candidate):
            raise ValueError("stripe signature mismatch")
        return

    if mode in ("github", "github_hmac"):
        header = _header_value(headers, "X-Hub-Signature-256").strip()
        if not header:
            raise ValueError("missing X-Hub-Signature-256 header")
        if not header.startswith("sha256="):
            raise ValueError("invalid GitHub signature format")
        candidate = header[len("sha256=") :].strip()
        expected = hmac.new(raw_secret, raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, candidate):
            raise ValueError("github signature mismatch")
        return

    if mode in ("shopify", "shopify_hmac"):
        header = _header_value(headers, "X-Shopify-Hmac-Sha256").strip()
        if not header:
            raise ValueError("missing X-Shopify-Hmac-Sha256 header")
        digest = hmac.new(raw_secret, raw_body, hashlib.sha256).digest()
        expected = base64.b64encode(digest).decode("utf-8")
        if not hmac.compare_digest(expected.strip(), header.strip()):
            raise ValueError("shopify signature mismatch")
        return

    if mode in ("gitlab", "gitlab_token"):
        header = _header_value(headers, "X-Gitlab-Token").strip()
        if not header:
            raise ValueError("missing X-Gitlab-Token header")
        if not hmac.compare_digest(str(secret or "").strip(), header.strip()):
            raise ValueError("gitlab token mismatch")
        return

    if mode == "custom_hmac_sha256":
        header = _header_value(headers, "X-Signature-SHA256").strip()
        if not header:
            raise ValueError("missing X-Signature-SHA256 header")
        candidate = header
        if candidate.lower().startswith("sha256="):
            candidate = candidate[len("sha256=") :].strip()
        expected = hmac.new(raw_secret, raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, candidate.strip()):
            raise ValueError("custom signature mismatch")
        return

    raise ValueError("unsupported provider/signature mode")

