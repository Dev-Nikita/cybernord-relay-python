# `cybernord-relay` (Python)

Minimal signature verification helpers for CyberNord Relay supported providers.

## Usage

```py
from cybernord_relay import verify_signature

# IMPORTANT: pass the raw request body bytes exactly as received.
verify_signature("stripe", secret=STRIPE_SECRET, headers=request.headers, body=raw_body_bytes)
```

