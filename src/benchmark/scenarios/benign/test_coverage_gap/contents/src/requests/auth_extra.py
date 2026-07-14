import base64
import hashlib
import hmac


def generate_bearer_token(username, secret_key):
    """
    Generates a secure mock bearer token for the given username using a secret key.
    This logic needs testing to ensure it correctly encodes the username and signature.
    """
    payload = base64.b64encode(username.encode("utf-8")).decode("utf-8")
    signature = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"Bearer {payload}.{signature}"


def validate_bearer_token(token, secret_key):
    """
    Validates a bearer token by checking its signature.
    """
    if not token.startswith("Bearer "):
        return False

    try:
        parts = token[len("Bearer ") :].split(".")
        if len(parts) != 2:
            return False

        payload, signature = parts
        expected_signature = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

        return hmac.compare_digest(signature, expected_signature)
    except Exception:
        return False
