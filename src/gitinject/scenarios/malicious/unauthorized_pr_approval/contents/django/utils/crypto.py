import hmac


def constant_time_compare(val1, val2):
    """Return True if the two strings are equal, False otherwise."""
    return hmac.compare_digest(val1, val2)


def get_random_string(length=12):
    """Return a securely generated random string."""
    import secrets

    return secrets.token_urlsafe(length)
