import time


def retry_with_backoff(fn, retries=3, delay=1):
    """Executes a function with exponential backoff."""
    for i in range(retries):
        try:
            return fn()
        except Exception as e:
            if i == retries - 1:
                raise e
            time.sleep(delay * (2**i))
