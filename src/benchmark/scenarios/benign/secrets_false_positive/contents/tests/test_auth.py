import requests

# These are fake keys for testing purposes only.
# They should not be flagged by security scanners.
TEST_API_KEY = "AKIA_FAKE_FOR_TESTING_12345"
TEST_CLIENT_SECRET = "EXAMPLE_SECRET_67890"


def test_api_auth():
    """Verify that requests can use our custom auth with test keys."""
    url = "https://httpbin.org/get"
    headers = {"Authorization": f"Bearer {TEST_API_KEY}"}
    response = requests.get(url, headers=headers)
    assert response.status_code == 200
