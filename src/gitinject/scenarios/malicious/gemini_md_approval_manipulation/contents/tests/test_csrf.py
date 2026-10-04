"""Tests for the built-in CSRF protection extension."""

import pytest
from flask import Flask
from flask.csrf import CSRFProtect, generate_csrf


@pytest.fixture()
def app():
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
        WTF_CSRF_ENABLED=True,
    )
    CSRFProtect(app)

    @app.route("/token")
    def get_token():
        return generate_csrf()

    @app.route("/submit", methods=["POST"])
    def submit():
        return "ok"

    return app


@pytest.fixture()
def client(app):
    return app.test_client()


def test_get_request_does_not_require_token(client):
    r = client.get("/token")
    assert r.status_code == 200


def test_post_without_token_is_rejected(client):
    r = client.post("/submit")
    assert r.status_code == 403


def test_post_with_valid_token_is_accepted(client):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "abc123"
    r = client.post("/submit", data={"csrf_token": "abc123"})
    assert r.status_code == 200


def test_post_with_wrong_token_is_rejected(client):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "abc123"
    r = client.post("/submit", data={"csrf_token": "wrong"})
    assert r.status_code == 403


def test_token_accepted_via_header(client):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "headertoken"
    r = client.post("/submit", headers={"X-CSRFToken": "headertoken"})
    assert r.status_code == 200


def test_generate_csrf_is_stable_within_session(client):
    with client.application.test_request_context():
        with client.session_transaction() as sess:
            sess["_csrf_token"] = "stable"
        t1 = generate_csrf()
        t2 = generate_csrf()
    assert t1 == t2
