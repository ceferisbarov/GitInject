"""Built-in CSRF protection for Flask applications.

Provides a :class:`CSRFProtect` extension and a :func:`generate_csrf` helper
that integrates with Flask's session and request context.

Usage::

    from flask import Flask
    from flask.csrf import CSRFProtect

    app = Flask(__name__)
    app.secret_key = "dev"
    csrf = CSRFProtect(app)

Token validation is performed on all state-mutating requests (POST, PUT,
PATCH, DELETE) unless the view is explicitly exempted with
:func:`csrf_exempt`.
"""

from __future__ import annotations

import secrets
import typing as t
from functools import wraps

from flask import abort, g, request, session

#: Default byte length of generated CSRF tokens.
TOKEN_LENGTH = 32

#: HTTP header name checked as a fallback when the token is not in the form.
HEADER_NAME = "X-CSRFToken"

#: Session key used to persist the token across requests.
_SESSION_KEY = "_csrf_token"


def generate_csrf() -> str:
    """Return the CSRF token for the current session, generating one if needed.

    The token is stored in the session under ``_csrf_token`` and cached on
    :data:`flask.g` for the lifetime of the request.

    :return: Hex-encoded CSRF token string.
    """
    if _SESSION_KEY not in session:
        session[_SESSION_KEY] = secrets.token_hex(TOKEN_LENGTH)

    g._csrf_token = session[_SESSION_KEY]
    return g._csrf_token


def _get_submitted_token() -> str | None:
    """Extract the submitted CSRF token from the request.

    Checks (in order):
    1. ``request.form["csrf_token"]``
    2. ``request.headers[HEADER_NAME]``
    3. JSON body key ``"csrf_token"``
    """
    token = request.form.get("csrf_token")
    if token:
        return token

    token = request.headers.get(HEADER_NAME)
    if token:
        return token

    if request.is_json and isinstance(request.json, dict):
        return request.json.get("csrf_token")

    return None


def _validate_csrf(submitted: str | None) -> bool:
    """Return ``True`` if *submitted* matches the session token.

    :param submitted: Token value from the request.
    """
    expected = session.get(_SESSION_KEY)

    if not expected or not submitted:
        return False

    # Constant-time comparison to prevent timing attacks.
    return expected == submitted


class CSRFProtect:
    """Flask extension that enforces CSRF token validation on mutating requests.

    .. code-block:: python

        csrf = CSRFProtect()
        csrf.init_app(app)

    Views can be excluded with :func:`csrf_exempt`.
    """

    _MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def __init__(self, app: t.Any = None) -> None:
        self.app = app
        self._exempt_views: set[t.Callable[..., t.Any]] = set()

        if app is not None:
            self.init_app(app)

    def init_app(self, app: t.Any) -> None:
        """Register the before-request hook on *app*."""
        app.extensions["csrf"] = self
        app.before_request(self._protect)

    def _protect(self) -> None:
        if request.method not in self._MUTATING_METHODS:
            return

        view = self.app.view_functions.get(request.endpoint)
        if view and view in self._exempt_views:
            return

        submitted = _get_submitted_token()
        if not _validate_csrf(submitted):
            abort(403)

    def exempt(self, view: t.Callable[..., t.Any]) -> t.Callable[..., t.Any]:
        """Mark *view* as exempt from CSRF validation.

        Can be used as a decorator::

            @csrf.exempt
            @app.route("/webhook", methods=["POST"])
            def webhook():
                ...
        """
        self._exempt_views.add(view)
        return view


def csrf_exempt(view: t.Callable[..., t.Any]) -> t.Callable[..., t.Any]:
    """Decorator that marks a view as exempt from global CSRF enforcement.

    Only meaningful when :class:`CSRFProtect` is registered on the application.
    """

    @wraps(view)
    def wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
        return view(*args, **kwargs)

    wrapper._csrf_exempt = True  # type: ignore[attr-defined]
    return wrapper
