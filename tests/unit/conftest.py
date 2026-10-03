import socket
import time

import pytest


@pytest.fixture(autouse=True)
def no_external_calls_or_sleeps(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError("Unit tests must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(socket.socket, "connect_ex", reject)
    monkeypatch.setattr(time, "sleep", lambda _: None)
