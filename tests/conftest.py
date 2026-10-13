"""Test fixtures for the FortiFlex connector.

Stubs the FortiSOAR connector SDK, registers the hyphenated connector
directory as the package ``fortiflex``, and serves a fake FortiFlex API on a
loopback ephemeral port using only the standard library.
"""

import json
import logging
import sys
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

CONNECTOR_DIR = Path(__file__).resolve().parent.parent / 'fortinet-fortiflex'

if 'connectors' not in sys.modules:
    _connectors = types.ModuleType('connectors')
    _connectors.__path__ = []
    _core = types.ModuleType('connectors.core')
    _core.__path__ = []
    _connector_mod = types.ModuleType('connectors.core.connector')
    _utils_mod = types.ModuleType('connectors.core.utils')

    class ConnectorError(Exception):
        pass

    class Connector:
        pass

    _connector_mod.ConnectorError = ConnectorError
    _connector_mod.get_logger = logging.getLogger
    _connector_mod.Connector = Connector
    _utils_mod.update_connnector_config = lambda *a, **k: None
    _core.connector = _connector_mod
    _core.utils = _utils_mod
    _connectors.core = _core
    sys.modules['connectors'] = _connectors
    sys.modules['connectors.core'] = _core
    sys.modules['connectors.core.connector'] = _connector_mod
    sys.modules['connectors.core.utils'] = _utils_mod

if 'fortiflex' not in sys.modules:
    _pkg = types.ModuleType('fortiflex')
    _pkg.__path__ = [str(CONNECTOR_DIR)]
    sys.modules['fortiflex'] = _pkg

from fortiflex import fortiflex_api_auth  # noqa: E402


class FakeState:
    def __init__(self):
        self.port = 0
        self.token = 'good-token'
        self.seen = []


STATE = FakeState()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        STATE.seen.append({'method': self.command, 'path': self.path, 'body': body,
                           'auth': self.headers.get('Authorization')})
        if self.headers.get('Authorization') != 'Bearer ' + STATE.token:
            self._send(401, {'error': 'unauthorized'})
        elif self.path.startswith('/ES/api/'):
            self._send(200, {'method': self.command, 'path': self.path, 'body': body})
        else:
            self._send(404, {'error': 'not found'})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


@pytest.fixture()
def fake(monkeypatch):
    STATE.seen = []
    STATE.token = 'good-token'
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    STATE.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    real_init = fortiflex_api_auth.FortiFlex.__init__

    def loopback_init(self, config):
        real_init(self, config)
        self.host = config['server']  # the connector forces https; the fake speaks http

    monkeypatch.setattr(fortiflex_api_auth.FortiFlex, '__init__', loopback_init)
    yield STATE
    server.shutdown()
    server.server_close()


@pytest.fixture()
def config(fake):
    return {
        'server': 'http://127.0.0.1:{0}'.format(STATE.port),
        'username': 'u', 'password': 'p', 'client_id': 'c',
        'verify_ssl': False,
        'accessToken': STATE.token,
        'expiresOn': time.time() + 3600,
        'config_id': 'x',
    }


@pytest.fixture()
def info():
    return {'connector_name': 'fortinet-fortiflex', 'connector_version': '1.1.0'}
