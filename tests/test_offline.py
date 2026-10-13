"""Offline tests for the generic Execute API Request operation."""

import pytest

from fortiflex import operations as ops
from connectors.core.connector import ConnectorError

PATH = '/ES/api/fortiflex/v2/programs/list'


def test_get_sends_the_bearer_token(fake, config, info):
    out = ops.execute_api_request(config, {'endpoint': PATH}, info)
    assert out['method'] == 'GET'
    assert fake.seen[-1]['auth'] == 'Bearer good-token'


def test_post_sends_a_body_given_as_string_or_dict(fake, config, info):
    out = ops.execute_api_request(config, {'endpoint': PATH, 'method': 'post',
                                           'request_body': '{"a": 1}'}, info)
    assert out['body'] == {'a': 1}
    out = ops.execute_api_request(config, {'endpoint': 'ES/api/x', 'method': 'PUT',
                                           'request_body': {'b': 2}}, info)
    assert out['body'] == {'b': 2} and out['path'] == '/ES/api/x'


def test_delete_and_query_params(fake, config, info):
    out = ops.execute_api_request(config, {'endpoint': PATH, 'method': 'DELETE',
                                           'query_params': {'q': 'v'}}, info)
    assert out['method'] == 'DELETE' and out['path'].endswith('?q=v')


def test_blank_json_means_none(fake, config, info):
    ops.execute_api_request(config, {'endpoint': PATH, 'method': 'POST',
                                     'request_body': '', 'query_params': {}}, info)
    assert fake.seen[-1]['body'] is None


def test_auth_failure_is_surfaced(fake, config, info):
    fake.token = 'rotated'
    with pytest.raises(ConnectorError, match='HTTP 401'):
        ops.execute_api_request(config, {'endpoint': PATH}, info)


def test_server_error_is_surfaced(fake, config, info):
    with pytest.raises(ConnectorError, match='HTTP 404'):
        ops.execute_api_request(config, {'endpoint': '/nope'}, info)


@pytest.mark.parametrize('endpoint', [
    'https://evil.example.com/x', 'http://evil.example.com/x', '//evil.example.com/x',
    'ftp://x/y', '/ES/../etc', '/ES/%2e%2e/etc', '/ES/%252e%252e/etc',
    '/ES/%25252e%25252e/etc', '/ES/..%5cetc', '/ES\\etc'])
def test_refuses_anything_that_could_send_the_token_elsewhere(fake, config, info, endpoint):
    with pytest.raises(ConnectorError, match='path on the configured server'):
        ops.execute_api_request(config, {'endpoint': endpoint}, info)
    assert fake.seen == []


def test_validates_input(fake, config, info):
    with pytest.raises(ConnectorError, match='Endpoint is required'):
        ops.execute_api_request(config, {}, info)
    with pytest.raises(ConnectorError, match='Method must be'):
        ops.execute_api_request(config, {'endpoint': PATH, 'method': 'TRACE'}, info)
    with pytest.raises(ConnectorError, match='valid JSON'):
        ops.execute_api_request(config, {'endpoint': PATH, 'request_body': '{nope'}, info)
    with pytest.raises(ConnectorError, match='JSON object'):
        ops.execute_api_request(config, {'endpoint': PATH, 'query_params': '[1]'}, info)


def test_operation_is_registered():
    assert ops.operations['execute_api_request'] is ops.execute_api_request
