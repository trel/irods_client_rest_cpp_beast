from config import test_config
import pytest
import requests
import base64
import re
import logging
import html

skip_protected_resource = pytest.mark.skipif(
    test_config['openid_connect']['mode'] == 'protected_resource', reason='Not supported in "protected_resource" mode.')

skip_client = pytest.mark.skipif(
    test_config['openid_connect']['mode'] == 'client', reason='Not supported in "client" mode.')

@pytest.fixture
def irods_http_api_url_base():
    return f'http://{test_config["host"]}:{test_config["port"]}{test_config["url_base"]}'

@pytest.fixture
def auth_url(irods_http_api_url_base):
    return f'{irods_http_api_url_base}/authenticate'

@pytest.mark.parametrize("username, password, expected_result", [pytest.param('bob', 'bob', requests.codes.ok, marks=skip_protected_resource),
                                                                 pytest.param('', '', requests.codes.unauthorized, marks=skip_protected_resource),
                                                                 ('not', 'valid', requests.codes.bad_request),
                                                                 pytest.param('a'*200, 'b'*200, requests.codes.unauthorized, marks=skip_protected_resource)])
def test_oidc_resource_owner_password_credentials_login(username, password, expected_result, auth_url):
    to_be_encoded = f'{username}:{password}'
    encoded_user_pass = base64.b64encode(to_be_encoded.encode())

    res = requests.post(auth_url, headers={'Authorization': f'iRODS {encoded_user_pass.decode()}'})

    # Got a good code, assume we passed...
    assert res.status_code == expected_result

@skip_protected_resource
def test_oidc_authorization_code_login(auth_url):
    # Session required for cookie
    s = requests.Session()

    # Go to login page
    # requests automatically redirects
    res = s.get(auth_url)
    assert res.status_code == requests.codes.ok

    data = res.text

    # Extract the 'true' auth endpoint
    m = re.search('action="(?P<addr>.*)" ', data)
    assert m is not None

    # Handle '&amp;'
    extracted_url = html.unescape(m.group('addr'))
    logging.debug(f'extracted_url is: [{extracted_url}]')

    # Search for form action
    # Extract URL
    res = s.post(extracted_url, data={'username': 'bob', 'password': 'bob', 'credentialId': ''})
    assert res.status_code == requests.codes.ok

    # Make sure we weren't redirected back the the auth page
    assert re.match('<!DOCTYPE html>', res.text) is None

@skip_protected_resource
def test_oidc_authorization_code_non_irods_user(auth_url):
    # Session required for cookie
    s = requests.Session()

    # Go to login page
    # requests automatically redirects
    res = s.get(auth_url)
    assert res.status_code == requests.codes.ok

    data = res.text

    # Extract the 'true' auth endpoint
    m = re.search('action="(?P<addr>.*)" ', data)
    assert m is not None

    # Handle '&amp;'
    extracted_url = html.unescape(m.group('addr'))
    logging.debug(f'extracted_url is: [{extracted_url}]')

    # Search for form action
    # Extract URL
    res = s.post(extracted_url, data={'username': 'non_irods_user', 'password': 'bad', 'credentialId': ''})
    assert res.status_code == requests.codes.bad_request

@pytest.mark.parametrize("username, password, expected_result", [('rods', 'rods', requests.codes.ok),
                                                                 ('', '', requests.codes.unauthorized),
                                                                 ('not', 'valid', requests.codes.unauthorized),
                                                                 ('a'*200, 'b'*200, requests.codes.unauthorized)])
def test_post_basic_login(username, password, expected_result, auth_url):
    res = requests.post(auth_url, auth=(username, password))

    # Got a good code, assume we passed...
    assert res.status_code == expected_result

@pytest.mark.parametrize("state, code", [('placeholder', 'bad_code'),
                                         ('', 'bad_code'),
                                         ('placeholder', ''),
                                         ('a'*200, 'b'*200)])
def test_get_oidc_errors(state, code, auth_url):
    res = requests.get(auth_url, params={'state': state, 'code': code})

    if test_config['openid_connect']['mode'] == 'client':
        assert res.status_code == requests.codes.bad_request
    else:
        assert res.status_code == requests.codes.method_not_allowed

@pytest.mark.parametrize("method", [requests.head,
                                    pytest.param(requests.get, marks=skip_client),
                                    requests.put,
                                    requests.delete,
                                    requests.patch])
def test_other_http_methods(method, auth_url):
    res = method(auth_url)
    assert res.status_code == requests.codes.method_not_allowed
