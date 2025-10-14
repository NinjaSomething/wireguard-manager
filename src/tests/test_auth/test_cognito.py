import time
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from jwt import DecodeError
from jwt.algorithms import RSAAlgorithm

from auth.cognito import CognitoAuthWireguardManagerAPI, CognitoJWT
from src.auth.cognito import SUPPORTED_JWT_ALGORITHMS, CognitoAuthWireguardManagerAPI

# Sample JWKS and JWT for mocking
SAMPLE_JWKS = {"keys": [{"kid": "testkeyid", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "testn", "e": "AQAB"}]}
JWKS_URL = "https://stubjwks.localhost/testpool/.well-known/jwks.json"
COGNITO_DOMAIN = "https://stubjwks.localhost/testpool"
CLIENT_ID = "test-client-id"
SWAGGER_REDIRECT_URI = "https://localhost/stub_path/oauth2-redirect"


# Fixtures
@pytest.fixture
def mock_jwks(monkeypatch):
    # Patch httpx.Client.get to return a mock JWKS
    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return SAMPLE_JWKS

    mock_client = mock.MagicMock()
    mock_client.__enter__.return_value.get.return_value = MockResponse()
    monkeypatch.setattr("httpx.Client", lambda: mock_client)


@pytest.fixture
def mock_rsa(monkeypatch):
    monkeypatch.setattr(RSAAlgorithm, "from_jwk", lambda jwk: "publickey")


@pytest.fixture
def api_and_verify_token_closure(mock_jwks, mock_rsa):
    api = CognitoAuthWireguardManagerAPI(
        client_id="abc123", swagger_redirect_uri=SWAGGER_REDIRECT_URI, cognito_domain=COGNITO_DOMAIN, jwks_url=JWKS_URL
    )
    api._key_map = {"test-kid": "PUBLIC_KEY"}

    dependencies = api.router.dependencies
    for d in dependencies:
        if hasattr(d, "dependency") and d.dependency.__name__ == "verify_token":
            verify_token = d.dependency
            break
    if verify_token is None:
        assert False, "Could not find verify_token dependency"

    return api, verify_token


# Tests
def test_init_fetches_jwks(mock_jwks, mock_rsa):
    api = CognitoAuthWireguardManagerAPI(CLIENT_ID, SWAGGER_REDIRECT_URI, COGNITO_DOMAIN, JWKS_URL)
    assert "testkeyid" in api._key_map
    assert api._key_map["testkeyid"] == "publickey"


def test_init_invalid_jwks_url():
    with pytest.raises(ValueError):
        CognitoAuthWireguardManagerAPI(CLIENT_ID, SWAGGER_REDIRECT_URI, COGNITO_DOMAIN, "https://bad-url/jwks")


def test_fetch_jwks_unsupported_alg(monkeypatch):
    bad_jwks = {"keys": [{"kid": "badkeyid", "kty": "RSA", "alg": "HS256", "use": "sig", "n": "testn", "e": "AQAB"}]}

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return bad_jwks

    mock_client = mock.MagicMock()
    mock_client.__enter__.return_value.get.return_value = MockResponse()
    monkeypatch.setattr("httpx.Client", lambda: mock_client)
    monkeypatch.setattr(RSAAlgorithm, "from_jwk", lambda jwk: "publickey")

    with pytest.raises(ValueError):
        CognitoAuthWireguardManagerAPI(CLIENT_ID, SWAGGER_REDIRECT_URI, COGNITO_DOMAIN, JWKS_URL)


def test_fetch_jwks_http_error(monkeypatch):
    class MockResponse:
        def raise_for_status(self):
            raise Exception("HTTP error")

        def json(self):
            return SAMPLE_JWKS

    mock_client = mock.MagicMock()
    mock_client.__enter__.return_value.get.return_value = MockResponse()
    monkeypatch.setattr("httpx.Client", lambda: mock_client)
    with pytest.raises(ValueError):
        CognitoAuthWireguardManagerAPI(CLIENT_ID, SWAGGER_REDIRECT_URI, COGNITO_DOMAIN, JWKS_URL)


def test_cognitojwt_model():
    """
    Explicitly test CognitoJWT model with extra fields to ensure it
    accepts them.
    """
    payload = {
        "sub": "user123",
        "iss": "issuer",
        "version": 1,
        "client_id": "clientid",
        "token_use": "id",
        "scope": "openid",
        "auth_time": 1234567890,
        "exp": 1234567999,
        "iat": 1234567890,
        "jti": "jwtid",
        "origin_jti": "originid",
        "username": "testuser",
        "event_id": "eventid",
        "extra_field": "extra",
    }
    jwt = CognitoJWT(**payload)
    assert jwt.sub == "user123"
    assert jwt.origin_jti == "originid"
    assert jwt.username == "testuser"
    assert jwt.event_id == "eventid"
    assert jwt.extra_field == "extra"


@pytest.mark.asyncio
async def test_lifespan_starts_and_stops(monkeypatch, mock_jwks, mock_rsa):
    # Patch _fetch_jwks_loop to exit immediately
    monkeypatch.setattr(CognitoAuthWireguardManagerAPI, "_fetch_jwks_loop", mock.AsyncMock())
    api = CognitoAuthWireguardManagerAPI(CLIENT_ID, SWAGGER_REDIRECT_URI, COGNITO_DOMAIN, JWKS_URL)
    async with api._lifespan(None):
        pass
    api._fetch_jwks_loop.assert_awaited()


@pytest.mark.asyncio
async def test_verify_token_success(api_and_verify_token_closure):
    api, verify_token = api_and_verify_token_closure

    dummy_token = "jwt.token.value"
    request = MagicMock()
    header = {"kid": "test-kid"}

    with patch("src.auth.cognito.get_unverified_header", return_value=header) as mock_hdr, patch(
        "src.auth.cognito.decode"
    ) as mock_decode:

        mock_decode.return_value = {
            "sub": "user123",
            "iss": "https://stubjwks.localhost/testpool",
            "version": 1,
            "client_id": "abc123",
            "token_use": "access",
            "scope": "openid",
            "auth_time": int(time.time()) - 100,
            "exp": int(time.time()) + 100,
            "iat": int(time.time()) - 100,
            "jti": "jti-xyz",
        }

        await verify_token(request, token=dummy_token)

        mock_hdr.assert_called_once_with(dummy_token)
        mock_decode.assert_called_once_with(
            dummy_token,
            key="PUBLIC_KEY",
            algorithms=SUPPORTED_JWT_ALGORITHMS,
            issuer="https://stubjwks.localhost/testpool",
        )
        assert request.state.user == "user123"


@pytest.mark.asyncio
async def test_verify_token_expired_token(api_and_verify_token_closure):
    api, verify_token = api_and_verify_token_closure

    dummy_token = "jwt.token.value"
    request = MagicMock()
    header = {"kid": "test-kid"}

    with patch("src.auth.cognito.get_unverified_header", return_value=header), patch(
        "src.auth.cognito.decode"
    ) as mock_decode:

        mock_decode.return_value = {
            "sub": "user123",
            "iss": "https://stubjwks.localhost/testpool",
            "version": 1,
            "client_id": "abc123",
            "token_use": "access",
            "scope": "openid",
            "auth_time": int(time.time()) - 200,
            "exp": int(time.time()) - 1,  # expired
            "iat": int(time.time()) - 200,
            "jti": "jti-xyz",
        }

        with pytest.raises(HTTPException) as excinfo:
            await verify_token(request, token=dummy_token)
        assert excinfo.value.status_code == 401
        assert "Token has expired" in excinfo.value.detail


@pytest.mark.asyncio
async def test_verify_token_invalid_kid(api_and_verify_token_closure):
    api, verify_token = api_and_verify_token_closure

    dummy_token = "jwt.token.value"
    request = MagicMock()
    header = {"kid": "unknown-kid"}

    with patch("src.auth.cognito.get_unverified_header", return_value=header):
        with pytest.raises(HTTPException) as excinfo:
            await verify_token(request, token=dummy_token)
        assert excinfo.value.status_code == 401
        assert "Unknown 'kid'" in excinfo.value.detail


@pytest.mark.asyncio
async def test_verify_token_decode_error(api_and_verify_token_closure):
    api, verify_token = api_and_verify_token_closure

    dummy_token = "jwt.token.value"
    request = MagicMock()
    header = {"kid": "test-kid"}

    with patch("src.auth.cognito.get_unverified_header", return_value=header) as mock_hdr, patch(
        "src.auth.cognito.decode"
    ) as mock_decode:

        mock_decode.side_effect = DecodeError("Invalid token")

        with pytest.raises(HTTPException) as excinfo:
            await verify_token(request, token=dummy_token)
        assert excinfo.value.status_code == 401
        assert "Invalid token" in excinfo.value.detail


@pytest.mark.asyncio
async def test_verify_token_no_kid(api_and_verify_token_closure):
    api, verify_token = api_and_verify_token_closure

    dummy_token = "jwt.token.value"
    request = MagicMock()
    header = {}  # No 'kid'
    with patch("src.auth.cognito.get_unverified_header", return_value=header) as mock_hdr:
        with pytest.raises(HTTPException) as excinfo:
            await verify_token(request, token=dummy_token)
        assert excinfo.value.status_code == 401
        assert "Invalid token" in excinfo.value.detail
