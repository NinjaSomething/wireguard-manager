import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jwt import decode, get_unverified_header
from jwt.algorithms import RSAAlgorithm
from pydantic import BaseModel

from auth.unauthenticated import WireguardManagerAPI

log = logging.getLogger(__name__)

SUPPORTED_JWT_ALGORITHMS = ["RS256"]
JWKS_FETCH_INTERVAL = 3600  # seconds


class CognitoJWT(BaseModel):
    """
    Schema for the JWT returned by AWS Cognito. The fields vary slightly
    between user and M2M tokens, so those fields are optional.
    """

    sub: str
    iss: str
    version: int
    client_id: str
    token_use: str
    scope: str
    auth_time: int
    exp: int
    iat: int
    jti: str
    origin_jti: Optional[str] = None
    username: Optional[str] = None
    event_id: Optional[str] = None

    class Config:
        extra = "allow"


class CognitoAuthWireguardManagerAPI(WireguardManagerAPI):
    """
    AWS Cognito authentication for Wireguard API.
    """

    def __init__(self, client_id: str, swagger_redirect_uri: str, cognito_domain: str, jwks_url: str):
        """
        Instantiate the FastAPI app using AWS Cognito for
        authentication. Includes support for user login on the Swagger
        UI via PKCE.
        """
        self._key_map = {}
        self._jwks_url = jwks_url
        oauth2_scheme = OAuth2AuthorizationCodeBearer(
            authorizationUrl=f"{cognito_domain}/login", tokenUrl=f"{cognito_domain}/oauth2/token"
        )

        if not jwks_url.endswith("/.well-known/jwks.json"):
            raise ValueError("The jwks_url must be the full URL to the JWKS, ending in /.well-known/jwks.json")
        issuer_url = jwks_url.replace("/.well-known/jwks.json", "")

        # Fetch the JWKS and start a background task to refresh it periodically in case keys are rotated
        self._fetch_jwks(jwks_url)

        # Create a dependency to verify the token on each request using the cached keys from the key map
        async def verify_token(request: Request, token: str = Depends(oauth2_scheme)):
            # Decode the header to identify the key ID (kid) used to sign the token
            try:
                header = get_unverified_header(token)
                key_id = header["kid"]
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid token: {e}",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            issuer_public_signing_key = self._key_map.get(key_id, None)
            if issuer_public_signing_key is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: Unknown 'kid'",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Verify the token signature and claims
            try:
                decoded_token = decode(
                    token, key=issuer_public_signing_key, algorithms=SUPPORTED_JWT_ALGORITHMS, issuer=issuer_url
                )
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid token: {e}",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            token_payload = CognitoJWT(**decoded_token)

            # Check token expiration
            if token_payload.exp < time.time():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: Token has expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # Pass in the user information in the request state for use in endpoints
            request.state.user = token_payload.sub

        super().__init__(
            dependencies=[Depends(verify_token)],
            swagger_ui_oauth2_redirect_url="/oauth2-redirect",
            swagger_ui_init_oauth={
                "clientId": client_id,
                "appName": "Wireguard Manager",
                "scopes": "openid",
                "usePkceWithAuthorizationCodeGrant": True,
                "redirectUri": swagger_redirect_uri,
            },
            lifespan=self._lifespan,
        )

    def _fetch_jwks(self, jwks_url: str):
        """
        Fetch the JSON Web Key Set (JWKS) from the specified URL.
        """
        log.debug(f"Fetching JWKS from {jwks_url}")
        try:
            with httpx.Client() as client:
                response = client.get(jwks_url)
                response.raise_for_status()
                jwks_json = response.json()
        except Exception as e:
            raise ValueError(f"Failed to fetch JWKS from {jwks_url}") from e

        jwks = {key["kid"]: key for key in jwks_json["keys"]}

        key_map = {}
        for key in jwks.values():
            if key["alg"] == "RS256":  # Cognito only appears to use RSA256 keys currently
                key_map[key["kid"]] = RSAAlgorithm.from_jwk(key)
            else:
                raise ValueError(f"Unsupported key type/algorithm in JWKS. Type: {key['kty']}, Algorithm: {key['alg']}")
        self._key_map = key_map
        log.debug(f"Fetched {len(key_map)} keys from JWKS")

    async def _fetch_jwks_loop(self, jwks_url: str, stop_event: asyncio.Event):
        """
        Background task to periodically fetch the JWKS to refresh keys
        in case of rotation. If the app is shutting down, the task
        will exit immediately.
        """
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=JWKS_FETCH_INTERVAL)
            except asyncio.TimeoutError:
                try:
                    self._fetch_jwks(jwks_url)
                except Exception as e:
                    log.exception(f"Failed to refresh JWKS: {e}")

    @asynccontextmanager
    async def _lifespan(self, _):
        """
        This is the FastAPI lifespan handler. Start the background task
        to periodically refresh the JWKS on startup, and stop it on
        shutdown.

        The FastAPI object itself is passed as the first argument, it is
        unused.
        """
        stop_event = asyncio.Event()
        task = asyncio.create_task(self._fetch_jwks_loop(self._jwks_url, stop_event))
        try:
            yield
        finally:
            stop_event.set()
            await task
