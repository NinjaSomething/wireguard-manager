from fastapi import Depends
from fastapi.security import OAuth2AuthorizationCodeBearer

from auth.unauthenticated import WireguardManagerAPI


class CognitoAuthWireguardManagerAPI(WireguardManagerAPI):
    """
    AWS Cognito authentication for Wireguard API.
    """

    def __init__(self, client_id: str, swagger_redirect_uri: str, cognito_domain: str):
        """
        Instantiate the FastAPI app using AWS Cognito for
        authentication. Includes support for user login on the Swagger
        UI via PKCE.
        """
        oauth2_scheme = OAuth2AuthorizationCodeBearer(
            authorizationUrl=f"{cognito_domain}/login", tokenUrl=f"{cognito_domain}/oauth2/token"
        )

        super().__init__(
            dependencies=[Depends(oauth2_scheme)],
            swagger_ui_oauth2_redirect_url="/oauth2-redirect",
            swagger_ui_init_oauth={
                "clientId": client_id,
                "appName": "Wireguard Manager",
                "scopes": "openid",
                "usePkceWithAuthorizationCodeGrant": True,
                "redirectUri": swagger_redirect_uri,
            },
        )
