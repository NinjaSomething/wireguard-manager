import jwt
import requests
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from jwt.algorithms import RSAAlgorithm

app = FastAPI()

# These need to be read in from config somehow
REDIRECT_PATH = "oauth2-redirect"  # this is the default FastAPI redirect path
COGNITO_DOMAIN = "https://wireguard-manager-jschaan.auth.us-west-2.amazoncognito.com"
CLIENT_ID = "4foo16sl6fsk38i8kceifphvkq"
REDIRECT_URI_SWAGGER = f"http://localhost:8000/{REDIRECT_PATH}"

COGNITO_REGION = "us-west-2"
USER_POOL_ID = "us-west-2_vOQo9QSoy"  # This changes each time the stack is created :(

# Maybe I just set it the URL (or accepted URLs) when creating the resource server?
RESOURCE_SERVER_ID = (
    "default-m2m-resource-server-aspgxq"  # This is the "API Identifier" you set when creating the resource server
)

jwks_url = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"
jwks = requests.get(jwks_url).json()["keys"]


app = FastAPI(
    title="My API with Cognito",
    swagger_ui_oauth2_redirect_url=f"/{REDIRECT_PATH}",
    swagger_ui_init_oauth={
        "clientId": CLIENT_ID,
        "appName": "My API",
        "scopes": "openid",  # This allows the claim 'cognito:groups' to be included in the id token
        "usePkceWithAuthorizationCodeGrant": True,  # needed if no client secret
        "redirectUri": REDIRECT_URI_SWAGGER,  # make Swagger explicit
    },
)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{COGNITO_DOMAIN}/login", tokenUrl=f"{COGNITO_DOMAIN}/oauth2/token"
)


def decode_cognito_jwt(token: str):
    headers = jwt.get_unverified_header(token)
    kid = headers["kid"]
    key_data = next(k for k in jwks if k["kid"] == kid)
    public_key = RSAAlgorithm.from_jwk(key_data)

    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        # audience=CLIENT_ID,
        issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USER_POOL_ID}",
    )


# Default versions would be just to "return" if no auth is used
# If using the "cognito" auth provider, it could just replace the calls using the ones below
# If using an alternative auth provider, you could write your own versions of these functions
# and use them instead
def is_authenticated(token: str = Depends(oauth2_scheme)):
    try:
        claims = decode_cognito_jwt(token)
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token") from e


def is_admin(claims: str = Depends(is_authenticated)):
    if "cognito:groups" in claims:
        groups = claims["cognito:groups"]
        if "admins" in groups:
            return
    if "scopes" in claims:
        scopes = claims["scopes"].split()
        if f"{RESOURCE_SERVER_ID}/admin" in scopes:
            return
    raise HTTPException(status_code=403, detail="Admins only!")


def is_user(claims: str = Depends(is_authenticated)):
    if "cognito:groups" in claims:
        groups = claims["cognito:groups"]
        if "users" in groups:
            return
    if "scopes" in claims:
        scopes = claims["scopes"].split()
        if f"{RESOURCE_SERVER_ID}/user" in scopes:
            return
    raise HTTPException(status_code=403, detail="Users only!")


@app.get("/protected", dependencies=[Depends(is_authenticated)])
def protected():
    return {"message": "Authenticated!"}


@app.get("/admin_only", dependencies=[Depends(is_admin)])
def admins_only():
    return {"message": "Welcome, admin!"}


@app.get("/user_only", dependencies=[Depends(is_user)])
def users_only():
    return {"message": "Welcome, user!"}


@app.get("/unprotected")
def unprotected():
    return {"message": "No authentication required"}
