import logging
import signal
import sys
from http import HTTPStatus

import coloredlogs
import typer
import uvicorn
from fastapi import Response

from auth import AuthProvider, CognitoAuthWireguardManagerAPI, WireguardManagerAPI
from databases.dynamodb import DynamoDb
from interfaces.peers import peer_router
from interfaces.vpn import vpn_router
from vpn_manager import VpnManager

ROUTERS = [vpn_router, peer_router]

log = logging.getLogger(__name__)
coloredlogs.install()

typer_app = typer.Typer()


def setup_app_routes(app: WireguardManagerAPI) -> None:
    for router in ROUTERS:
        app.include_router(router)

    # Add any root level routes here
    app.add_api_route("/", health, methods=["GET"], tags=["wg-manager"])
    app.add_api_route("/health", health, methods=["GET"], tags=["wg-manager"])


def health() -> Response:
    return Response(status_code=HTTPStatus.OK)


def exit_application():
    log.info("Shutting down the application")
    sys.exit(0)


def signal_handler(signal_num, _frame):
    log.info("Got signal " + str(signal_num) + ", exiting now")
    exit_application()


@typer_app.command()
def main(
    uvicorn_host: str = typer.Option("wg-manager", "--uvicorn-host", help="Uvicorn hostname"),
    uvicorn_port: int = typer.Option(5000, "--uvicorn-port", help="Uvicorn port"),
    aws_region: str = typer.Option("us-west-2", "--aws-region", help="The AWS region"),
    dynamodb_endpoint: str = typer.Option(
        None,
        "--dynamodb-endpoint",
        help="The dynamodb endpoint.  This is only used for local dev testing.  E.g. http://dynamodb-local:8000",
    ),
    environment: str = typer.Option(
        ...,
        "--environment",
        help="Use this to configure which environment the service should use. This is used to determine which database to use.",
    ),
    ssl_keyfile: str = typer.Option(None, "--ssl-keyfile", help="Path to your private key file for SSL"),
    ssl_certfile: str = typer.Option(None, "--ssl-certfile", help="Path to your SSL certificate file"),
    auth_provider: AuthProvider = typer.Option(AuthProvider.NONE, "--auth", help="The authentication provider to use"),
    cognito_client_id: str = typer.Option(
        None,
        "--cognito-client-id",
        help="The Client ID corresponding to the app client in Cognito, required if using Cognito authentication.",
    ),
    cognito_domain: str = typer.Option(
        None, "--cognito-domain", help="The Cognito domain, required if using Cognito authentication."
    ),
    cognito_redirect_uri: str = typer.Option(
        None,
        "--cognito-redirect-uri",
        help=(
            "The redirect URI for Cognito Login Page. This must match the one set in the Cognito App Client settings. "
            "Defaults to http://<uvicorn-host>:<uvicorn-port>/oauth2-redirect"
        ),
    ),
):
    """
    Set network monitoring to true for all sites in environment.
    """
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    match auth_provider:
        case AuthProvider.COGNITO:
            print("Using Cognito authentication.")
            if not cognito_client_id or not cognito_domain:
                print(
                    "ERROR: Parameters cognito_client_id and cognito_domain are required when using Cognito authentication."
                )
                sys.exit(1)
            if not cognito_redirect_uri:
                cognito_redirect_uri = f"http://{uvicorn_host}:{uvicorn_port}/oauth2-redirect"
            app = CognitoAuthWireguardManagerAPI(
                client_id=cognito_client_id, swagger_redirect_uri=cognito_redirect_uri, cognito_domain=cognito_domain
            )
        case AuthProvider.NONE:
            print("No authentication configured.")
            app = WireguardManagerAPI()
        case _:
            raise ValueError(f"Unsupported auth provider: {auth_provider}")
    setup_app_routes(app)

    dynamo_db = DynamoDb(environment=environment, dynamodb_endpoint_url=dynamodb_endpoint, aws_region=aws_region)
    vpn_manager = VpnManager(db_manager=dynamo_db)

    for _router in ROUTERS:
        _router.vpn_manager = vpn_manager

    try:
        print("Starting uvicorn")
        uvicorn.run(
            app,
            host=uvicorn_host,
            port=uvicorn_port,
            log_config=None,
            ssl_keyfile=ssl_keyfile,  # Path to your private key file
            ssl_certfile=ssl_certfile,  # Path to your certificate file
        )
    except SystemExit as ex:
        msg = "Service FAILED DURING STARTUP"
        log.exception(f"{msg}: {ex}")
        raise RuntimeError(msg) from ex
    finally:
        exit_application()


if __name__ == "__main__":
    typer_app()
