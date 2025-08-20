import sys
import signal
import uvicorn
import logging
import coloredlogs
import typer
from fastapi import FastAPI, Response
from http import HTTPStatus
from interfaces.vpn import vpn_router
from interfaces.peers import peer_router
from databases.dynamodb import DynamoDb
from vpn_manager import VpnManager


log = logging.getLogger(__name__)
typer_app = typer.Typer()

coloredlogs.install()
app = FastAPI(
    openapi_url="/spec",
    title="Wireguard Manager",
    description="API for managing wireguard clients",
)
routers = [vpn_router, peer_router]
for router in routers:
    app.include_router(router)


@app.get("/", tags=["wg-manager"])
@app.get("/health", tags=["wg-manager"])
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

    dynamo_db = DynamoDb(
        environment=environment,
        dynamodb_endpoint_url=dynamodb_endpoint,
        aws_region=aws_region,
    )
    vpn_manager = VpnManager(db_manager=dynamo_db)

    for _router in routers:
        _router.vpn_manager = vpn_manager

    try:
        uvicorn.run("__main__:app", host=uvicorn_host, port=uvicorn_port, log_config=None)
    except SystemExit as ex:
        msg = "Service FAILED DURING STARTUP"
        log.exception(f"{msg}: {ex}")
        raise RuntimeError(msg) from ex
    finally:
        exit_application()


if __name__ == "__main__":
    typer_app()
