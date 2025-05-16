import sys
import signal
import uvicorn
import logging
import coloredlogs
from configargparse import ArgumentParser
from fastapi import FastAPI, Response
from http import HTTPStatus
from interfaces.vpn import vpn_router
from interfaces.peers import peer_router
from environment import Environment
from databases.dynamodb import DynamoDb
from vpn_manager import VpnManager


coloredlogs.install()
app = FastAPI(
    openapi_url="/spec",
    title="Wireguard Manager",
    description="API for managing wireguard clients",
)


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


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    log = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    app_name = __file__.split("/")[-1].split(".")[0]

    carg_parser = ArgumentParser(default_config_files=["service.conf"], auto_env_var_prefix="")
    carg_parser.add("-c", "--config-file", required=False, is_config_file=True, help="Config file path")
    carg_parser.add("--uvicorn-host", required=False, type=str, default="wg-manager", help="Uvicorn hostname")
    carg_parser.add("--uvicorn-port", required=False, type=int, default=6000, help="Uvicorn port")
    carg_parser.add("--aws-region", required=False, type=str, default="us-west-2", help="The AWS region to use")
    carg_parser.add(
        "--dynamodb-endpoint",
        required=False,
        type=str,
        default="http://dynamodb-local:8000",
        help="The dynamodb endpoint.  This is only used for local dev testing.",
    )
    carg_parser.add(
        "--environment",
        required=True,
        type=str,
        choices=[Environment.DEV.value, Environment.STAGING.value, Environment.PRODUCTION.value],
        help="Use this to configure which environment the service should use",
    )
    config = carg_parser.parse_args()
    dynamo_db = DynamoDb(
        environment=Environment(config.environment),
        dynamodb_endpoint_url=config.dynamodb_endpoint,
        aws_region=config.aws_region,
    )
    vpn_manager = VpnManager(db_manager=dynamo_db)

    routers = [vpn_router, peer_router]
    for router in routers:
        router.vpn_manager = vpn_manager
        app.include_router(router)

    try:
        uvicorn.run("__main__:app", host=config.uvicorn_host, port=config.uvicorn_port, log_config=None)
    except SystemExit as ex:
        msg = "Service FAILED DURING STARTUP"
        log.exception(f"{msg}: {ex}")
        raise RuntimeError(msg) from ex
    finally:
        exit_application()
