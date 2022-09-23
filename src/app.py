import sys
import signal
import uvicorn
import logging
import coloredlogs
from configargparse import ArgumentParser
from fastapi import FastAPI, Response
from http import HTTPStatus
from interfaces.vpn import vpn_router
from databases.postgres import PgStuff
from version import SERVICE_VERSION


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


def init_service(pg):
    # Ensure the database tables exist
    pg.tables_exist()


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
    carg_parser.add("--pg-host", required=True, type=str, help="PostGRES hostname")
    carg_parser.add("--pg-port", required=False, type=int, default=5432, help="PostGRES port")
    carg_parser.add("--pg-username", required=False, type=str, help="PostGRES username")
    carg_parser.add("--pg-password", required=False, type=str, help="PostGRES password")
    carg_parser.add("--uvicorn-host", required=False, type=str, default="wg-manager", help="Uvicorn hostname")
    carg_parser.add("--uvicorn-port", required=False, type=int, default=6000, help="Uvicorn port")
    carg_parser.add(
        "--ssh-key-path",
        required=False,
        type=str,
        default="/opt/wireguard-manager/sshkeys",
        help="The path the the ssh keys for the wireguard servers",
    )
    config = carg_parser.parse_args()

    vpn_router.ssh_key_path = config.ssh_key_path
    vpn_router.db_interface = PgStuff(
        host=config.pg_host, port=config.pg_port, user=config.pg_username, password=config.pg_password
    )
    routers = [vpn_router]
    [app.include_router(router) for router in routers]

    init_service(vpn_router.db_interface)
    try:
        uvicorn.run("__main__:app", host=config.uvicorn_host, port=config.uvicorn_port, log_config=None)
    except SystemExit as ex:
        msg = "Service FAILED DURING STARTUP"
        log.exception(f"{msg}: {ex}")
        raise RuntimeError(msg) from ex
    finally:
        exit_application()
