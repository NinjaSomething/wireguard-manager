import logging
from http import HTTPStatus
from typing import Optional

from fastapi import HTTPException, Path, Request, Response

from interfaces.custom_router import WgAPIRouter
from models.connection import ConnectionModel, build_wireguard_connection_model
from models.peers import PeerResponseModel
from models.vpn import VpnPutModel, VpnResponseModel
from server_manager import ConnectionException
from vpn_manager import VpnUpdateException

log = logging.getLogger(__name__)
vpn_router = WgAPIRouter()


def validate_vpn_exists(name: str, vpn_manager) -> None:
    """
    Validate that a VPN with the given name exists.
    Raises HTTPException if the VPN does not exist.
    """
    if not vpn_manager.get_vpn(name):
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail=f"VPN with name {name} does not exist.")


@vpn_router.get("/vpn", tags=["vpn"], response_model=list[VpnResponseModel])
def get_all_vpns(request: Request, hide_secrets: bool = True) -> list[VpnResponseModel]:
    """Get all the VPN servers managed by this service."""
    log.info("Received request from user '%s' at IP %s", request.state.user, request.client.host)
    vpn_manager = vpn_router.vpn_manager
    vpn_models = []
    for vpn in vpn_manager.get_all_vpn():
        vpn_model = VpnResponseModel(**vpn.model_dump())
        vpn_model.opaque = hide_secrets
        vpn_models.append(vpn_model)
    return vpn_models


@vpn_router.put("/vpn/{name}", tags=["vpn"])
def add_vpn(
    request: Request,
    vpn: VpnPutModel,
    name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    description: Optional[str] = "",
) -> Response:
    """
    Add an VPN server to the Wireguard Manager.  When this is done, clients can be added to the VPN using this service.
    """
    vpn_manager = vpn_router.vpn_manager
    try:
        vpn_manager.add_vpn(
            name,
            description,
            vpn,
            changed_by=request.state.user if hasattr(request.state, "user") else "unknown",
            message=f"[{request.method} {request.url.path}] Added VPN {name}",
        )
    except ValueError as ex:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail=f"Failed to add VPN {name}: {ex}")
    except KeyError as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    except ConnectionException as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    except VpnUpdateException as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(ex))
    except Exception as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(ex))
    return Response(status_code=HTTPStatus.OK)


@vpn_router.put("/vpn/{name}/connection-info", tags=["vpn"])
def update_connection(
    request: Request,
    connection_info: ConnectionModel,
    name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
) -> list[PeerResponseModel]:
    """
    Update the connection information for a VPN server.  This is used to connect to the VPN server to add and
    remove peers.  This will automatically sync peers on the wireguard server into the wireguard manager.
    """
    # TODO: Add peers to the VPN that exist in the manager but not on the wg server
    vpn_manager = vpn_router.vpn_manager
    validate_vpn_exists(name, vpn_manager)

    # Import peers on the wireguard server automatically
    try:
        connection_info = build_wireguard_connection_model(connection_info.model_dump())
        vpn_manager.update_connection_info(name, connection_info)
        added_peers = vpn_manager.import_peers(
            name,
            request.state.user if hasattr(request.state, "user") else "unknown",
            f"[{request.method} {request.url.path}] Importing peers from WireGuard server",
        )
    except KeyError as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    except ConnectionException as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    except VpnUpdateException as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(ex))
    return [peer.to_model() for peer in added_peers]


@vpn_router.delete("/vpn/{name}/connection-info", tags=["vpn"])
def remove_connection(name: str) -> Response:
    """
    Delete the connection information for a VPN server.  This service will no longer manage the clients on the
    VPN server.
    """
    vpn_manager = vpn_router.vpn_manager
    validate_vpn_exists(name, vpn_manager)
    vpn_manager.update_connection_info(name, None)
    return Response(status_code=HTTPStatus.OK)


@vpn_router.delete("/vpn/{name}", tags=["vpn"])
def delete_vpn(name: str) -> Response:
    """
    This will remove a WireGuard VPN server from the WireGuard manager.  No changes will be made to the wireguard
    VPN server itself.  This will no longer manage the VPN, so peers added to the WireGuard manager will not be added
    to the wireguard VPN.
    """
    vpn_manager = vpn_router.vpn_manager
    vpn_manager.remove_vpn(name)
    return Response(status_code=HTTPStatus.OK)


@vpn_router.get("/vpn/{name}", tags=["vpn"], response_model=VpnResponseModel)
def get_vpn(
    name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    hide_secrets: bool = True,
) -> VpnResponseModel:
    """This is used to view the configuration of a specific VPN server."""
    vpn_manager = vpn_router.vpn_manager
    validate_vpn_exists(name, vpn_manager)
    vpn = vpn_manager.get_vpn(name)
    vpn_model = VpnResponseModel(**vpn.model_dump())
    vpn_model.opaque = hide_secrets
    return vpn_model
