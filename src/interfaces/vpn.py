from fastapi import Response, HTTPException
from http import HTTPStatus
from typing import Optional

from interfaces.custom_router import WgAPIRouter
from models.vpn import VpnResponseModel, VpnPutModel
from models.connection import build_connection_model, ConnectionModel
from models.peers import PeerResponseModel
from vpn_manager import VpnUpdateException
from server_manager import ConnectionException
import logging


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
def get_all_vpns(hide_secrets: bool = True) -> list[VpnResponseModel]:
    """Get all the VPN servers managed by this service."""
    vpn_manager = vpn_router.vpn_manager
    vpn_models = [VpnResponseModel(**vpn.to_model().model_dump()) for vpn in vpn_manager.get_all_vpn()]
    for vpn_model in vpn_models:
        vpn_model.opaque = hide_secrets
    return vpn_models


@vpn_router.put("/vpn/{name}", tags=["vpn"])
def add_vpn(name: str, vpn: VpnPutModel, description: Optional[str] = "") -> Response:
    """
    Add an existing VPN to the Wireguard Manager.  When this is done, clients can be added to the VPN using this service.
    """
    vpn_manager = vpn_router.vpn_manager
    try:
        vpn_manager.add_vpn(name, description, vpn)
        if vpn.connection_info:
            #  Keep the manager aligned with the wireguard server.  Import existing peers.
            try:
                vpn_manager.import_peers(name)
            except VpnUpdateException as ex:
                raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(ex))
    except ValueError as ex:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail=f"Failed to add VPN {name}: {ex}")
    except KeyError as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    except ConnectionException as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    return Response(status_code=HTTPStatus.OK)


@vpn_router.put("/vpn/{name}/connection-info", tags=["vpn"])
def update_ssh(name: str, connection_info: ConnectionModel) -> list[PeerResponseModel]:
    """
    Update the SSH connection information for a VPN server.  This is used to connect to the VPN server to add and
    remove peers.  This will automatically sync peers on the wireguard server into the wireguard manager.
    """
    # TODO: Add peers to the VPN that exist in the manager but not on the wg server
    vpn_manager = vpn_router.vpn_manager
    validate_vpn_exists(name, vpn_manager)
    vpn = vpn_manager.get_vpn(name)

    # Import peers on the wireguard server automatically
    try:
        vpn.connection_info = build_connection_model(connection_info.model_dump())
        added_peers = vpn_manager.import_peers(name)
    except KeyError as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    except ConnectionException as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    except VpnUpdateException as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(ex))
    return [peer.to_model() for peer in added_peers]


@vpn_router.delete("/vpn/{name}/connection-info", tags=["vpn"])
def remove_ssh(name: str) -> Response:
    """
    Delete the SSH connection information for a VPN server.  This service will no longer manage the clients on the VPN server.
    """
    vpn_manager = vpn_router.vpn_manager
    validate_vpn_exists(name, vpn_manager)
    vpn = vpn_manager.get_vpn(name)
    vpn.connection_info = None
    return Response(status_code=HTTPStatus.OK)


@vpn_router.delete("/vpn/{name}", tags=["vpn"])
def delete_vpn(name: str) -> Response:
    """
    This will remove a WireGuard VPN server from the WireGuard manager.  No changes will be made to the wireguard
    network itself.  This service will no longer manage the VPN.
    """
    vpn_manager = vpn_router.vpn_manager
    vpn_manager.remove_vpn(name)
    return Response(status_code=HTTPStatus.OK)


@vpn_router.get("/vpn/{name}", tags=["vpn"], response_model=VpnResponseModel)
def get_vpn(name: str, hide_secrets: bool = True) -> VpnResponseModel:
    vpn_manager = vpn_router.vpn_manager
    validate_vpn_exists(name, vpn_manager)
    vpn = vpn_manager.get_vpn(name)
    vpn_model = VpnResponseModel(**vpn.to_model().model_dump())
    vpn_model.opaque = hide_secrets
    return vpn_model
