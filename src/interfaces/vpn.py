from fastapi import Response, HTTPException
from http import HTTPStatus
from typing import Optional

from setuptools.windows_support import hide_file

from interfaces.custom_router import WgAPIRouter
from models.vpn import VpnModel, VpnPutRequestModel
from models.ssh import SshConnectionModel
from vpn_manager import VpnUpdateException
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


@vpn_router.get("/vpn", tags=["vpn"], response_model=list[VpnModel])
def get_all_vpns(hide_secrets: bool = True) -> list[VpnModel]:
    """Get all the VPN servers managed by this service."""
    vpn_manager = vpn_router.vpn_manager
    vpn_models = [vpn.to_model() for vpn in vpn_manager.get_all_vpn()]
    for vpn_model in vpn_models:
        vpn_model.opaque = hide_secrets
    return vpn_models


@vpn_router.put("/vpn/{name}", tags=["vpn"])
def add_vpn(name: str, vpn: VpnPutRequestModel, description: Optional[str] = "") -> Response:
    """
    Add an existing VPN to the Wireguard Manager.  When this is done, clients can be added to the VPN using this service.
    """
    vpn_manager = vpn_router.vpn_manager
    try:
        vpn_manager.add_vpn(name, description, vpn)
        if vpn.ssh_connection_info:
            #  Keep the manager aligned with the wireguard server.  Import existing peers.
            try:
                vpn_manager.import_peers(name)
            except VpnUpdateException as ex:
                raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(ex))
    except ValueError as ex:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail=f"Failed to add VPN {name}: {ex}")
    except KeyError as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    return Response(status_code=HTTPStatus.OK)


@vpn_router.put("/vpn/{name}/ssh-connection-info", tags=["vpn"])
def update_ssh(name: str, ssh_connection_info: SshConnectionModel) -> Response:
    """
    Update the SSH connection information for a VPN server.  This is used to connect to the VPN server to add and
    remove peers.
    """
    # TODO: Add peers to the VPN that exist in the manager but not on the wg server
    vpn_manager = vpn_router.vpn_manager
    validate_vpn_exists(name, vpn_manager)
    vpn = vpn_manager.get_vpn(name)
    vpn.ssh_connection_info = ssh_connection_info
    return Response(status_code=HTTPStatus.OK)


@vpn_router.delete("/vpn/{name}/ssh-connection-info", tags=["vpn"])
def remove_ssh(name: str) -> Response:
    """
    Delete the SSH connection information for a VPN server.  This service will no longer manage the clients on the VPN server.
    """
    vpn_manager = vpn_router.vpn_manager
    validate_vpn_exists(name, vpn_manager)
    vpn = vpn_manager.get_vpn(name)
    vpn.ssh_connection_info = None
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


@vpn_router.get("/vpn/{name}", tags=["vpn"], response_model=VpnModel)
def get_vpn(name: str, hide_secrets: bool = True) -> VpnModel:
    vpn_manager = vpn_router.vpn_manager
    validate_vpn_exists(name, vpn_manager)
    vpn = vpn_manager.get_vpn(name)
    vpn_model = vpn.to_model()
    vpn_model.opaque = hide_secrets
    return vpn_model
