from fastapi import APIRouter, Response, HTTPException
from http import HTTPStatus
from srv_manager.ssh import dump_interface_config
from models.vpn import VpnPostRequestModel, VpnDbModel, VpnPutRequestModel, PeerDbModel


class VpnAPIRouter(APIRouter):
    """
    An extension to the base FastAPI router, that adds a params_manager property. It is expected that you set
    this property at app startup, so that the endpoints within the router will have access to the ParamsManager.
    """

    def __init__(self):
        super().__init__()
        self._ssh_key_path = None
        self._db_interface = None

    @property
    def ssh_key_path(self):
        if self._ssh_key_path is None:
            raise Exception("ssh_key_path has not been configured in APIRouter, set it before use")
        else:
            return self._ssh_key_path

    @ssh_key_path.setter
    def ssh_key_path(self, value: str):
        self._ssh_key_path = value

    @property
    def db_interface(self):
        if self._db_interface is None:
            raise Exception("db_interface has not been configured in APIRouter, set it before use")
        else:
            return self._db_interface

    @db_interface.setter
    def db_interface(self, value: str):
        self._db_interface = value


vpn_router = VpnAPIRouter()


@vpn_router.post("/vpn", tags=["wg-manager"])
def import_vpn(vpn: VpnPostRequestModel) -> Response:
    """
    This will import a WireGuard interface config into the WireGuard manager.  When this is done, clients can be
    added to the VPN using this service.
    """
    existing_iface = vpn_router.db_interface.get_interface(vpn.name)
    if existing_iface:
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail=f"A WireGuard interface using this configuration has already been " f"imported: {vpn.name}",
        )

    wg_config_data = dump_interface_config(vpn.wg_interface, vpn.ssh_connection_info, vpn_router.ssh_key_path)
    if isinstance(wg_config_data, str):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Unable to import WireGuard server {vpn.name} via " f"SSH: {wg_config_data}",
        )
    new_vpn = VpnDbModel(
        interface=vpn.wg_interface,
        public_key=wg_config_data.public_key,
        listen_port=wg_config_data.listen_port,
        wg_ip_address=vpn.wg_ip_address,
        private_key=wg_config_data.private_key,
        ssh_connection_info=vpn.ssh_connection_info,
        name=vpn.name,
        description=vpn.description,
    )
    for peer in wg_config_data.peers:
        new_vpn.peers.append(
            PeerDbModel(
                wg_ip_address=peer.wg_ip_address,
                public_key=peer.public_key,
                preshared_key=peer.preshared_key,
                persistent_keepalive=peer.persistent_keepalive,
            )
        )

    result = vpn_router.db_interface.add_interface(new_vpn)
    return Response(status_code=HTTPStatus.OK)


@vpn_router.put("/vpn/{name}", tags=["wg-manager"])
def update_vpn(vpn: VpnPutRequestModel, name: str) -> Response:
    """
    This can be used to update an existing wireguard VPN server
    """
    existing_iface = vpn_router.db_interface.get_interface(name)
    if not existing_iface:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {name}",
        )

    ssh_connection_info = (
        vpn.ssh_connection_info if vpn.ssh_connection_info is not None else existing_iface.ssh_connection_info
    )
    wg_config_data = dump_interface_config(existing_iface.interface, ssh_connection_info, vpn_router.ssh_key_path)
    if isinstance(wg_config_data, str):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Unable to update the WireGuard server {name} via " f"SSH: {wg_config_data}",
        )
    updated_vpn = VpnDbModel(
        interface=existing_iface.interface,
        public_key=wg_config_data.public_key,
        listen_port=wg_config_data.listen_port,
        wg_ip_address=vpn.wg_ip_address if vpn.wg_ip_address is not None else existing_iface.wg_ip_address,
        private_key=wg_config_data.private_key,
        ssh_connection_info=ssh_connection_info,
        name=vpn.name if vpn.name is not None else name,
        description=vpn.description if vpn.description is not None else existing_iface.description,
    )
    result = vpn_router.db_interface.update_interface(updated_vpn)
    # TODO: Import Peers
    return Response(status_code=HTTPStatus.OK)


@vpn_router.delete("/vpn/{name}", tags=["wg-manager"])
def delete_vpn(name: str) -> Response:
    """
    This will remove a WireGuard VPN server from the WireGuard manager.  No changes will be made to the wireguard
    network itself.
    """
    vpn_router.db_interface.delete_interface(name)
    return Response(status_code=HTTPStatus.OK)


@vpn_router.get("/vpn/{name}", tags=["wg-manager"], response_model=VpnDbModel)
def get_vpn(name: str) -> Response:
    existing_iface = vpn_router.db_interface.get_interface(name)
    if not existing_iface:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {name}",
        )
    return existing_iface
