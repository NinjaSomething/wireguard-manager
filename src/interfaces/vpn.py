from fastapi import APIRouter, Response, HTTPException
from fastapi.responses import PlainTextResponse
from http import HTTPStatus
from typing import Optional, List, Any
from srv_manager.ssh import dump_interface_config
from models.vpn import VpnModel, VpnPutRequestModel, PeerModel, PeerRequestModel
from vpn import VpnServer
from peers import PeerList, Peer


class VpnAPIRouter(APIRouter):
    """
    An extension to the base FastAPI router, that adds a params_manager property. It is expected that you set
    this property at app startup, so that the endpoints within the router will have access to the ParamsManager.
    """

    def __init__(self):
        super().__init__()
        self._vpn_manager = None

    @property
    def vpn_manager(self):
        if self._vpn_manager is None:
            raise Exception("vpn_manager has not been configured in APIRouter, set it before use")
        else:
            return self._vpn_manager

    @vpn_manager.setter
    def vpn_manager(self, value):
        self._vpn_manager = value


vpn_router = VpnAPIRouter()


@vpn_router.put("/vpn/{name}", tags=["wg-manager"])
def add_vpn(name: str, vpn: VpnPutRequestModel, description: Optional[str] = "") -> Response:
    """
    Add an existing VPN to the Wireguard Manager.  When this is done, clients can be added to the VPN using this service.
    """
    # Validate the IP address space
    vpn_manager = vpn_router.vpn_manager
    try:
        vpn_manager.add_vpn(name, description, vpn)
    except ValueError as ex:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail=f"Failed to add VPN {name}: {ex}")
    return Response(status_code=HTTPStatus.OK)


@vpn_router.delete("/vpn/{name}", tags=["wg-manager"])
def delete_vpn(name: str) -> Response:
    """
    This will remove a WireGuard VPN server from the WireGuard manager.  No changes will be made to the wireguard
    network itself.  This service will no longer manage the VPN.
    """
    vpn_manager = vpn_router.vpn_manager
    vpn_manager.remove_vpn(name)
    return Response(status_code=HTTPStatus.OK)


@vpn_router.get("/vpn/{name}", tags=["wg-manager"], response_model=VpnModel)
def get_vpn(name: str) -> Response:
    vpn_manager = vpn_router.vpn_manager
    vpn = vpn_manager.get_vpn(name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {name}",
        )
    return vpn.to_model()


@vpn_router.get("/vpn/{name}/peers", tags=["wg-manager"], response_model=list[PeerModel])
def get_peers(name: str) -> Response:
    """Get all the peers for a given VPN."""
    vpn_manager = vpn_router.vpn_manager
    vpn = vpn_manager.get_vpn(name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {name}",
        )
    return vpn.peers.to_model()


@vpn_router.get("/vpn/{name}/peer/{ip_address}", tags=["wg-manager"], response_model=PeerModel)
def get_peer(name: str, ip_address: str) -> Response:
    """Return the peer with the given IP address on a given VPN."""
    vpn_manager = vpn_router.vpn_manager
    vpn = vpn_manager.get_vpn(name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {name}",
        )
    peer = vpn_manager.get_peers_by_ip(vpn_name=name, ip_address=ip_address)

    if peer is not None:
        return peer.to_model()
    else:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No peer with IP {ip_address} was found in VPN {name}",
        )


@vpn_router.get("/vpn/{name}/peer/{ip_address}/config", tags=["wg-manager"], response_class=PlainTextResponse)
def get_peer_wg_config(name: str, ip_address: str):
    """Return the wireguard configuration for a peer on a given VPN."""
    vpn_manager = vpn_router.vpn_manager
    vpn = vpn_manager.get_vpn(name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {name}",
        )
    peer = vpn_manager.get_peers_by_ip(vpn_name=name, ip_address=ip_address)
    if peer is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No peer with IP {ip_address} was found in VPN {name}",
        )

    response = f"""[Interface]
Address = {peer.ip_address}
ListenPort = 40023
PrivateKey = {peer.private_key if peer.private_key else "[INSERT_PRIVATE_KEY]"}

[Peer]
PublicKey = {vpn.public_key}
AllowedIPs = {peer.allowed_ips}
Endpoint = {vpn.ip_address}
PersistentKeepalive = {peer.persistent_keepalive}"""
    return response


@vpn_router.get("/vpn/{name}/peer/tag/{tag}", tags=["wg-manager"], response_model=list[PeerModel])
def get_peer_by_tag(name: str, tag: str) -> list[PeerModel]:
    """Return the peers with the given tag on a given VPN."""
    vpn_manager = vpn_router.vpn_manager
    vpn = vpn_manager.get_vpn(name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {name}",
        )
    peers = vpn_manager.get_peers_by_tag(vpn_name=name, tag=tag)
    return [peer.to_model() for peer in peers]


@vpn_router.post("/vpn/{name}/peer", tags=["wg-manager"], response_model=PeerModel)
def add_peer(name: str, peer: PeerRequestModel) -> PeerModel:
    """Add a new peer to a VPN."""
    vpn_manager = vpn_router.vpn_manager
    vpn = vpn_manager.get_vpn(name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {name}",
        )

    # Assign an IP address if not provided
    if peer.ip_address is None:
        peer.ip_address = vpn.get_next_available_ip()

    # Verify the IP address is not already in use
    for existing_peer in vpn.peers:
        if existing_peer.ip_address == peer.ip_address:
            raise HTTPException(
                status_code=HTTPStatus.CONFLICT,
                detail=f"Peer with IP {peer.ip_address} already exists in VPN {name}",
            )

    # Verify the IP address is available in the VPN address space
    if peer.ip_address not in vpn.available_ips:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"IP address {peer.ip_address} is not available in VPN {name}",
        )

    # Verify the allowed_ips are within the bounds of the VPN server address space
    try:
        vpn.validate_address_space(peer.allowed_ips)
    except ValueError as ex:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Allowed IPs Error: {ex}",
        )

    # Create a new peer
    new_peer = Peer(
        ip_address=peer.ip_address,
        public_key=peer.public_key,
        private_key=peer.private_key,
        persistent_keepalive=peer.persistent_keepalive,
        allowed_ips=peer.allowed_ips,
        tags=peer.tags,
    )
    vpn.peers.append(new_peer)
    return new_peer.to_model()


@vpn_router.delete("/vpn/{name}/peer/{ip_address}", tags=["wg-manager"], response_model=PeerModel)
def delete_peer(name: str, ip_address: str) -> Response:
    """Delete a peer from a VPN."""
    vpn_manager = vpn_router.vpn_manager
    vpn_manager.delete_peer(name, ip_address)
    return Response(status_code=HTTPStatus.OK)


@vpn_router.post("/vpn/{name}/import", tags=["wg-manager"])
def import_vpn_peers(name: str) -> Response:
    """This imports peers from the WireGuard VPN into this service."""
    vpn = vpn_router.vpn_manager.get_interface(name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"The wireguard VPN was not found: {name}",
        )

    # This downloads the wireguard server config and extracts the data.
    wg_config_data = dump_interface_config(vpn.wg_interface, vpn.ssh_connection_info, vpn_router.ssh_key_path)
    if isinstance(wg_config_data, str):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Unable to import WireGuard server {vpn.name} via " f"SSH: {wg_config_data}",
        )

    add_peers = []
    for peer in wg_config_data.peers:
        expected_peer = PeerModel(
            wg_ip_address=peer.wg_ip_address,
            public_key=peer.public_key,
            persistent_keepalive=peer.persistent_keepalive,
        )
        if expected_peer not in vpn.peers:
            vpn_router.vpn_manager.add_peer(name, expected_peer)

    return Response(status_code=HTTPStatus.OK)
