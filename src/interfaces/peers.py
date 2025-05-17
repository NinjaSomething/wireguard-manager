from fastapi import Response, HTTPException
from fastapi.responses import PlainTextResponse
from uuid import uuid4
from http import HTTPStatus
from vpn_manager.ssh import dump_interface_config
from models.peers import PeerModel, PeerRequestModel
from vpn_manager.peers import Peer
import logging
from interfaces.custom_router import WgAPIRouter
from vpn_manager.ssh import add_peer as ssh_add_peer
from vpn_manager.ssh import remove_peer as ssh_remove_peer
from vpn_manager.ssh import SshException
from vpn_manager.ssh import generate_wireguard_keys


log = logging.getLogger(__name__)
peer_router = WgAPIRouter()


@peer_router.get("/vpn/{vpn_name}/peers", tags=["peers"], response_model=list[PeerModel])
def get_peers(vpn_name: str) -> Response:
    """Get all the peers for a given VPN."""
    vpn_manager = peer_router.vpn_manager
    vpn = vpn_manager.get_vpn(vpn_name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {vpn_name}",
        )
    return vpn.peers.to_model()


@peer_router.post("/vpn/{vpn_name}/peer", tags=["peers"], response_model=PeerModel)
def add_peer(vpn_name: str, peer: PeerRequestModel) -> PeerModel:
    """Add a new peer to a VPN."""
    vpn_manager = peer_router.vpn_manager
    vpn = vpn_manager.get_vpn(vpn_name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {vpn_name}",
        )

    # Assign an IP address if not provided
    if peer.ip_address is None:
        peer.ip_address = vpn.get_next_available_ip()

    if peer.public_key is None:
        # Generate the key-pair
        peer.private_key, peer.public_key = generate_wireguard_keys()

    for existing_peer in vpn.peers:
        # Verify the IP address is not already in use on this VPN
        if existing_peer.ip_address == peer.ip_address:
            raise HTTPException(
                status_code=HTTPStatus.CONFLICT,
                detail=f"Peer with IP {peer.ip_address} already exists in VPN {vpn_name}",
            )

        # Verify the Public Key is not already in use on this VPN
        if existing_peer.public_key == peer.public_key:
            raise HTTPException(
                status_code=HTTPStatus.CONFLICT,
                detail=f"Peer {peer.ip_address} is already using that public key on VPN {vpn_name}",
            )

    # Verify the IP address is available in the VPN address space
    if peer.ip_address not in vpn.available_ips:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"IP address {peer.ip_address} is not available in VPN {vpn_name}",
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
        peer_id=str(uuid4()),
        ip_address=peer.ip_address,
        public_key=peer.public_key,
        private_key=peer.private_key,
        persistent_keepalive=peer.persistent_keepalive,
        allowed_ips=peer.allowed_ips,
        tags=peer.tags,
    )
    if vpn.ssh_connection_info is not None:
        try:
            ssh_add_peer(vpn, new_peer)
        except SshException as ex:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
    vpn.peers.append(new_peer)
    vpn.calculate_available_ips()
    return new_peer.to_model()


@peer_router.delete("/vpn/{vpn_name}/peer/{ip_address}", tags=["peers"], response_model=PeerModel)
def delete_peer(vpn_name: str, ip_address: str) -> Response:
    """Delete a peer from a VPN."""
    vpn_manager = peer_router.vpn_manager
    vpn = vpn_manager.get_vpn(vpn_name)
    peer = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)
    if peer is not None:
        if vpn.ssh_connection_info is not None:
            try:
                ssh_remove_peer(vpn, peer)
            except SshException as ex:
                raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
        vpn_manager.delete_peer(vpn_name, ip_address)
    vpn.calculate_available_ips()
    return Response(status_code=HTTPStatus.OK)


@peer_router.get("/vpn/{vpn_name}/peer/{ip_address}", tags=["peers"], response_model=PeerModel)
def get_peer(vpn_name: str, ip_address: str) -> PeerModel:
    """Return the peer with the given IP address on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    vpn = vpn_manager.get_vpn(vpn_name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {vpn_name}",
        )
    peer = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)

    if peer is not None:
        return peer.to_model()
    else:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No peer with IP {ip_address} was found in VPN {vpn_name}",
        )


@peer_router.get("/vpn/{vpn_name}/peer/{ip_address}/config", tags=["peers"], response_class=PlainTextResponse)
def get_peer_wg_config(vpn_name: str, ip_address: str):
    """Return the wireguard configuration for a peer on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    vpn = vpn_manager.get_vpn(vpn_name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {vpn_name}",
        )
    peer = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)
    if peer is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No peer with IP {ip_address} was found in VPN {vpn_name}",
        )

    response = f"""[Interface]
Address = {peer.ip_address}
PrivateKey = {peer.private_key if peer.private_key else "[INSERT_PRIVATE_KEY]"}

[Peer]
PublicKey = {vpn.public_key}
AllowedIPs = {peer.allowed_ips}
Endpoint = {vpn.ssh_connection_info.ip_address}:{vpn.listen_port}
PersistentKeepalive = {peer.persistent_keepalive}"""
    return response


@peer_router.get("/vpn/{vpn_name}/peer/tag/{tag}", tags=["peers"], response_model=list[PeerModel])
def get_peer_by_tag(vpn_name: str, tag: str) -> list[PeerModel]:
    """Return the peers with the given tag on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    vpn = vpn_manager.get_vpn(vpn_name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {vpn_name}",
        )
    peers = vpn_manager.get_peers_by_tag(vpn_name=vpn_name, tag=tag)
    return [peer.to_model() for peer in peers]


@peer_router.post(
    "/vpn/{vpn_name}/peers/{ip_address}/generate-wireguard-keys", tags=["peers"], response_model=PeerModel
)
def generate_new_wireguard_keys(vpn_name: str, ip_address: str) -> PeerModel:
    """Generate new WireGuard keys for a peer."""
    vpn_manager = peer_router.vpn_manager
    vpn = vpn_manager.get_vpn(vpn_name)
    peer = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)
    if not peer:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"An existing WireGuard interface using this configuration could not be found: {vpn_name}",
        )

    if vpn.ssh_connection_info is not None:
        ssh_remove_peer(vpn, peer)

    vpn_manager.generate_new_peer_keys(vpn_name, peer)
    if vpn.ssh_connection_info is not None:
        try:
            ssh_add_peer(vpn, peer)
        except SshException as ex:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
    return peer.to_model()


@peer_router.post("/vpn/{vpn_name}/import", tags=["peers"], response_model=list[PeerModel])
def import_vpn_peers(vpn_name: str) -> list[PeerModel]:
    """This imports peers from the WireGuard VPN into this service."""
    vpn_manager = peer_router.vpn_manager
    vpn = vpn_manager.get_vpn(vpn_name)
    if not vpn:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"The wireguard VPN was not found: {vpn_name}",
        )

    if vpn.ssh_connection_info is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"SSH connection information is not found for VPN {vpn_name}",
        )

    # This downloads the wireguard server config and extracts the data.
    wg_config_data = dump_interface_config(vpn.interface, vpn.ssh_connection_info)
    if isinstance(wg_config_data, str):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Unable to import WireGuard server {vpn.name} via " f"SSH: {wg_config_data}",
        )

    add_peers = []
    for peer in wg_config_data.peers:
        import_peer = Peer(
            peer_id=str(uuid4()),
            ip_address=peer.wg_ip_address,
            public_key=peer.public_key,
            persistent_keepalive=peer.persistent_keepalive,
            allowed_ips=vpn.address_space,
            tags=["imported"],
        )
        # Check if the peer already exists in the VPN
        skip_peer = False
        for existing_peer in vpn.peers:
            if existing_peer.ip_address == import_peer.ip_address:
                log.warning(f"Skipping import of peer {import_peer.ip_address} as it already exists.")
                skip_peer = True

        if not skip_peer:
            add_peers.append(import_peer)
            vpn.peers.append(import_peer)
    vpn.calculate_available_ips()

    return [peer.to_model() for peer in add_peers]
