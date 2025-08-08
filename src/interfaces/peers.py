from fastapi import Response, HTTPException
from fastapi.responses import PlainTextResponse
from http import HTTPStatus
from models.peers import PeerResponseModel, PeerRequestModel
import logging
from interfaces.custom_router import WgAPIRouter
from server_manager import server_manager_factory, ConnectionException
from vpn_manager import VpnUpdateException
from interfaces.vpn import validate_vpn_exists


log = logging.getLogger(__name__)
peer_router = WgAPIRouter()


def validate_peer_exists(vpn_name: str, ip_address: str, vpn_manager) -> None:
    """
    Validate that a peer exists within the given vpn.
    Raises HTTPException if the peer does not exist.
    """
    validate_vpn_exists(vpn_name, vpn_manager)
    if not vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address):
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No peer with IP {ip_address} was found in VPN {vpn_name}",
        )


@peer_router.get("/vpn/{vpn_name}/peers", tags=["peers"], response_model=list[PeerResponseModel])
def get_peers(vpn_name: str, hide_secrets: bool = True) -> list[PeerResponseModel]:
    """Get all the peers for a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    peers_db = vpn_manager.get_all_peers(vpn_name)
    peer_models = [PeerResponseModel(**peer.model_dump()) for peer in peers_db]
    for peer_model in peer_models:
        peer_model.opaque = hide_secrets
    return peer_models


@peer_router.post("/vpn/{vpn_name}/peer", tags=["peers"], response_model=PeerResponseModel)
def add_peer(vpn_name: str, peer: PeerRequestModel) -> PeerResponseModel:
    """Add a new peer to a VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    vpn = vpn_manager.get_vpn(vpn_name)
    # Assign an IP address if not provided
    if peer.ip_address is None:
        peer.ip_address = vpn.get_next_available_ip()

    if peer.public_key is None:
        # Generate the key-pair
        peer.private_key, peer.public_key = vpn_manager.generate_wireguard_keys()

    vpn_peers = vpn_manager.get_all_peers(vpn_name)

    for existing_peer in vpn_peers:
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
        vpn.validate_ip_network(peer.allowed_ips)
    except ValueError as ex:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Allowed IPs Error: {ex}",
        )

    if vpn.connection_info is not None:
        try:
            server_manager = server_manager_factory(vpn.connection_info.type)
            server_manager.add_peer(vpn, peer)
        except ConnectionException as ex:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
    vpn_manager.add_peer(vpn_name, peer)
    vpn.calculate_available_ips()
    return PeerResponseModel(**peer.model_dump())


@peer_router.delete("/vpn/{vpn_name}/peer/{ip_address}", tags=["peers"])
def delete_peer(vpn_name: str, ip_address: str) -> Response:
    """Delete a peer from a VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    vpn = vpn_manager.get_vpn(vpn_name)

    peer = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)
    if peer is not None:
        if vpn.connection_info is not None:
            try:
                server_manager = server_manager_factory(vpn.connection_info.type)
                server_manager.remove_peer(vpn, peer)
            except ConnectionException as ex:
                raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
        vpn_manager.delete_peer(vpn_name, ip_address)
    vpn.calculate_available_ips()
    return Response(status_code=HTTPStatus.OK)


@peer_router.get("/vpn/{vpn_name}/peer/{ip_address}", tags=["peers"], response_model=PeerResponseModel)
def get_peer(vpn_name: str, ip_address: str, hide_secrets: bool = True) -> PeerResponseModel:
    """Return the peer with the given IP address on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    peer_db_model = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)
    peer_model = PeerResponseModel(**peer_db_model.model_dump())
    peer_model.opaque = hide_secrets
    return peer_model


@peer_router.get("/vpn/{vpn_name}/peer/{ip_address}/config", tags=["peers"], response_class=PlainTextResponse)
def get_peer_wg_config(vpn_name: str, ip_address: str):
    """Return the wireguard configuration for a peer on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)

    vpn = vpn_manager.get_vpn(vpn_name)
    peer = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)
    response = f"""[Interface]
Address = {peer.ip_address}
PrivateKey = {peer.private_key if peer.private_key else "[INSERT_PRIVATE_KEY]"}

[Peer]
PublicKey = {vpn.public_key}
AllowedIPs = {peer.allowed_ips}
Endpoint = {vpn.connection_info.data.ip_address if vpn.connection_info else "[INSERT_VPN_IP]"}:{vpn.listen_port}
PersistentKeepalive = {peer.persistent_keepalive}"""
    return response


@peer_router.get("/vpn/{vpn_name}/peer/tag/{tag}", tags=["peers"], response_model=list[PeerResponseModel])
def get_peer_by_tag(vpn_name: str, tag: str, hide_secrets: bool = True) -> list[PeerResponseModel]:
    """Return the peers with the given tag on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    peers = vpn_manager.get_peers_by_tag(vpn_name=vpn_name, tag=tag)
    peer_models = [PeerResponseModel(**peer.model_dump()) for peer in peers]
    for peer_model in peer_models:
        peer_model.opaque = hide_secrets
    return peer_models


@peer_router.post(
    "/vpn/{vpn_name}/peer/{ip_address}/generate-wireguard-keys", tags=["peers"], response_model=PeerResponseModel
)
def generate_new_wireguard_keys(vpn_name: str, ip_address: str) -> PeerResponseModel:
    """Generate new WireGuard keys for a peer."""
    server_manager = None
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    vpn = vpn_manager.get_vpn(vpn_name)
    peer = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)

    if vpn.connection_info is not None:
        try:
            server_manager = server_manager_factory(vpn.connection_info.type)
            server_manager.remove_peer(vpn, peer)
        except ConnectionException as ex:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)

    vpn_manager.generate_new_peer_keys(vpn_name, peer)
    if vpn.connection_info is not None:
        try:
            server_manager.add_peer(vpn, peer)
        except ConnectionException as ex:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
    peer_response = PeerResponseModel(**peer.model_dump())
    peer_response.opaque = False  # Hide secrets in the response
    return peer_response


@peer_router.post("/vpn/{vpn_name}/import", tags=["peers"], response_model=list[PeerResponseModel])
def import_vpn_peers(vpn_name: str) -> list[PeerResponseModel]:
    """This imports peers from the WireGuard VPN into this service."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    vpn = vpn_manager.get_vpn(vpn_name)

    if vpn.connection_info is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"The information required to get data from the Wireguard Server has not been configured",
        )

    try:
        added_peers = vpn_manager.import_peers(vpn_name)
    except VpnUpdateException as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(ex))
    return [PeerResponseModel(**peer.model_dump()) for peer in added_peers]


@peer_router.put("/vpn/{vpn_name}/peer/{ip_address}/tag/{tag}", tags=["peers"], response_model=PeerResponseModel)
def add_tag_to_peer(vpn_name: str, ip_address: str, tag: str) -> PeerResponseModel:
    """Add a tag to a peer."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    vpn_manager.add_tag_to_peer(vpn_name=vpn_name, peer_ip=ip_address, tag=tag)
    return PeerResponseModel(**vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address).model_dump())


@peer_router.delete("/vpn/{vpn_name}/peer/{ip_address}/tag/{tag}", tags=["peers"], response_model=PeerResponseModel)
def delete_tag_from_peer(vpn_name: str, ip_address: str, tag: str) -> PeerResponseModel:
    """Remove a tag from a peer."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    vpn_manager.delete_tag_from_peer(vpn_name=vpn_name, peer_ip=ip_address, tag=tag)
    return PeerResponseModel(**vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address).model_dump())
