from datetime import datetime
from http import HTTPStatus
from ipaddress import IPv4Address
from uuid import uuid4

from fastapi import Response, HTTPException, Path
from fastapi.responses import PlainTextResponse

from models.peer_history import PeerHistoryResponseModel
from models.peers import PeerResponseModel, PeerRequestModel
from vpn_manager.peers import Peer
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
def get_peers(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    hide_secrets: bool = True,
) -> Response:
    """Get all the peers for a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    vpn = vpn_manager.get_vpn(vpn_name)
    peer_models = vpn.peers.to_model()
    for peer_model in peer_models:
        peer_model.opaque = hide_secrets
    return peer_models


@peer_router.post("/vpn/{vpn_name}/peer", tags=["peers"], response_model=PeerResponseModel)
def add_peer(
    peer: PeerRequestModel,
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
) -> PeerResponseModel:
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
        vpn.validate_ip_network(peer.allowed_ips)
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
    if vpn.connection_info is not None:
        try:
            server_manager = server_manager_factory(vpn.connection_info.type)
            server_manager.add_peer(vpn, new_peer)
        except ConnectionException as ex:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
    vpn.peers.append(new_peer)
    vpn.calculate_available_ips()
    return new_peer.to_model()


@peer_router.delete("/vpn/{vpn_name}/peer/{ip_address}", tags=["peers"])
def delete_peer(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    ip_address: IPv4Address = Path(..., description="Must be a valid IPv4 address"),
) -> Response:
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
def get_peer(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    ip_address: IPv4Address = Path(..., description="Must be a valid IPv4 address"),
    hide_secrets: bool = True,
) -> PeerResponseModel:
    """Return the peer with the given IP address on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    peer_model = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address).to_model()
    peer_model.opaque = hide_secrets
    return peer_model


@peer_router.get("/vpn/{vpn_name}/peer/{ip_address}/config", tags=["peers"], response_class=PlainTextResponse)
def get_peer_wg_config(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    ip_address: IPv4Address = Path(..., description="Must be a valid IPv4 address"),
):
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
def get_peer_by_tag(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    tag: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    hide_secrets: bool = True,
) -> list[PeerResponseModel]:
    """Return the peers with the given tag on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    peers = vpn_manager.get_peers_by_tag(vpn_name=vpn_name, tag=tag)
    peer_models = [peer.to_model() for peer in peers]
    for peer_model in peer_models:
        peer_model.opaque = hide_secrets
    return peer_models


@peer_router.post(
    "/vpn/{vpn_name}/peer/{ip_address}/generate-wireguard-keys", tags=["peers"], response_model=PeerResponseModel
)
def generate_new_wireguard_keys(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    ip_address: IPv4Address = Path(..., description="Must be a valid IPv4 address"),
) -> PeerResponseModel:
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
    peer_response = peer.to_model()
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
    return [peer.to_model() for peer in added_peers]


@peer_router.put("/vpn/{vpn_name}/peer/{ip_address}/tag/{tag}", tags=["peers"], response_model=PeerResponseModel)
def add_tag_to_peer(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    ip_address: IPv4Address = Path(..., description="Must be a valid IPv4 address"),
    tag: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
) -> PeerResponseModel:
    """Add a tag to a peer."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    vpn_manager.add_tag_to_peer(vpn_name=vpn_name, peer_ip=ip_address, tag=tag)
    return vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address).to_model()


@peer_router.delete("/vpn/{vpn_name}/peer/{ip_address}/tag/{tag}", tags=["peers"], response_model=PeerResponseModel)
def delete_tag_from_peer(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    ip_address: IPv4Address = Path(..., description="Must be a valid IPv4 address"),
    tag: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
) -> PeerResponseModel:
    """Remove a tag from a peer."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    vpn_manager.delete_tag_from_peer(vpn_name=vpn_name, peer_ip=ip_address, tag=tag)
    return vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address).to_model()


@peer_router.get(
    "/vpn/{vpn_name}/peer/{ip_address}/history", tags=["peer-history"], response_model=list[PeerHistoryResponseModel]
)
def get_peer_history_ip_address(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    ip_address: IPv4Address = Path(..., description="Must be a valid IPv4 address"),
    start_time: datetime = None,
    end_time: datetime = None,
) -> list[PeerHistoryResponseModel]:
    """Get the history of a peer."""
    vpn_manager = peer_router.vpn_manager
    start_time_ns = int(start_time.timestamp()) * 1_000_000_000 if start_time else None
    end_time_ns = int(end_time.timestamp()) * 1_000_000_000 if end_time else None

    if start_time_ns and end_time_ns and start_time_ns >= end_time_ns:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Start time must be before end time.",
        )

    peer_history = vpn_manager.get_peer_history_endpoint(vpn_name, ip_address, start_time_ns, end_time_ns)
    if not peer_history:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No peer history found with IP address {ip_address} in VPN {vpn_name}",
        )
    return [PeerHistoryResponseModel(**history.dict()) for history in reversed(peer_history)]


@peer_router.get(
    "/vpn/{vpn_name}/tag/{tag}/history", tags=["tag-history"], response_model=list[PeerHistoryResponseModel]
)
def get_tag_history_tag(
    vpn_name: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    tag: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    start_time: datetime = None,
    end_time: datetime = None,
) -> list[PeerHistoryResponseModel]:
    """Get the history of a peer by tag."""
    vpn_manager = peer_router.vpn_manager
    start_time_ns = int(start_time.timestamp()) * 1_000_000_000 if start_time else None
    end_time_ns = int(end_time.timestamp()) * 1_000_000_000 if end_time else None

    if start_time_ns and end_time_ns and start_time_ns >= end_time_ns:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Start time must be before end time.",
        )

    tag_history = vpn_manager.get_tag_history_endpoint(vpn_name, tag, start_time_ns, end_time_ns)
    if not tag_history:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No tag_history found with tag {tag} in VPN {vpn_name}",
        )
    return [PeerHistoryResponseModel(**history.dict()) for history in reversed(tag_history)]
