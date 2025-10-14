import logging
from datetime import datetime
from http import HTTPStatus

from fastapi import HTTPException, Path, Request, Response
from fastapi.responses import PlainTextResponse

from interfaces.custom_router import WgAPIRouter
from interfaces.vpn import validate_vpn_exists
from models.connection import ConnectionType
from models.peer_history import PeerHistoryResponseModel
from models.peers import (
    AddTagToPeerRequestModel,
    DeleteTagFromPeerRequestModel,
    ImportVpnPeersRequestModel,
    PeerDeleteRequestModel,
    PeerGenerateKeysRequestModel,
    PeerRequestModel,
    PeerResponseModel,
    PeerUpdateRequestModel,
)
from server_manager import ConnectionException
from vpn_manager import BadRequestException, ConflictException, VpnUpdateException

log = logging.getLogger(__name__)
peer_router = WgAPIRouter()
ipv4_regex = r"^(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}$"


def validate_peer_exists(vpn_name: str, ip_address: str, vpn_manager) -> None:
    """
    Validate that a peer exists within the given vpn.
    Raises HTTPException if the peer does not exist.
    """
    validate_vpn_exists(vpn_name, vpn_manager)
    if not vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address):
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=f"No peer with IP {ip_address} was found in VPN {vpn_name}"
        )


@peer_router.get("/vpn/{vpn_name}/peers", tags=["peers"], response_model=list[PeerResponseModel])
def get_peers(
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."), hide_secrets: bool = True
) -> list[PeerResponseModel]:
    """Get all the peers for a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    peer_models = []
    for peer in vpn_manager.get_all_peers(vpn_name):
        peer_model = PeerResponseModel(**peer.model_dump())
        peer_model.opaque = hide_secrets
        peer_models.append(peer_model)
    return peer_models


@peer_router.get("/vpn/{vpn_name}/peer/{ip_address}", tags=["peers"], response_model=PeerResponseModel)
def get_peer(
    vpn_name: str = Path(..., description="The name of the VPN the peers are connected to."),
    ip_address: str = Path(..., regex=ipv4_regex, description="Must be a valid IPv4 address", example="192.180.0.1"),
    hide_secrets: bool = True,
) -> PeerResponseModel:
    """Return the peer with the given IP address on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    peer_db_model = vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)
    peer_model = PeerResponseModel(**peer_db_model.model_dump())
    peer_model.opaque = hide_secrets
    return peer_model


@peer_router.get("/vpn/{vpn_name}/peer/tag/{tag}", tags=["peers"], response_model=list[PeerResponseModel])
def get_peer_by_tag(
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
    tag: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the tag name."
    ),
    hide_secrets: bool = True,
) -> list[PeerResponseModel]:
    """Return the peers with the given tag on a given VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)

    peer_models = []
    for peer in vpn_manager.get_peers_by_tag(vpn_name=vpn_name, tag=tag):
        peer_model = PeerResponseModel(**peer.model_dump())
        peer_model.opaque = hide_secrets
        peer_models.append(peer_model)
    return sorted(peer_models, key=lambda p: p.ip_address)


@peer_router.get("/vpn/{vpn_name}/peer/{ip_address}/config", tags=["peers"], response_class=PlainTextResponse)
def get_peer_wg_config(
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
    ip_address: str = Path(..., regex=ipv4_regex, description="Must be a valid IPv4 address", example="192.180.0.1"),
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
PublicKey = {vpn.wireguard.public_key}
AllowedIPs = {','.join(peer.allowed_ips)}
Endpoint = {vpn.connection_info.data.ip_address if vpn.connection_info and vpn.connection_info.type==ConnectionType.SSH else "[INSERT_VPN_IP]"}:{vpn.wireguard.listen_port}
PersistentKeepalive = {peer.persistent_keepalive}"""
    return response


@peer_router.post("/vpn/{vpn_name}/peer", tags=["peers"], response_model=PeerResponseModel)
def add_peer(
    request: Request,
    peer: PeerRequestModel,
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
) -> PeerResponseModel:
    """Add a new peer to a VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    peer.message = f"[{request.method} {request.url.path}] " + peer.message
    try:
        vpn_manager.add_peer(
            vpn_name, peer, changed_by=request.state.user if hasattr(request.state, "user") else "unknown"
        )
    except ConnectionException as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
    except BadRequestException as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    except ConflictException as ex:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail=str(ex))

    return PeerResponseModel(**peer.model_dump())


@peer_router.put("/vpn/{vpn_name}/peer/{ip_address}", tags=["peers"], response_model=PeerResponseModel)
def update_peer(
    request: Request,
    peer: PeerUpdateRequestModel,
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
    ip_address: str = Path(..., description="The IP address of the peer to update.", example="10.98.0.99"),
) -> PeerResponseModel:
    """Update an existing peer or add a new one if it does not exist."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    peer.message = f"[{request.method} {request.url.path}] " + peer.message
    try:
        vpn_manager.update_peer(
            vpn_name,
            PeerRequestModel(**peer.model_dump(), ip_address=ip_address),
            changed_by=request.state.user if hasattr(request.state, "user") else "unknown",
        )
    except ConnectionException as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
    except BadRequestException as ex:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(ex))
    except ConflictException as ex:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail=str(ex))

    return PeerResponseModel(**peer.model_dump(), ip_address=ip_address)


@peer_router.delete("/vpn/{vpn_name}/peer/{ip_address}", tags=["peers"])
def delete_peer(
    request: Request,
    peer: PeerDeleteRequestModel,
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
    ip_address: str = Path(..., regex=ipv4_regex, description="Must be a valid IPv4 address", example="192.180.0.1"),
) -> Response:
    """Delete a peer from a VPN."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    peer.message = f"[{request.method} {request.url.path}] " + peer.message
    try:
        vpn_manager.delete_peer(
            vpn_name,
            ip_address,
            changed_by=request.state.user if hasattr(request.state, "user") else "unknown",
            message=peer.message,
        )
    except ConnectionException as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)
    return Response(status_code=HTTPStatus.OK)


@peer_router.post(
    "/vpn/{vpn_name}/peer/{ip_address}/generate-wireguard-keys", tags=["peers"], response_model=PeerResponseModel
)
def generate_new_wireguard_keys(
    request: Request,
    peer_generate_keys_request: PeerGenerateKeysRequestModel,
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
    ip_address: str = Path(..., regex=ipv4_regex, description="Must be a valid IPv4 address", example="192.180.0.1"),
) -> PeerResponseModel:
    """Generate new WireGuard keys for a peer."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    peer_generate_keys_request.message = (
        f"[{request.method} {request.url.path}] '" + peer_generate_keys_request.message + "'"
    )
    try:
        updated_peer = vpn_manager.generate_new_peer_keys(
            vpn_name,
            ip_address,
            changed_by=request.state.user if hasattr(request.state, "user") else "unknown",
            message=peer_generate_keys_request.message,
        )
    except ConnectionException as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=ex)

    peer_response = PeerResponseModel(**updated_peer.model_dump())
    peer_response.opaque = False  # Hide secrets in the response
    return peer_response


@peer_router.post("/vpn/{vpn_name}/import", tags=["peers"], response_model=list[PeerResponseModel])
def import_vpn_peers(
    request: Request,
    import_vpn_peers_request: ImportVpnPeersRequestModel,
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
) -> list[PeerResponseModel]:
    """This imports peers from the WireGuard VPN into this service."""
    vpn_manager = peer_router.vpn_manager
    validate_vpn_exists(vpn_name, vpn_manager)
    vpn = vpn_manager.get_vpn(vpn_name)
    if vpn.connection_info is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="The information required to get data from the Wireguard Server has not been configured",
        )
    import_vpn_peers_request.message = f"[{request.method} {request.url.path}] " + import_vpn_peers_request.message
    try:
        added_peers = vpn_manager.import_peers(
            vpn_name,
            changed_by=request.state.user if hasattr(request.state, "user") else "unknown",
            message=import_vpn_peers_request.message,
        )
    except VpnUpdateException as ex:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(ex))
    return [PeerResponseModel(**peer.model_dump()) for peer in added_peers]


@peer_router.put("/vpn/{vpn_name}/peer/{ip_address}/tag/{tag}", tags=["peers"], response_model=PeerResponseModel)
def add_tag_to_peer(
    request: Request,
    add_tag_to_peer_request: AddTagToPeerRequestModel,
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
    ip_address: str = Path(..., regex=ipv4_regex, description="Must be a valid IPv4 address", example="192.180.0.1"),
    tag: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
) -> PeerResponseModel:
    """Add a tag to a peer."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    add_tag_to_peer_request.message = f"[{request.method} {request.url.path}] " + add_tag_to_peer_request.message
    vpn_manager.add_tag_to_peer(
        vpn_name=vpn_name,
        peer_ip=ip_address,
        tag=tag,
        changed_by=request.state.user if hasattr(request.state, "user") else "unknown",
        message=add_tag_to_peer_request.message,
    )
    return PeerResponseModel(**vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address).model_dump())


@peer_router.delete("/vpn/{vpn_name}/peer/{ip_address}/tag/{tag}", tags=["peers"], response_model=PeerResponseModel)
def delete_tag_from_peer(
    request: Request,
    delete_tag_from_peer_request: DeleteTagFromPeerRequestModel,
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
    ip_address: str = Path(..., regex=ipv4_regex, description="Must be a valid IPv4 address", example="192.180.0.1"),
    tag: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
) -> PeerResponseModel:
    """Remove a tag from a peer."""
    vpn_manager = peer_router.vpn_manager
    validate_peer_exists(vpn_name, ip_address, vpn_manager)
    delete_tag_from_peer_request.message = (
        f"[{request.method} {request.url.path}] " + delete_tag_from_peer_request.message
    )
    vpn_manager.delete_tag_from_peer(
        vpn_name=vpn_name,
        peer_ip=ip_address,
        tag=tag,
        changed_by=request.state.user if hasattr(request.state, "user") else "unknown",
        message=delete_tag_from_peer_request.message,
    )
    return PeerResponseModel(**vpn_manager.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address).model_dump())


@peer_router.get(
    "/vpn/{vpn_name}/peer/{ip_address}/history", tags=["history"], response_model=list[PeerHistoryResponseModel]
)
def get_peer_history_ip_address(
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
    ip_address: str = Path(..., regex=ipv4_regex, description="Must be a valid IPv4 address", example="192.180.0.1"),
    start_time: datetime = None,
    end_time: datetime = None,
    hide_secrets: bool = True,
) -> list[PeerHistoryResponseModel]:
    """
    Get the history of a peer. History represents moments when changes were made to the peer. The start and end time are optional filters for identifying time ranges of interest.
    Both start and end time are inclusive. If no start or end time is provided, the entire history will be returned. Returned results are sorted by time in descending order.
    """
    vpn_manager = peer_router.vpn_manager
    start_time_ns = int(start_time.timestamp()) * 1_000_000_000 if start_time else None
    end_time_ns = int(end_time.timestamp()) * 1_000_000_000 if end_time else None

    if start_time_ns and end_time_ns and start_time_ns > end_time_ns:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Start time must be before end time.")

    peer_history = vpn_manager.get_peer_history(vpn_name, ip_address, start_time_ns, end_time_ns)
    if not peer_history:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No peer history found with IP address {ip_address} in VPN {vpn_name}",
        )

    peer_history_responses = []
    for peer_history in [PeerHistoryResponseModel(**history.dict()) for history in peer_history]:
        peer_history.opaque = hide_secrets
        peer_history_responses.append(peer_history)
    return peer_history_responses


@peer_router.get(
    "/vpn/{vpn_name}/tag/{tag}/history", tags=["history"], response_model=dict[str, list[PeerHistoryResponseModel]]
)
def get_tag_history(
    vpn_name: str = Path(..., description="The name of the VPN the peer is connected to."),
    tag: str = Path(
        ..., regex="^[A-Za-z0-9_-]+$", description="Only alphanumeric characters and - _ are allowed in the VPN name."
    ),
    start_time: datetime = None,
    end_time: datetime = None,
    hide_secrets: bool = True,
) -> dict[str, list[PeerHistoryResponseModel]]:
    """
    Get the history of a peer by tag. This will return the history of all peers that have the given tag in the VPN.
    History represents moments when changes were made to the peer(s) associated with that tag. The start and end time are optional filters for identifying time ranges of interest.
    Both start and end time are inclusive. If no start or end time is provided, the entire history will be returned. Results are grouped by peer and for each peer, results are sorted by time in descending order.
    """
    vpn_manager = peer_router.vpn_manager
    start_time_ns = int(start_time.timestamp()) * 1_000_000_000 if start_time else None
    end_time_ns = int(end_time.timestamp()) * 1_000_000_000 if end_time else None

    if start_time_ns and end_time_ns and start_time_ns > end_time_ns:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Start time must be before end time.")

    tag_histories = vpn_manager.get_tag_history(vpn_name, tag, start_time_ns, end_time_ns)
    if not tag_histories:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=f"No tag_history found with tag {tag} in VPN {vpn_name}"
        )

    peer_history_responses = {}
    for ip, tag_history in tag_histories.items():
        peer_history_responses[ip] = []
        for peer_history in [PeerHistoryResponseModel(**history.dict()) for history in tag_history]:
            peer_history.opaque = hide_secrets
            peer_history_responses[ip].append(peer_history)
    return peer_history_responses
