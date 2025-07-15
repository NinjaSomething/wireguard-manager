from pydantic import BaseModel, SecretStr
from typing import Optional


"""This module contains pydantic modules for data gathered from the wireguard server itself"""


class WgServerPeerModel(BaseModel):
    """This is the peer configuration from the server itself after performing a dump command."""

    endpoint: str
    public_key: str
    wg_ip_address: str
    preshared_key: Optional[str]
    latest_handshake: int
    transfer_rx: int
    transfer_tx: int
    persistent_keepalive: int


class WgServerModel(BaseModel):
    """This is the wireguard configuration from the server itself after performing a dump command"""

    interface: str
    public_key: str
    private_key: SecretStr
    listen_port: int
    fw_mark: str
    peers: Optional[list[WgServerPeerModel]] = []
