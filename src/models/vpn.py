from pydantic import BaseModel
from typing import Optional, List


class VpnMetaData(BaseModel):
    name: Optional[str]
    description: Optional[str]


class PeerMetaData(VpnMetaData):
    machine_id: Optional[str]


# -----------------------------------------------------------
# Models for the SSH class
class SshConnectionModel(BaseModel):
    ssh_ip_address: str
    ssh_username: str
    ssh_pem_filename: str


class SshPeer(BaseModel):
    endpoint: str
    public_key: str
    wg_ip_address: str
    preshared_key: Optional[str]
    latest_handshake: int
    transfer_rx: int
    transfer_tx: int
    persistent_keepalive: int


class VpnSshInterfaceModel(BaseModel):
    interface: str
    public_key: str
    private_key: str
    listen_port: int
    fw_mark: str
    peers: Optional[List[SshPeer]] = []


# -----------------------------------------------------------
# API Request Models
class VpnPostRequestModel(VpnMetaData):
    wg_ip_address: str
    wg_interface: str
    ssh_connection_info: SshConnectionModel


class VpnPutRequestModel(VpnMetaData):
    wg_ip_address: Optional[str]
    ssh_connection_info: Optional[SshConnectionModel]


# -----------------------------------------------------------
# Database Models
class PeerDbModel(PeerMetaData):
    wg_ip_address: str
    public_key: str
    private_key: Optional[str]
    preshared_key: Optional[str]
    persistent_keepalive: int


class VpnDbModel(VpnMetaData):
    wg_ip_address: str
    interface: str
    public_key: str
    private_key: Optional[str]
    listen_port: int
    ssh_connection_info: SshConnectionModel
    peers: List[PeerDbModel] = []
