from pydantic import BaseModel, Field
from typing import Optional, List


class VpnMetaData(BaseModel):
    name: Optional[str] = Field(..., description="The name of the wireguard VPN")
    description: Optional[str] = Field(..., description="A description of the wireguard VPN")


# -----------------------------------------------------------
# Models for the SSH class
class SshConnectionModel(BaseModel):
    ip_address: str = Field(..., description="The IP address SSH will use to connect to the VPN server")
    username: str = Field(..., description="The SSH username")
    key: str = Field(..., description="The SSH private key")
    key_password: Optional[str] = Field(None, description="The password for the SSH private key")


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
class WireguardRequestModel(BaseModel):
    ip_address: str = Field(..., description="The wireguard IP address")
    address_space: str = Field(..., description="The subnet for the wireguard VPN. E.g. 10.0.0.0/16")
    interface: str = Field(..., description="The wireguard interface name")
    public_key: str = Field(..., description="The wireguard public key")
    private_key: str = Field(..., description="The wireguard private key")
    listen_port: int = Field(..., description="The wireguard listen port")


class VpnPutRequestModel(BaseModel):
    wireguard: WireguardRequestModel = Field(
        ..., description="This contains all the wireguard configuration for the VPN server"
    )
    ssh_connection_info: Optional[SshConnectionModel] = Field(
        None,
        description="This contains all the SSH information required for this service to manage the VPN server. If "
        "provided, this service will add and remove peers from the VPN server itself.",
    )


class PeerRequestModel(BaseModel):
    ip_address: Optional[str] = Field(
        None,
        description="The wireguard IP address of the peer.  If not provided, the next available IP on the VPN will be used.",
    )
    allowed_ips: str = Field(..., description="This defines the IPs that are allowed ")
    public_key: str = Field(..., description="The public wireguard key for the peer")
    private_key: Optional[str] = Field(None, description="The private wireguard key for the peer.")
    persistent_keepalive: int = Field(..., description="The wireguard keep-alive configuration for the peer.")
    tags: list[str] = Field(..., description="Tags associated with the wireguard peer.")


# -----------------------------------------------------------
# Database Models
class PeerModel(BaseModel):
    ip_address: str = Field(..., description="The wireguard IP address of the peer")
    allowed_ips: str = Field(..., description="This defines the IPs that are allowed ")
    public_key: str = Field(..., description="The public wireguard key for the peer")
    private_key: Optional[str] = Field(None, description="The private wireguard key for the peer.")
    persistent_keepalive: int = Field(..., description="The wireguard keep-alive configuration for the peer.")
    tags: list[str] = Field(..., description="Tags associated with the wireguard peer.")


class VpnModel(VpnPutRequestModel, VpnMetaData):
    pass
