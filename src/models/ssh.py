from pydantic import BaseModel, Field
from typing import Optional, List


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
