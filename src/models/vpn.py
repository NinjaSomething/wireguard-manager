from pydantic import BaseModel, Field
from typing import Optional, List
from models.ssh import SshConnectionModel


class VpnMetaData(BaseModel):
    name: Optional[str] = Field(..., description="The name of the wireguard VPN")
    description: Optional[str] = Field(..., description="A description of the wireguard VPN")


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


# -----------------------------------------------------------
# Database Models
class VpnModel(VpnPutRequestModel, VpnMetaData):
    pass
