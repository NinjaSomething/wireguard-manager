from pydantic import BaseModel, Field
from typing import Optional


# -----------------------------------------------------------
# API Request Models
class PeerRequestModel(BaseModel):
    ip_address: Optional[str] = Field(
        None,
        description="The wireguard IP address of the peer.  If not provided, the next available IP on the VPN will be used.",
    )
    allowed_ips: str = Field(..., description="This defines the IPs that are allowed ")
    public_key: Optional[str] = Field(
        None,
        description="The public wireguard key for the peer.  I this is not provide the key-pair will be auto generated.",
    )
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


class PeerDbModel(PeerModel):
    peer_id: str = Field(..., description="This is the unique database ID for the peer.")
