from pydantic import BaseModel, Field, SecretStr, PrivateAttr, field_serializer
from typing import Optional


# -----------------------------------------------------------
# API Request Models
class PeerRequestModel(BaseModel):
    ip_address: Optional[str] = Field(
        None,
        description="The wireguard IP address of the peer.  If not provided, the next available IP on the VPN will be used.",
    )
    allowed_ips: list[str] = Field(..., description="This defines the IPs that are allowed ")
    public_key: str | None = Field(
        None,
        description="The public wireguard key for the peer.  If this is not provide the key-pair will be auto "
        "generated.",
    )
    private_key: str | None = Field(None, description="The private wireguard key for the peer.")
    persistent_keepalive: int = Field(..., description="The wireguard keep-alive configuration for the peer.")
    tags: list[str] = Field(..., description="Tags associated with the wireguard peer.")


# -----------------------------------------------------------
# Database Models
class PeerResponseModel(BaseModel):
    _opaque: bool = PrivateAttr(default=True)

    ip_address: str = Field(..., description="The wireguard IP address of the peer")
    allowed_ips: list[str] = Field(..., description="This defines the IPs that are allowed ")
    public_key: str = Field(..., description="The public wireguard key for the peer")
    private_key: Optional[SecretStr] = Field(None, description="The private wireguard key for the peer.")
    persistent_keepalive: int = Field(..., description="The wireguard keep-alive configuration for the peer.")
    tags: list[str] = Field(..., description="Tags associated with the wireguard peer.")

    @property
    def opaque(self):
        return self._opaque

    @opaque.setter
    def opaque(self, value: bool) -> None:
        # here you can implement custom logic, like propagating to children models for example (my case)
        self._opaque = value

    @field_serializer("private_key", when_used="json")
    def dump_secret_json(self, secret: SecretStr):
        if self._opaque:
            return secret
        else:
            return secret.get_secret_value() if secret is not None else None


class PeerDbModel(PeerRequestModel):
    peer_id: str = Field(..., description="This is the unique database ID for the peer.")
