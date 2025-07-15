from pydantic import BaseModel, Field, SecretStr, PrivateAttr, field_serializer
from typing import Optional, List
from models.connection import ConnectionModel


class VpnMetaData(BaseModel):
    name: Optional[str] = Field(..., description="The name of the wireguard VPN")
    description: Optional[str] = Field(..., description="A description of the wireguard VPN")


# -----------------------------------------------------------
# API Request Models
class WireguardRequestModel(BaseModel):
    _opaque: bool = PrivateAttr(default=True)

    ip_address: str = Field(..., description="The wireguard IP address")
    address_space: str = Field(..., description="The subnet for the wireguard VPN. E.g. 10.0.0.0/16")
    interface: str = Field(..., description="The wireguard interface name")
    public_key: str = Field(..., description="The wireguard public key")
    private_key: SecretStr = Field(..., description="The wireguard private key")
    listen_port: int = Field(..., description="The wireguard listen port")

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


class VpnPutRequestModel(BaseModel):
    wireguard: WireguardRequestModel = Field(
        ..., description="This contains all the wireguard configuration for the VPN server"
    )
    connection_info: Optional[ConnectionModel] = Field(
        None,
        description="This contains all the information required for this service to manage the VPN server. If "
        "provided, this service will add and remove peers from the VPN server itself.",
    )


# -----------------------------------------------------------
# Database Models
class VpnModel(VpnPutRequestModel, VpnMetaData):
    @property
    def opaque(self):
        return self.wireguard.opaque

    @opaque.setter
    def opaque(self, value: bool) -> None:
        self.wireguard.opaque = value
        if self.connection_info is not None:
            self.connection_info.data.opaque = value
