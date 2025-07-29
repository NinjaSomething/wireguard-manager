from pydantic import BaseModel, Field, SecretStr, field_serializer, field_validator
from fastapi import HTTPException
from http import HTTPStatus
import ipaddress
from typing import Optional
from models.wireguard_connection import ConnectionModel, ConnectionResponseModel
from models import OpaqueModel


class VpnMetaData(BaseModel):
    name: Optional[str] = Field(..., description="The name of the wireguard VPN")
    description: Optional[str] = Field(..., description="A description of the wireguard VPN")


class WireguardModel(BaseModel):
    ip_address: str = Field(..., description="The wireguard server IP address.", examples=["10.0.0.1"])
    ip_network: str = Field(
        ...,
        description="The ip network for the wireguard VPN. This must use the CIDR notation",
        examples=["10.0.0.1/24"],
    )
    interface: str = Field(..., description="The wireguard interface name", examples=["wg0"])
    public_key: str = Field(
        ..., description="The wireguard public key", examples=["knXNHhRRgFQVBSTD60c81oqbFvslnpzAx5Y0/rrJuBY="]
    )
    private_key: str = Field(
        ..., description="The wireguard private key", examples=["8NJdfUxW1deRmrGLW+yVFxH0xCKmfOqxyQCw9O5J4mI="]
    )
    listen_port: int = Field(..., description="The wireguard listen port", examples=[40000])

    @field_validator("ip_network")
    def validate_ip_address(cls, v):
        try:
            ipaddress.ip_network(v)
        except ValueError:
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=f"Invalid Address Space: {v}")
        return v


class VpnPutModel(BaseModel):
    wireguard: WireguardModel = Field(
        ..., description="This contains all the wireguard configuration for the VPN server"
    )
    connection_info: Optional[ConnectionModel] = Field(
        None,
        description="This contains all the information required for this service to manage the VPN server. If "
        "provided, this service will add and remove peers from the VPN server itself.",
    )


# -----------------------------------------------------------
# API Response Models
class WireguardResponseModel(WireguardModel, OpaqueModel):
    private_key: SecretStr = Field(..., description="The wireguard private key")

    @field_serializer("private_key", when_used="json")
    def dump_secret_json(self, secret: SecretStr):
        if self._opaque:
            return secret
        else:
            return secret.get_secret_value() if secret is not None else None


class VpnPutResponseModel(BaseModel):
    wireguard: WireguardResponseModel = Field(
        ..., description="This contains all the wireguard configuration for the VPN server"
    )
    connection_info: Optional[ConnectionResponseModel] = Field(
        None,
        description="This contains all the information required for this service to manage the VPN server. If "
        "provided, this service will add and remove peers from the VPN server itself.",
    )


# -----------------------------------------------------------
# Database Models
class VpnResponseModel(VpnPutResponseModel, VpnMetaData):
    @property
    def opaque(self):
        return self.wireguard.opaque

    @opaque.setter
    def opaque(self, value: bool) -> None:
        self.wireguard.opaque = value
        if self.connection_info is not None:
            self.connection_info.data.opaque = value


class VpnModel(VpnPutModel, VpnMetaData):
    pass
