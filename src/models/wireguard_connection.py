from pydantic import BaseModel
from enum import Enum

from models.ssh import SshConnectionModel, SshConnectionResponseModel
from models.ssm import SsmConnectionModel, SsmConnectionResponseModel

"""
This module contains pydantic modules for how the wireguard manager should manage (add/remove peers) from the
wireguard server
"""


class WireguardConnectionType(str, Enum):
    """This is an enumerations of the supported connection types"""

    SSH = "ssh"
    SSM = "ssm"


class WireguardConnectionModel(BaseModel):
    """
    This model includes all the information required to connect to the wireguard server.  The data field is generic.
    """

    type: WireguardConnectionType
    data: SshConnectionModel | SsmConnectionModel


class WireguardConnectionResponseModel(BaseModel):
    """
    This model includes all the information required to connect to the wireguard server.  The data field is generic.
    """

    type: WireguardConnectionType
    data: SshConnectionResponseModel | SsmConnectionResponseModel


def build_wireguard_connection_model(connection_info: dict | None) -> WireguardConnectionModel | None:
    """This will build a WireguardConnectionModel object of the appropriate type"""
    if not connection_info:
        return None

    match connection_info["type"]:
        case WireguardConnectionType.SSH:
            data = SshConnectionModel(**connection_info["data"])
        case WireguardConnectionType.SSM:
            data = SsmConnectionModel(**connection_info["data"])
        case _:
            raise Exception(f"Unknown connection type {connection_info['type']}")
    return WireguardConnectionModel(type=connection_info["type"], data=data)
