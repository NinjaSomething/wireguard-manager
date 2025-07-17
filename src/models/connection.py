from pydantic import BaseModel
from enum import Enum
from models.ssh import SshConnectionModel, SshConnectionResponseModel

"""
This module contains pydantic modules for how the wireguard manager should manage (add/remove peers) from the 
wireguard server
"""


class ConnectionType(str, Enum):
    """This is an enumerations of the supported connection types"""

    SSH = "ssh"


class ConnectionModel(BaseModel):
    """
    This model includes all the information required to connect to the wireguard server.  The data field is generic.
    """

    type: ConnectionType
    data: SshConnectionModel


class ConnectionResponseModel(BaseModel):
    """
    This model includes all the information required to connect to the wireguard server.  The data field is generic.
    """

    type: ConnectionType
    data: SshConnectionResponseModel


def build_connection_model(connection_info: dict | None) -> ConnectionModel | None:
    """This will build a ConnectionModel object of the appropriate type"""
    if not connection_info:
        return None

    match connection_info["type"]:
        case ConnectionType.SSH:
            data = SshConnectionModel(**connection_info["data"])
        case _:
            raise Exception(f"Unknown connection type {connection_info['type']}")
    return ConnectionModel(type=connection_info["type"], data=data)
