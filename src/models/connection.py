from pydantic import BaseModel, Field
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

    type: ConnectionType = Field(
        ...,
        description="This is used to determine how the wireguard manager will communicate with the wireguard server.  "
        "This is used to add and remove peers.",
    )
    data: SshConnectionModel = Field(
        ..., description="These are the connection details for how to connect to the wireguard server. "
    )


class ConnectionResponseModel(BaseModel):
    """
    This model includes all the information required to connect to the wireguard server.  The data field is generic.
    """

    type: ConnectionType = Field(
        ...,
        description="This is used to determine how the wireguard manager will communicate with the wireguard server.  "
        "This is used to add and remove peers.",
    )
    data: SshConnectionResponseModel = Field(
        ..., description="These are the connection details for how to connect to the wireguard server. "
    )


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
