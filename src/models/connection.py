from pydantic import BaseModel, Field

from models import OpaqueModel


# Generic model for connection requests
class ConnectionModel(BaseModel):
    target: str = Field(..., description="The IP/host address to connect to the VPN server")


class ConnectionResponseModel(ConnectionModel, OpaqueModel):
    pass
