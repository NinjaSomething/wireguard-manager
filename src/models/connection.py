from pydantic import BaseModel, Field

from models import OpaqueModel


# Generic model for connection requests
class ConnectionModel(BaseModel):
    pass


class ConnectionResponseModel(ConnectionModel, OpaqueModel):
    pass
