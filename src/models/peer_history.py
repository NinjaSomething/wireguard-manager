from pydantic import Field

from models.peers import PeerResponseModel


class PeerHistoryResponseModel(PeerResponseModel):
    timestamp: int = Field(..., description="The timestamp of when the peer history was updated.")
    changed_by: str = Field(..., description="The user that made the change.")
    message: str = Field(..., description="The reason for the change.")
