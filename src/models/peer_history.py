from pydantic import Field

from models.peers import PeerResponseModel


class PeerHistoryResponseModel(PeerResponseModel):
    timestamp: int = Field(..., description="The timestamp of when the peer history was updated.")
