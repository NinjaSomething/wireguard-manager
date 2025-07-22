from pydantic import Field, SecretStr, field_serializer
from typing import Optional

from models.connection import ConnectionModel, ConnectionResponseModel


# Models for the SSH class
class SshConnectionModel(ConnectionModel):
    username: str = Field(..., description="The SSH username")
    key: str = Field(..., description="The SSH private key")
    key_password: Optional[str] = Field(None, description="The password for the SSH private key")


class SshConnectionResponseModel(SshConnectionModel, ConnectionResponseModel):
    key: SecretStr = Field(..., description="The SSH private key")

    @field_serializer("key")
    @field_serializer("key_password")
    def dump_secret_json(self, secret: SecretStr):
        if self._opaque:
            return secret
        else:
            return secret.get_secret_value() if secret is not None else None
