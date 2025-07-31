from pydantic import Field, SecretStr, field_serializer, BaseModel
from typing import Optional

from models import OpaqueModel


# Models for the SSH class
class SshConnectionModel(BaseModel):
    ip_address: str = Field(..., description="The IP address SSH will use to connect to the VPN server")
    username: str = Field(..., description="The SSH username")
    key: str = Field(..., description="The SSH private key")
    key_password: Optional[str] = Field(None, description="The password for the SSH private key")


class SshConnectionResponseModel(SshConnectionModel, OpaqueModel):
    key: SecretStr = Field(..., description="The SSH private key")

    @field_serializer("key")
    @field_serializer("key_password")
    def dump_secret_json(self, secret: SecretStr):
        if self._opaque:
            return secret
        else:
            return secret.get_secret_value() if secret is not None else None
