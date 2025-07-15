from pydantic import BaseModel, Field, SecretStr, PrivateAttr, field_serializer, model_serializer
from typing import Optional, List


# Models for the SSH class
class SshConnectionModel(BaseModel):
    _opaque: bool = PrivateAttr(default=True)

    ip_address: str = Field(..., description="The IP address SSH will use to connect to the VPN server")
    username: str = Field(..., description="The SSH username")
    key: SecretStr = Field(..., description="The SSH private key")
    key_password: Optional[SecretStr] = Field(None, description="The password for the SSH private key")

    @property
    def opaque(self):
        return self._opaque

    @opaque.setter
    def opaque(self, value: bool) -> None:
        # here you can implement custom logic, like propagating to children models for example (my case)
        self._opaque = value

    @field_serializer("key")
    @field_serializer("key_password")
    def dump_secret_json(self, secret: SecretStr):
        if self._opaque:
            return secret
        else:
            return secret.get_secret_value() if secret is not None else None
