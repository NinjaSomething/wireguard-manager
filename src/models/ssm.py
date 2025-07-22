from pydantic import Field, SecretStr, field_serializer
from typing import Optional

from models.connection import ConnectionModel, ConnectionResponseModel


# Models for the SSM class
class SsmConnectionModel(ConnectionModel):
    target_id: str = Field(..., description="The ID of the EC2 instance to connect to")
    aws_access_key_id: str = Field(..., description="The AWS access key ID")
    aws_secret_access_key: str = Field(..., description="The AWS secret access key")
    region: Optional[str] = Field("us-west-2", description="The AWS region to connect to")


class SsmConnectionResponseModel(SsmConnectionModel, ConnectionResponseModel):
    @field_serializer("aws_access_key_id")
    @field_serializer("aws_secret_access_key")
    def dump_secret_json(self, secret: SecretStr):
        if self._opaque:
            return secret
        else:
            return secret.get_secret_value() if secret is not None else None
