from pydantic import Field, SecretStr, field_serializer, BaseModel
from typing import Optional

from models import OpaqueModel


# Models for the SSM class
class SsmConnectionModel(BaseModel):
    target_id: str = Field(..., description="The ID of the EC2 instance to connect to")
    aws_access_key_id: Optional[str] = Field(None, description="The AWS access key ID")
    aws_secret_access_key: Optional[str] = Field(None, description="The AWS secret access key")
    region: Optional[str] = Field("us-west-2", description="The AWS region to connect to")


class SsmConnectionResponseModel(SsmConnectionModel, OpaqueModel):
    aws_access_key_id: SecretStr = Field(..., description="The AWS access key ID")
    aws_secret_access_key: SecretStr = Field(..., description="The AWS secret access key")

    @field_serializer("aws_access_key_id", "aws_secret_access_key")
    def dump_secret_json(self, secret: SecretStr):
        if self._opaque:
            return secret
        else:
            return secret.get_secret_value() if secret is not None else None
