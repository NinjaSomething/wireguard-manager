from enum import Enum

from .cognito import CognitoAuthWireguardAPI
from .unauthenticated import WireguardAPI


class AuthProvider(str, Enum):
    NONE = "none"
    COGNITO = "cognito"
