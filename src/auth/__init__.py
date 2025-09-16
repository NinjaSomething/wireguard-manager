from enum import Enum

from .cognito import CognitoAuthWireguardManagerAPI
from .unauthenticated import WireguardManagerAPI


class AuthProvider(str, Enum):
    NONE = "none"
    COGNITO = "cognito"
