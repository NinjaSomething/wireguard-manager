class DynamoUpdatePeerException(Exception):
    """Custom exception for errors during peer updates."""


class DynamoAddPeerException(Exception):
    """Custom exception for errors during peer additions."""


class DynamoUpdateConnectionInfoException(Exception):
    """Custom exception for errors during Connection info updates."""


class DynamoDeletePeerException(Exception):
    """Custom exception for errors during peer deletions."""


class DynamoAddVpnException(Exception):
    """Custom exception for errors during VPN additions."""


class DynamoDeleteVpnException(Exception):
    """Custom exception for errors during VPN deletions."""


class DynamoRecordHistoryException(Exception):
    """Custom exception for errors when recording history."""
