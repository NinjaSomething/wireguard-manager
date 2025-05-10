from typing import Optional
from databases.interface import AbstractDatabase
from models.vpn import PeerModel


class Peer:
    def __init__(
        self,
        ip_address: str,
        public_key: str,
        persistent_keepalive: int,
        allowed_ips: str,
        private_key: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ):
        self._public_key = public_key
        self._allowed_ips = allowed_ips
        self._ip_address = ip_address
        self._private_key = private_key
        self._persistent_keepalive = persistent_keepalive
        self._tags = tags if tags is not None else []

    @property
    def ip_address(self) -> str:
        return self._ip_address

    @property
    def allowed_ips(self) -> str:
        return self._allowed_ips

    @property
    def public_key(self) -> str:
        return self._public_key

    @property
    def private_key(self) -> Optional[str]:
        return self._private_key

    @property
    def persistent_keepalive(self) -> int:
        return self._persistent_keepalive

    @property
    def tags(self) -> list[str]:
        return self._tags

    def to_model(self) -> PeerModel:
        return PeerModel(
            ip_address=self._ip_address,
            allowed_ips=self._allowed_ips,
            public_key=self._public_key,
            private_key=self._private_key,
            persistent_keepalive=self._persistent_keepalive,
            tags=self._tags,
        )


class PeerList(list):
    def __init__(self, vpn_name: str, db_interface: AbstractDatabase):
        super().__init__()
        self.vpn_name = vpn_name
        self.db_interface = db_interface
        self.initialize_from_db()

    def initialize_from_db(self):
        """Initialize the peer list from the database."""
        peers = self.db_interface.get_peers(vpn_name=self.vpn_name)
        for peer in peers:
            super().append(peer)

    def append(self, value: Peer):
        self.db_interface.add_peer(vpn_name=self.vpn_name, peer=value.to_model())
        super().append(value)

    def remove(self, value: Peer):
        self.db_interface.delete_peer(vpn_name=self.vpn_name, peer=value.to_model())
        super().remove(value)

    def to_model(self) -> list[PeerModel]:
        """Convert the peer list to a list of PeerModel."""
        return [peer.to_model() for peer in self]
