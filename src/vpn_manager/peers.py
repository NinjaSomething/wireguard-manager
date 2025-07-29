from typing import Optional
from databases.interface import AbstractDatabase
from models.peers import PeerResponseModel, PeerDbModel


class Peer:
    def __init__(
        self,
        peer_id: str,
        ip_address: str,
        public_key: str,
        persistent_keepalive: int,
        allowed_ips: str,
        private_key: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ):
        self._peer_id = peer_id
        self._public_key = public_key
        self._allowed_ips = allowed_ips
        self._ip_address = ip_address
        self._private_key = private_key
        self._persistent_keepalive = persistent_keepalive
        self._tags = tags if tags is not None else []

    @property
    def peer_id(self) -> str:
        return self._peer_id

    @property
    def ip_address(self) -> str:
        return self._ip_address

    @property
    def allowed_ips(self) -> str:
        return self._allowed_ips

    @property
    def public_key(self) -> str:
        return self._public_key

    @public_key.setter
    def public_key(self, public_key: str):
        self._public_key = public_key

    @property
    def private_key(self) -> Optional[str]:
        return self._private_key

    @private_key.setter
    def private_key(self, private_key: str):
        self._private_key = private_key

    @property
    def persistent_keepalive(self) -> int:
        return self._persistent_keepalive

    @property
    def tags(self) -> list[str]:
        return self._tags

    def to_model(self) -> PeerResponseModel:
        return PeerResponseModel(
            ip_address=self._ip_address,
            allowed_ips=self._allowed_ips,
            public_key=self._public_key,
            private_key=self._private_key,
            persistent_keepalive=self._persistent_keepalive,
            tags=self._tags,
        )

    def to_db_model(self) -> PeerDbModel:
        return PeerDbModel(
            peer_id=self._peer_id,
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
        self.db_interface.add_peer(vpn_name=self.vpn_name, peer=value.to_db_model())
        super().append(value)

    def remove(self, value: Peer):
        self.db_interface.delete_peer(vpn_name=self.vpn_name, peer=value.to_db_model())
        super().remove(value)

    def clear(self):
        """Clear the peer list and remove all peers from the database."""
        for peer in self:
            self.db_interface.delete_peer(vpn_name=self.vpn_name, peer=peer.to_db_model())
        super().clear()

    def to_model(self) -> list[PeerResponseModel]:
        """Convert the peer list to a list of PeerResponseModel."""
        return [peer.to_model() for peer in self]
