from __future__ import annotations

import abc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from databases.dynamodb import PeerHistoryDynamoModel
    from models.connection import ConnectionModel
    from models.peers import PeerDbModel
    from models.vpn import VpnModel


class AbstractDatabase(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def tables_exist(self, create_table: bool = True) -> bool:
        """Return true if the required tables exist in the database.  If create_table is true, auto create the tables."""
        pass

    @abc.abstractmethod
    def get_all_vpn(self) -> dict[str, VpnModel]:
        """Return a copy of all the VPN networks."""
        pass

    @abc.abstractmethod
    def get_vpn(self, name) -> VpnModel | None:
        """Return a VPN network by name.  If it doesn't exist, return None."""
        pass

    @abc.abstractmethod
    def add_vpn(self, new_vpn: VpnModel):
        """Add a new VPN network to the database.  If it already exists, raise a ValueError exception."""
        pass

    @abc.abstractmethod
    def delete_vpn(self, name: str):
        """Remove a VPN network from the database."""
        pass

    @abc.abstractmethod
    def add_peer(self, vpn_name: str, peer: PeerDbModel, changed_by: str):
        """Add a new peer to the database.  If it already exists, raise a ValueError exception."""
        pass

    @abc.abstractmethod
    def update_peer(self, vpn_name: str, updated_peer: PeerDbModel, changed_by: str):
        """Update an existing peer in the database.  If the peer does not exist, raise a ValueError exception."""
        pass

    @abc.abstractmethod
    def delete_peer(self, vpn_name: str, peer: PeerDbModel, changed_by: str):
        """Remove a peer from the database."""
        pass

    @abc.abstractmethod
    def get_peers(self, vpn_name: str) -> list[PeerDbModel]:
        """Return a list of peers for a given VPN network."""
        pass

    @abc.abstractmethod
    def get_peers_by_tag(self, vpn_name: str, tag: str) -> list[PeerDbModel]:
        """Return a list of peers for a given VPN network by tag."""
        pass

    @abc.abstractmethod
    def get_peer(self, vpn_name: str, peer_ip: str) -> PeerDbModel:
        """Return a specific peer from the database.  If the peer does not exist, return None."""
        pass

    @abc.abstractmethod
    def update_connection_info(self, vpn_name: str, connection_info: ConnectionModel):
        """Update the connection info"""
        pass

    @abc.abstractmethod
    def get_tag_history(
        self, vpn_name: str, tag: str, start_time: str = None, end_time: str = None
    ) -> dict[str, list[PeerHistoryDynamoModel]]:
        """Return a list of peer history for a given tag in a VPN network."""
        pass

    @abc.abstractmethod
    def get_peer_history(
        self, vpn_name: str, ip_address: str, start_time: str = None, end_time: str = None
    ) -> list[PeerHistoryDynamoModel]:
        """Return a list of peer history for a given peer in a VPN network."""
        pass
