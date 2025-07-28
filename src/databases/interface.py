from __future__ import annotations
import abc
import typing

if typing.TYPE_CHECKING:
    from models.peers import PeerModel
    from vpn_manager.vpn import VpnServer
    from vpn_manager.peers import Peer
    from models.wireguard_connection import ConnectionModel


class AbstractDatabase(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def tables_exist(self, create_table: bool = True) -> bool:
        """Return true if the required tables exist in the database.  If create_table is true, auto create the tables."""
        pass

    @abc.abstractmethod
    def get_all_vpn(self) -> dict[str, VpnServer]:
        """Return a copy of all the VPN networks."""
        pass

    @abc.abstractmethod
    def get_vpn(self, name) -> VpnServer:
        """Return a VPN network by name.  If it doesn't exist, return None."""
        pass

    @abc.abstractmethod
    def add_vpn(self, new_vpn: VpnServer):
        """Add a new VPN network to the database.  If it already exists, raise a ValueError exception."""
        pass

    @abc.abstractmethod
    def delete_vpn(self, name: str):
        """Remove a VPN network from the database."""
        pass

    @abc.abstractmethod
    def add_peer(self, vpn_name: str, peer: PeerModel):
        """Add a new peer to the database.  If it already exists, raise a ValueError exception."""
        pass

    @abc.abstractmethod
    def delete_peer(self, vpn_name: str, peer: PeerModel):
        """Remove a peer from the database."""
        pass

    @abc.abstractmethod
    def get_peers(self, vpn_name: str) -> list[Peer]:
        """Return a list of peers for a given VPN network."""
        pass

    @abc.abstractmethod
    def get_peer(self, vpn_name: str, peer_ip: str) -> Peer:
        """Return a specific peer from the database.  If the peer does not exist, return None."""
        pass

    @abc.abstractmethod
    def add_tag_to_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Add a tag to a peer."""
        pass

    @abc.abstractmethod
    def delete_tag_from_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Delete tag from a peer."""
        pass

    @abc.abstractmethod
    def update_connection_info(self, vpn_name: str, connection_info: ConnectionModel):
        """Update the connection info"""
        pass
