import abc
from copy import deepcopy
from databases.interface import AbstractDatabase
from models.vpn import VpnModel
from models.peers import PeerDbModel
from models.connection import ConnectionModel


class InMemoryDataStore(AbstractDatabase):
    def __init__(self):
        self._vpn_networks: dict[str, VpnModel] = {}
        self._vpn_peers: dict[str, list[PeerDbModel]] = {}
        self._init_vpn_from_db()
        self._init_peers_from_db()

    def _init_vpn_from_db(self):
        """Get existing VPNs from DynamoDb and add them to the in-memory datastore."""
        all_vpns = self._get_all_vpn_from_server()
        for vpn in all_vpns:
            self._vpn_networks[vpn.name] = vpn
            self._vpn_peers[vpn.name] = []

    def _init_peers_from_db(self):
        """Get existing Peers from DynamoDb and add them to the in-memory datastore."""
        self._vpn_peers = self._get_all_peers_from_server()

    @abc.abstractmethod
    def _get_all_vpn_from_server(self) -> list[VpnModel]:
        """Fetch all the VPN networks from the database server."""
        pass

    @abc.abstractmethod
    def _get_all_peers_from_server(self) -> dict[str, list[PeerDbModel]]:
        """Fetch all the peers from the database server."""
        pass

    def tables_exist(self, create_table: bool = True) -> bool:
        """Return true if the required tables exist in the database.  If create_table is true, auto create the tables."""
        pass

    def get_all_vpn(self) -> dict[str, VpnModel]:
        """Return a copy of all the VPN networks."""
        return {name: self.get_vpn(name) for name in self._vpn_networks.keys()}

    def get_vpn(self, name) -> VpnModel | None:
        """Return a VPN network by name.  If it doesn't exist, return None."""
        return self._vpn_networks.get(name)

    def add_vpn(self, new_vpn: VpnModel):
        """Add a new VPN network to the database.  If it already exists, raise a ValueError exception."""
        self._vpn_networks[new_vpn.name] = new_vpn
        self._vpn_peers[new_vpn.name] = []

    def delete_vpn(self, name: str):
        """Remove a VPN network from the database."""
        if name in self._vpn_networks:
            del self._vpn_networks[name]

    def add_peer(self, vpn_name: str, peer: PeerDbModel):
        """Add a new peer to the database."""
        if peer in self._vpn_peers[vpn_name]:
            raise ValueError("Duplicate peer")
        self._vpn_peers[vpn_name].append(peer)

    def delete_peer(self, vpn_name: str, peer: PeerDbModel):
        if vpn_name in self._vpn_peers:
            if peer in self._vpn_peers[vpn_name]:
                self._vpn_peers[vpn_name].remove(peer)

    def get_peers(self, vpn_name: str) -> list[PeerDbModel]:
        """Return a list of peers for a given VPN network."""
        if vpn_name in self._vpn_peers:
            return deepcopy(self._vpn_peers[vpn_name])
        return []

    def get_peers_by_tag(self, vpn_name: str, tag: str) -> list[PeerDbModel]:
        """Return a list of peers for a given VPN network by tag."""
        matching_tags = []
        _peers = self.get_peers(vpn_name)
        if _peers is None:
            return []
        else:
            for peer in _peers:
                if tag in peer.tags:
                    matching_tags.append(peer)
        return matching_tags

    def get_peer(self, vpn_name: str, peer_ip: str) -> PeerDbModel | None:
        """Return a specific peer from the database.  If the peer does not exist, return None."""
        for peer in self.get_peers(vpn_name):
            if peer.ip_address == peer_ip:
                return peer
        return None

    def add_tag_to_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Add a tag to a peer."""
        if vpn_name in self._vpn_peers:
            for peer in self._vpn_peers[vpn_name]:
                if peer.ip_address == peer_ip:
                    if peer is not None and tag not in peer.tags:
                        peer.tags.append(tag)

    def delete_tag_from_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Delete tag from a peer."""
        if vpn_name in self._vpn_peers:
            for peer in self._vpn_peers[vpn_name]:
                if peer.ip_address == peer_ip:
                    if peer is not None and tag in peer.tags:
                        peer.tags.remove(tag)

    def update_connection_info(self, vpn_name: str, connection_info: ConnectionModel):
        """Update the connection info"""
        self._vpn_networks[vpn_name].connection_info = connection_info
