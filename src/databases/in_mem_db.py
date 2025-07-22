from databases.interface import AbstractDatabase
from models.vpn import WireguardModel, VpnModel
from models.peers import PeerDbModel
from models.wireguard_connection import WireguardConnectionModel, WireguardConnectionType
from vpn_manager.vpn import VpnServer
from vpn_manager.peers import PeerList, Peer


class InMemoryDataStore(AbstractDatabase):
    def __init__(self):
        self._vpn_networks: dict[str, VpnModel] = {}
        self._vpn_peers: dict[str, list[PeerDbModel]] = {}

    def tables_exist(self, create_table: bool = True) -> bool:
        """Return true if the required tables exist in the database.  If create_table is true, auto create the tables."""
        pass

    def get_all_vpn(self) -> dict[str, VpnServer]:
        """Return a copy of all the VPN networks."""
        return {name: self.get_vpn(name) for name in self._vpn_networks.keys()}

    def get_vpn(self, name) -> VpnServer | None:
        """Return a VPN network by name.  If it doesn't exist, return None."""
        if name in self._vpn_networks:
            stored_vpn = self._vpn_networks[name]
            peer_list = PeerList(vpn_name="test", db_interface=self)
            vpn = VpnServer(
                database=self,
                name=name,
                description=stored_vpn.description,
                ip_address=stored_vpn.wireguard.ip_address,
                address_space=stored_vpn.wireguard.address_space,
                interface=stored_vpn.wireguard.interface,
                public_key=stored_vpn.wireguard.public_key,
                private_key=stored_vpn.wireguard.private_key,
                listen_port=stored_vpn.wireguard.listen_port,
                connection_info=stored_vpn.connection_info,
                peers=peer_list,
            )
            return vpn
        else:
            return None

    def add_vpn(self, new_vpn: VpnServer):
        """Add a new VPN network to the database.  If it already exists, raise a ValueError exception."""
        self._vpn_networks[new_vpn.name] = VpnModel(
            name=new_vpn.name,
            description=new_vpn.description,
            wireguard=WireguardModel(
                ip_address=new_vpn.ip_address,
                address_space=new_vpn.address_space,
                interface=new_vpn.interface,
                public_key=new_vpn.public_key,
                private_key=new_vpn.private_key,
                listen_port=new_vpn.listen_port,
            ),
            connection_info=new_vpn.connection_info,
        )
        self._vpn_peers[new_vpn.name] = []

    def delete_vpn(self, name: str):
        """Remove a VPN network from the database."""
        if name in self._vpn_networks:
            del self._vpn_networks[name]

    def add_peer(self, vpn_name: str, peer: PeerDbModel):
        """Add a new peer to the database."""
        self._vpn_peers[vpn_name].append(peer)

    def delete_peer(self, vpn_name: str, peer: PeerDbModel):
        if vpn_name in self._vpn_peers:
            if peer in self._vpn_peers[vpn_name]:
                self._vpn_peers[vpn_name].remove(peer)

    def get_peers(self, vpn_name: str) -> list[Peer]:
        """Return a list of peers for a given VPN network."""
        result = []
        if vpn_name in self._vpn_peers:
            for stored_peer in self._vpn_peers[vpn_name]:
                peer = Peer(
                    peer_id=stored_peer.peer_id,
                    public_key=stored_peer.public_key,
                    ip_address=stored_peer.ip_address,
                    private_key=stored_peer.private_key,
                    allowed_ips=stored_peer.allowed_ips,
                    persistent_keepalive=stored_peer.persistent_keepalive,
                    tags=stored_peer.tags,
                )
                result.append(peer)
        return result

    def get_peer(self, vpn_name: str, peer_ip: str) -> Peer | None:
        """Return a specific peer from the database.  If the peer does not exist, return None."""
        for peer in self.get_peers(vpn_name):
            if peer.ip_address == peer_ip:
                return peer
        return None

    def add_tag_to_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Add a tag to a peer."""
        peer = self.get_peer(vpn_name, peer_ip)
        if peer is not None and tag not in peer.tags:
            peer.tags.append(tag)

    def delete_tag_from_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Delete tag from a peer."""
        peer = self.get_peer(vpn_name, peer_ip)
        if peer is not None and tag in peer.tags:
            peer.tags.remove(tag)

    def update_connection_info(self, vpn_name: str, connection_info: WireguardConnectionModel):
        """Update the connection info"""
        self._vpn_networks[vpn_name].connection_info = connection_info
