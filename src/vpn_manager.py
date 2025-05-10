import ipaddress
from vpn import VpnServer
from databases.interface import AbstractDatabase
from peers import PeerList, Peer
from models.vpn import VpnPutRequestModel


class VpnManager:
    def __init__(self, db_manager: AbstractDatabase):
        self._db_manager = db_manager
        self._vpn_networks: dict[str, VpnServer] = {}
        self._initialize_from_db()

    def _initialize_from_db(self):
        all_vpn = self._db_manager.get_all_vpn()
        for name, vpn in all_vpn.items():
            self._vpn_networks[name] = vpn

    def add_vpn(self, name: str, description: str, vpn_request: VpnPutRequestModel):
        # TODO: Verify the ssh ip_address isn't already being used by another VPN
        if name in self._vpn_networks:
            raise ValueError(f"VPN with name {name} already exists.")

        # Validate the IP address space.  ValueError will be raised if the address space is invalid.
        ipaddress.ip_network(vpn_request.wireguard.address_space).hosts()

        vpn = VpnServer(
            name=name,
            description=description,
            ip_address=vpn_request.wireguard.ip_address,
            address_space=vpn_request.wireguard.address_space,
            interface=vpn_request.wireguard.interface,
            public_key=vpn_request.wireguard.public_key,
            private_key=vpn_request.wireguard.private_key,
            listen_port=vpn_request.wireguard.listen_port,
            ssh_connection_info=vpn_request.ssh_connection_info,
            peers=PeerList(name, self._db_manager),
        )
        if vpn_request.wireguard.ip_address not in vpn.all_ip_addresses:
            raise ValueError(
                f"IP address {vpn_request.wireguard.ip_address} is not in the address space {vpn_request.wireguard.address_space}."
            )
        self._db_manager.add_vpn(vpn)
        self._vpn_networks[vpn.name] = vpn

    def get_vpn(self, name: str) -> VpnServer | None:
        if name not in self._vpn_networks:
            return None
        return self._vpn_networks[name]

    def remove_vpn(self, name: str):
        if name in self._vpn_networks:
            self._db_manager.delete_vpn(name)
            del self._vpn_networks[name]

    def get_peers_by_ip(self, vpn_name: str, ip_address: str) -> Peer | None:
        if vpn_name not in self._vpn_networks:
            return None

        vpn = self._vpn_networks[vpn_name]
        for peer in vpn.peers:
            if ip_address == peer.ip_address:
                return peer
        return None

    def get_peers_by_tag(self, vpn_name: str, tag: str) -> list[Peer]:
        matching_tags = []
        if vpn_name not in self._vpn_networks:
            return []

        vpn = self._vpn_networks[vpn_name]
        for peer in vpn.peers:
            if tag in peer.tags:
                matching_tags.append(peer)
        return matching_tags

    def delete_peer(self, vpn_name: str, ip_address: str):
        if vpn_name not in self._vpn_networks:
            return

        vpn = self._vpn_networks[vpn_name]
        peer = self.get_peers_by_ip(vpn_name, ip_address)
        if peer:
            vpn.peers.remove(peer)
            self._db_manager.delete_peer(vpn_name, peer.to_model())
