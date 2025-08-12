import codecs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import logging
import ipaddress
from uuid import uuid4
from databases.interface import AbstractDatabase
from models.connection import ConnectionModel
from models.peers import PeerDbModel, PeerRequestModel
from models.vpn import VpnPutModel, VpnModel
from server_manager import server_manager_factory


log = logging.getLogger(__name__)

"""This module is an interface between the API and the database"""


class VpnUpdateException(Exception):
    """Custom exception for VPN update errors."""

    pass


class ConflictException(Exception):
    """Custom exception for conflicts, such as duplicate entries."""

    pass


class BadRequestException(Exception):
    """Custom exception for bad requests."""

    pass


class VpnManager:
    def __init__(self, db_manager: AbstractDatabase):
        self._db_manager = db_manager

    def add_vpn(self, name: str, description: str, vpn_request: VpnPutModel):
        _vpn = self.get_vpn(name)
        if _vpn is not None:
            raise ValueError(f"VPN with name {name} already exists.")

        for existing_vpn in self.get_all_vpn():
            if existing_vpn.wireguard.public_key == vpn_request.wireguard.public_key:
                raise ValueError(
                    f"A Wireguard VPN using the public key {vpn_request.wireguard.public_key} already exists."
                )

        # Validate the connection info works
        if vpn_request.connection_info is not None:
            server_manager = server_manager_factory(vpn_request.connection_info.type)
            wg_config_data = server_manager.dump_interface_config(
                vpn_request.wireguard.interface, vpn_request.connection_info
            )
            if isinstance(wg_config_data, str):
                raise KeyError(f"SSH information for VPN {name} failed: {wg_config_data}")

        _vpn = VpnModel(**vpn_request.model_dump(), name=name, description=description)
        if vpn_request.wireguard.ip_address not in self.all_ip_addresses(vpn_request.wireguard.ip_network):
            raise ValueError(
                f"IP address {vpn_request.wireguard.ip_address} is not in the address space "
                f"{vpn_request.wireguard.ip_network}."
            )
        self._db_manager.add_vpn(_vpn)

        #  Keep the manager aligned with the wireguard server.  Import existing peers.
        if _vpn.connection_info:
            self.import_peers(name)

    def get_all_vpn(self) -> list[VpnModel]:
        return [_vpn for _vpn in self._db_manager.get_all_vpn().values()]

    def get_vpn(self, name: str) -> VpnModel | None:
        return self._db_manager.get_vpn(name)

    def remove_vpn(self, name: str):
        _vpn = self.get_vpn(name)
        if _vpn is not None:
            self._db_manager.delete_vpn(name)

    def update_connection_info(self, vpn_name: str, connection_info: ConnectionModel | None):
        # Validate the SSH connection info works
        if connection_info is not None:
            _vpn = self.get_vpn(vpn_name)
            server_manager = server_manager_factory(connection_info.type)
            wg_config_data = server_manager.dump_interface_config(_vpn.wireguard.interface, connection_info)
            if isinstance(wg_config_data, str):
                raise KeyError(f"SSH information for VPN {vpn_name} failed: {wg_config_data}")
        self._db_manager.update_connection_info(vpn_name, connection_info)

    @staticmethod
    def all_ip_addresses(ip_network: str) -> list[str]:
        """This will return all the IP addresses in a VPN network."""
        return [str(ip) for ip in set(ipaddress.ip_network(ip_network).hosts())]

    def available_ips(self, vpn_name: str) -> list[str]:
        """This will return all the unused IP addresses in a VPN network."""
        _vpn = self.get_vpn(vpn_name)
        if _vpn is None:
            return []

        used_ips = set([ipaddress.ip_address(peer.ip_address) for peer in self._db_manager.get_peers(vpn_name)])
        used_ips.add(ipaddress.ip_address(_vpn.wireguard.ip_address))  # Include the servers IP as being used

        # Get a list of IPs that are available for use
        available_ips = list(set(ipaddress.ip_network(_vpn.wireguard.ip_network).hosts()) - used_ips)
        available_ips.sort()
        return [str(available_ip) for available_ip in available_ips]

    def get_next_available_ip(self, vpn_name: str) -> str:
        """Get the next available IP address from the pool."""
        available_ips = self.available_ips(vpn_name)
        if not available_ips:
            raise ValueError("No available IP addresses in the pool.")
        return available_ips[0]

    def validate_ip_network(self, vpn_name, peer_allowed_ips: str):
        """Will raise a ValueError if the address space is not valid."""
        if int(peer_allowed_ips.split("/")[1]) < 16:
            # Don't allow a peer to use address spaces larger than /16.  Generating that many IPs is not practical and
            # could crash the service.
            raise ValueError(f"Address space [{peer_allowed_ips}] is too large. Allowed IPs must be /16 or smaller.")
        peer_ip_network = set(ipaddress.ip_network(peer_allowed_ips).hosts())
        _vpn = self.get_vpn(vpn_name)
        if len(list(peer_ip_network - set(ipaddress.ip_network(_vpn.wireguard.ip_network).hosts()))) > 0:
            raise BadRequestException(
                f"Address space [{peer_allowed_ips}] is larger than the address space of the "
                f"VPN server [{_vpn.wireguard.ip_network}]."
            )

    def add_peer(self, vpn_name: str, peer: PeerRequestModel):
        """
        This will add the peer to the database.
        :param vpn_name: The name of the VPN to add the peer to.
        :param peer: The PeerRequestModel containing the peer details.
        :raises ConnectionException: If there is an error connecting to the VPN server
        :raises ConflictException: If the IP address or public key is already being used
        :raises BadRequestException: If the peer's allowed IPs is a larger address space than the one on the VPN server
        :raises BadRequestException: If the peers IP address is outside the VPN address space
        """
        vpn = self.get_vpn(vpn_name)
        # Assign an IP address if not provided
        if peer.ip_address is None:
            peer.ip_address = self.get_next_available_ip(vpn_name)

        if peer.public_key is None:
            # Generate the key-pair
            peer.private_key, peer.public_key = self.generate_wireguard_keys()

        for existing_peer in self.get_all_peers(vpn_name):
            # Verify the IP address is not already in use on this VPN
            if existing_peer.ip_address == peer.ip_address:
                raise ConflictException(f"Peer with IP {peer.ip_address} already exists in VPN {vpn_name}")

            # Verify the Public Key is not already in use on this VPN
            if existing_peer.public_key == peer.public_key:
                raise ConflictException(f"Peer {peer.ip_address} is already using that public key on VPN {vpn_name}")

        # Verify the IP address is available in the VPN address space
        if peer.ip_address not in self.available_ips(vpn_name):
            raise BadRequestException(f"IP address {peer.ip_address} is not available in VPN {vpn_name}")

        # Verify the allowed_ips are within the bounds of the VPN server address space
        self.validate_ip_network(vpn_name, peer.allowed_ips)

        if vpn.connection_info is not None:
            server_manager = server_manager_factory(vpn.connection_info.type)
            server_manager.add_peer(vpn, peer)

        self._db_manager.add_peer(vpn_name=vpn_name, peer=PeerDbModel(**peer.model_dump(), peer_id=str(uuid4())))

    def get_all_peers(self, vpn_name: str) -> list[PeerDbModel]:
        """
        Get all peers for a given VPN.
        :param vpn_name: The name of the VPN to get peers for.
        :return: A list of PeerDbModel objects representing the peers.
        """
        return self._db_manager.get_peers(vpn_name)

    def get_peers_by_ip(self, vpn_name: str, ip_address: str) -> PeerDbModel | None:
        return self._db_manager.get_peer(vpn_name, ip_address)

    def get_peers_by_tag(self, vpn_name: str, tag: str) -> list[PeerDbModel]:
        return self._db_manager.get_peers_by_tag(vpn_name, tag)

    def delete_peer(self, vpn_name: str, ip_address: str):
        """
        This will remove a peer from the wireguard server and the database.  A ConnectionException will be raised if
        this fails to add the peer to the wireguard server.
        """
        peer = self.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)
        if peer is not None:
            vpn = self.get_vpn(vpn_name)
            if vpn.connection_info is not None:
                server_manager = server_manager_factory(vpn.connection_info.type)
                server_manager.remove_peer(vpn, peer)
            self._db_manager.delete_peer(vpn_name, peer)

    @staticmethod
    def generate_wireguard_keys() -> tuple[str, str]:
        """
        Generate a new WireGuard key pair
        :return: (private_key, public_key)
        """
        # generate private key
        private_key = X25519PrivateKey.generate()
        bytes_ = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_str = codecs.encode(bytes_, "base64").decode("utf8").strip()

        # derive public key
        pubkey = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        public_key_str = codecs.encode(pubkey, "base64").decode("utf8").strip()

        return private_key_str, public_key_str

    def generate_new_peer_keys(self, vpn_name: str, ip_address: str):
        """
        This will generate new keys for the peer and update the database.  If the connection_info is set, it will
        also remove the old peer from the wireguard server and add the peer with the new keys.
        :param vpn_name: The name of the VPN the peer is in.
        :param ip_address: The IP address of the peer to update.
        """
        vpn = self.get_vpn(vpn_name)
        peer = self.get_peers_by_ip(vpn_name=vpn_name, ip_address=ip_address)
        if vpn.connection_info is not None:
            server_manager = server_manager_factory(vpn.connection_info.type)
            server_manager.remove_peer(vpn, peer)

        self._db_manager.delete_peer(vpn_name, peer)
        peer.private_key, peer.public_key = self.generate_wireguard_keys()
        self._db_manager.add_peer(vpn_name, peer)

        if vpn.connection_info is not None:
            server_manager.add_peer(vpn, peer)
        return peer

    def import_peers(self, vpn_name: str) -> list[PeerRequestModel]:
        """This downloads the wireguard server peers and imports any that don't already exist."""
        _vpn = self.get_vpn(vpn_name)
        server_manager = server_manager_factory(_vpn.connection_info.type)
        wg_config_data = server_manager.dump_interface_config(_vpn.wireguard.interface, _vpn.connection_info)
        if isinstance(wg_config_data, str):
            raise VpnUpdateException(f"Unable to import peers from {_vpn.name}: {wg_config_data}")

        added_peers = []
        for peer in wg_config_data.peers:
            import_peer = PeerRequestModel(
                ip_address=peer.wg_ip_address,
                public_key=peer.public_key,
                private_key=None,
                persistent_keepalive=peer.persistent_keepalive,
                allowed_ips=_vpn.wireguard.ip_network,
                tags=["imported"],
            )
            # Check if the peer already exists in the VPN
            skip_peer = False
            for existing_peer in self._db_manager.get_peers(vpn_name):
                if existing_peer.ip_address == import_peer.ip_address:
                    log.warning(f"Skipping import of peer {import_peer.ip_address} as it already exists.")
                    skip_peer = True

            if not skip_peer:
                self.add_peer(vpn_name, import_peer)
                added_peers.append(import_peer)

        return added_peers

    def add_tag_to_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Add a tag to an existing peer"""
        self._db_manager.add_tag_to_peer(vpn_name, peer_ip, tag)

    def delete_tag_from_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Delete a tag from an existing peer"""
        self._db_manager.delete_tag_from_peer(vpn_name, peer_ip, tag)

    def get_tag_history_endpoint(self, vpn_name: str, tag: str, start_time: str = None, end_time: str = None):
        return self._db_manager.get_tag_history_endpoint(vpn_name, tag, start_time, end_time)

    def get_peer_history_endpoint(self, vpn_name: str, ip_address: str, start_time: str = None, end_time: str = None):
        return self._db_manager.get_peer_history_endpoint(vpn_name, ip_address, start_time, end_time)
