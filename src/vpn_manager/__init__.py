import codecs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import logging
from uuid import uuid4
from databases.interface import AbstractDatabase
from models.peers import PeerDbModel, PeerRequestModel
from vpn_manager.vpn import VpnServer
from models.vpn import VpnPutModel
from server_manager import server_manager_factory

log = logging.getLogger(__name__)


class VpnUpdateException(Exception):
    """Custom exception for VPN update errors."""

    pass


class VpnManager:
    def __init__(self, db_manager: AbstractDatabase):
        self._db_manager = db_manager

    def add_vpn(self, name: str, description: str, vpn_request: VpnPutModel):
        _vpn = self.get_vpn(name)
        if _vpn is not None:
            raise ValueError(f"VPN with name {name} already exists.")

        for existing_vpn in self.get_all_vpn():
            if existing_vpn.public_key == vpn_request.wireguard.public_key:
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

        _vpn = VpnServer(
            database=self._db_manager,
            name=name,
            description=description,
            ip_address=vpn_request.wireguard.ip_address,
            ip_network=vpn_request.wireguard.ip_network,
            interface=vpn_request.wireguard.interface,
            public_key=vpn_request.wireguard.public_key,
            private_key=vpn_request.wireguard.private_key,
            listen_port=vpn_request.wireguard.listen_port,
            connection_info=vpn_request.connection_info,
        )
        if vpn_request.wireguard.ip_address not in _vpn.all_ip_addresses:
            raise ValueError(
                f"IP address {vpn_request.wireguard.ip_address} is not in the address space "
                f"{vpn_request.wireguard.ip_network}."
            )
        self._db_manager.add_vpn(_vpn)

    def get_all_vpn(self) -> list[VpnServer]:
        return [_vpn for _vpn in self._db_manager.get_all_vpn().values()]

    def get_vpn(self, name: str) -> VpnServer | None:
        return self._db_manager.get_vpn(name)

    def remove_vpn(self, name: str):
        _vpn = self.get_vpn(name)
        if _vpn is not None:
            self._db_manager.delete_vpn(name)

    def add_peer(self, vpn_name: str, peer: PeerRequestModel):
        """This will add the peer to the database"""
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
        peer = self.get_peers_by_ip(vpn_name, ip_address)
        if peer:
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

    def generate_new_peer_keys(self, vpn_name: str, peer: PeerDbModel):
        self._db_manager.delete_peer(vpn_name, peer)
        peer.private_key, peer.public_key = self.generate_wireguard_keys()
        self._db_manager.add_peer(vpn_name, peer)
        return peer

    def import_peers(self, vpn_name: str) -> list[PeerRequestModel]:
        # This downloads the wireguard server config and extracts the data.
        _vpn = self.get_vpn(vpn_name)
        server_manager = server_manager_factory(_vpn.connection_info.type)
        wg_config_data = server_manager.dump_interface_config(_vpn.interface, _vpn.connection_info)
        if isinstance(wg_config_data, str):
            raise VpnUpdateException(f"Unable to import peers from {_vpn.name}: {wg_config_data}")

        add_peers = []
        for peer in wg_config_data.peers:
            import_peer = PeerRequestModel(
                ip_address=peer.wg_ip_address,
                public_key=peer.public_key,
                persistent_keepalive=peer.persistent_keepalive,
                allowed_ips=_vpn.ip_network,
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
                add_peers.append(import_peer)
        _vpn.calculate_available_ips()

        return add_peers

    def add_tag_to_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Add a tag to an existing peer"""
        self._db_manager.add_tag_to_peer(vpn_name, peer_ip, tag)

    def delete_tag_from_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Delete a tag from an existing peer"""
        self._db_manager.delete_tag_from_peer(vpn_name, peer_ip, tag)
