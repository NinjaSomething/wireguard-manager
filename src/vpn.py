from typing import Optional
import ipaddress
from models.vpn import PeerModel, SshConnectionModel, VpnModel, WireguardRequestModel
from peers import PeerList


class VpnServer:
    def __init__(
        self,
        name: str,
        ip_address: str,
        address_space: str,
        interface: str,
        public_key: str,
        listen_port: int,
        ssh_connection_info: SshConnectionModel,
        peers: PeerList,
        description: Optional[str] = None,
        private_key: Optional[str] = None,
    ):
        self._name = name
        self._address_space = address_space
        self._description = description
        self._ip_address = ip_address
        self._interface = interface
        self._public_key = public_key
        self._private_key = private_key
        self._listen_port = listen_port
        self._ssh_connection_info = ssh_connection_info
        self._peers = peers

        # Get a list of all IPs for this subnet
        self._all_ip_addresses = set(ipaddress.ip_network(self.address_space).hosts())
        self._available_ips = []
        self.calculate_available_ips()

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str | None:
        return self._description

    @property
    def ip_address(self) -> str:
        return self._ip_address

    @property
    def address_space(self) -> str:
        return self._address_space

    @property
    def interface(self) -> str:
        return self._interface

    @property
    def public_key(self) -> str:
        return self._public_key

    @property
    def private_key(self) -> Optional[str]:
        return self._private_key

    @property
    def listen_port(self) -> int:
        return self._listen_port

    @property
    def ssh_connection_info(self) -> SshConnectionModel:
        return self._ssh_connection_info

    @property
    def peers(self) -> list[PeerModel]:
        return self._peers

    @property
    def all_ip_addresses(self) -> list[str]:
        return [str(ip) for ip in self._all_ip_addresses]

    @property
    def available_ips(self) -> list[str]:
        return self._available_ips

    def validate_address_space(self, address_space: str) -> bool:
        """Will raise a ValueError if the address space is not valid."""
        peer_address_space = set(ipaddress.ip_network(address_space).hosts())
        if len(list(peer_address_space - self._all_ip_addresses)) > 0:
            raise ValueError(
                f"Address space [{address_space}] is larger than the address space of the VPN server [{self.address_space}]."
            )

    def get_next_available_ip(self) -> str:
        """Get the next available IP address from the pool."""
        if not self._available_ips:
            raise ValueError("No available IP addresses in the pool.")
        return self._available_ips[0]

    def calculate_available_ips(self):
        # Get a list of all IPs that are already used by peers
        used_ips = set([ipaddress.ip_address(peer.ip_address) for peer in self.peers])
        used_ips.add(ipaddress.ip_address(self.ip_address))  # Include the servers IP as being used

        # Get a list of IPs that are available for use
        available_ips = list(self._all_ip_addresses - used_ips)
        available_ips.sort()
        self._available_ips = [str(available_ip) for available_ip in available_ips]

    def to_model(self) -> VpnModel:
        return VpnModel(
            name=self.name,
            description=self._description,
            wireguard=WireguardRequestModel(
                ip_address=self.ip_address,
                address_space=self.address_space,
                interface=self.interface,
                public_key=self.public_key,
                private_key=self.private_key,
                listen_port=self.listen_port,
            ),
            ssh_connection_info=self.ssh_connection_info,
            peers=self.peers,
        )
