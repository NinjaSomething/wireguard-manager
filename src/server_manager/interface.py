from __future__ import annotations
import abc
from typing import Union, Optional
import typing

if typing.TYPE_CHECKING:
    from vpn_manager.vpn import VpnServer
    from vpn_manager.peers import Peer
    from models.connection import ConnectionModel
    from models.wg_server import WgServerModel


class AbstractServerManager(metaclass=abc.ABCMeta):
    """This is an interface that abstracts away the functionality required to manage the wireguard server itself"""

    @staticmethod
    @abc.abstractmethod
    def extract_wg_server_config(wg_interface, wg_config: list[str]) -> WgServerModel | None:
        pass

    @staticmethod
    @abc.abstractmethod
    def dump_interface_config(
        wg_interface: str, connection_info: ConnectionModel
    ) -> Union[Optional[WgServerModel], str]:
        """Return the full VPN config"""
        pass

    @staticmethod
    @abc.abstractmethod
    def remove_peer(vpn: VpnServer, peer: Peer):
        pass

    @staticmethod
    @abc.abstractmethod
    def add_peer(vpn: VpnServer, peer: Peer):
        pass

    @staticmethod
    @abc.abstractmethod
    def generate_wireguard_keys() -> tuple[str, str]:
        """
        Generate a new WireGuard key pair
        :return: (private_key, public_key)
        """
        pass
