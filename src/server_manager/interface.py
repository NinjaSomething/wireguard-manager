from __future__ import annotations
import abc
from typing import Union, Optional
import typing

if typing.TYPE_CHECKING:
    from vpn_manager.vpn import VpnServer
    from vpn_manager.peers import Peer
    from models.wireguard_connection import WireguardConnectionModel
    from models.wg_server import WgServerModel


class AbstractServerManager(metaclass=abc.ABCMeta):
    """This is an interface that abstracts away the functionality required to manage the wireguard server itself"""

    @abc.abstractmethod
    def dump_interface_config(
        self, wg_interface: str, connection_info: WireguardConnectionModel
    ) -> Union[Optional[WgServerModel], str]:
        """Return the full VPN config.  If this returns a string, it is an error message."""
        pass

    @abc.abstractmethod
    def remove_peer(self, vpn: VpnServer, peer: Peer):
        """Remove a peer from the VPN server"""
        pass

    @abc.abstractmethod
    def add_peer(self, vpn: VpnServer, peer: Peer):
        """Add a peer to the VPN server"""
        pass
