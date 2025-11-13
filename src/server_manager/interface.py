from __future__ import annotations
import abc
from typing import Union, Optional
import typing

if typing.TYPE_CHECKING:
    from models.vpn import VpnModel
    from models.peers import PeerRequestModel, PeerDbModel
    from models.connection import ConnectionModel
    from models.wg_server import WgServerModel


class AbstractServerManager(metaclass=abc.ABCMeta):
    """This is an interface that abstracts away the functionality required to manage the wireguard server itself"""

    @abc.abstractmethod
    def test_interface_config(self, wg_interface: str, connection_info: ConnectionModel) -> tuple[bool, str]:
        """
        This will test communication with the VPN server.
        Returns (True, "") if the connection is good.
        Returns (False, Error Message) if the connection is bad.
        """
        pass

    @abc.abstractmethod
    def dump_interface_config(
        self, wg_interface: str, connection_info: ConnectionModel
    ) -> Union[Optional[WgServerModel], str]:
        """Return the full VPN config.  If this returns a string, it is an error message."""
        pass

    @abc.abstractmethod
    def remove_peer(self, vpn: VpnModel, peer: PeerRequestModel):
        """Remove a peer from the VPN server"""
        pass

    @abc.abstractmethod
    def add_peer(self, vpn: VpnModel, peer: PeerRequestModel):
        """Add a peer to the VPN server"""
        pass
