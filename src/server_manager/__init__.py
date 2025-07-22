from __future__ import annotations
import typing
from typing import Optional
from models.wireguard_connection import WireguardConnectionType
from models.wg_server import WgServerPeerModel, WgServerModel

if typing.TYPE_CHECKING:
    from server_manager.interface import AbstractServerManager


class ConnectionException(Exception):
    """Custom exception for errors when communicating with the wireguard server."""


def server_manager_factory(connection_type: WireguardConnectionType) -> AbstractServerManager:
    """
    Factory function to create an instance of the appropriate server manager based on the connection type.
    :param connection_type: The type of connection (e.g., SSH).
    :return: An instance of a class that implements AbstractServerManager.
    """
    if connection_type == WireguardConnectionType.SSH:
        from server_manager.ssh import SshConnection

        return SshConnection()
    if connection_type == WireguardConnectionType.SSM:
        from server_manager.ssm import SsmConnection

        return SsmConnection()
    else:
        raise ValueError(f"Unsupported connection type: {connection_type}")


def extract_wg_server_config(wg_interface, wg_config: list[str]) -> Optional[WgServerModel]:
    """
    This will extract the WireGuard server configuration from the output of a wireguard dump command.  The
      following defines the dump format:

    Several lines are returned; the first contains in order separated by tab:
      private-key, public-key, listen-port, fwmark.

    Subsequent lines are printed for each peer and contain in order separated by tab:
      public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx,
      persistent-keepalive.
    """
    # Extract the vpn server config
    private_key, public_key, listen_port, fw_mark = wg_config.pop(0).split("\t")
    vpn_model = WgServerModel(
        interface=wg_interface,
        private_key=private_key,
        public_key=public_key,
        listen_port=listen_port,
        fw_mark=fw_mark,
    )

    # Extract the peers
    for line in wg_config:
        (
            public_key,
            preshared_key,
            endpoint,
            allowed_ips,
            latest_handshake,
            transfer_rx,
            transfer_tx,
            persistent_keepalive,
        ) = line.split("\t")
        peer = WgServerPeerModel(
            endpoint=endpoint,
            public_key=public_key,
            wg_ip_address=allowed_ips.split("/")[0],
            preshared_key=preshared_key if preshared_key != "(none)" else None,
            latest_handshake=int(latest_handshake),
            transfer_rx=int(transfer_rx),
            transfer_tx=int(transfer_tx),
            persistent_keepalive=int(persistent_keepalive),
        )
        vpn_model.peers.append(peer)

    return vpn_model
