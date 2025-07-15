from __future__ import annotations
import typing
from typing import Optional, List, Union
import paramiko
from io import StringIO
from models.connection import ConnectionModel
from models.wg_server import WgServerModel
from vpn_manager.peers import Peer
import logging
from server_manager import ConnectionException, extract_wg_server_config
from server_manager.interface import AbstractServerManager

if typing.TYPE_CHECKING:
    from vpn_manager.vpn import VpnServer


log = logging.getLogger(__name__)


class SshConnection(AbstractServerManager):
    @staticmethod
    def _remote_ssh_command(cmd: str, connection_info: ConnectionModel) -> Union[List[str], str]:
        """
        Remotely execute SSH command
        :return
        If successful, a list of strings.  Each item is a line of the stdout.
        If unsuccessful, a message.
        """
        ssh_connection_info = connection_info.data
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            key_password = (
                ssh_connection_info.key_password.get_secret_value() if ssh_connection_info.key_password else None
            )
            ssh.connect(
                ssh_connection_info.ip_address,
                username=ssh_connection_info.username,
                pkey=paramiko.RSAKey.from_private_key(
                    StringIO(ssh_connection_info.key.get_secret_value()), password=key_password
                ),
            )
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd, timeout=10)
            # TODO: Add support for other corner-cases
            if ssh_stdout.channel.recv_exit_status() == 0:
                result = ssh_stdout.readlines()
                result = [line.lstrip().strip("\n") for line in result]
            else:
                msg = ""
                for line in ssh_stderr.readlines():
                    msg += line
                result = msg
            ssh.close()
        except paramiko.SSHException as ex:
            result = f"Failed to SSH into server: {ex}"
        return result

    def dump_interface_config(
        self, wg_interface: str, connection_info: ConnectionModel
    ) -> Union[Optional[WgServerModel], str]:
        """Return the full VPN config.  If this returns a string, it is an error message."""
        cmd_to_execute = f"sudo wg show {wg_interface} dump"
        wg_dump_response = SshConnection._remote_ssh_command(cmd_to_execute, connection_info)
        if isinstance(wg_dump_response, list):
            result = extract_wg_server_config(wg_interface, wg_dump_response)
        else:
            result = wg_dump_response
        return result

    def remove_peer(self, vpn: VpnServer, peer: Peer):
        """Remove a peer from the VPN server"""
        cmd_to_execute = f"sudo wg set {vpn.interface} peer {peer.public_key} remove && sudo wg-quick save wg0"
        ssh_response = SshConnection._remote_ssh_command(cmd_to_execute, vpn.connection_info)
        if isinstance(ssh_response, str):
            raise ConnectionException(f"Failed to remove peer from vpn: {ssh_response}")

    def add_peer(self, vpn: VpnServer, peer: Peer):
        """Add a peer to the VPN server"""
        cmd_to_execute = f"sudo wg set {vpn.interface} peer {peer.public_key} persistent-keepalive {peer.persistent_keepalive} allowed-ips {peer.ip_address} && sudo wg-quick save wg0"
        ssh_response = SshConnection._remote_ssh_command(cmd_to_execute, vpn.connection_info)
        if isinstance(ssh_response, str):
            raise ConnectionException(f"Failed to add peer to vpn: {ssh_response}")
