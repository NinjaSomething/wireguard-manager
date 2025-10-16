from __future__ import annotations
from typing import Optional, List, Union
import paramiko
from io import StringIO
from models.connection import ConnectionModel
from models.wg_server import WgServerModel
from models.peers import PeerRequestModel, PeerDbModel
from models.vpn import VpnModel
import logging
from server_manager import ConnectionException, extract_wg_server_config
from server_manager.interface import AbstractServerManager


log = logging.getLogger(__name__)


class SshConnection(AbstractServerManager):
    @staticmethod
    def _remote_ssh_command(cmd: str, connection_info: ConnectionModel) -> tuple[bool, Union[List[str], str]]:
        """
        Remotely execute SSH command
        :return
        If successful, (True, a list of strings).  Each item is a line of the stdout.
        If unsuccessful, (False, a message).
        """
        success = True
        ssh_connection_info = connection_info.data
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            try:
                ssh.connect(
                    ssh_connection_info.ip_address,
                    username=ssh_connection_info.username,
                    pkey=paramiko.RSAKey.from_private_key(
                        StringIO(ssh_connection_info.key), password=ssh_connection_info.key_password
                    ),
                    timeout=30,
                )
            except Exception as ex:
                raise ConnectionException(f"Failed to connect to server via SSH: {ex}")

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
                success = False
            ssh.close()
        except paramiko.SSHException as ex:
            result = f"Failed to SSH into server: {ex}"
            success = False
        return success, result

    def test_interface_config(self, wg_interface: str, connection_info: ConnectionModel) -> tuple[bool, str]:
        cmd_to_execute = f"sudo wg show {wg_interface} public-key"
        success, test_response = SshConnection._remote_ssh_command(cmd_to_execute, connection_info)
        if success:
            return True, ""
        else:
            return False, "Failed to connect to instance via SSM"

    def dump_interface_config(
        self, wg_interface: str, connection_info: ConnectionModel
    ) -> Union[Optional[WgServerModel], str]:
        """Return the full VPN config.  If this returns a string, it is an error message."""
        cmd_to_execute = f"sudo wg show {wg_interface} dump"
        success, wg_dump_response = SshConnection._remote_ssh_command(cmd_to_execute, connection_info)
        if success:
            result = extract_wg_server_config(wg_interface, wg_dump_response)
        else:
            result = wg_dump_response
        return result

    def remove_peer(self, vpn: VpnModel, peer: PeerDbModel):
        """Remove a peer from the VPN server"""
        cmd_to_execute = (
            f"sudo wg set {vpn.wireguard.interface} peer {peer.public_key} remove && sudo wg-quick save wg0"
        )
        ssh_response = SshConnection._remote_ssh_command(cmd_to_execute, vpn.connection_info)
        if isinstance(ssh_response, str):
            raise ConnectionException(f"Failed to remove peer from vpn: {ssh_response}")

    def add_peer(self, vpn: VpnModel, peer: PeerRequestModel):
        """Add a peer to the VPN server"""
        cmd_to_execute = f"sudo wg set {vpn.wireguard.interface} peer {peer.public_key} persistent-keepalive {peer.persistent_keepalive} allowed-ips {peer.ip_address} && sudo wg-quick save {vpn.wireguard.interface}"
        ssh_response = SshConnection._remote_ssh_command(cmd_to_execute, vpn.connection_info)
        if isinstance(ssh_response, str):
            raise ConnectionException(f"Failed to add peer to vpn: {ssh_response}")
