from __future__ import annotations
import typing
from typing import Optional
from models.connection import ConnectionModel
from models.wg_server import WgServerModel
from vpn_manager.peers import Peer
import logging
from server_manager import ConnectionException, extract_wg_server_config
from server_manager.interface import AbstractServerManager
import time
from typing import List, Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

if typing.TYPE_CHECKING:
    from vpn_manager.vpn import VpnServer


log = logging.getLogger(__name__)


class SsmConnection(AbstractServerManager):
    @staticmethod
    def _remote_ssm_command(cmd: str, connection_info: ConnectionModel) -> Union[List[str], str]:
        """
        Run a single shell command on an EC2 instance via SSM.
        Returns stdout as a list of lines on success, or stderr as a string on error.
        """
        # build AWS credentials and client
        try:
            if connection_info.data.aws_access_key_id and connection_info.data.aws_secret_access_key:
                ssm = boto3.client(
                    "ssm",
                    region_name=connection_info.data.region,
                    aws_access_key_id=connection_info.data.aws_access_key_id,
                    aws_secret_access_key=connection_info.data.aws_secret_access_key,
                    config=Config(retries={"max_attempts": 3, "mode": "standard"}),
                )
            else:
                # revert to the IAM role of the instance if no credentials are provided
                ssm = boto3.client(
                    "ssm",
                    region_name=connection_info.data.region,
                    config=Config(retries={"max_attempts": 3, "mode": "standard"}),
                )
            resp = ssm.send_command(
                InstanceIds=[connection_info.data.target_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [cmd]},
                TimeoutSeconds=600,
            )
            cmd_id = resp["Command"]["CommandId"]
        except ClientError as e:
            return f"SSM connection failed: {e}"

        # poll until the command finishes
        while True:
            try:
                inv = ssm.get_command_invocation(
                    CommandId=cmd_id, InstanceId=connection_info.data.target_id, PluginName="aws:RunShellScript"
                )
                status = inv["Status"]
                if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                    break
            except ClientError as e:
                if not e.response["Error"]["Code"] == "InvocationDoesNotExist":
                    return f"SSM get_command_invocation failed: {e}"
            time.sleep(1)

        # return output or error
        if status == "Success":
            return inv.get("StandardOutputContent", "").splitlines()
        else:
            return inv.get("StandardErrorContent", "")

    def dump_interface_config(
        self, wg_interface: str, connection_info: ConnectionModel
    ) -> Union[Optional[WgServerModel], str]:
        """Return the full VPN config.  If this returns a string, it is an error message."""
        cmd_to_execute = f"sudo wg show {wg_interface} dump"
        wg_dump_response = SsmConnection._remote_ssm_command(cmd_to_execute, connection_info)
        if isinstance(wg_dump_response, list):
            result = extract_wg_server_config(wg_interface, wg_dump_response)
        else:
            result = wg_dump_response
        return result

    def remove_peer(self, vpn: VpnServer, peer: Peer):
        """Remove a peer from the VPN server"""
        cmd_to_execute = f"sudo wg set {vpn.interface} peer {peer.public_key} remove && sudo wg-quick save wg0"
        ssm_response = SsmConnection._remote_ssm_command(cmd_to_execute, vpn.connection_info)
        if isinstance(ssm_response, str):
            raise ConnectionException(f"Failed to remove peer from vpn: {ssm_response}")

    def add_peer(self, vpn: VpnServer, peer: Peer):
        """Add a peer to the VPN server"""
        cmd_to_execute = f"sudo wg set {vpn.interface} peer {peer.public_key} persistent-keepalive {peer.persistent_keepalive} allowed-ips {peer.ip_address} && sudo wg-quick save wg0"
        ssm_response = SsmConnection._remote_ssm_command(cmd_to_execute, vpn.connection_info)
        if isinstance(ssm_response, str):
            raise ConnectionException(f"Failed to add peer to vpn: {ssm_response}")
