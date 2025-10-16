from __future__ import annotations
from typing import Optional
from models.connection import ConnectionModel
from models.peers import PeerRequestModel
from models.vpn import VpnModel
from models.wg_server import WgServerModel
import logging
from server_manager import ConnectionException, extract_wg_server_config
from server_manager.interface import AbstractServerManager
import time
from typing import Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


log = logging.getLogger(__name__)


class SsmConnection(AbstractServerManager):
    @staticmethod
    def _remote_ssm_command(cmd: str, connection_info: ConnectionModel) -> tuple[bool, str]:
        """
        Run a single shell command on an EC2 instance via SSM.
        If successful, (True, a string of the stdout).
        If unsuccessful, (False, the stderr message).
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
            return False, f"SSM connection failed: {e}"
        except Exception as e:
            return False, f"SSM connection failed: {e}"

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
                    return False, f"SSM get_command_invocation failed: {e}"
            time.sleep(1)

        # return output or error
        if status == "Success":
            output = inv.get("StandardOutputContent", "")
            if "--output truncated--" not in output:
                return True, output
            else:
                return False, "SSM command output exceeded 24,000 character limit and was truncated."
        else:
            return False, inv.get("StandardErrorContent", "")

    def test_interface_config(self, wg_interface: str, connection_info: ConnectionModel) -> tuple[bool, str]:
        cmd_to_execute = f"sudo wg show {wg_interface} public-key"
        success, _ = SsmConnection._remote_ssm_command(cmd_to_execute, connection_info)
        if success:
            return True, ""
        else:
            return False, "Failed to connect to instance via SSM"

    def dump_interface_config(
        self, wg_interface: str, connection_info: ConnectionModel
    ) -> Union[Optional[WgServerModel], str]:
        """Return the full VPN config.  If this returns a string, it is an error message."""
        cmd_to_execute = f"sudo wg show {wg_interface} dump"
        success, wg_dump_response = SsmConnection._remote_ssm_command(cmd_to_execute, connection_info)
        if success:
            wg_dump_list = wg_dump_response.splitlines()
            result = extract_wg_server_config(wg_interface, wg_dump_list)
        else:
            result = wg_dump_response
        return result

    def remove_peer(self, vpn: VpnModel, peer: PeerRequestModel):
        """Remove a peer from the VPN server"""
        cmd_to_execute = (
            f"sudo wg set {vpn.wireguard.interface} peer {peer.public_key} remove && sudo wg-quick save wg0"
        )
        ssm_response = SsmConnection._remote_ssm_command(cmd_to_execute, vpn.connection_info)
        if isinstance(ssm_response, str):
            raise ConnectionException(f"Failed to remove peer from vpn: {ssm_response}")

    def add_peer(self, vpn: VpnModel, peer: PeerRequestModel):
        """Add a peer to the VPN server"""
        cmd_to_execute = f"sudo wg set {vpn.wireguard.interface} peer {peer.public_key} persistent-keepalive {peer.persistent_keepalive} allowed-ips {peer.ip_address} && sudo wg-quick save wg0"
        ssm_response = SsmConnection._remote_ssm_command(cmd_to_execute, vpn.connection_info)
        if isinstance(ssm_response, str):
            raise ConnectionException(f"Failed to add peer to vpn: {ssm_response}")
