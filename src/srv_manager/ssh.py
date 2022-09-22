from pydantic import BaseModel
from typing import Optional, List
import paramiko
import os


class SshConnectionModel(BaseModel):
    ssh_username: str = "ubuntu"
    ssh_pem_filename: str = "test-wireguard-server.pem"


class VpnRequestModel(BaseModel):
    name: str = "test1"
    description: str = "test1"
    ip_address: str = "35.167.168.44"
    wg_interface: Optional[str] = "wg0"
    ssh_connection_info: Optional[SshConnectionModel] = None


class VpnModel(VpnRequestModel):
    listen_port: int
    public_key: str


def extract_wg_server_config(wg_config: List[str], vpn_request) -> Optional[VpnModel]:
    result = None
    interface = None
    pub_key = None
    listening_port = None

    for line in wg_config:
        if line != "\n":
            key, value = line.lstrip().strip("\n").split(": ")
            match key:
                case "interface":
                    interface = value if vpn_request.wg_interface == value else None
                case "public key":
                    if interface is not None:
                        pub_key = value
                case "listening port":
                    if interface is not None:
                        listening_port = int(value)
                case "peer":
                    break

    if interface is not None:
        result = VpnModel(listen_port=listening_port, public_key=pub_key, **vpn_request.dict())
    return result


def get_vpn_config(vpn: VpnRequestModel, ssh_key_path: str) -> Optional[VpnModel]:
    """Return the full VPN config"""
    result = None
    if vpn.ssh_connection_info is not None:
        cmd_to_execute = "sudo wg"
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            vpn.ip_address,
            username=vpn.ssh_connection_info.ssh_username,
            key_filename=os.path.join(ssh_key_path, vpn.ssh_connection_info.ssh_pem_filename),
        )
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd_to_execute, timeout=10)
        if ssh_stdout.channel.recv_exit_status() == 0:
            result = ssh_stdout.readlines()
        ssh.close()
    return result
