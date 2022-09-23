from typing import Optional, List, Union
import paramiko
import os
from models.vpn import VpnSshInterfaceModel, SshPeer, SshConnectionModel


def _remote_ssh_command(cmd: str, ssh_connection_info: SshConnectionModel, ssh_key_path: str) -> Union[List[str], str]:
    """
    Remotely execute SSH command
    :return
    If successful, a list of strings.  Each item is a line of the stdout.
    If unsuccessful, a message.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            ssh_connection_info.ssh_ip_address,
            username=ssh_connection_info.ssh_username,
            key_filename=os.path.join(ssh_key_path, ssh_connection_info.ssh_pem_filename),
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


def extract_wg_server_config(wg_interface, wg_config: List[str]) -> Optional[VpnSshInterfaceModel]:
    # Extract the interface config
    private_key, public_key, listen_port, fw_mark = wg_config.pop(0).split("\t")
    vpn_model = VpnSshInterfaceModel(
        interface=wg_interface, private_key=private_key, public_key=public_key, listen_port=listen_port, fw_mark=fw_mark
    )
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
        peer = SshPeer(
            endpoint=endpoint,
            public_key=public_key,
            wg_ip_address=allowed_ips.split("/")[0],
            preshared_key=preshared_key if preshared_key != '(none)' else None,
            latest_handshake=latest_handshake,
            transfer_rx=transfer_rx,
            transfer_tx=transfer_tx,
            persistent_keepalive=persistent_keepalive,
        )
        vpn_model.peers.append(peer)

    return vpn_model


def dump_interface_config(
    wg_interface: str, ssh_connection_info: SshConnectionModel, ssh_key_path: str
) -> Union[Optional[VpnSshInterfaceModel], str]:
    """Return the full VPN config"""
    cmd_to_execute = f"sudo wg show {wg_interface} dump"
    ssh_response = _remote_ssh_command(cmd_to_execute, ssh_connection_info, ssh_key_path)
    if isinstance(ssh_response, list):
        result = extract_wg_server_config(wg_interface, ssh_response)
    else:
        result = ssh_response
    return result
