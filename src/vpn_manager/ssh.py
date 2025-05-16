from __future__ import annotations
import typing
from typing import Optional, List, Union
import codecs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import paramiko
from io import StringIO
from models.ssh import VpnSshInterfaceModel, SshPeer, SshConnectionModel
from vpn_manager.peers import Peer
import logging

if typing.TYPE_CHECKING:
    from vpn_manager.vpn import VpnServer


log = logging.getLogger(__name__)


class SshException(Exception):
    """Custom exception for SSH errors"""


def _remote_ssh_command(cmd: str, ssh_connection_info: SshConnectionModel) -> Union[List[str], str]:
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
            ssh_connection_info.ip_address,
            username=ssh_connection_info.username,
            pkey=paramiko.RSAKey.from_private_key(
                StringIO(ssh_connection_info.key), password=ssh_connection_info.key_password
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


def extract_wg_server_config(wg_interface, wg_config: List[str]) -> Optional[VpnSshInterfaceModel]:
    """
    If dump is specified, then several lines are printed; the first contains in order separated by tab:
    private-key, public-key, listen-port, fwmark. Subsequent lines are printed for each peer and contain in order separated
    by tab: public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx,
    persistent-keepalive.
    """
    # Extract the vpn server config
    private_key, public_key, listen_port, fw_mark = wg_config.pop(0).split("\t")
    vpn_model = VpnSshInterfaceModel(
        interface=wg_interface, private_key=private_key, public_key=public_key, listen_port=listen_port, fw_mark=fw_mark
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
        peer = SshPeer(
            endpoint=endpoint,
            public_key=public_key,
            wg_ip_address=allowed_ips.split("/")[0],
            preshared_key=preshared_key if preshared_key != "(none)" else None,
            latest_handshake=latest_handshake,
            transfer_rx=transfer_rx,
            transfer_tx=transfer_tx,
            persistent_keepalive=persistent_keepalive,
        )
        vpn_model.peers.append(peer)

    return vpn_model


def dump_interface_config(
    wg_interface: str, ssh_connection_info: SshConnectionModel
) -> Union[Optional[VpnSshInterfaceModel], str]:
    """Return the full VPN config"""
    cmd_to_execute = f"sudo wg show {wg_interface} dump"
    ssh_response = _remote_ssh_command(cmd_to_execute, ssh_connection_info)
    if isinstance(ssh_response, list):
        result = extract_wg_server_config(wg_interface, ssh_response)
    else:
        result = ssh_response
    return result


def remove_peer(vpn: VpnServer, peer: Peer):
    cmd_to_execute = f"sudo wg set {vpn.interface} peer {peer.public_key} remove && sudo wg-quick save wg0"
    ssh_response = _remote_ssh_command(cmd_to_execute, vpn.ssh_connection_info)
    if isinstance(ssh_response, str):
        raise SshException(f"Failed to remove peer from vpn: {ssh_response}")


def add_peer(vpn: VpnServer, peer: Peer):
    cmd_to_execute = f"sudo wg set {vpn.interface} peer {peer.public_key} persistent-keepalive {peer.persistent_keepalive} allowed-ips {peer.ip_address} && sudo wg-quick save wg0"
    ssh_response = _remote_ssh_command(cmd_to_execute, vpn.ssh_connection_info)
    if isinstance(ssh_response, str):
        raise SshException(f"Failed to add peer to vpn: {ssh_response}")


def generate_wireguard_keys() -> tuple[str, str]:
    """
    Generate a new WireGuard key pair
    :return: (private_key, public_key)
    """
    # generate private key
    private_key = X25519PrivateKey.generate()
    bytes_ = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_str = codecs.encode(bytes_, "base64").decode("utf8").strip()

    # derive public key
    pubkey = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    public_key_str = codecs.encode(pubkey, "base64").decode("utf8").strip()

    return private_key_str, public_key_str
