from pydantic import SecretStr
from http import HTTPStatus
import urllib.parse
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from models.vpn import VpnModel, VpnPutModel
from models.connection import ConnectionType
from models.peers import PeerRequestModel, PeerResponseModel, PeerDbModel
from models.wg_server import WgServerModel, WgServerPeerModel
from databases.dynamodb import DynamoDb
from tests.client.mock_client import MockCommand


def compare_peer_request_and_response(request: PeerRequestModel, response: PeerResponseModel, hide_secrets: bool):
    """
    Compare a PeerRequestModel to a PeerResponseModel to ensure they
    match the overlapping fields.
    """
    assert isinstance(request, PeerRequestModel)
    assert isinstance(response, PeerResponseModel)

    assert request.ip_address == response.ip_address
    assert request.allowed_ips == response.allowed_ips
    assert request.public_key == response.public_key
    if request.private_key is not None:
        if hide_secrets:
            assert response.private_key == SecretStr("**********")
        else:
            assert request.private_key == response.private_key.get_secret_value()
    else:
        assert response.private_key is None
    assert request.persistent_keepalive == response.persistent_keepalive
    assert request.tags == response.tags


@patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
@patch("server_manager.ssh.paramiko.SSHClient")
@patch("server_manager.ssm.boto3.client")
def add_vpn(
    vpn: VpnModel,
    dynamo_db,
    mock_ssm_command,
    mock_ssh_command,
    mock_ssm_client,
    mock_ssh_client,
):
    if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH:
        mock_ssh_client_instance = mock_ssh_client()
        mock_ssh_client_instance.exec_command = mock_ssh_command.command

    elif vpn.connection_info and vpn.connection_info.type == ConnectionType.SSM:
        mock_ssm_client_instance = mock_ssm_client()
        mock_ssm_client_instance.send_command = mock_ssm_command.send_command  # Random ID
        mock_ssm_client_instance.get_command_invocation = mock_ssm_command.command

    all_vpns = dynamo_db._get_all_vpn_from_server()
    assert len(all_vpns) == 0

    # Execute Test
    dynamo_db.add_vpn(vpn)

    # Validate Results
    all_vpns = dynamo_db._get_all_vpn_from_server()
    assert all_vpns == [vpn]


def add_peer(
    vpn: VpnModel, dynamo_db: DynamoDb, peer: PeerDbModel = None, mock_command: MockCommand = None
) -> PeerDbModel:
    if peer is None:
        peer = PeerDbModel(
            peer_id="1234",
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key="PEER_PRIVATE_KEY",
            persistent_keepalive=25,
            tags=["tag1"],
            message="Add Peer",
        )
    dynamo_db.add_peer(
        vpn_name=vpn.name,
        changed_by="doug",
        peer=peer,
    )
    if mock_command is not None:
        mock_command.inject_peer(
            WgServerPeerModel(
                public_key=peer.public_key,
                persistent_keepalive=peer.persistent_keepalive,
                wg_ip_address=peer.ip_address,
                preshared_key=None,
                endpoint="(none)",
                latest_handshake=0,
                transfer_rx=0,
                transfer_tx=0,
            )
        )
    return peer


@patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
@patch("server_manager.ssh.paramiko.SSHClient")
@patch("server_manager.ssm.boto3.client")
@patch("vpn_manager.codecs")
def seed_history(
    vpn: VpnModel,
    dynamo_db: DynamoDb,
    mock_ssm_command,
    mock_ssh_command,
    http_client: TestClient,
    mock_codecs,
    mock_ssm_client,
    mock_ssh_client,
):
    mock_codecs.encode.side_effect = ["GENERATED_PRIVATE_KEY2".encode(), "GENERATED_PUBLIC_KEY2".encode()]
    mock_ssh_command.server = WgServerModel(
        interface=vpn.wireguard.interface,
        public_key=vpn.wireguard.public_key,
        private_key=vpn.wireguard.private_key,
        listen_port=vpn.wireguard.listen_port,
        fw_mark="off",
    )

    mock_command = None
    if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH:
        ssh_client = mock_ssh_client()
        ssh_client.exec_command = mock_ssh_command.command
        mock_command = mock_ssh_command
    elif vpn.connection_info and vpn.connection_info.type == ConnectionType.SSM:
        mock_ssm_client_instance = mock_ssm_client()
        mock_ssm_client_instance.send_command = mock_ssm_command.send_command  # Random ID
        mock_ssm_client_instance.get_command_invocation = mock_ssm_command.command
        mock_command = mock_ssm_command

    peer1 = add_peer(
        vpn,
        dynamo_db,
        PeerDbModel(
            peer_id="1234",
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER1_PUBLIC_KEY",
            private_key="PEER1_PRIVATE_KEY",
            persistent_keepalive=25,
            tags=["tag1"],
            message="Add new peer",
        ),
        mock_command=mock_command,
    )
    peer2 = add_peer(
        vpn,
        dynamo_db,
        PeerDbModel(
            peer_id="1234",
            ip_address="10.20.40.3",
            allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
            public_key="PEER2_PUBLIC_KEY",
            private_key="PEER2_PRIVATE_KEY",
            persistent_keepalive=25,
            tags=["tag1"],
            message="Add second peer",
        ),
        mock_command=mock_command,
    )

    http_client.put(f"/vpn/{vpn.name}/peer/{peer1.ip_address}/tag/tag2", json={"message": "Add tag2"})
    http_client.request("DELETE", f"/vpn/{vpn.name}/peer/{peer1.ip_address}/tag/tag2", json={"message": "Delete Tag2"})
    http_client.post(
        f"/vpn/{vpn.name}/peer/{peer1.ip_address}/generate-wireguard-keys", json={"message": "Generate new keys"}
    )

    http_client.put(f"/vpn/{vpn.name}/peer/{peer2.ip_address}/tag/tag3", json={"message": "Add tag3"})
    return peer1, peer2
