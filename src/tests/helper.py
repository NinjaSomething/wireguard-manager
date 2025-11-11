from pydantic import SecretStr
from http import HTTPStatus
import urllib.parse
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from models.vpn import VpnModel, VpnPutModel
from models.connection import ConnectionType
from models.peers import PeerRequestModel, PeerResponseModel, PeerDbModel
from models.wg_server import WgServerModel
from databases.dynamodb import DynamoDb


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
    vpn,
    vpn_manager,
    dynamo_db,
    mock_ssm_command,
    mock_ssh_command,
    http_client: TestClient,
    vpn_router,
    mock_ssm_client,
    mock_ssh_client,
):
    vpn_config = VpnPutModel(wireguard=vpn.wireguard, connection_info=vpn.connection_info)
    vpn_router.vpn_manager = vpn_manager
    if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH:
        mock_ssh_client_instance = mock_ssh_client()
        mock_ssh_client_instance.exec_command = mock_ssh_command.command

    elif vpn.connection_info and vpn.connection_info.type == ConnectionType.SSM:
        mock_ssm_client_instance = mock_ssm_client()
        mock_ssm_client_instance.send_command = mock_ssm_command.send_command  # Random ID
        mock_ssm_client_instance.get_command_invocation = mock_ssm_command.command

    vpn_response = http_client.get("/vpn")
    assert len(vpn_response.json()) == 0

    # Execute Test
    url = f"/vpn/{vpn.name}?{urllib.parse.urlencode(dict(description=vpn.description))}"
    response = http_client.put(url, data=vpn_config.model_dump_json())

    # Validate Results
    assert response.status_code == HTTPStatus.OK
    all_vpns = dynamo_db._get_all_vpn_from_server()
    assert all_vpns == [vpn]


def add_peer(vpn: VpnModel, dynamo_db: DynamoDb, peer: PeerDbModel = None) -> PeerDbModel:
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

    if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH:
        ssh_client = mock_ssh_client()
        ssh_client.exec_command = mock_ssh_command.command
    elif vpn.connection_info and vpn.connection_info.type == ConnectionType.SSM:
        mock_ssm_client_instance = mock_ssm_client()
        mock_ssm_client_instance.send_command = mock_ssm_command.send_command  # Random ID
        mock_ssm_client_instance.get_command_invocation = mock_ssm_command.command

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
    )

    http_client.put(f"/vpn/{vpn.name}/peer/{peer1.ip_address}/tag/tag2", json={"message": "Add tag2"})
    http_client.delete(f"/vpn/{vpn.name}/peer/{peer1.ip_address}/tag/tag2")
    http_client.post(
        f"/vpn/{vpn.name}/peer/{peer1.ip_address}/generate-wireguard-keys", json={"message": "Generate new keys"}
    )

    http_client.put(f"/vpn/{vpn.name}/peer/{peer2.ip_address}/tag/tag3", json={"message": "Add tag3"})
    return peer1, peer2
