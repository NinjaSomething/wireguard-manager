import datetime
from http import HTTPStatus
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from models.peers import PeerDbModel

from vpn_manager import VpnManager
from app import setup_app_routes, vpn_router
from auth import WireguardManagerAPI
from interfaces.peers import peer_router
from models.connection import ConnectionModel, ConnectionType
from models.peers import PeerRequestModel, PeerResponseModel
from models.peer_history import PeerHistoryResponseModel
from models.ssh import SshConnectionModel
from models.ssm import SsmConnectionModel
from models.vpn import VpnModel, WireguardModel
from models.wg_server import WgServerModel, WgServerPeerModel
from tests.helper import compare_peer_request_and_response, add_peer, seed_history, add_vpn


app = WireguardManagerAPI()
client = TestClient(app)
setup_app_routes(app)

test_parameters = [
    VpnModel(
        name="test-vpn",
        description="Test VPN Server",
        wireguard=WireguardModel(
            ip_address="10.20.40.1",
            ip_network="10.20.40.0/24",
            interface="wg0",
            public_key="PUBLIC_KEY",
            private_key="PRIVATE_KEY",
            listen_port=12345,
        ),
        connection_info=None,
    ),
    VpnModel(
        name="test-vpn",
        description="Test VPN Server",
        wireguard=WireguardModel(
            ip_address="10.20.40.1",
            ip_network="10.20.40.0/24",
            interface="wg0",
            public_key="PUBLIC_KEY",
            private_key="PRIVATE_KEY",
            listen_port=12345,
        ),
        connection_info=ConnectionModel(
            type=ConnectionType.SSH,
            data=SshConnectionModel(ip_address="10.0.0.1", username="test_user", key="SSH_KEY", key_password=None),
        ),
    ),
    VpnModel(
        name="test-vpn",
        description="Test VPN Server",
        wireguard=WireguardModel(
            ip_address="10.20.40.1",
            ip_network="10.20.40.0/24",
            interface="wg0",
            public_key="PUBLIC_KEY",
            private_key="PRIVATE_KEY",
            listen_port=12345,
        ),
        connection_info=ConnectionModel(
            type=ConnectionType.SSM,
            data=SsmConnectionModel(
                target_id="i-xxxxxxxxxxxxxxxxx", aws_access_key_id="abc", aws_secret_access_key="def"
            ),
        ),
    ),
]


@pytest.fixture(scope="function")
def mock_vpn_manager(mock_dynamodb):
    return VpnManager(db_manager=mock_dynamodb)


class TestPeerInterface:
    @pytest.mark.parametrize("test_input", test_parameters)
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    def test_add_peer_server_not_exist(self, mock_vpn_manager, test_input):
        """Try adding a peer to a vpn that doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key=None,
            persistent_keepalive=25,
            tags=["tag1"],
            message="Sample message",
        )

        # -----------------------------------------
        # Execute Test -
        response = client.post("/vpn/blah/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_add_peer_server_invalid_ip_network(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try adding a peer to a server using an IP in a different subnet."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.41.2",
            allowed_ips=["10.20.41.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key=None,
            persistent_keepalive=25,
            tags=["tag1"],
            message="Sample message",
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.BAD_REQUEST

    @pytest.mark.parametrize("test_input", test_parameters)
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    def test_add_peer(
        self,
        mock_ssm_client,
        mock_ssh_client,
        mock_ssm_command,
        mock_ssh_command,
        mock_dynamodb,
        mock_vpn_manager,
        test_input,
    ):
        """Try adding a peer successfully."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

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

        peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key="PEER_PRIVATE_KEY",
            persistent_keepalive=25,
            tags=["tag1"],
            message="Sample message",
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())
        actual_peer = PeerResponseModel(**response.json())
        compare_peer_request_and_response(peer_config, actual_peer, hide_secrets=True)

        # Validate Results
        assert response.status_code == HTTPStatus.OK

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamodb._get_all_peers_from_server()
        peer_from_db = PeerResponseModel(**all_peers[vpn.name][0].model_dump())
        compare_peer_request_and_response(peer_config, peer_from_db, hide_secrets=False)

        # Validate the peer was added to the mock WireGuard server
        if vpn.connection_info is not None:
            if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH:
                peers = mock_ssh_command.peers
            elif vpn.connection_info and vpn.connection_info.type == ConnectionType.SSM:
                peers = mock_ssm_command.peers
            else:
                peers = []

            found_wg_peer = False
            for wg_peer in peers:
                if wg_peer.wg_ip_address == peer_config.ip_address:
                    found_wg_peer = True
                    assert wg_peer.public_key == peer_config.public_key
                    assert wg_peer.persistent_keepalive == peer_config.persistent_keepalive
                    break
            assert found_wg_peer is True

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_add_peer_server_invalid_ip(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try adding peer using an existing IP address"""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Inject existing peer
        add_peer(vpn, mock_dynamodb)

        peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY2",
            private_key=None,
            persistent_keepalive=25,
            tags=["tag1"],
            message="Sample message",
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.CONFLICT

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_add_peer_server_invalid_public_key(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try adding peer using an existing public key"""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Inject existing peer
        add_peer(vpn, mock_dynamodb)

        peer_config = PeerRequestModel(
            ip_address="10.20.40.3",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key=None,
            persistent_keepalive=25,
            tags=["tag1"],
            message="Sample message",
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.CONFLICT

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_all_peers_hide_secrets(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try getting all peers."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Inject existing peer
        add_peer(vpn, mock_dynamodb)

        expected_peers = [
            PeerResponseModel(
                ip_address="10.20.40.2",
                allowed_ips=["10.20.40.0/24"],
                public_key="PEER_PUBLIC_KEY",
                private_key=SecretStr("**********"),
                persistent_keepalive=25,
                tags=["tag1"],
            )
        ]

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peers")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert [PeerResponseModel(**peer) for peer in response.json()] == expected_peers

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_all_peers_no_hide_secrets(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try getting all peers.  Don't hide the secrets"""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Inject existing peer
        add_peer(vpn, mock_dynamodb)

        expected_peers = [
            PeerResponseModel(
                ip_address="10.20.40.2",
                allowed_ips=["10.20.40.0/24"],
                public_key="PEER_PUBLIC_KEY",
                private_key=SecretStr("PEER_PRIVATE_KEY"),
                persistent_keepalive=25,
                tags=["tag1"],
            )
        ]

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peers?hide_secrets=false")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert [PeerResponseModel(**peer) for peer in response.json()] == expected_peers

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_all_peers_no_vpn(self, mock_vpn_manager, test_input):
        """Try getting all peers but the VPN server doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peers")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_no_vpn(self, mock_vpn_manager, test_input):
        """Try to get a peer but the VPN server doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/10.20.40.2")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_not_exist(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Try to get a peer but the peer doesn't exist."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/10.20.40.3")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Try getting a peer.  Don't hide the secrets."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Inject existing peer
        add_peer(vpn, mock_dynamodb)

        expected_peer = PeerResponseModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key=SecretStr("PEER_PRIVATE_KEY"),
            persistent_keepalive=25,
            tags=["tag1"],
        )

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}?hide_secrets=false")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert PeerResponseModel(**response.json()) == expected_peer

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_hide_secrets(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try getting a peer but hide the secrets."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Inject existing peer
        add_peer(vpn, mock_dynamodb)

        expected_peer = PeerResponseModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key=SecretStr("**********"),
            persistent_keepalive=25,
            tags=["tag1"],
        )

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert PeerResponseModel(**response.json()) == expected_peer

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_config_no_vpn(self, mock_vpn_manager, test_input):
        """Try to get a peer config but the VPN server doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/10.20.40.2/config")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_config_not_exist(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try to get a peer config but the peer doesn't exist."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/10.20.40.3/config")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_config(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Try getting a peer config."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Inject existing peer
        add_peer(vpn, mock_dynamodb)

        expected_peer = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key="PEER_PRIVATE_KEY",
            persistent_keepalive=25,
            tags=["tag1"],
            message="Sample message",
        )

        expected_config = f"""[Interface]
Address = {expected_peer.ip_address}
PrivateKey = {expected_peer.private_key}

[Peer]
PublicKey = {vpn.wireguard.public_key}
AllowedIPs = {",".join(expected_peer.allowed_ips)}
Endpoint = {vpn.connection_info.data.ip_address if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH else "[INSERT_VPN_IP]"}:{vpn.wireguard.listen_port}
PersistentKeepalive = {expected_peer.persistent_keepalive}"""

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/config")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert response.text == expected_config

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_generate_peer_keys_no_vpn(self, mock_vpn_manager, test_input):
        """Try to generate new peer keys but the vpn doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.post(
            f"/vpn/{vpn.name}/peer/10.20.40.2/generate-wireguard-keys", json={"message": "Sample message"}
        )

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_generate_peer_keys_no_peer(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try to generate new peer keys but the peer doesn't exist."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.post(
            f"/vpn/{vpn.name}/peer/10.20.40.23/generate-wireguard-keys", json={"message": "Sample message"}
        )

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    @patch("vpn_manager.codecs")
    def test_generate_peer_keys(
        self,
        mock_codecs,
        mock_ssm_client,
        mock_ssh_client,
        mock_ssm_command,
        mock_ssh_command,
        mock_dynamodb,
        mock_vpn_manager,
        test_input,
    ):
        """Try generating a new key-pair for a peer."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        add_peer(vpn, mock_dynamodb)  # Inject existing peer

        mock_codecs.encode.side_effect = ["GENERATED_PRIVATE_KEY".encode(), "GENERATED_PUBLIC_KEY".encode()]
        expected_peer = PeerResponseModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="GENERATED_PUBLIC_KEY",
            private_key=SecretStr("GENERATED_PRIVATE_KEY"),
            persistent_keepalive=25,
            tags=["tag1"],
        )

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

        # Execute Test
        response = client.post(
            f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/generate-wireguard-keys",
            json={"message": "Sample message"},
        )
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamodb._get_all_peers_from_server()
        for db_peer in all_peers[vpn.name]:
            if db_peer.ip_address == expected_peer.ip_address:
                assert db_peer.public_key == "GENERATED_PUBLIC_KEY"
                assert db_peer.private_key == "GENERATED_PRIVATE_KEY"

        # Validate the peer was added to the mock WireGuard server
        if vpn.connection_info is not None:
            for wg_peer in mock_ssh_command.peers:
                if wg_peer.wg_ip_address == expected_peer.ip_address:
                    assert wg_peer.public_key == expected_peer.public_key

    @pytest.mark.parametrize("test_input", test_parameters)
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    @patch("vpn_manager.codecs")
    def test_add_peer_auto_gen_parameters(
        self,
        mock_codecs,
        mock_ssm_client,
        mock_ssh_client,
        mock_ssm_command,
        mock_ssh_command,
        mock_dynamodb,
        mock_vpn_manager,
        test_input,
    ):
        """
        Try adding a peer but have the server auto-generate the keys and IP address.  This also tests adding multiple
        allowed IPs and tags.
        """
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        add_peer(vpn, mock_dynamodb)  # Inject existing peer
        mock_codecs.encode.side_effect = ["GENERATED_PRIVATE_KEY2".encode(), "GENERATED_PUBLIC_KEY2".encode()]
        peer_config = PeerRequestModel(
            allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
            persistent_keepalive=25,
            tags=["tag1", "tag2"],
            message="Sample message",
        )

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

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        actual_peer = PeerResponseModel(**response.json())

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamodb._get_all_peers_from_server()
        assert actual_peer.ip_address in [peer.ip_address for peer in all_peers[vpn.name]]

        # Validate the peer was added to the mock WireGuard server
        if vpn.connection_info is not None:
            if vpn.connection_info.type == ConnectionType.SSH:
                peers = mock_ssh_command.peers
            elif vpn.connection_info.type == ConnectionType.SSM:
                peers = mock_ssm_command.peers
            else:
                peers = []

            found_wg_peer = False
            for wg_peer in peers:
                if wg_peer.wg_ip_address == actual_peer.ip_address:
                    found_wg_peer = True
                    assert wg_peer.public_key == actual_peer.public_key
                    assert wg_peer.persistent_keepalive == actual_peer.persistent_keepalive
                    break
            assert found_wg_peer is True

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_add_tag_no_vpn(self, mock_vpn_manager, test_input):
        """Try to add a tag but the vpn doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.put(f"/vpn/{vpn.name}/peer/10.20.40.2/tag/tag4", json={"message": "Sample message"})

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_add_tag_no_peer(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Try to add a tag but the peer doesn't exist."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.put(f"/vpn/{vpn.name}/peer/10.20.40.23/tag/tag4", json={"message": "Sample message"})

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_add_tag(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Add a tag to a peer."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        new_peer = add_peer(vpn, mock_dynamodb)  # Inject existing peer

        expected_tag = "tag3"
        expected_peer = PeerResponseModel(
            ip_address=new_peer.ip_address,
            allowed_ips=new_peer.allowed_ips,
            public_key=new_peer.public_key,
            private_key=SecretStr("**********"),
            persistent_keepalive=new_peer.persistent_keepalive,
            tags=new_peer.tags + [expected_tag],
        )

        # Execute Test
        response = client.put(
            f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/tag/{expected_tag}", json={"message": "Sample message"}
        )
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamodb._get_all_peers_from_server()
        for db_peer in all_peers[vpn.name]:
            if db_peer.ip_address == expected_peer.ip_address:
                assert expected_tag in db_peer.tags

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_add_tag_again(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Try adding the same tag again.  This validates that it is idempotent."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        new_peer = add_peer(vpn, mock_dynamodb)  # Inject existing peer

        expected_peer = PeerResponseModel(
            ip_address=new_peer.ip_address,
            allowed_ips=new_peer.allowed_ips,
            public_key=new_peer.public_key,
            private_key=SecretStr("**********"),
            persistent_keepalive=new_peer.persistent_keepalive,
            tags=new_peer.tags,
        )

        # Execute Test
        response = client.put(
            f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/tag/{new_peer.tags[0]}",
            json={"message": "Sample message"},
        )
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamodb._get_all_peers_from_server()
        for db_peer in all_peers[vpn.name]:
            if db_peer.ip_address == expected_peer.ip_address:
                assert expected_peer.tags == db_peer.tags

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_remove_tag_no_vpn(self, mock_vpn_manager, test_input):
        """Try to remove a tag but the vpn doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.request(
            "DELETE", f"/vpn/{vpn.name}/peer/10.20.40.2/tag/tag1", json={"message": "Sample message"}
        )

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_remove_tag_no_peer(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Try to remove a tag but the peer doesn't exist."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.request(
            "DELETE", f"/vpn/{vpn.name}/peer/10.20.40.23/tag/tag1", json={"message": "Sample message"}
        )

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_remove_tag(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Remove a tag from a peer."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        new_peer = add_peer(vpn, mock_dynamodb)  # Inject existing peer

        remove_tag = "tag1"
        expected_peer = PeerResponseModel(
            ip_address=new_peer.ip_address,
            allowed_ips=new_peer.allowed_ips,
            public_key=new_peer.public_key,
            private_key=SecretStr("**********"),
            persistent_keepalive=new_peer.persistent_keepalive,
            tags=[],
        )

        # Execute Test
        response = client.request(
            "DELETE",
            f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/tag/{remove_tag}",
            json={"message": "Sample message"},
        )
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamodb._get_all_peers_from_server()
        for db_peer in all_peers[vpn.name]:
            if db_peer.ip_address == expected_peer.ip_address:
                assert remove_tag not in db_peer.tags

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_remove_tag_again(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Remove a tag that does not exist to validate it is idempotent."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        new_peer = add_peer(vpn, mock_dynamodb)  # Inject existing peer

        remove_tag = "tag_not_exist"
        expected_peer = PeerResponseModel(
            ip_address=new_peer.ip_address,
            allowed_ips=new_peer.allowed_ips,
            public_key=new_peer.public_key,
            private_key=SecretStr("**********"),
            persistent_keepalive=new_peer.persistent_keepalive,
            tags=new_peer.tags,
        )

        # Execute Test
        response = client.request(
            "DELETE",
            f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/tag/{remove_tag}",
            json={"message": "Sample message"},
        )
        assert response.status_code == HTTPStatus.OK
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

        # Validate the tags in the db are as expected
        all_peers = mock_dynamodb._get_all_peers_from_server()
        for db_peer in all_peers[vpn.name]:
            if db_peer.ip_address == expected_peer.ip_address:
                assert expected_peer.tags == db_peer.tags

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_by_tag_no_vpn(self, mock_vpn_manager, test_input):
        """Try to get a peer by tag but the VPN server doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/tag/tag1")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_by_tag_not_exist(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try to get a peer by tag but no peers match."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        add_peer(vpn, mock_dynamodb)  # Inject existing peer

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/tag/blah")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert response.json() == []

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_by_tag(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Try getting a peer by tag. Don't hide the secrets."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        add_peer(vpn, mock_dynamodb)  # Inject existing peer
        # Inject a second peer
        add_peer(
            vpn,
            mock_dynamodb,
            PeerDbModel(
                peer_id="2345",
                ip_address="10.20.40.3",
                allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
                public_key="PEER2_PUBLIC_KEY",
                private_key="PEER2_PRIVATE_KEY",
                persistent_keepalive=25,
                tags=["tag1", "tag2"],
                message="Sample message",
            ),
        )

        expected_peers = [
            PeerResponseModel(
                ip_address="10.20.40.2",
                allowed_ips=["10.20.40.0/24"],
                public_key="PEER_PUBLIC_KEY",
                private_key=SecretStr("PEER_PRIVATE_KEY"),
                persistent_keepalive=25,
                tags=["tag1"],
            ),
            PeerResponseModel(
                ip_address="10.20.40.3",
                allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
                public_key="PEER2_PUBLIC_KEY",
                private_key=SecretStr("PEER2_PRIVATE_KEY"),
                persistent_keepalive=25,
                tags=["tag1", "tag2"],
            ),
        ]

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/tag/tag1?hide_secrets=false")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert [PeerResponseModel(**peer_data) for peer_data in response.json()] == expected_peers

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_get_peer_by_tag_hide_secrets(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try getting a peer by tag but hide the secrets."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        new_peer = add_peer(vpn, mock_dynamodb)  # Inject existing peer
        # Inject a second peer
        add_peer(
            vpn,
            mock_dynamodb,
            PeerDbModel(
                peer_id="2345",
                ip_address="10.20.40.3",
                allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
                public_key="PEER2_PUBLIC_KEY",
                private_key="PEER2_PRIVATE_KEY",
                persistent_keepalive=25,
                tags=["tag1", "tag2"],
                message="Sample message",
            ),
        )

        expected_peers = [
            PeerResponseModel(
                ip_address="10.20.40.2",
                allowed_ips=["10.20.40.0/24"],
                public_key="PEER_PUBLIC_KEY",
                private_key=SecretStr("**********"),
                persistent_keepalive=25,
                tags=["tag1"],
            ),
            PeerResponseModel(
                ip_address="10.20.40.3",
                allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
                public_key="PEER2_PUBLIC_KEY",
                private_key=SecretStr("**********"),
                persistent_keepalive=25,
                tags=["tag1", "tag2"],
            ),
        ]

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/tag/tag1?hide_secrets=true")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert [PeerResponseModel(**peer_data) for peer_data in response.json()] == expected_peers

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_import_peers_no_vpn(self, mock_vpn_manager, test_input):
        """Try to import peers from the wireguard server but the vpn doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/import", json={"message": "Sample message"})

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    def test_import_peers(
        self,
        mock_ssm_client,
        mock_ssh_client,
        mock_ssm_command,
        mock_ssh_command,
        mock_dynamodb,
        mock_vpn_manager,
        test_input,
    ):
        """Importing peers from the wireguard server."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        add_peer(vpn, mock_dynamodb)  # Inject existing peer

        expected_peer = PeerResponseModel(
            ip_address="10.20.40.4",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY4",
            private_key=None,
            persistent_keepalive=25,
            tags=["imported"],
        )
        wg_peer = WgServerPeerModel(
            wg_ip_address=expected_peer.ip_address,
            public_key=expected_peer.public_key,
            persistent_keepalive=expected_peer.persistent_keepalive,
            endpoint="(none)",
            latest_handshake=25,
            transfer_rx=25,
            transfer_tx=25,
            preshared_key=None,
        )

        if vpn.connection_info is not None:
            # Inject the peer into the mock WireGuard server
            if vpn.connection_info.type == ConnectionType.SSH:
                mock_ssh_command.inject_peer(wg_peer)
            if vpn.connection_info.type == ConnectionType.SSM:
                mock_ssm_command.inject_peer(wg_peer)

            if vpn.connection_info.type == ConnectionType.SSH:
                ssh_client = mock_ssh_client()
                ssh_client.exec_command = mock_ssh_command.command
            elif vpn.connection_info.type == ConnectionType.SSM:
                mock_ssm_client_instance = mock_ssm_client()
                mock_ssm_client_instance.send_command = mock_ssm_command.send_command  # Random ID
                mock_ssm_client_instance.get_command_invocation = mock_ssm_command.command

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/import", json={"message": "Sample message"})

        # Validate Results
        if vpn.connection_info is None:
            assert response.status_code == HTTPStatus.NOT_FOUND
        elif vpn.connection_info.type == ConnectionType.SSM:
            # Importing peers over SSM is not supported currently
            assert response.status_code == HTTPStatus.BAD_REQUEST
        else:
            assert response.status_code == HTTPStatus.OK
            assert response.json() == [expected_peer.model_dump()]

            # Validate the peer was added to DynamoDB
            found_db_peer = False
            all_peers = mock_dynamodb._get_all_peers_from_server()
            for db_peer in all_peers[vpn.name]:
                if db_peer.ip_address == expected_peer.ip_address:
                    found_db_peer = True
                    assert expected_peer == PeerResponseModel(**db_peer.model_dump())
                    break
            assert found_db_peer is True

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_delete_peer_no_vpn(self, mock_vpn_manager, test_input):
        """Try to delete a peer by tag but the VPN server doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.request("DELETE", f"/vpn/{vpn.name}/peer/10.20.40.1", json={"message": "Sample message"})

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_delete_peer_not_exist(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Try to delete a peer by tag but no peers match.  This also validates that it is idempotent."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.request("DELETE", f"/vpn/{vpn.name}/peer/10.20.40.1", json={"message": "Sample message"})

        # Validate Results
        assert response.status_code == HTTPStatus.OK

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_peer_history_no_vpn(self, mock_vpn_manager, test_input):
        """Test peer history endpoint with invalid start/end time."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        ip = "10.20.40.2"
        now = datetime.datetime.now()
        start = now
        end = now - datetime.timedelta(hours=1)
        response = client.get(
            f"/vpn/{vpn.name}/peer/{ip}/history", params={"start_time": start.isoformat(), "end_time": end.isoformat()}
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_peer_history_invalid_time(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Test peer history endpoint with invalid start/end time."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        add_peer(vpn, mock_dynamodb)  # Inject existing peer
        ip = "10.20.40.2"
        now = datetime.datetime.now()
        start = now
        end = now - datetime.timedelta(hours=1)
        response = client.get(
            f"/vpn/{vpn.name}/peer/{ip}/history", params={"start_time": start.isoformat(), "end_time": end.isoformat()}
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert "Start time must be before end time" in response.text

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_peer_history_no_peer(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Test peer history endpoint when there is no peer."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        ip = "10.20.40.99"
        response = client.get(f"/vpn/{vpn.name}/peer/{ip}/history")
        assert response.status_code == HTTPStatus.NOT_FOUND
        assert "No peer history found" in response.text

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_tag_history_no_history(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Test tag history endpoint when there is no history."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        add_peer(vpn, mock_dynamodb)  # Inject existing peer
        tag = "nope"

        response = client.get(f"/vpn/{vpn.name}/tag/{tag}/history")
        assert response.status_code == HTTPStatus.NOT_FOUND
        assert "No tag_history found" in response.text

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_peer_history_all(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Test peer history endpoint returns all history."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        peer1, peer2 = seed_history(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command, client)

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/{peer1.ip_address}/history")

        # Validate Results
        assert response.status_code == 200
        data = response.json()
        # Assert all entries contains the expected ip address
        assert all(d["ip_address"] == peer1.ip_address for d in data)
        # Assert the entries are in descending order by timestamp
        assert all(a["timestamp"] >= b["timestamp"] for a, b in zip(data, data[1:]))
        # Assert the expected messages exist in the history
        for message in ["Generate new keys", "Add new peer"]:
            assert any(message in d["message"] for d in data)

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_tag_history_all(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Test peer history endpoint returns all history."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        peer1, peer2 = seed_history(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command, client)
        tag = "tag1"

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/tag/{tag}/history")

        # Validate Results
        assert response.status_code == 200
        data = response.json()
        # Assert all entries contains the expected tag
        assert all(tag in peer_history["tags"] for peer_histories in data.values() for peer_history in peer_histories)
        for peer in [peer1, peer2]:
            history_records = data.get(peer.ip_address)
            assert history_records is not None
            # Assert the entries are in descending order by timestamp
            assert all(a["timestamp"] >= b["timestamp"] for a, b in zip(history_records, history_records[1:]))
            if peer == peer1:
                assert len(history_records) == 3
                # Assert the expected messages exist in the history
                for message in ["Generate new keys", "Add new peer"]:
                    assert any(message in d["message"] for d in history_records)
            elif peer == peer2:
                assert len(history_records) == 2
                # Assert the expected messages exist in the history
                for message in ["Add second peer"]:
                    assert any(message in d["message"] for d in history_records)

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_peer_history_with_time(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Test peer history endpoint returns all history."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager

        peer1, peer2 = seed_history(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command, client)

        # Execute Test
        start = 1626000000000000000
        end = 1626000002000000000
        response = client.get(
            f"/vpn/{vpn.name}/peer/{peer1.ip_address}/history",
            params={"start_time": start / 1_000_000_000, "end_time": end / 1_000_000_000},
        )

        # Validate Results
        assert response.status_code == 200
        data = response.json()
        # Assert all entries contains the expected ip address
        assert all(d["ip_address"] == peer1.ip_address for d in data)
        # Assert the entries are in descending order by timestamp
        assert all(a["timestamp"] >= b["timestamp"] for a, b in zip(data, data[1:]))
        # Assert the expected messages exist in the history
        assert any("Add new peer" in d["message"] for d in data)
        assert any("Add tag2" in d["message"] for d in data)
        assert not any("Generate new keys" in d["message"] for d in data)

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_tag_history_with_time(
        self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input
    ):
        """Test peer history endpoint returns all history."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        peer1, peer2 = seed_history(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command, client)
        tag = "tag1"

        # Execute Test
        start = 1626000000000000000
        end = 1626000002000000000
        response = client.get(
            f"/vpn/{vpn.name}/tag/{tag}/history",
            params={"start_time": start / 1_000_000_000, "end_time": end / 1_000_000_000},
        )

        # Validate Results
        assert response.status_code == 200
        data = response.json()

        # Assert all entries contains the expected tag
        assert all(tag in peer_history["tags"] for peer_histories in data.values() for peer_history in peer_histories)

        for peer in [peer1, peer2]:
            history_records = data.get(peer.ip_address)
            assert history_records is not None
            # Assert the entries are in descending order by timestamp
            assert all(a["timestamp"] >= b["timestamp"] for a, b in zip(history_records, history_records[1:]))
            if peer == peer1:
                assert len(history_records) == 2
                # Assert the expected messages exist in the history
                for message in ["Add tag2", "Add new peer"]:
                    assert any(message in d["message"] for d in history_records)
                assert not any("Generate new keys" in d["message"] for d in history_records)
            elif peer == peer2:
                assert len(history_records) == 1
                # Assert the expected messages exist in the history
                for message in ["Add second peer"]:
                    assert any(message in d["message"] for d in history_records)

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_update_peer_server_not_exist(self, mock_vpn_manager, test_input):
        """Try updating a peer to a server that doesn't exist."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key=None,
            persistent_keepalive=25,
            tags=["tag1"],
            message="Sample message",
        )

        # -----------------------------------------
        # Execute Test -
        response = client.put(f"/vpn/{vpn.name}/peer/{peer_config.ip_address}", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @pytest.mark.parametrize("test_input", test_parameters)
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    def test_update_peer_not_exist(
        self,
        mock_ssm_client,
        mock_ssh_client,
        mock_ssh_command,
        mock_ssm_command,
        mock_vpn_manager,
        mock_dynamodb,
        test_input,
    ):
        """Try updating a peer that doesn't exist.  This should add the peer."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        expected_peer_config = PeerRequestModel(
            ip_address="10.20.40.4",
            allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
            public_key="PEER_PUBLIC_KEY4",
            private_key="PEER_PRIVATE_KEY4",
            persistent_keepalive=25,
            tags=["tag4"],
            message="Sample message",
        )

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

        # Execute Test
        response = client.put(
            f"/vpn/{vpn.name}/peer/{expected_peer_config.ip_address}", data=expected_peer_config.model_dump_json()
        )
        updated_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        compare_peer_request_and_response(expected_peer_config, updated_peer, hide_secrets=True)

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamodb._get_all_peers_from_server()
        dynamo_peer = PeerResponseModel(**all_peers[vpn.name][0].model_dump())
        compare_peer_request_and_response(expected_peer_config, dynamo_peer, hide_secrets=False)

        # Validate the peer was added to the mock WireGuard server
        if vpn.connection_info is not None:
            if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH:
                peers = mock_ssh_command.peers
            elif vpn.connection_info and vpn.connection_info.type == ConnectionType.SSM:
                peers = mock_ssm_command.peers
            else:
                peers = []

            found_wg_peer = False
            for wg_peer in peers:
                if wg_peer.wg_ip_address == expected_peer_config.ip_address:
                    found_wg_peer = True
                    assert wg_peer.public_key == expected_peer_config.public_key
                    assert wg_peer.persistent_keepalive == expected_peer_config.persistent_keepalive
                    break
            assert found_wg_peer is True

    @pytest.mark.parametrize("test_input", test_parameters)
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    def test_update_peer(
        self,
        mock_ssm_client,
        mock_ssh_client,
        mock_ssm_command,
        mock_ssh_command,
        mock_dynamodb,
        mock_vpn_manager,
        test_input,
    ):
        """Update a peer.  Update the allowed IPs, public key, private key, persistent keepalive, and tags."""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        add_peer(vpn, mock_dynamodb)  # Inject existing peer
        expected_peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
            public_key="PEER_PUBLIC_KEY_UPDATED",
            private_key="PEER_PRIVATE_KEY_UPDATED",
            persistent_keepalive=30,
            tags=["tag1", "updated_tag2"],
            message="Sample message",
        )

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

        # Execute Test
        response = client.put(
            f"/vpn/{vpn.name}/peer/{expected_peer_config.ip_address}", data=expected_peer_config.model_dump_json()
        )
        updated_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        compare_peer_request_and_response(expected_peer_config, updated_peer, hide_secrets=True)

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamodb._get_all_peers_from_server()
        dynamo_peer = PeerResponseModel(**all_peers[vpn.name][0].model_dump())
        compare_peer_request_and_response(expected_peer_config, dynamo_peer, hide_secrets=False)

        # Validate the peer was added to the mock WireGuard server
        if vpn.connection_info is not None:
            if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH:
                peers = mock_ssh_command.peers
            elif vpn.connection_info and vpn.connection_info.type == ConnectionType.SSM:
                peers = mock_ssm_command.peers
            else:
                peers = []

            found_wg_peer = False
            for wg_peer in peers:
                if wg_peer.wg_ip_address == expected_peer_config.ip_address:
                    found_wg_peer = True
                    assert wg_peer.public_key == expected_peer_config.public_key
                    assert wg_peer.persistent_keepalive == expected_peer_config.persistent_keepalive
                    break
            assert found_wg_peer is True

    @pytest.mark.parametrize("test_input", test_parameters)
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    def test_delete_peer(
        self,
        mock_ssm_client,
        mock_ssh_client,
        mock_ssm_command,
        mock_ssh_command,
        mock_dynamodb,
        mock_vpn_manager,
        test_input,
    ):
        """Delete a peer."""
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        peer_router.vpn_manager = mock_vpn_manager
        add_peer(vpn, mock_dynamodb)  # Inject existing peer
        delete_ips = ["10.20.40.2", "10.20.40.3"]

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

        for delete_ip in delete_ips:
            # Execute Test
            response = client.request("DELETE", f"/vpn/{vpn.name}/peer/{delete_ip}", json={"message": "Sample message"})

            # Validate Results
            assert response.status_code == HTTPStatus.OK
            get_response = client.get(f"/vpn/{vpn.name}/peer/{delete_ip}")
            assert get_response.status_code == HTTPStatus.NOT_FOUND

            # Validate the peer was deleted from DynamoDB
            all_peers = mock_dynamodb._get_all_peers_from_server()
            if len(all_peers) > 0:
                assert [db_peer for db_peer in all_peers[vpn.name] if db_peer.ip_address == delete_ip] == []

            # Validate the peer was removed from the mock WireGuard server
            if vpn.connection_info is not None:
                for wg_peer in mock_ssh_command.peers:
                    if wg_peer.wg_ip_address == delete_ip:
                        assert wg_peer.wg_ip_address != delete_ip

    @pytest.mark.parametrize("test_input", test_parameters)
    def test_delete_vpn(self, mock_ssm_command, mock_ssh_command, mock_dynamodb, mock_vpn_manager, test_input):
        """Test deleting a VPN server"""
        # Set up Test
        vpn = test_input
        add_vpn(vpn, mock_dynamodb, mock_ssm_command, mock_ssh_command)
        vpn_router.vpn_manager = mock_vpn_manager

        # Execute Test - Delete the VPN server
        response = client.request("DELETE", f"/vpn/{vpn.name}", json={"message": "Delete VPN server"})

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        response = client.get(f"/vpn/{vpn.name}")
        assert response.status_code == HTTPStatus.NOT_FOUND

        # ---------------------------------------------------
        # Execute Test - Verify this is idempotent
        response = client.request("DELETE", f"/vpn/{vpn.name}", json={"message": "Delete VPN server again"})

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        all_vpns = mock_dynamodb._get_all_vpn_from_server()
        assert all_vpns == []
