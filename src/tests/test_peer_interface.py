import urllib.parse
from http import HTTPStatus
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import pytest
from pydantic import SecretStr
import datetime

from app import app, vpn_router
from models.peer_history import PeerHistoryResponseModel
from models.ssh import SshConnectionModel
from models.ssm import SsmConnectionModel
from models.vpn import VpnPutModel, WireguardModel, VpnModel
from models.connection import ConnectionModel, ConnectionType
from models.wg_server import WgServerModel, WgServerPeerModel
from models.peers import PeerRequestModel, PeerResponseModel
from interfaces.peers import peer_router


client = TestClient(app)

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


@pytest.mark.parametrize("test_input", test_parameters, scope="class")
class TestPeerInterface:
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    def test_add_server_successfully(
        self,
        mock_ssm_client,
        mock_ssh_client,
        mock_ssm_command,
        mock_ssh_command,
        mock_vpn_table,
        mock_peer_table,
        mock_peer_history_table,
        mock_vpn_manager,
        mock_dynamo_db,
        test_input,
    ):
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager
        vpn = test_input
        vpn_config = VpnPutModel(
            wireguard=vpn.wireguard,
            connection_info=vpn.connection_info,
        )
        vpn_router.vpn_manager = mock_vpn_manager
        if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH:
            mock_ssh_client_instance = mock_ssh_client()
            mock_ssh_client_instance.exec_command = mock_ssh_command.command

        elif vpn.connection_info and vpn.connection_info.type == ConnectionType.SSM:
            mock_ssm_client_instance = mock_ssm_client()
            mock_ssm_client_instance.send_command = mock_ssm_command.send_command  # Random ID
            mock_ssm_client_instance.get_command_invocation = mock_ssm_command.command

        # Execute Test
        url = f"/vpn/{vpn.name}?{urllib.parse.urlencode(dict(description=vpn.description))}"
        response = client.put(url, data=vpn_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        all_vpns = mock_dynamo_db._get_all_vpn_from_server()
        assert all_vpns == [vpn]

    def test_add_peer_server_not_exist(self, test_input, mock_vpn_manager):
        """Try adding a peer to a server that doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key=None,
            persistent_keepalive=25,
            tags=["tag1"],
        )

        # -----------------------------------------
        # Execute Test -
        response = client.post(f"/vpn/blah/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_add_peer_server_invalid_ip_network(self, test_input, mock_vpn_manager):
        """Try adding a peer to a server using an IP in a different subnet."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.41.2",
            allowed_ips=["10.20.41.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key=None,
            persistent_keepalive=25,
            tags=["tag1"],
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.BAD_REQUEST

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    def test_add_peer(
        self,
        mock_ssm_client,
        mock_ssh_client,
        test_input,
        mock_ssh_command,
        mock_ssm_command,
        mock_vpn_manager,
        mock_vpn_table,
        mock_peer_table,
        mock_peer_history_table,
        mock_dynamo_db,
    ):
        """Try adding a peer successfully."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key="PEER_PRIVATE_KEY",
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
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert response.status_code == HTTPStatus.OK

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamo_db._get_all_peers_from_server()
        assert PeerRequestModel(**all_peers[vpn.name][0].model_dump()) == peer_config

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

    def test_add_peer_server_invalid_ip(self, test_input, mock_vpn_manager):
        """Try adding peer using an existing IP address"""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY2",
            private_key=None,
            persistent_keepalive=25,
            tags=["tag1"],
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.CONFLICT

    def test_add_peer_server_invalid_public_key(self, test_input, mock_vpn_manager):
        """Try adding peer using an existing public key"""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.40.3",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key=None,
            persistent_keepalive=25,
            tags=["tag1"],
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.CONFLICT

    def test_get_all_peers_hide_secrets(self, test_input, mock_vpn_manager):
        """Try getting all peers."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
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

    def test_get_all_peers_no_hide_secrets(self, test_input, mock_vpn_manager):
        """Try getting all peers.  Don't hide the secrets"""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
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

    def test_get_all_peers_no_vpn(self, test_input, mock_vpn_manager):
        """Try getting all peers but the VPN server doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/blah/peers")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_get_peer_no_vpn(self, test_input, mock_vpn_manager):
        """Try to get a peer but the VPN server doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/blah/peer/10.20.40.2")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_get_peer_not_exist(self, test_input, mock_vpn_manager):
        """Try to get a peer but the peer doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{test_input.name}/peer/10.20.40.3")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_get_peer(self, test_input, mock_vpn_manager):
        """Try getting a peer.  Don't hide the secrets."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
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

    def test_get_peer_hide_secrets(self, test_input, mock_vpn_manager):
        """Try getting a peer but hide the secrets."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
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

    def test_get_peer_config_no_vpn(self, test_input, mock_vpn_manager):
        """Try to get a peer config but the VPN server doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/blah/peer/10.20.40.2/config")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_get_peer_config_not_exist(self, test_input, mock_vpn_manager):
        """Try to get a peer config but the peer doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{test_input.name}/peer/10.20.40.3/config")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_get_peer_config(self, test_input, mock_vpn_manager):
        """Try getting a peer config."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager

        expected_peer = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="PEER_PUBLIC_KEY",
            private_key="PEER_PRIVATE_KEY",
            persistent_keepalive=25,
            tags=["tag1"],
        )

        expected_config = f"""[Interface]
Address = {expected_peer.ip_address}
PrivateKey = {expected_peer.private_key}

[Peer]
PublicKey = {vpn.wireguard.public_key}
AllowedIPs = {",".join(expected_peer.allowed_ips)}
Endpoint = {vpn.connection_info.data.ip_address if vpn.connection_info and vpn.connection_info.type==ConnectionType.SSH else "[INSERT_VPN_IP]"}:{vpn.wireguard.listen_port}
PersistentKeepalive = {expected_peer.persistent_keepalive}"""

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/config")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert response.text == expected_config

    def test_generate_peer_keys_no_vpn(self, test_input, mock_vpn_manager):
        """Try to generate new peer keys but the vpn doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.post(f"/vpn/blah/peer/10.20.40.2/generate-wireguard-keys")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_generate_peer_keys_no_peer(self, test_input, mock_vpn_manager):
        """Try to generate new peer keys but the peer doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.post(f"/vpn/{test_input.name}/peer/10.20.40.23/generate-wireguard-keys")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    @patch("vpn_manager.codecs")
    def test_generate_peer_keys(
        self,
        mock_codecs,
        mock_ssm_client,
        mock_ssh_client,
        mock_vpn_manager,
        mock_ssh_command,
        mock_ssm_command,
        mock_dynamo_db,
        test_input,
    ):
        """Try generating a new key-pair for a peer."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
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
        response = client.post(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/generate-wireguard-keys")
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamo_db._get_all_peers_from_server()
        for db_peer in all_peers[vpn.name]:
            if db_peer.ip_address == expected_peer.ip_address:
                assert db_peer.public_key == "GENERATED_PUBLIC_KEY"
                assert db_peer.private_key == "GENERATED_PRIVATE_KEY"

        # Validate the peer was added to the mock WireGuard server
        if vpn.connection_info is not None:
            for wg_peer in mock_ssh_command.peers:
                if wg_peer.wg_ip_address == expected_peer.ip_address:
                    assert wg_peer.public_key == expected_peer.public_key

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    @patch("vpn_manager.codecs")
    def test_add_peer_auto_gen_parameters(
        self,
        mock_codecs,
        mock_ssm_client,
        mock_ssh_client,
        test_input,
        mock_ssh_command,
        mock_ssm_command,
        mock_vpn_manager,
        mock_vpn_table,
        mock_peer_table,
        mock_peer_history_table,
        mock_dynamo_db,
    ):
        """
        Try adding a peer but have the server auto-generate the keys and IP address.  This also tests adding multiple
        allowed IPs and tags.
        """
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        mock_codecs.encode.side_effect = ["GENERATED_PRIVATE_KEY2".encode(), "GENERATED_PUBLIC_KEY2".encode()]
        peer_config = PeerRequestModel(
            allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
            persistent_keepalive=25,
            tags=["tag1", "tag2"],
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
        all_peers = mock_dynamo_db._get_all_peers_from_server()
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

    def test_add_tag_no_vpn(self, test_input, mock_vpn_manager):
        """Try to add a tag but the vpn doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.put(f"/vpn/blah/peer/10.20.40.2/tag/tag4")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_add_tag_no_peer(self, test_input, mock_vpn_manager):
        """Try to add a tag but the peer doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.put(f"/vpn/{test_input.name}/peer/10.20.40.23/tag/tag4")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_add_tag(self, test_input, mock_vpn_manager, mock_vpn_table, mock_peer_table, mock_dynamo_db):
        """Add a tag to a peer."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        expected_tag = "tag3"
        expected_peer = PeerResponseModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="GENERATED_PUBLIC_KEY",
            private_key=SecretStr("**********"),
            persistent_keepalive=25,
            tags=["tag1", expected_tag],
        )

        # Execute Test
        response = client.put(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/tag/{expected_tag}")
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamo_db._get_all_peers_from_server()
        for db_peer in all_peers[vpn.name]:
            if db_peer.ip_address == expected_peer.ip_address:
                assert expected_tag in db_peer.tags

    def test_add_tag_again(self, test_input, mock_vpn_manager, mock_vpn_table, mock_peer_table, mock_dynamo_db):
        """Try adding the same tag again.  This validates that it is idempotent."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        expected_tag = "tag3"
        expected_peer = PeerResponseModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="GENERATED_PUBLIC_KEY",
            private_key=SecretStr("**********"),
            persistent_keepalive=25,
            tags=["tag1", expected_tag],
        )

        # Execute Test
        response = client.put(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/tag/{expected_tag}")
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

    def test_remove_tag_no_vpn(self, test_input, mock_vpn_manager):
        """Try to remove a tag but the vpn doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.delete(f"/vpn/blah/peer/10.20.40.2/tag/tag1")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_remove_tag_no_peer(self, test_input, mock_vpn_manager):
        """Try to remove a tag but the peer doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.delete(f"/vpn/{test_input.name}/peer/10.20.40.23/tag/tag1")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_remove_tag(self, test_input, mock_vpn_manager, mock_vpn_table, mock_peer_table, mock_dynamo_db):
        """Remove a tag from a peer."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        expected_tag = "tag3"
        expected_peer = PeerResponseModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="GENERATED_PUBLIC_KEY",
            private_key=SecretStr("**********"),
            persistent_keepalive=25,
            tags=["tag1"],
        )

        # Execute Test
        response = client.delete(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/tag/{expected_tag}")
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamo_db._get_all_peers_from_server()
        for db_peer in all_peers[vpn.name]:
            if db_peer.ip_address == expected_peer.ip_address:
                assert expected_tag not in db_peer.tags

    def test_remove_tag_again(self, test_input, mock_vpn_manager, mock_vpn_table, mock_peer_table, mock_dynamo_db):
        """Remove same tag again to validate it is idempotent."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        expected_tag = "tag3"
        expected_peer = PeerResponseModel(
            ip_address="10.20.40.2",
            allowed_ips=["10.20.40.0/24"],
            public_key="GENERATED_PUBLIC_KEY",
            private_key=SecretStr("**********"),
            persistent_keepalive=25,
            tags=["tag1"],
        )

        # Execute Test
        response = client.delete(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/tag/{expected_tag}")
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert actual_peer == expected_peer

    def test_get_peer_by_tag_no_vpn(self, test_input, mock_vpn_manager):
        """Try to get a peer by tag but the VPN server doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/blah/peer/tag/tag1")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_get_peer_by_tag_not_exist(self, test_input, mock_vpn_manager):
        """Try to get a peer by tag but no peers match."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{test_input.name}/peer/tag/blah")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert response.json() == []

    def test_get_peer_by_tag(self, test_input, mock_vpn_manager):
        """Try getting a peer by tag. Don't hide the secrets."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        expected_peers = [
            PeerResponseModel(
                ip_address="10.20.40.2",
                allowed_ips=["10.20.40.0/24"],
                public_key="GENERATED_PUBLIC_KEY",
                private_key=SecretStr("GENERATED_PRIVATE_KEY"),
                persistent_keepalive=25,
                tags=["tag1"],
            ),
            PeerResponseModel(
                ip_address="10.20.40.3",
                allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
                public_key="GENERATED_PUBLIC_KEY2",
                private_key=SecretStr("GENERATED_PRIVATE_KEY2"),
                persistent_keepalive=25,
                tags=["tag1", "tag2"],
            ),
        ]

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/tag/tag1?hide_secrets=false")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert [PeerResponseModel(**peer_data) for peer_data in response.json()] == expected_peers

    def test_get_peer_by_tag_hide_secrets(self, test_input, mock_vpn_manager):
        """Try getting a peer by tag but hide the secrets."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        expected_peer = PeerResponseModel(
            ip_address="10.20.40.3",
            allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
            public_key="GENERATED_PUBLIC_KEY2",
            private_key=SecretStr("**********"),
            persistent_keepalive=25,
            tags=["tag1", "tag2"],
        )

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/tag/tag2")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert [PeerResponseModel(**peer_data) for peer_data in response.json()] == [expected_peer]

    def test_import_peers_no_vpn(self, test_input, mock_vpn_manager):
        """Try to import peers from the wireguard server but the vpn doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.post(f"/vpn/blah/import")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    def test_import_peers(
        self,
        mock_ssm_client,
        mock_ssh_client,
        test_input,
        mock_ssh_command,
        mock_ssm_command,
        mock_vpn_manager,
        mock_vpn_table,
        mock_peer_table,
        mock_peer_history_table,
        mock_dynamo_db,
    ):
        """Importing peers from the wireguard server."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        expected_peer = PeerRequestModel(
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

        mock_ssh_command.server = WgServerModel(
            interface=vpn.wireguard.interface,
            public_key=vpn.wireguard.public_key,
            private_key=vpn.wireguard.private_key,
            listen_port=vpn.wireguard.listen_port,
            fw_mark="off",
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
        response = client.post(f"/vpn/{vpn.name}/import")

        # Validate Results
        if vpn.connection_info is None:
            assert response.status_code == HTTPStatus.NOT_FOUND
        else:
            assert response.status_code == HTTPStatus.OK

            # Validate the peer was added to DynamoDB
            found_db_peer = False
            all_peers = mock_dynamo_db._get_all_peers_from_server()
            for db_peer in all_peers[vpn.name]:
                if db_peer.ip_address == expected_peer.ip_address:
                    found_db_peer = True
                    assert PeerRequestModel(**db_peer.model_dump()) == expected_peer
                    break
            assert found_db_peer is True

            # Validate the peer was added to the mock WireGuard server
            if vpn.connection_info.type == ConnectionType.SSH:
                peers = mock_ssh_command.peers
            elif vpn.connection_info.type == ConnectionType.SSM:
                peers = mock_ssm_command.peers
            else:
                peers = []

            found_wg_peer = False
            for wg_peer in peers:
                if wg_peer.wg_ip_address == expected_peer.ip_address:
                    found_wg_peer = True
                    assert wg_peer.public_key == expected_peer.public_key
                    assert wg_peer.persistent_keepalive == expected_peer.persistent_keepalive
                    break
            assert found_wg_peer is True

            del_response = client.delete(f"/vpn/{test_input.name}/peer/10.20.40.4")
            assert del_response.status_code == HTTPStatus.OK

    def test_delete_peer_no_vpn(self, test_input, mock_vpn_manager):
        """Try to delete a peer by tag but the VPN server doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.delete(f"/vpn/blah/peer/10.20.40.2")

        # Validate Results
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_delete_peer_not_exist(self, test_input, mock_vpn_manager):
        """Try to delete a peer by tag but no peers match.  This also validates that it is idempotent."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.delete(f"/vpn/{test_input.name}/peer/10.20.40.23")

        # Validate Results
        assert response.status_code == HTTPStatus.OK

    def test_peer_history_invalid_time(
        self,
        test_input,
        mock_vpn_manager,
        mock_vpn_table,
        mock_peer_table,
        mock_peer_history_table,
        mock_dynamo_db,
    ):
        """Test peer history endpoint with invalid start/end time."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        ip = "10.20.40.2"
        now = datetime.datetime.now()
        start = now
        end = now - datetime.timedelta(hours=1)
        response = client.get(
            f"/vpn/{vpn.name}/peer/{ip}/history",
            params={"start_time": start.isoformat(), "end_time": end.isoformat()},
        )
        assert response.status_code == 400
        assert "Start time must be before end time" in response.text

    def test_tag_history_invalid_time(self, test_input, mock_vpn_manager):
        """Test tag history endpoint with invalid start/end time."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        tag = "tag1"
        now = datetime.datetime.now()
        start = now
        end = now - datetime.timedelta(hours=1)
        response = client.get(
            f"/vpn/{vpn.name}/tag/{tag}/history",
            params={"start_time": start.isoformat(), "end_time": end.isoformat()},
        )
        assert response.status_code == 400
        assert "Start time must be before end time" in response.text

    def test_peer_history_no_history(self, test_input, mock_vpn_manager):
        """Test peer history endpoint when there is no history."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        ip = "10.20.40.99"
        response = client.get(f"/vpn/{vpn.name}/peer/{ip}/history")
        assert response.status_code == 404
        assert "No peer history found" in response.text

    def test_tag_history_no_history(self, test_input, mock_vpn_manager):
        """Test tag history endpoint when there is no history."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        tag = "nope"
        response = client.get(f"/vpn/{vpn.name}/tag/{tag}/history")
        assert response.status_code == 404
        assert "No tag_history found" in response.text

    def test_peer_history_all(self, test_input, mock_vpn_manager, mock_peer_history_table):
        """Test peer history endpoint returns all history."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        ip = "10.20.40.2"
        response = client.get(f"/vpn/{vpn.name}/peer/{ip}/history")
        assert response.status_code == 200
        data = response.json()
        # Assert all entries contains the expect ip address
        assert all(d["ip_address"] == ip for d in data)
        # Assert the entries are in descending order by timestamp
        assert all(a["timestamp"] >= b["timestamp"] for a, b in zip(data, data[1:]))

    def test_tag_history_all(self, test_input, mock_vpn_manager, mock_peer_history_table):
        """Test tag history endpoint returns all history."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        tag = "tag1"
        response = client.get(f"/vpn/{vpn.name}/tag/{tag}/history")
        assert response.status_code == 200
        data = response.json()
        # Assert all entries contains the expected tag
        assert all(tag in peer_history["tags"] for peer_histories in data.values() for peer_history in peer_histories)

    def test_peer_history_with_time(self, test_input, mock_vpn_manager, mock_peer_history_table):
        """Test peer history endpoint with start/end time filters."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        ip = "10.20.40.2"
        start = 1626000000000000000
        end = 1626000003000000000
        response = client.get(
            f"/vpn/{vpn.name}/peer/{ip}/history",
            params={"start_time": start / 1_000_000_000, "end_time": end / 1_000_000_000},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
        # Assert all entries contains the expect ip address
        assert all(d["ip_address"] == ip for d in data)
        # Assert the entries are in descending order by timestamp
        assert all(a["timestamp"] >= b["timestamp"] for a, b in zip(data, data[1:]))

    def test_tag_history_with_time(self, test_input, mock_vpn_manager, mock_peer_history_table):
        """Test tag history endpoint with start/end time filters."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        tag = "tag1"
        start = 1626000000000000000
        end = 1626000003000000000
        response = client.get(
            f"/vpn/{vpn.name}/tag/{tag}/history",
            params={"start_time": start / 1_000_000_000, "end_time": end / 1_000_000_000},
        )
        assert response.status_code == 200
        data = response.json()
        assert sum(len(items) for items in data.values()) == 4
        # Assert all entries contains the expected tag
        assert all(tag in peer_history["tags"] for peer_histories in data.values() for peer_history in peer_histories)

    def test_remove_tag_history(self, test_input, mock_vpn_manager, mock_vpn_table, mock_peer_table, mock_dynamo_db):
        """Remove a tag from a peer. Assert that the tag is removed from the peer's history."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        test_tag = "tag1"
        test_ip_address = "10.20.40.2"

        # Execute Test
        client.delete(f"/vpn/{vpn.name}/peer/{test_ip_address}/tag/{test_tag}")

        # Validate Results
        response = client.get(f"/vpn/{vpn.name}/peer/{test_ip_address}/history")
        assert response.status_code == 200
        data = response.json()

        assert test_tag not in PeerHistoryResponseModel(**data[0]).tags

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("server_manager.ssm.boto3.client")
    def test_delete_peer(
        self,
        mock_ssm_client,
        mock_ssh_client,
        test_input,
        mock_ssh_command,
        mock_ssm_command,
        mock_vpn_manager,
        mock_vpn_table,
        mock_peer_table,
        mock_peer_history_table,
        mock_dynamo_db,
    ):
        """Delete a peer."""
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
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
            response = client.delete(f"/vpn/{vpn.name}/peer/{delete_ip}")

            # Validate Results
            assert response.status_code == HTTPStatus.OK
            get_response = client.get(f"/vpn/{vpn.name}/peer/{delete_ip}")
            assert get_response.status_code == HTTPStatus.NOT_FOUND

            # Validate the peer was deleted from DynamoDB
            all_peers = mock_dynamo_db._get_all_peers_from_server()
            if len(all_peers) > 0:
                assert [db_peer for db_peer in all_peers[vpn.name] if db_peer.ip_address == delete_ip] == []

            # Validate the peer was removed from the mock WireGuard server
            if vpn.connection_info is not None:
                for wg_peer in mock_ssh_command.peers:
                    if wg_peer.wg_ip_address == delete_ip:
                        assert wg_peer.wg_ip_address != delete_ip

    def test_peer_history_no_exist(self, test_input, mock_vpn_manager, mock_vpn_table, mock_peer_table, mock_dynamo_db):
        """Test peer history was removed after deletion"""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        delete_ips = ["10.20.40.2", "10.20.40.3"]

        for delete_ip in delete_ips:
            # Execute Test - Get history of deleted peer
            response = client.get(f"/vpn/{vpn.name}/peer/{delete_ip}/history")
            assert response.status_code == 200
            data = PeerHistoryResponseModel(**response.json()[0])

            # Validate Results
            assert data.ip_address == delete_ip
            assert data.allowed_ips == ""
            assert data.public_key == ""
            assert data.private_key == None
            assert data.persistent_keepalive == 0

    def test_delete_vpn(self, mock_vpn_table, mock_peer_table, mock_vpn_manager, mock_dynamo_db, test_input):
        """Test deleting a VPN server"""
        # Set up Test
        vpn = test_input
        vpn_router.vpn_manager = mock_vpn_manager

        # Execute Test - Delete the VPN server
        response = client.delete(f"/vpn/{vpn.name}")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        response = client.get(f"/vpn/{vpn.name}")
        assert response.status_code == HTTPStatus.NOT_FOUND

        # ---------------------------------------------------
        # Execute Test - Verify this is idempotent
        response = client.delete(f"/vpn/{vpn.name}")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        all_vpns = mock_dynamo_db._get_all_vpn_from_server()
        assert all_vpns == []
