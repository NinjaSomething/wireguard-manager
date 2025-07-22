import urllib.parse
from copy import deepcopy
from http import HTTPStatus
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import pytest
from pydantic import SecretStr

from app import app, vpn_router
from models.ssh import SshConnectionModel
from models.vpn import VpnPutModel, WireguardModel, VpnModel
from models.connection import ConnectionModel, ConnectionType
from models.wg_server import WgServerModel
from models.peers import PeerRequestModel, PeerResponseModel
from interfaces.peers import peer_router


client = TestClient(app)

test_parameters = [
    VpnModel(
        name="test-vpn",
        description="Test VPN Server",
        wireguard=WireguardModel(
            ip_address="10.20.40.1",
            address_space="10.20.40.0/24",
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
            address_space="10.20.40.0/24",
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
]


@pytest.mark.parametrize("test_input", test_parameters, scope="class")
class TestPeerInterface:
    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_add_server_successfully(
        self,
        mock_ssh_client,
        mock_exec_command,
        mock_vpn_table,
        mock_peer_table,
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
        mock_ssh_client().exec_command = mock_exec_command.exec_command

        # Execute Test
        url = f"/vpn/{vpn.name}?{urllib.parse.urlencode(dict(description=vpn.description))}"
        response = client.put(url, data=vpn_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        all_vpns = mock_dynamo_db.get_all_vpns()
        assert all_vpns == [vpn]

    def test_add_peer_server_not_exist(self, test_input, mock_vpn_manager):
        """Try adding a peer to a server that doesn't exist."""
        # Set up Test
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips="10.20.40.0/24",
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

    def test_add_peer_server_invalid_address_space(self, test_input, mock_vpn_manager):
        """Try adding a peer to a server using an IP in a different subnet."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.41.2",
            allowed_ips="10.20.41.0/24",
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
    def test_add_peer(
        self,
        mock_ssh_client,
        test_input,
        mock_exec_command,
        mock_vpn_manager,
        mock_vpn_table,
        mock_peer_table,
        mock_dynamo_db,
    ):
        """Try adding a peer successfully."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        peer_config = PeerRequestModel(
            ip_address="10.20.40.2",
            allowed_ips="10.20.40.0/24",
            public_key="PEER_PUBLIC_KEY",
            private_key="PEER_PRIVATE_KEY",
            persistent_keepalive=25,
            tags=["tag1"],
        )

        ssh_client = mock_ssh_client()
        ssh_client.exec_command = mock_exec_command.exec_command
        mock_exec_command.server = WgServerModel(
            interface=vpn.wireguard.interface,
            public_key=vpn.wireguard.public_key,
            private_key=vpn.wireguard.private_key,
            listen_port=vpn.wireguard.listen_port,
            fw_mark="off",
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())
        actual_peer = PeerResponseModel(**response.json())

        # Validate Results
        assert response.status_code == HTTPStatus.OK

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamo_db.get_all_peers()
        assert PeerRequestModel(**all_peers[vpn.name][0].model_dump()) == peer_config

        # Validate the peer was added to the mock WireGuard server
        if vpn.connection_info is not None:
            actual_wg_peer = mock_exec_command.peers.pop()
            assert actual_wg_peer.wg_ip_address == peer_config.ip_address
            assert actual_wg_peer.public_key == peer_config.public_key
            assert actual_wg_peer.persistent_keepalive == peer_config.persistent_keepalive

    def test_get_all_peers_hide_secrets(self, test_input, mock_vpn_manager):
        """Try getting all peers."""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        expected_peers = [
            PeerResponseModel(
                ip_address="10.20.40.2",
                allowed_ips="10.20.40.0/24",
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
                allowed_ips="10.20.40.0/24",
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
            allowed_ips="10.20.40.0/24",
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
            allowed_ips="10.20.40.0/24",
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
            allowed_ips="10.20.40.0/24",
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
AllowedIPs = {expected_peer.allowed_ips}
Endpoint = {vpn.connection_info.data.ip_address if vpn.connection_info else "[INSERT_VPN_IP]"}:{vpn.wireguard.listen_port}
PersistentKeepalive = {expected_peer.persistent_keepalive}"""

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/{expected_peer.ip_address}/config")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert response.text == expected_config

    def test_import_peers(self, test_input):
        """Try importing peers."""
        # Set up Test

        # Execute Test

        # Validate Results
        pass

    def test_generate_peer_keys(self, test_input):
        """Try generating a new key-pair for a peer."""
        # TODO: Get peer from server that doesn't exist
        # TODO: Get peer that doesn't exist on the server
        # TODO: Get peer that does exist on the server
        # Set up Test

        # Execute Test

        # Validate Results
        pass

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("vpn_manager.codecs")
    def test_add_peer_auto_gen_parameters(
        self,
        mock_codecs,
        mock_ssh_client,
        test_input,
        mock_exec_command,
        mock_vpn_manager,
        mock_vpn_table,
        mock_peer_table,
        mock_dynamo_db,
    ):
        """Try adding a peer but have the server auto-generate the keys and IP address"""
        # Set up Test
        vpn = test_input
        peer_router.vpn_manager = mock_vpn_manager
        mock_codecs.encode.side_effect = ["GENERATED_PRIVATE_KEY".encode(), "GENERATED_PUBLIC_KEY".encode()]
        peer_config = PeerRequestModel(
            allowed_ips="10.20.40.0/24",
            persistent_keepalive=25,
            tags=["tag1", "tag2"],
        )

        ssh_client = mock_ssh_client()
        ssh_client.exec_command = mock_exec_command.exec_command
        mock_exec_command.server = WgServerModel(
            interface=vpn.wireguard.interface,
            public_key=vpn.wireguard.public_key,
            private_key=vpn.wireguard.private_key,
            listen_port=vpn.wireguard.listen_port,
            fw_mark="off",
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=peer_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        actual_peer = PeerResponseModel(**response.json())

        # Validate the peer was added to DynamoDB
        all_peers = mock_dynamo_db.get_all_peers()
        assert actual_peer.ip_address in [peer.ip_address for peer in all_peers[vpn.name]]

        # Validate the peer was added to the mock WireGuard server
        if vpn.connection_info is not None:
            actual_wg_peer = mock_exec_command.peers.pop()
            assert actual_wg_peer.wg_ip_address == actual_peer.ip_address
            assert actual_wg_peer.public_key == actual_peer.public_key
            assert actual_wg_peer.persistent_keepalive == actual_peer.persistent_keepalive

    def test_add_tag(self, test_input):
        """Try adding a tag to a peer."""
        # TODO: Add tag to peer from server that doesn't exist
        # TODO: Add tag to peer that doesn't exist on the server
        # TODO: Add tag to peer that does exist on the server
        # TODO: Add same tag again to validate it is idempotent
        # TODO: Add second tag to validate you can assign multiple tags to a peer
        # Set up Test

        # Execute Test

        # Validate Results
        pass

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
                allowed_ips="10.20.40.0/24",
                public_key="PEER_PUBLIC_KEY",
                private_key=SecretStr("PEER_PRIVATE_KEY"),
                persistent_keepalive=25,
                tags=["tag1"],
            ),
            PeerResponseModel(
                ip_address="10.20.40.3",
                allowed_ips="10.20.40.0/24",
                public_key="GENERATED_PUBLIC_KEY",
                private_key=SecretStr("GENERATED_PRIVATE_KEY"),
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
            allowed_ips="10.20.40.0/24",
            public_key="GENERATED_PUBLIC_KEY",
            private_key=SecretStr("**********"),
            persistent_keepalive=25,
            tags=["tag1", "tag2"],
        )

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}/peer/tag/tag2")

        # Validate Results
        assert response.status_code == HTTPStatus.OK
        assert [PeerResponseModel(**peer_data) for peer_data in response.json()] == [expected_peer]

    def test_delete_tag(self, test_input):
        """Try adding a tag to a peer."""
        # TODO: Remove tag from peer from server that doesn't exist
        # TODO: Remove tag from peer that doesn't exist on the server
        # TODO: Remove tag from peer
        # TODO: Remove same tag again to validate it is idempotent
        # Set up Test

        # Execute Test

        # Validate Results
        pass

    def test_delete_peer(self, test_input):
        """Try deleting a peer."""
        # TODO: Try deleting a peer that doesn't exist and the server doesn't exist either
        # TODO: Try deleting a peer that doesn't exist.
        # TODO: Try deleting a peer that does exist on the server
        # TODO: Delete the peer again to validate it is idempotent
        # Set up Test

        # Execute Test

        # Validate Results
        pass

    def test_delete_vpn(self, mock_vpn_table, mock_peer_table, mock_vpn_manager, mock_dynamo_db, test_input):
        """Test deleting a VPN server"""
        # Set up Test
        vpn = test_input
        vpn_router.vpn_manager = mock_vpn_manager

        # Execute Test - Delete the VPN server
        response = client.delete(f"/vpn/{vpn.name}")

        # Validate Results
        assert response.status_code == 200
        response = client.get(f"/vpn/{vpn.name}")
        assert response.status_code == HTTPStatus.NOT_FOUND

        # ---------------------------------------------------
        # Execute Test - Verify this is idempotent
        response = client.delete(f"/vpn/{vpn.name}")

        # Validate Results
        assert response.status_code == 200
        all_vpns = mock_dynamo_db.get_all_vpns()
        assert all_vpns == []
