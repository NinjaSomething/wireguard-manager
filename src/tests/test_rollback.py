from http import HTTPStatus
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from app import setup_app_routes
from models.connection import ConnectionType, ConnectionModel
from models.peers import PeerRequestModel, PeerDbModel
from models.ssh import SshConnectionModel
from auth import WireguardManagerAPI
from tests.helper import add_vpn, add_peer
from models.vpn import VpnModel, WireguardModel
from interfaces.peers import peer_router
from models.wg_server import WgServerModel, WgServerPeerModel


app = WireguardManagerAPI()
client = TestClient(app)
setup_app_routes(app)


class TestRollback:
    """
    This validates rollback scenarios where DynamoDB, the in-memory datastore, or wireguard server might get out of
    sync.
    """

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_add_peer_dynamo_failed_exception(self, mock_ssh_client, mock_ssh_command, mock_dynamodb, mock_vpn_manager):
        """Validate changes made to the wireguard server are rolled back if updating DynamoDB fails."""
        # Set up Test
        vpn = VpnModel(
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
        )
        peer_router.vpn_manager = mock_vpn_manager
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

        add_vpn(vpn, mock_dynamodb, None, mock_ssh_command)
        # Add a second peer to ensure we are not interfering with existing peers
        peer2 = add_peer(
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
            mock_ssh_command,
        )

        mock_dynamodb.peer_table = MagicMock()
        mock_dynamodb.peer_table.put_item.side_effect = ClientError(
            error_response={
                "Error": {"Code": "InternalServerError", "Message": "Simulated DynamoDB failure"},
                "ResponseMetadata": {"HTTPStatusCode": 500, "RequestId": "TEST_REQUEST_ID"},
            },
            operation_name="PutItem",
        )

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/peer", data=expected_peer_config.model_dump_json())
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

        # Validate the WireGuard server peer was rolled back
        assert all([wg_peer.public_key != expected_peer_config.public_key for wg_peer in mock_ssh_command.peers])

        # Validate the in-memory peer was rolled back
        in_mem_peer = mock_dynamodb.get_peer(vpn.name, expected_peer_config.ip_address)
        assert in_mem_peer is None

        # Validate the existing peer is still present
        assert any([wg_peer.public_key == peer2.public_key for wg_peer in mock_ssh_command.peers])

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_update_peer_dynamo_failed_exception(
        self, mock_ssh_client, mock_ssh_command, mock_dynamodb, mock_vpn_manager
    ):
        """Validate changes made to the wireguard server are rolled back if updating DynamoDB fails."""
        # Set up Test
        vpn = VpnModel(
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
        )
        peer_router.vpn_manager = mock_vpn_manager

        updated_peer_config = PeerRequestModel(
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

        # Add a vpn, and two peers.  One of the peers will fail to update and need to be rolled back.  The second peer
        # will be used to validate it is not affected by the rollback.
        add_vpn(vpn, mock_dynamodb, None, mock_ssh_command)
        original_peer = add_peer(vpn, mock_dynamodb, mock_command=mock_ssh_command)
        peer2 = add_peer(
            vpn,
            mock_dynamodb,
            peer=PeerDbModel(
                peer_id="2345",
                ip_address="10.20.40.3",
                allowed_ips=["10.20.40.0/24", "172.30.0.0/16"],
                public_key="PEER2_PUBLIC_KEY",
                private_key="PEER2_PRIVATE_KEY",
                persistent_keepalive=25,
                tags=["tag1", "tag2"],
                message="Sample message",
            ),
            mock_command=mock_ssh_command,
        )

        mock_dynamodb.peer_table = MagicMock()
        mock_dynamodb.peer_table.update_item.side_effect = ClientError(
            error_response={
                "Error": {"Code": "InternalServerError", "Message": "Simulated DynamoDB failure"},
                "ResponseMetadata": {"HTTPStatusCode": 500, "RequestId": "TEST_REQUEST_ID"},
            },
            operation_name="PutItem",
        )

        # Execute Test
        response = client.put(
            f"/vpn/{vpn.name}/peer/{updated_peer_config.ip_address}", data=updated_peer_config.model_dump_json()
        )
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

        # Validate the WireGuard server peer was rolled back
        assert any([wg_peer.public_key == original_peer.public_key for wg_peer in mock_ssh_command.peers])
        assert all([wg_peer.public_key != updated_peer_config.public_key for wg_peer in mock_ssh_command.peers])

        # Validate the other existing peer is still present
        assert any([wg_peer.public_key == peer2.public_key for wg_peer in mock_ssh_command.peers])

        # Validate the in-memory peer was rolled back
        in_mem_peer = mock_dynamodb.get_peer(vpn.name, original_peer.ip_address)
        assert original_peer == in_mem_peer

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_delete_peer_dynamo_failed_exception(
        self, mock_ssh_client, mock_ssh_command, mock_dynamodb, mock_vpn_manager
    ):
        """Validate changes made to the wireguard server are rolled back if deleting a peer in DynamoDB fails."""
        # Set up Test
        vpn = VpnModel(
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
        )
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

        # Add a vpn, and two peers.  One of the peers will fail to update and need to be rolled back.  The second peer
        # will be used to validate it is not affected by the rollback.
        add_vpn(vpn, mock_dynamodb, None, mock_ssh_command)
        original_peer = add_peer(vpn, mock_dynamodb, mock_command=mock_ssh_command)
        expected_wg_peer = mock_ssh_command.peers[0]

        mock_dynamodb.peer_table = MagicMock()
        mock_dynamodb.peer_table.delete_item.side_effect = ClientError(
            error_response={
                "Error": {"Code": "InternalServerError", "Message": "Simulated DynamoDB failure"},
                "ResponseMetadata": {"HTTPStatusCode": 500, "RequestId": "TEST_REQUEST_ID"},
            },
            operation_name="PutItem",
        )

        # Execute Test
        response = client.request(
            "DELETE", f"/vpn/{vpn.name}/peer/{original_peer.ip_address}", json={"message": "Sample message"}
        )
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

        # Validate the WireGuard server peer was rolled back
        assert mock_ssh_command.peers == [expected_wg_peer]

        # Validate the in-memory peer was rolled back
        in_mem_peer = mock_dynamodb.get_peer(vpn.name, original_peer.ip_address)
        assert original_peer == in_mem_peer

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_add_tag_to_peer_dynamo_failed_exception(
        self, mock_ssh_client, mock_ssh_command, mock_dynamodb, mock_vpn_manager
    ):
        """Validate changes made to the wireguard server are rolled back if adding a tag in DynamoDB fails."""
        # Set up Test
        vpn = VpnModel(
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
        )
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

        # Add a vpn, and two peers.  One of the peers will fail to update and need to be rolled back.  The second peer
        # will be used to validate it is not affected by the rollback.
        add_vpn(vpn, mock_dynamodb, None, mock_ssh_command)
        original_peer = add_peer(vpn, mock_dynamodb, mock_command=mock_ssh_command)

        mock_dynamodb.peer_table = MagicMock()
        mock_dynamodb.peer_table.update_item.side_effect = ClientError(
            error_response={
                "Error": {"Code": "InternalServerError", "Message": "Simulated DynamoDB failure"},
                "ResponseMetadata": {"HTTPStatusCode": 500, "RequestId": "TEST_REQUEST_ID"},
            },
            operation_name="PutItem",
        )
        add_tag = "tag2"

        # Execute Test
        response = client.put(
            f"/vpn/{vpn.name}/peer/{original_peer.ip_address}/tag/{add_tag}", json={"message": "Add Tag"}
        )
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

        # Validate the in-memory peer was rolled back
        in_mem_peer = mock_dynamodb.get_peer(vpn.name, original_peer.ip_address)
        assert original_peer == in_mem_peer
        assert add_tag not in in_mem_peer.tags

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_delete_tag_from_peer_dynamo_failed_exception(
        self, mock_ssh_client, mock_ssh_command, mock_dynamodb, mock_vpn_manager
    ):
        """Validate changes made to the wireguard server are rolled back if deleting a tag in DynamoDB fails."""
        # Set up Test
        vpn = VpnModel(
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
        )
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

        # Add a vpn, and two peers.  One of the peers will fail to update and need to be rolled back.  The second peer
        # will be used to validate it is not affected by the rollback.
        add_vpn(vpn, mock_dynamodb, None, mock_ssh_command)
        original_peer = add_peer(vpn, mock_dynamodb, mock_command=mock_ssh_command)

        mock_dynamodb.peer_table = MagicMock()
        mock_dynamodb.peer_table.update_item.side_effect = ClientError(
            error_response={
                "Error": {"Code": "InternalServerError", "Message": "Simulated DynamoDB failure"},
                "ResponseMetadata": {"HTTPStatusCode": 500, "RequestId": "TEST_REQUEST_ID"},
            },
            operation_name="PutItem",
        )
        delete_tag = "tag1"

        # Execute Test
        response = client.request(
            "DELETE",
            f"/vpn/{vpn.name}/peer/{original_peer.ip_address}/tag/{delete_tag}",
            json={"message": "Delete Tag"},
        )
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

        # Validate the in-memory peer was rolled back
        in_mem_peer = mock_dynamodb.get_peer(vpn.name, original_peer.ip_address)
        assert original_peer == in_mem_peer
        assert delete_tag in in_mem_peer.tags

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    @patch("vpn_manager.codecs")
    def test_gen_keys_peer_dynamo_failed_exception(
        self, mock_codecs, mock_ssh_client, mock_ssh_command, mock_dynamodb, mock_vpn_manager
    ):
        """Validate changes made to the wireguard server are rolled back if deleting a peer in DynamoDB fails."""
        # Set up Test
        vpn = VpnModel(
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
        )
        peer_router.vpn_manager = mock_vpn_manager
        mock_codecs.encode.side_effect = ["GENERATED_PRIVATE_KEY".encode(), "GENERATED_PUBLIC_KEY".encode()]

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

        # Add a vpn, and two peers.  One of the peers will fail to update and need to be rolled back.  The second peer
        # will be used to validate it is not affected by the rollback.
        add_vpn(vpn, mock_dynamodb, None, mock_ssh_command)
        original_peer = add_peer(vpn, mock_dynamodb, mock_command=mock_ssh_command)

        mock_dynamodb.peer_table = MagicMock()
        mock_dynamodb.peer_table.update_item.side_effect = ClientError(
            error_response={
                "Error": {"Code": "InternalServerError", "Message": "Simulated DynamoDB failure"},
                "ResponseMetadata": {"HTTPStatusCode": 500, "RequestId": "TEST_REQUEST_ID"},
            },
            operation_name="PutItem",
        )

        # Execute Test
        response = client.post(
            f"/vpn/{vpn.name}/peer/{original_peer.ip_address}/generate-wireguard-keys",
            json={"message": "Generate Keys"},
        )
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

        # Validate the WireGuard server peer was rolled back
        assert any([wg_peer.public_key == original_peer.public_key for wg_peer in mock_ssh_command.peers])
        assert all([wg_peer.public_key != "GENERATED_PUBLIC_KEY" for wg_peer in mock_ssh_command.peers])

        # Validate the in-memory peer was rolled back
        in_mem_peer = mock_dynamodb.get_peer(vpn.name, original_peer.ip_address)
        assert original_peer == in_mem_peer

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_import_peers_dynamo_failed_exception(
        self, mock_ssh_client, mock_ssh_command, mock_dynamodb, mock_vpn_manager
    ):
        """Validate changes made to the wireguard server are rolled back if deleting a peer in DynamoDB fails."""
        # Set up Test
        vpn = VpnModel(
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
        )
        peer_router.vpn_manager = mock_vpn_manager

        mock_ssh_command.server = WgServerModel(
            interface=vpn.wireguard.interface,
            public_key=vpn.wireguard.public_key,
            private_key=vpn.wireguard.private_key,
            listen_port=vpn.wireguard.listen_port,
            fw_mark="off",
        )

        wg_peer1 = WgServerPeerModel(
            wg_ip_address="10.20.40.2",
            public_key="PEER1_PUBLIC_KEY",
            persistent_keepalive=25,
            endpoint="(none)",
            latest_handshake=25,
            transfer_rx=25,
            transfer_tx=25,
            preshared_key=None,
        )
        wg_peer2 = WgServerPeerModel(
            wg_ip_address="10.20.40.3",
            public_key="PEER2_PUBLIC_KEY",
            persistent_keepalive=25,
            endpoint="(none)",
            latest_handshake=25,
            transfer_rx=25,
            transfer_tx=25,
            preshared_key=None,
        )
        mock_ssh_command.peers = [wg_peer1, wg_peer2]

        if vpn.connection_info and vpn.connection_info.type == ConnectionType.SSH:
            ssh_client = mock_ssh_client()
            ssh_client.exec_command = mock_ssh_command.command

        # Add a vpn, and two peers.  One of the peers will fail to update and need to be rolled back.  The second peer
        # will be used to validate it is not affected by the rollback.
        add_vpn(vpn, mock_dynamodb, None, mock_ssh_command)

        def add_item_generator(*args, **kwargs):
            """Generator to simulate adding items to DynamoDB."""
            yield  # First call succeeds
            raise ClientError(  # Second call fails
                error_response={
                    "Error": {"Code": "InternalServerError", "Message": "Simulated DynamoDB failure"},
                    "ResponseMetadata": {"HTTPStatusCode": 500, "RequestId": "TEST_REQUEST_ID"},
                },
                operation_name="PutItem",
            )

        mock_dynamodb.peer_table = MagicMock()
        mock_dynamodb.peer_table.put_item.side_effect = add_item_generator()

        # Execute Test
        response = client.post(f"/vpn/{vpn.name}/import", json={"message": "Import Peers"})
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

        # Validate the WireGuard server peer was rolled back
        assert mock_ssh_command.peers == [wg_peer1, wg_peer2]

        # Validate the in-memory peer was rolled back
        in_mem_peers = mock_dynamodb.get_peers(vpn.name)
        assert len(in_mem_peers) == 1  # We expect to see the first peer imported but not the second.
        assert in_mem_peers[0].public_key == wg_peer1.public_key
        assert "imported" in in_mem_peers[0].tags
