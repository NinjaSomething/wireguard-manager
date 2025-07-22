import urllib.parse
from copy import deepcopy
from http import HTTPStatus
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import pytest

from app import app, vpn_router
from models.ssh import SshConnectionModel
from models.vpn import VpnPutModel, WireguardModel, VpnModel
from models.wireguard_connection import WireguardConnectionModel, WireguardConnectionType
from models.wg_server import WgServerModel

"""
ALL THE TESTS HERE ARE RUN SUCCESSIVELY.  IF THE FIRST TEST FAILS, THE REST WILL PROBABLY FAIL TOO.
"""

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
        connection_info=WireguardConnectionModel(
            type=WireguardConnectionType.SSH,
            data=SshConnectionModel(ip_address="10.0.0.1", username="test_user", key="SSH_KEY", key_password=None),
        ),
    ),
]


@pytest.mark.parametrize("test_input", test_parameters, scope="class")
class TestVpnInterface:
    """
    The DynamoDB tables will persist across tests.  This is intentional to avoid repeatedly creating and the same
    VPN server for each test.

    The first test will validate the behavior if there is no connection information provided.  This means it won't be
      dealing with the VPN server itself.

    The second test will validate the behavior if there is connection information provided.  This means it will be
      managing the VPN server.
    """

    def test_get_all_vpn_no_servers(self, mock_vpn_table, mock_peer_table, mock_vpn_manager, test_input):
        """Test getting all servers before any are added"""
        vpn_router.vpn_manager = mock_vpn_manager
        response = client.get("/vpn")
        assert response.status_code == 200
        assert response.json() == []

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_add_server_invalid_wg_interface(
        self,
        mock_ssh_client,
        mock_exec_command,
        mock_vpn_table,
        mock_peer_table,
        mock_vpn_manager,
        mock_dynamo_db,
        test_input,
    ):
        """Try adding an VPN server with an invalid wireguard interface"""
        # Set up Test
        vpn = deepcopy(test_input)
        if vpn.connection_info is not None:
            vpn.wireguard.interface = "wg1"  # Bad interface name to simulate a failure
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
            assert response.status_code == HTTPStatus.BAD_REQUEST
            all_vpns = mock_dynamo_db.get_all_vpns()
            assert all_vpns == []

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_add_server_ssh_connection_failure(
        self,
        mock_ssh_client,
        mock_exec_command,
        mock_vpn_table,
        mock_peer_table,
        mock_vpn_manager,
        mock_dynamo_db,
        test_input,
    ):
        """Try adding an VPN server but there are communication issues with the server"""
        # Set up Test
        vpn = deepcopy(test_input)
        if vpn.connection_info is not None:
            vpn_config = VpnPutModel(
                wireguard=vpn.wireguard,
                connection_info=vpn.connection_info,
            )

            vpn_router.vpn_manager = mock_vpn_manager
            ssh_client = mock_ssh_client()
            ssh_client.connect.side_effect = Exception("SSH connection failed")  # Simulate SSH connection failure
            ssh_client.exec_command = mock_exec_command.exec_command

            # Execute Test
            url = f"/vpn/{vpn.name}?{urllib.parse.urlencode(dict(description=vpn.description))}"
            response = client.put(url, data=vpn_config.model_dump_json())

            # Validate Results
            assert response.status_code == HTTPStatus.BAD_REQUEST
            all_vpns = mock_dynamo_db.get_all_vpns()
            assert all_vpns == []

    def test_add_server_invalid_address_space(
        self, mock_vpn_table, mock_peer_table, mock_vpn_manager, mock_dynamo_db, test_input
    ):
        """Try adding an VPN server with an invalid address space"""
        # Set up Test
        vpn = deepcopy(test_input)
        vpn.wireguard.address_space = "10.20.400"  # Not a valid address space
        vpn_config = VpnPutModel(
            wireguard=vpn.wireguard,
            connection_info=vpn.connection_info,
        )

        vpn_router.vpn_manager = mock_vpn_manager

        # Execute Test
        url = f"/vpn/{vpn.name}?{urllib.parse.urlencode(dict(description=vpn.description))}"
        response = client.put(url, data=vpn_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.BAD_REQUEST
        all_vpns = mock_dynamo_db.get_all_vpns()
        assert all_vpns == []

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
        """Successfully add a VPN server"""
        # Set up Test
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

    def test_add_server_existing_name(
        self, mock_vpn_table, mock_peer_table, mock_vpn_manager, mock_dynamo_db, test_input
    ):
        """Try adding a VPN server vpn with a name that already exists"""
        # Set up Test
        vpn = deepcopy(test_input)
        vpn.wireguard.ip_address = "10.20.40.2"  # Change IP address to avoid conflict
        vpn.wireguard.public_key = "DIFFERENT_KEY"
        vpn_config = VpnPutModel(
            wireguard=vpn.wireguard,
            connection_info=vpn.connection_info,
        )

        vpn_router.vpn_manager = mock_vpn_manager

        # Execute Test
        url = f"/vpn/{vpn.name}?{urllib.parse.urlencode(dict(description=vpn.description))}"
        response = client.put(url, data=vpn_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.CONFLICT
        all_vpns = mock_dynamo_db.get_all_vpns()
        assert all_vpns == [test_input]

    def test_add_server_existing_public_key(
        self, mock_vpn_table, mock_peer_table, mock_vpn_manager, mock_dynamo_db, test_input
    ):
        """Try adding an VPN server that already exists using the same private key"""
        # Set up Test
        vpn = deepcopy(test_input)
        vpn.wireguard.ip_address = "10.20.40.2"  # Change IP address to avoid conflict
        vpn.name = "DIFFERENT_NAME"
        vpn_config = VpnPutModel(
            wireguard=vpn.wireguard,
            connection_info=vpn.connection_info,
        )
        vpn_router.vpn_manager = mock_vpn_manager

        # Execute Test
        url = f"/vpn/{vpn.name}?{urllib.parse.urlencode(dict(description=vpn.description))}"
        response = client.put(url, data=vpn_config.model_dump_json())

        # Validate Results
        assert response.status_code == HTTPStatus.CONFLICT
        all_vpns = mock_dynamo_db.get_all_vpns()
        assert all_vpns == [test_input]

    def test_get_vpn(self, mock_vpn_table, mock_peer_table, mock_vpn_manager, test_input):
        """Test getting a single VPN server"""
        # Set up Test - Get the VPN server.  Don't hide secrets
        vpn = test_input
        vpn_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}?hide_secrets=false")

        # Validate Results
        assert response.status_code == 200
        assert VpnModel(**response.json()) == vpn

        # ---------------------------------------------------
        # Set up Test - Get the VPN server.  Hide secrets
        expected_value = deepcopy(vpn)
        expected_value.wireguard.private_key = "**********"
        if vpn.connection_info is not None:
            expected_value.connection_info.data.key = "**********"
            if expected_value.connection_info.data.key_password is not None:
                expected_value.connection_info.data.key_password = "**********"

        # Execute Test
        response = client.get(f"/vpn/{vpn.name}")

        # Validate Results
        assert response.status_code == 200
        assert VpnModel(**response.json()) == expected_value

    def test_get_all_vpn(self, mock_vpn_table, mock_peer_table, mock_vpn_manager, test_input):
        """Test Getting all VPN servers"""
        # Set up Test - Get all VPN servers but don't hide secrets
        vpn = test_input
        vpn_router.vpn_manager = mock_vpn_manager

        # Execute Test
        response = client.get(f"/vpn?hide_secrets=false")
        assert response.status_code == 200
        assert [VpnModel(**vpn) for vpn in response.json()] == [vpn]

        # ---------------------------------------------------
        # Set up Test - Get all VPN servers but hide secrets
        expected_value = deepcopy(vpn)
        expected_value.wireguard.private_key = "**********"
        if vpn.connection_info is not None:
            expected_value.connection_info.data.key = "**********"
            if expected_value.connection_info.data.key_password is not None:
                expected_value.connection_info.data.key_password = "**********"

        # Execute Test
        response = client.get(f"/vpn")

        # Validate Results
        assert response.status_code == 200
        assert [VpnModel(**vpn) for vpn in response.json()] == [expected_value]

    def test_delete_connection(self, mock_vpn_table, mock_peer_table, mock_vpn_manager, mock_dynamo_db, test_input):
        # Set up Test - Get all VPN servers but don't hide secrets
        vpn = test_input
        vpn_router.vpn_manager = mock_vpn_manager

        if vpn.connection_info is not None:
            # Execute Test
            response = client.delete(f"/vpn/{vpn.name}/connection-info")

            # Validate Results
            assert response.status_code == 200
            response = client.get(f"/vpn/{vpn.name}?hide_secrets=false")
            updated_vpn = VpnModel(**response.json())
            assert updated_vpn.connection_info is None
            all_vpns = mock_dynamo_db.get_all_vpns()
            assert all_vpns == [updated_vpn]

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_add_connection_invalid_wg_interface(
        self,
        mock_ssh_client,
        mock_exec_command,
        mock_vpn_table,
        mock_peer_table,
        mock_vpn_manager,
        mock_dynamo_db,
        test_input,
    ):
        """Try adding a connection with an invalid wireguard interface"""
        # Set up Test
        if test_input.connection_info is not None:
            expected_vpn = deepcopy(test_input)
            expected_vpn.connection_info = None
            mock_exec_command.server = WgServerModel(
                interface="wg1", public_key="PUBLIC_KEY1", private_key="PRIVATE_KEY1", listen_port=40023, fw_mark="off"
            )

            vpn_router.vpn_manager = mock_vpn_manager
            ssh_client = mock_ssh_client()
            ssh_client.connect.side_effect = None
            ssh_client.exec_command = mock_exec_command.exec_command

            # Execute Test
            response = client.put(
                f"/vpn/{test_input.name}/connection-info", data=test_input.connection_info.model_dump_json()
            )

            # Validate Results
            assert response.status_code == HTTPStatus.BAD_REQUEST
            all_vpns = mock_dynamo_db.get_all_vpns()
            assert all_vpns == [expected_vpn]

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_add_connection_ssh_connection_failure(
        self,
        mock_ssh_client,
        mock_exec_command,
        mock_vpn_table,
        mock_peer_table,
        mock_vpn_manager,
        mock_dynamo_db,
        test_input,
    ):
        """Try adding a connection but there are communication issues with the server"""
        # Set up Test
        if test_input.connection_info is not None:
            expected_vpn = deepcopy(test_input)
            expected_vpn.connection_info = None
            vpn_router.vpn_manager = mock_vpn_manager
            ssh_client = mock_ssh_client()
            ssh_client.connect.side_effect = Exception("SSH connection failed")  # Simulate SSH connection failure
            ssh_client.exec_command = mock_exec_command.exec_command

            # Execute Test
            response = client.put(
                f"/vpn/{test_input.name}/connection-info", data=test_input.connection_info.model_dump_json()
            )

            # Validate Results
            assert response.status_code == HTTPStatus.BAD_REQUEST
            all_vpns = mock_dynamo_db.get_all_vpns()
            assert all_vpns == [expected_vpn]

            # Break down test
            ssh_client.connect.side_effect = None

    @patch("server_manager.ssh.paramiko.RSAKey", MagicMock())
    @patch("server_manager.ssh.paramiko.SSHClient")
    def test_add_connection(
        self,
        mock_ssh_client,
        mock_exec_command,
        mock_vpn_table,
        mock_peer_table,
        mock_vpn_manager,
        mock_dynamo_db,
        test_input,
    ):
        """Successfully add a connection to an existing VPN server"""
        # Set up Test - Get all VPN servers but don't hide secrets
        vpn = test_input
        vpn_router.vpn_manager = mock_vpn_manager
        ssh_client = mock_ssh_client()
        ssh_client.exec_command = mock_exec_command.exec_command

        mock_exec_command.server = WgServerModel(
            interface="wg0", public_key="PUBLIC_KEY1", private_key="PRIVATE_KEY1", listen_port=40023, fw_mark="off"
        )

        if vpn.connection_info is not None:
            # Execute Test
            response = client.put(f"/vpn/{vpn.name}/connection-info", data=vpn.connection_info.model_dump_json())

            # Validate Results
            assert response.status_code == 200
            assert response.json() == []
            response = client.get(f"/vpn/{vpn.name}?hide_secrets=false")
            updated_vpn = VpnModel(**response.json())
            assert updated_vpn.connection_info == vpn.connection_info
            all_vpns = mock_dynamo_db.get_all_vpns()
            assert all_vpns == [test_input]

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
