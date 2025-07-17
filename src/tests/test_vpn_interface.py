import urllib.parse
from copy import deepcopy
from http import HTTPStatus
from fastapi.testclient import TestClient

from app import app, vpn_router
from models.vpn import VpnPutModel, WireguardModel, VpnModel


client = TestClient(app)


class TestVpnInterface:
    vpn1 = VpnModel(
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
    )

    def test_get_all_vpn_no_servers(self, mock_vpn_table, mock_peer_table, mock_vpn_manager):
        """Test getting all servers before any are added"""
        vpn_router.vpn_manager = mock_vpn_manager
        response = client.get("/vpn")
        assert response.status_code == 200
        assert response.json() == []

    def test_add_server_no_connection_info(self, mock_vpn_table, mock_peer_table, mock_vpn_manager):
        """
        Add VPN server vpn1
        """
        vpn_config = VpnPutModel(
            wireguard=TestVpnInterface.vpn1.wireguard,
            connection_info=TestVpnInterface.vpn1.connection_info,
        )

        vpn_router.vpn_manager = mock_vpn_manager

        # Add a VPN server
        url = f"/vpn/{TestVpnInterface.vpn1.name}?{urllib.parse.urlencode(dict(description=TestVpnInterface.vpn1.description))}"
        response = client.put(url, data=vpn_config.model_dump_json())
        assert response.status_code == 200

    def test_get_vpn(self, mock_vpn_table, mock_peer_table, mock_vpn_manager):
        """Test getting a single VPN server"""
        vpn_router.vpn_manager = mock_vpn_manager

        # Get the VPN server.  Don't hide secrets
        response = client.get(f"/vpn/{TestVpnInterface.vpn1.name}?hide_secrets=false")
        assert response.status_code == 200
        actual_value = VpnModel(**response.json())
        assert actual_value == TestVpnInterface.vpn1

        # Get the VPN server.  Hide secrets
        response = client.get(f"/vpn/{TestVpnInterface.vpn1.name}")
        assert response.status_code == 200
        actual_value = VpnModel(**response.json())
        expected_value = deepcopy(TestVpnInterface.vpn1)
        expected_value.wireguard.private_key = "**********"
        assert actual_value == expected_value

    def test_get_all_vpn(self, mock_vpn_table, mock_peer_table, mock_vpn_manager):
        """Test Getting all VPN servers"""
        vpn_router.vpn_manager = mock_vpn_manager

        # Get all VPN servers but don't hide secrets
        response = client.get(f"/vpn?hide_secrets=false")
        assert response.status_code == 200
        actual_value = [VpnModel(**vpn) for vpn in response.json()]
        assert actual_value == [TestVpnInterface.vpn1]

        # Get all VPN servers but hide secrets
        response = client.get(f"/vpn")
        assert response.status_code == 200
        actual_value = [VpnModel(**vpn) for vpn in response.json()]
        expected_value = deepcopy(TestVpnInterface.vpn1)
        expected_value.wireguard.private_key = "**********"
        assert actual_value == [expected_value]

    def test_delete_vpn(self, mock_vpn_table, mock_peer_table, mock_vpn_manager):
        """Test deleting a VPN server"""
        vpn_router.vpn_manager = mock_vpn_manager

        # Delete the VPN server
        response = client.delete(f"/vpn/{TestVpnInterface.vpn1.name}")
        assert response.status_code == 200

        # Verify it is deleted
        response = client.get(f"/vpn/{TestVpnInterface.vpn1.name}")
        assert response.status_code == HTTPStatus.NOT_FOUND
