from unittest.mock import MagicMock
from moto import mock_aws
from fastapi.testclient import TestClient

from app import app, vpn_router
from vpn_manager import VpnManager
from environment import Environment
from databases.dynamodb import DynamoDb
from models.vpn import VpnPutRequestModel, WireguardRequestModel, ConnectionModel, VpnModel, VpnRequestModel


client = TestClient(app)


class TestVpnInterface:
    def test_get_all_vpn_no_servers(self, mock_vpn_table, mock_peer_table):
        with mock_aws():
            dynamo_db = DynamoDb(
                environment=Environment.STAGING,
                dynamodb_endpoint_url="test-endpoint",
                aws_region="us-west-2",
            )
            vpn_manager = VpnManager(db_manager=dynamo_db)
            vpn_router.vpn_manager = vpn_manager
            response = client.get("/vpn")
            assert response.status_code == 200
            assert response.json() == []

    def test_add_server_no_connection_info(self, mock_vpn_table, mock_peer_table):
        vpn_name = "test-vpn"
        vpn_description = ""
        vpn_config = VpnPutRequestModel(
            wireguard=WireguardRequestModel(
                ip_address="10.20.40.1",
                address_space="10.20.40.0/24",
                interface="wg0",
                public_key="PUBLIC_KEY",
                private_key="PRIVATE_KEY",
                listen_port=12345,
            ),
            connection_info=None,
        )

        with mock_aws():
            dynamo_db = DynamoDb(
                environment=Environment.STAGING,
                dynamodb_endpoint_url="test-endpoint",
                aws_region="us-west-2",
            )
            vpn_manager = VpnManager(db_manager=dynamo_db)
            vpn_router.vpn_manager = vpn_manager

            # Add a VPN server
            response = client.put(f"/vpn/{vpn_name}", data=vpn_config.model_dump_json())
            assert response.status_code == 200

            # Get the VPN server
            response = client.get(f"/vpn/{vpn_name}?hide_secrets=false")
            assert response.status_code == 200
            assert VpnRequestModel(**response.json()) == VpnRequestModel(
                name=vpn_name, description=vpn_description, **vpn_config.model_dump()
            )

    def test_get_all_vpn_one_server(self, mock_vpn_table, mock_peer_table):
        with mock_aws():
            dynamo_db = DynamoDb(
                environment=Environment.STAGING,
                dynamodb_endpoint_url="test-endpoint",
                aws_region="us-west-2",
            )
            vpn_manager = VpnManager(db_manager=dynamo_db)
            vpn_router.vpn_manager = vpn_manager
