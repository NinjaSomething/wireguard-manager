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
