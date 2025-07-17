import pytest
import boto3
import yaml
from moto import mock_aws
from environment import Environment
from databases.dynamodb import DynamoDb
from vpn_manager import VpnManager


# Session-scoped fixture to load the serverless configuration for the infrastructure.
# This fixture is used by other fixtures to mock AWS resources, allowing us to
# thoroughly test the integration between our infrastructure and code.
@pytest.fixture(scope="session")
def serverless_configuration():
    with open("serverless-v4/serverless.yml", "r") as f:
        config = yaml.safe_load(f)
    return config["resources"]["Resources"]


@pytest.fixture(scope="class")
def mock_vpn_table(serverless_configuration):
    with mock_aws():
        table_config = serverless_configuration["WireguardManagerVpnServersTable"]["Properties"]
        # override table name
        table_config["TableName"] = f"wireguard-manager-vpn-servers-{Environment.STAGING.value}"
        conn = boto3.resource("dynamodb", region_name="us-west-2")
        vpn_table = conn.create_table(**table_config)
        yield vpn_table


@pytest.fixture(scope="class")
def mock_peer_table(serverless_configuration):
    with mock_aws():
        table_config = serverless_configuration["WireguardManagerPeersTable"]["Properties"]
        # override table name
        table_config["TableName"] = f"wireguard-manager-peers-{Environment.STAGING.value}"
        conn = boto3.resource("dynamodb", region_name="us-west-2")
        peer_table = conn.create_table(**table_config)
        yield peer_table


@pytest.fixture
def mock_vpn_manager():
    with mock_aws():
        dynamo_db = DynamoDb(
            environment=Environment.STAGING,
            dynamodb_endpoint_url="test-endpoint",
            aws_region="us-west-2",
        )
        vpn_manager = VpnManager(db_manager=dynamo_db)
    yield vpn_manager
