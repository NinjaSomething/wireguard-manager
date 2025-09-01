from itertools import count

import pytest
from unittest.mock import patch
import boto3
import yaml
from moto import mock_aws
from databases.dynamodb import DynamoDb
from tests.client.mock_ssh_client import MockSshCommand
from tests.client.mock_ssm_client import MockSsmCommand
from vpn_manager import VpnManager
from models.wg_server import WgServerModel


# Session-scoped fixture to load the serverless configuration for the infrastructure.
# This fixture is used by other fixtures to mock AWS resources, allowing us to
# thoroughly test the integration between our infrastructure and code.
class V2Loader(yaml.SafeLoader):
    """This will allow us to ignore the !Ref tags used by cloudformation but are not valid YAML."""

    def ignore_unknown(self, node):
        print("Ignoring unknown YAML node:", node)
        return None


V2Loader.add_constructor("!Ref", V2Loader.ignore_unknown)
V2Loader.add_constructor("!Sub", V2Loader.ignore_unknown)
V2Loader.add_constructor("!GetAtt", V2Loader.ignore_unknown)


@pytest.fixture(scope="session")
def serverless_configuration():
    with open("serverless/serverless.yml", "r") as f:
        config = yaml.load(f, Loader=V2Loader)
    return config["resources"]["Resources"]


START_TS = 1_626_000_000_000_000_000
ONE_SEC_NS = 1_000_000_000
ts_counter = count(START_TS, ONE_SEC_NS)


@pytest.fixture(scope="class", autouse=True)
def incr_time_ns():
    """
    Before any test in the class runs, patch time.time_ns to return
    next(ts_counter) on each call.
    """
    with patch("time.time_ns", side_effect=lambda: next(ts_counter)):
        yield


@pytest.fixture(scope="class")
def mock_vpn_table(serverless_configuration):
    with mock_aws():
        table_config = serverless_configuration["WireguardManagerVpnServersTable"]["Properties"]
        # override table name
        table_config["TableName"] = f"wireguard-manager-vpn-servers-test"
        conn = boto3.resource("dynamodb", region_name="us-west-2")
        vpn_table = conn.create_table(**table_config)
        yield vpn_table


@pytest.fixture(scope="class")
def mock_peer_table(serverless_configuration):
    with mock_aws():
        table_config = serverless_configuration["WireguardManagerPeersTable"]["Properties"]
        # override table name
        table_config["TableName"] = f"wireguard-manager-peers-test"
        conn = boto3.resource("dynamodb", region_name="us-west-2")
        peer_table = conn.create_table(**table_config)
        yield peer_table


@pytest.fixture(scope="class")
def mock_peer_history_table(serverless_configuration):
    with mock_aws():
        table_config = serverless_configuration["WireguardManagerPeersHistoryTable"]["Properties"]
        # override table name
        table_config["TableName"] = f"wireguard-manager-peers-history-test"
        conn = boto3.resource("dynamodb", region_name="us-west-2")
        peer_table = conn.create_table(**table_config)
        yield peer_table


@pytest.fixture(scope="class")
def mock_dynamo_db():
    with mock_aws():
        dynamo_db = DynamoDb(
            environment="test",
            dynamodb_endpoint_url=None,
            aws_region="us-west-2",
        )
    yield dynamo_db


@pytest.fixture(scope="class")
def mock_vpn_manager(mock_dynamo_db):
    vpn_manager = VpnManager(db_manager=mock_dynamo_db)
    yield vpn_manager


@pytest.fixture
def mock_ssh_command():
    """
    This fixture mocks the SSHClient.exec_command method for testing purposes.  This simulates the SSH commands to the
    server.  You can use this to add/remove peers, or dump the WireGuard configuration in the expected format.
    """
    new_server = WgServerModel(
        interface="wg0", public_key="PUBLIC_KEY1", private_key="PRIVATE_KEY1", listen_port=40023, fw_mark="off"
    )
    mock_ssh_command = MockSshCommand(server=new_server, peers=[])
    yield mock_ssh_command


@pytest.fixture
def mock_ssm_command():
    """
    This fixture mocks the SSM cmd execution for testing purposes. It simulates the SSM commands to the server.
    You can use this to add/remove peers, or dump the WireGuard configuration in the expected format.
    """
    new_server = WgServerModel(
        interface="wg0", public_key="PUBLIC_KEY1", private_key="PRIVATE_KEY1", listen_port=40023, fw_mark="off"
    )
    mock_ssm_command = MockSsmCommand(server=new_server, peers=[])
    yield mock_ssm_command
