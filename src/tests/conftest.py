import os
from itertools import count
from unittest.mock import patch

import boto3
import pytest
import yaml
from moto import mock_aws

from databases.dynamodb import DynamoDb
from models.wg_server import WgServerModel
from tests.client.mock_ssh_client import MockSshCommand
from tests.client.mock_ssm_client import MockSsmCommand
from vpn_manager import VpnManager

CURRENT_DIR = os.path.dirname(__file__)


# Session-scoped fixture to load the serverless configuration for the infrastructure.
# This fixture is used by other fixtures to mock AWS resources, allowing us to
# thoroughly test the integration between our infrastructure and code.
class V2Loader(yaml.SafeLoader):
    """This will allow us to ignore the !Ref tags used by cloudformation but are not valid YAML."""

    def ignore_unknown(self, node):
        print("Ignoring unknown YAML node:", node)
        return None


V2Loader.add_constructor("!Ref", V2Loader.ignore_unknown)


@pytest.fixture(scope="session")
def serverless_configuration():
    with open(os.path.join(CURRENT_DIR, "../../serverless/serverless.yml"), "r") as f:
        config = yaml.load(f, Loader=V2Loader)
    return config["resources"]["Resources"]


@pytest.fixture(scope="function", autouse=True)
def incr_time_ns():
    """
    Before any test in the class runs, patch time.time_ns to return
    next(ts_counter) on each call.
    """
    START_TS = 1_626_000_000_000_000_000
    ONE_SEC_NS = 1_000_000_000
    ts_counter = count(START_TS, ONE_SEC_NS)
    with patch("time.time_ns", side_effect=lambda: next(ts_counter)):
        yield


@pytest.fixture(scope="function")
def mock_dynamodb(serverless_configuration):
    with mock_aws():
        table_config = serverless_configuration["WireguardManagerVpnServersTable"]["Properties"]
        table_config["TableName"] = "wireguard-manager-vpn-servers-unittest"
        conn = boto3.resource("dynamodb", region_name="us-west-2")
        vpn_table = conn.create_table(**table_config)

        table_config = serverless_configuration["WireguardManagerPeersTable"]["Properties"]
        table_config["TableName"] = "wireguard-manager-peers-unittest"
        conn = boto3.resource("dynamodb", region_name="us-west-2")
        peer_table = conn.create_table(**table_config)

        table_config = serverless_configuration["WireguardManagerPeersHistoryTable"]["Properties"]
        table_config["TableName"] = "wireguard-manager-peers-history-unittest"
        conn = boto3.resource("dynamodb", region_name="us-west-2")
        peer_history_table = conn.create_table(**table_config)

        yield DynamoDb(environment="unittest", dynamodb_endpoint_url=None, aws_region="us-west-2")


@pytest.fixture(scope="function")
def mock_vpn_manager(mock_dynamodb):
    return VpnManager(db_manager=mock_dynamodb)


@pytest.fixture(scope="function")
def mock_ssm_command():
    new_server = WgServerModel(
        interface="wg0", public_key="PUBLIC_KEY1", private_key="PRIVATE_KEY1", listen_port=40023, fw_mark="off"
    )
    return MockSsmCommand(server=new_server, peers=[])


@pytest.fixture(scope="function")
def mock_ssh_command():
    new_server = WgServerModel(
        interface="wg0", public_key="PUBLIC_KEY1", private_key="PRIVATE_KEY1", listen_port=40023, fw_mark="off"
    )
    return MockSshCommand(server=new_server, peers=[])
