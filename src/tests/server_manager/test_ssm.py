# Necessary import for mocker
import pytest_mock
import pytest
from unittest.mock import MagicMock

from models.peers import PeerRequestModel
from models.ssm import SsmConnectionModel
from server_manager.ssm import SsmConnection, ConnectionException
from models.connection import ConnectionModel, ConnectionType
from models.wg_server import WgServerModel
from botocore.exceptions import ClientError


@pytest.fixture
def connection_info():
    info = MagicMock(spec=ConnectionModel)
    info.type = ConnectionType.SSM
    info.data = MagicMock(spec=SsmConnectionModel)
    info.data.region = "us-west-2"
    info.data.aws_access_key_id = "AKIA..."
    info.data.aws_secret_access_key = "SECRET..."
    info.data.target_id = "i-1234567890abcdef0"
    return info


def test_remote_ssm_command_success(mocker, connection_info):
    # Patch boto3.client to return a MagicMock SSM client
    output = "line1\nline2"
    mock_ssm = MagicMock()
    mocker.patch("server_manager.ssm.boto3.client", return_value=mock_ssm)
    mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
    mock_ssm.get_command_invocation.return_value = {"Status": "Success", "StandardOutputContent": output}
    success, result = SsmConnection._remote_ssm_command("echo test", connection_info)
    assert result == output
    assert success is True


def test_remote_ssm_command_failure(mocker, connection_info):
    # Patch boto3.client and simulate send_command raising an Exception
    mock_ssm = MagicMock()
    mocker.patch("server_manager.ssm.boto3.client", return_value=mock_ssm)
    error_response = {"Error": {"Code": "AccessDeniedException", "Message": "Not allowed"}}
    operation_name = "SendCommand"
    mock_ssm.send_command.side_effect = ClientError(error_response, operation_name)
    success, result = SsmConnection._remote_ssm_command("echo test", connection_info)
    assert "SSM connection failed" in result
    assert success is False


def test_dump_interface_config_success(mocker, connection_info):
    # Patch _remote_ssm_command and extract_wg_server_config
    mocker.patch("server_manager.ssm.SsmConnection._remote_ssm_command", return_value=(True, "config line"))
    mock_extract = mocker.patch(
        "server_manager.ssm.extract_wg_server_config", return_value=MagicMock(spec=WgServerModel)
    )
    ssm = SsmConnection()
    result = ssm.dump_interface_config("wg0", connection_info)
    mock_extract.assert_called_once()
    assert isinstance(result, WgServerModel)


def test_dump_interface_config_error(mocker, connection_info):
    # Patch _remote_ssm_command to return an error string
    mocker.patch("server_manager.ssm.SsmConnection._remote_ssm_command", return_value=(False, "error"))
    ssm = SsmConnection()
    result = ssm.dump_interface_config("wg0", connection_info)
    assert result == "error"


def test_remove_peer_success(mocker, connection_info):
    # Patch _remote_ssm_command to return success
    mocker.patch("server_manager.ssm.SsmConnection._remote_ssm_command", return_value=["ok"])
    ssm = SsmConnection()
    vpn = MagicMock()
    vpn.interface = "wg0"
    vpn.connection_info = connection_info
    peer = MagicMock(spec=PeerRequestModel)
    peer.public_key = "pubkey"
    ssm.remove_peer(vpn, peer)  # Should not raise


def test_remove_peer_failure(mocker, connection_info):
    # Patch _remote_ssm_command to return error string
    mocker.patch("server_manager.ssm.SsmConnection._remote_ssm_command", return_value="error")
    ssm = SsmConnection()
    vpn = MagicMock()
    vpn.interface = "wg0"
    vpn.connection_info = connection_info
    peer = MagicMock(spec=PeerRequestModel)
    peer.public_key = "pubkey"
    with pytest.raises(ConnectionException):
        ssm.remove_peer(vpn, peer)


def test_add_peer_success(mocker, connection_info):
    # Patch _remote_ssm_command to return success
    mocker.patch("server_manager.ssm.SsmConnection._remote_ssm_command", return_value=["ok"])
    ssm = SsmConnection()
    vpn = MagicMock()
    vpn.interface = "wg0"
    vpn.connection_info = connection_info
    peer = MagicMock(spec=PeerRequestModel)
    peer.public_key = "pubkey"
    peer.persistent_keepalive = 25
    peer.ip_address = "10.0.0.2/32"
    ssm.add_peer(vpn, peer)  # Should not raise


def test_add_peer_failure(mocker, connection_info):
    # Patch _remote_ssm_command to return error string
    mocker.patch("server_manager.ssm.SsmConnection._remote_ssm_command", return_value="error")
    ssm = SsmConnection()
    vpn = MagicMock()
    vpn.interface = "wg0"
    vpn.connection_info = connection_info
    peer = MagicMock(spec=PeerRequestModel)
    peer.public_key = "pubkey"
    peer.persistent_keepalive = 25
    peer.ip_address = "10.0.0.2/32"
    with pytest.raises(ConnectionException):
        ssm.add_peer(vpn, peer)
