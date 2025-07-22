import pytest
from server_manager import server_manager_factory, ConnectionException
from models.wireguard_connection import WireguardConnectionType


def test_server_manager_factory_ssh(monkeypatch):
    class DummySshConnection:
        pass

    monkeypatch.setattr("server_manager.ssh.SshConnection", DummySshConnection)
    manager = server_manager_factory(WireguardConnectionType.SSH)
    assert isinstance(manager, DummySshConnection)


def test_server_manager_factory_ssm(monkeypatch):
    class DummySsmConnection:
        pass

    monkeypatch.setattr("server_manager.ssm.SsmConnection", DummySsmConnection)
    manager = server_manager_factory(WireguardConnectionType.SSM)
    assert isinstance(manager, DummySsmConnection)


def test_server_manager_factory_invalid_type():
    with pytest.raises(ValueError):
        server_manager_factory("INVALID_TYPE")
