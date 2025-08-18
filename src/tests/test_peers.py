import pytest
from fastapi import HTTPException
from datetime import datetime
from http import HTTPStatus

from interfaces.peers import get_tag_history, get_peer_history_ip_address
from models.peer_history import PeerHistoryResponseModel


class DummyHistory:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def dict(self):
        return self.__dict__


@pytest.fixture(autouse=True)
def patch_peer_history_response_model(monkeypatch):
    # Patch PeerHistoryResponseModel to the real model for test
    from interfaces import peers as peers_mod

    monkeypatch.setattr(peers_mod, "PeerHistoryResponseModel", PeerHistoryResponseModel)


def make_vpn_manager(tag_histories=None, peer_history=None):
    class DummyVpnManager:
        def get_tag_history(self, vpn_name, tag, start_time_ns, end_time_ns):
            return tag_histories

        def get_peer_history(self, vpn_name, ip_address, start_time_ns, end_time_ns):
            return peer_history

    return DummyVpnManager()


@pytest.fixture
def patch_router_vpn_manager(monkeypatch):
    from interfaces import peers as peers_mod

    def _patch(manager):
        peers_mod.peer_router._vpn_manager = manager

    return _patch


def test_get_tag_history_success(patch_router_vpn_manager):
    patch_router_vpn_manager(
        make_vpn_manager(
            tag_histories={
                "1.2.3.4": [
                    DummyHistory(
                        ip_address="1.2.3.4",
                        allowed_ips="1.2.3.4/32",
                        public_key="pub",
                        private_key=None,
                        persistent_keepalive=25,
                        tags=["tag1"],
                        timestamp=123,
                    )
                ],
                "5.6.7.8": [
                    DummyHistory(
                        ip_address="5.6.7.8",
                        allowed_ips="5.6.7.8/32",
                        public_key="pub2",
                        private_key=None,
                        persistent_keepalive=25,
                        tags=["tag1"],
                        timestamp=456,
                    )
                ],
            }
        )
    )
    result = get_tag_history("vpn1", "tag1")
    assert "1.2.3.4" in result and "5.6.7.8" in result
    for ip, histories in result.items():
        for item in histories:
            assert isinstance(item, PeerHistoryResponseModel)
            assert hasattr(item, "ip_address")
            assert hasattr(item, "allowed_ips")
            assert hasattr(item, "public_key")
            assert hasattr(item, "persistent_keepalive")
            assert hasattr(item, "tags")
            assert hasattr(item, "timestamp")
            assert item.opaque is True
            # Assert that each returned tag is correct
            assert "tag1" in item.tags


def test_get_tag_history_multiple_tags(patch_router_vpn_manager):
    patch_router_vpn_manager(
        make_vpn_manager(
            tag_histories={
                "1.2.3.4": [
                    DummyHistory(
                        ip_address="1.2.3.4",
                        allowed_ips="1.2.3.4/32",
                        public_key="pub",
                        private_key=None,
                        persistent_keepalive=25,
                        tags=["tag1", "tag2"],
                        timestamp=123,
                    ),
                    DummyHistory(
                        ip_address="1.2.3.4",
                        allowed_ips="1.2.3.4/32",
                        public_key="pub",
                        private_key=None,
                        persistent_keepalive=25,
                        tags=["tag2"],
                        timestamp=124,
                    ),
                ],
                "5.6.7.8": [
                    DummyHistory(
                        ip_address="5.6.7.8",
                        allowed_ips="5.6.7.8/32",
                        public_key="pub2",
                        private_key=None,
                        persistent_keepalive=25,
                        tags=["tag2"],
                        timestamp=456,
                    )
                ],
            }
        )
    )
    result = get_tag_history("vpn1", "tag2")
    assert "1.2.3.4" in result and "5.6.7.8" in result
    for ip, histories in result.items():
        for item in histories:
            assert isinstance(item, PeerHistoryResponseModel)
            assert hasattr(item, "ip_address")
            assert hasattr(item, "allowed_ips")
            assert hasattr(item, "public_key")
            assert hasattr(item, "persistent_keepalive")
            assert hasattr(item, "tags")
            assert hasattr(item, "timestamp")
            assert item.opaque is True
            # Assert that each returned tag is correct for tag2
            assert "tag2" in item.tags


def test_get_tag_history_not_found(patch_router_vpn_manager):
    patch_router_vpn_manager(make_vpn_manager(tag_histories={}))
    with pytest.raises(HTTPException) as exc:
        get_tag_history("vpn1", "tag1")
    assert exc.value.status_code == HTTPStatus.NOT_FOUND


def test_get_tag_history_bad_time(patch_router_vpn_manager):
    patch_router_vpn_manager(make_vpn_manager(tag_histories={}))
    start = datetime(2024, 6, 10, 10, 0, 0)
    end = datetime(2024, 6, 9, 10, 0, 0)
    with pytest.raises(HTTPException) as exc:
        get_tag_history("vpn1", "tag1", start_time=start, end_time=end)
    assert exc.value.status_code == HTTPStatus.BAD_REQUEST


def test_get_peer_history_ip_address_success(patch_router_vpn_manager):
    patch_router_vpn_manager(
        make_vpn_manager(
            peer_history=[
                DummyHistory(
                    ip_address="1.2.3.4",
                    allowed_ips="1.2.3.4/32",
                    public_key="pub",
                    private_key=None,
                    persistent_keepalive=25,
                    tags=["tag1"],
                    timestamp=123,
                )
            ]
        )
    )
    result = get_peer_history_ip_address("vpn1", "1.2.3.4")
    assert isinstance(result, list)
    assert len(result) == 1
    item = result[0]
    assert isinstance(item, PeerHistoryResponseModel)
    assert hasattr(item, "ip_address")
    assert hasattr(item, "allowed_ips")
    assert hasattr(item, "public_key")
    assert hasattr(item, "persistent_keepalive")
    assert hasattr(item, "tags")
    assert hasattr(item, "timestamp")
    assert item.opaque is True


def test_get_peer_history_ip_address_not_found(patch_router_vpn_manager):
    patch_router_vpn_manager(make_vpn_manager(peer_history=[]))
    with pytest.raises(HTTPException) as exc:
        get_peer_history_ip_address("vpn1", "1.2.3.4")
    assert exc.value.status_code == HTTPStatus.NOT_FOUND


def test_get_peer_history_ip_address_bad_time(patch_router_vpn_manager):
    patch_router_vpn_manager(make_vpn_manager(peer_history=[]))
    start = datetime(2024, 6, 10, 10, 0, 0)
    end = datetime(2024, 6, 9, 10, 0, 0)
    with pytest.raises(HTTPException) as exc:
        get_peer_history_ip_address("vpn1", "1.2.3.4", start_time=start, end_time=end)
    assert exc.value.status_code == HTTPStatus.BAD_REQUEST
