import pytest
from src.databases.dynamodb import DynamoDb
from databases.dynamodb import PeerHistoryDynamoModel


@pytest.fixture
def dynamodb_instance():
    from unittest.mock import MagicMock

    DynamoDb.__init__ = MagicMock(return_value=None)
    db = DynamoDb.__new__(DynamoDb)
    return db


@pytest.fixture(autouse=True)
def patch_peer_history_response_model(monkeypatch):
    # Patch PeerHistoryResponseModel to a simple dict constructor for all tests
    monkeypatch.setattr("src.databases.dynamodb.PeerHistoryResponseModel", lambda **kwargs: kwargs)


@pytest.mark.parametrize(
    "items,expected",
    [
        # Basic: two items, same timestamp, different tags
        (
            [
                PeerHistoryDynamoModel(
                    vpn_name="vpn1",
                    ip_address="10.0.0.2",
                    public_key="pub1",
                    private_key=None,
                    persistent_keepalive=25,
                    allowed_ips="10.0.0.2/32",
                    peer_history_id="id1",
                    timestamp=123,
                    vpn_name_ip_addr="vpn1#10.0.0.2",
                    vpn_name_tag="vpn1#tag1",
                    tag="tag1",
                ),
                PeerHistoryDynamoModel(
                    vpn_name="vpn1",
                    ip_address="10.0.0.2",
                    public_key="pub1",
                    private_key=None,
                    persistent_keepalive=25,
                    allowed_ips="10.0.0.2/32",
                    peer_history_id="id2",
                    timestamp=123,
                    vpn_name_ip_addr="vpn1#10.0.0.2",
                    vpn_name_tag="vpn1#tag2",
                    tag="tag2",
                ),
            ],
            [
                {
                    "ip_address": "10.0.0.2",
                    "allowed_ips": "10.0.0.2/32",
                    "public_key": "pub1",
                    "private_key": None,
                    "persistent_keepalive": 25,
                    "tags": ["tag1", "tag2"],
                    "timestamp": 123,
                }
            ],
        ),
        # Edge: empty input
        (
            [],
            [],
        ),
        # Edge: duplicate tags for same timestamp
        (
            [
                PeerHistoryDynamoModel(
                    vpn_name="vpn1",
                    ip_address="10.0.0.3",
                    public_key="pub2",
                    private_key=None,
                    persistent_keepalive=30,
                    allowed_ips="10.0.0.3/32",
                    peer_history_id="id3",
                    timestamp=200,
                    vpn_name_ip_addr="vpn1#10.0.0.3",
                    vpn_name_tag="vpn1#tag3",
                    tag="tag3",
                ),
                PeerHistoryDynamoModel(
                    vpn_name="vpn1",
                    ip_address="10.0.0.3",
                    public_key="pub2",
                    private_key=None,
                    persistent_keepalive=30,
                    allowed_ips="10.0.0.3/32",
                    peer_history_id="id4",
                    timestamp=200,
                    vpn_name_ip_addr="vpn1#10.0.0.3",
                    vpn_name_tag="vpn1#tag3",
                    tag="tag3",
                ),
            ],
            [
                {
                    "ip_address": "10.0.0.3",
                    "allowed_ips": "10.0.0.3/32",
                    "public_key": "pub2",
                    "private_key": None,
                    "persistent_keepalive": 30,
                    "tags": ["tag3", "tag3"],
                    "timestamp": 200,
                }
            ],
        ),
        # Edge: None tag
        (
            [
                PeerHistoryDynamoModel(
                    vpn_name="vpn1",
                    ip_address="10.0.0.4",
                    public_key="pub3",
                    private_key=None,
                    persistent_keepalive=35,
                    allowed_ips="10.0.0.4/32",
                    peer_history_id="id5",
                    timestamp=300,
                    vpn_name_ip_addr="vpn1#10.0.0.4",
                    vpn_name_tag="vpn1#",
                    tag=None,
                ),
            ],
            [
                {
                    "ip_address": "10.0.0.4",
                    "allowed_ips": "10.0.0.4/32",
                    "public_key": "pub3",
                    "private_key": None,
                    "persistent_keepalive": 35,
                    "tags": [None],
                    "timestamp": 300,
                }
            ],
        ),
        # Edge: multiple timestamps, mixed tags, mixed private_key
        (
            [
                PeerHistoryDynamoModel(
                    vpn_name="vpn2",
                    ip_address="10.0.0.5",
                    public_key="pub4",
                    private_key="priv4",
                    persistent_keepalive=40,
                    allowed_ips="10.0.0.5/32",
                    peer_history_id="id6",
                    timestamp=400,
                    vpn_name_ip_addr="vpn2#10.0.0.5",
                    vpn_name_tag="vpn2#tag4",
                    tag="tag4",
                ),
                PeerHistoryDynamoModel(
                    vpn_name="vpn2",
                    ip_address="10.0.0.5",
                    public_key="pub4",
                    private_key=None,
                    persistent_keepalive=40,
                    allowed_ips="10.0.0.5/32",
                    peer_history_id="id7",
                    timestamp=500,
                    vpn_name_ip_addr="vpn2#10.0.0.5",
                    vpn_name_tag="vpn2#tag5",
                    tag="tag5",
                ),
            ],
            [
                {
                    "ip_address": "10.0.0.5",
                    "allowed_ips": "10.0.0.5/32",
                    "public_key": "pub4",
                    "private_key": "priv4",
                    "persistent_keepalive": 40,
                    "tags": ["tag4"],
                    "timestamp": 400,
                },
                {
                    "ip_address": "10.0.0.5",
                    "allowed_ips": "10.0.0.5/32",
                    "public_key": "pub4",
                    "private_key": None,
                    "persistent_keepalive": 40,
                    "tags": ["tag5"],
                    "timestamp": 500,
                },
            ],
        ),
        # Edge: tags order preserved
        (
            [
                PeerHistoryDynamoModel(
                    vpn_name="vpn3",
                    ip_address="10.0.0.6",
                    public_key="pub5",
                    private_key=None,
                    persistent_keepalive=50,
                    allowed_ips="10.0.0.6/32",
                    peer_history_id="id8",
                    timestamp=600,
                    vpn_name_ip_addr="vpn3#10.0.0.6",
                    vpn_name_tag="vpn3#tagA",
                    tag="tagA",
                ),
                PeerHistoryDynamoModel(
                    vpn_name="vpn3",
                    ip_address="10.0.0.6",
                    public_key="pub5",
                    private_key=None,
                    persistent_keepalive=50,
                    allowed_ips="10.0.0.6/32",
                    peer_history_id="id9",
                    timestamp=600,
                    vpn_name_ip_addr="vpn3#10.0.0.6",
                    vpn_name_tag="vpn3#tagB",
                    tag="tagB",
                ),
                PeerHistoryDynamoModel(
                    vpn_name="vpn3",
                    ip_address="10.0.0.6",
                    public_key="pub5",
                    private_key=None,
                    persistent_keepalive=50,
                    allowed_ips="10.0.0.6/32",
                    peer_history_id="id10",
                    timestamp=600,
                    vpn_name_ip_addr="vpn3#10.0.0.6",
                    vpn_name_tag="vpn3#tagC",
                    tag="tagC",
                ),
            ],
            [
                {
                    "ip_address": "10.0.0.6",
                    "allowed_ips": "10.0.0.6/32",
                    "public_key": "pub5",
                    "private_key": None,
                    "persistent_keepalive": 50,
                    "tags": ["tagA", "tagB", "tagC"],
                    "timestamp": 600,
                }
            ],
        ),
    ],
)
def test_compress_history_by_timestamp(dynamodb_instance, items, expected):
    result = dynamodb_instance._compress_history_by_timestamp(items)
    assert len(result) == len(expected)
    for idx, exp in enumerate(expected):
        actual = result[idx]
        # Check all fields
        for key in exp:
            if key == "tags":
                assert actual["tags"] == exp["tags"]
            else:
                assert actual[key] == exp[key]
