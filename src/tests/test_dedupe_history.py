import pytest
import uuid
from databases.dynamodb import PeerHistoryDynamoModel, DynamoDb


@pytest.fixture
def sample_peer_histories():
    # Two identical, one different
    base = {
        "vpn_name": "vpn1",
        "ip_address": "10.0.0.2",
        "public_key": "pubkey1",
        "private_key": "privkey1",
        "persistent_keepalive": 25,
        "allowed_ips": ["10.0.0.2/32"],
        "peer_history_id": str(uuid.uuid4()),
        "timestamp": 123456789,
        "vpn_name_ip_addr": "vpn1#10.0.0.2",
        "vpn_name_tag": "vpn1#tag1",
        "tags": ["tag1"],
    }
    peer1 = PeerHistoryDynamoModel(**base)
    peer2 = PeerHistoryDynamoModel(**{**base, "peer_history_id": str(uuid.uuid4())})  # duplicate except GUID
    peer3 = PeerHistoryDynamoModel(**{**base, "ip_address": "10.0.0.3", "peer_history_id": str(uuid.uuid4())})
    return [peer1, peer2, peer3]


def test_dedupe_history_removes_duplicates(sample_peer_histories):
    db = DynamoDb.__new__(DynamoDb)
    deduped = db.dedupe_history(sample_peer_histories)
    # peer1 and peer2 are duplicates, so only 2 unique should remain
    assert len(deduped) == 2
    ip_addresses = {p.ip_address for p in deduped}
    assert "10.0.0.2" in ip_addresses
    assert "10.0.0.3" in ip_addresses


def test_dedupe_history_empty_list():
    db = DynamoDb.__new__(DynamoDb)
    assert db.dedupe_history([]) == []


def test_dedupe_history_all_unique():
    db = DynamoDb.__new__(DynamoDb)
    base = {
        "vpn_name": "vpn1",
        "public_key": "pubkey1",
        "private_key": "privkey1",
        "persistent_keepalive": 25,
        "allowed_ips": ["10.0.0.2/32"],
        "timestamp": 123456789,
        "vpn_name_ip_addr": "vpn1#10.0.0.2",
        "vpn_name_tag": "vpn1#tag1",
        "tags": ["tag1"],
    }
    peer1 = PeerHistoryDynamoModel(**{**base, "ip_address": "10.0.0.2", "peer_history_id": str(uuid.uuid4())})
    peer2 = PeerHistoryDynamoModel(**{**base, "ip_address": "10.0.0.3", "peer_history_id": str(uuid.uuid4())})
    peer3 = PeerHistoryDynamoModel(**{**base, "ip_address": "10.0.0.4", "peer_history_id": str(uuid.uuid4())})
    peers = [peer1, peer2, peer3]
    deduped = db.dedupe_history(peers)
    assert len(deduped) == 3
    assert {p.ip_address for p in deduped} == {"10.0.0.2", "10.0.0.3", "10.0.0.4"}


def test_dedupe_history_different_list_order():
    db = DynamoDb.__new__(DynamoDb)
    base = {
        "vpn_name": "vpn1",
        "ip_address": "10.0.0.2",
        "public_key": "pubkey1",
        "private_key": "privkey1",
        "persistent_keepalive": 25,
        "peer_history_id": str(uuid.uuid4()),
        "timestamp": 123456789,
        "vpn_name_ip_addr": "vpn1#10.0.0.2",
        "vpn_name_tag": "vpn1#tag1",
    }
    peer1 = PeerHistoryDynamoModel(
        **{
            **base,
            "allowed_ips": ["10.0.0.2/32", "10.0.0.3/32"],
            "tags": ["tag1", "tag2"],
            "peer_history_id": str(uuid.uuid4()),
        }
    )
    peer2 = PeerHistoryDynamoModel(
        **{
            **base,
            "allowed_ips": ["10.0.0.3/32", "10.0.0.2/32"],
            "tags": ["tag2", "tag1"],
            "peer_history_id": str(uuid.uuid4()),
        }
    )
    deduped = db.dedupe_history([peer1, peer2])
    # Should not dedupe, as order matters for lists
    assert len(deduped) == 2


def test_dedupe_history_identical_except_non_key_field():
    db = DynamoDb.__new__(DynamoDb)
    base = {
        "vpn_name": "vpn1",
        "ip_address": "10.0.0.2",
        "public_key": "pubkey1",
        "private_key": "privkey1",
        "persistent_keepalive": 25,
        "allowed_ips": ["10.0.0.2/32"],
        "tags": ["tag1"],
        "timestamp": 123456789,
        "vpn_name_ip_addr": "vpn1#10.0.0.2",
        "vpn_name_tag": "vpn1#tag1",
    }
    peer1 = PeerHistoryDynamoModel(**{**base, "peer_history_id": str(uuid.uuid4())})
    peer2 = PeerHistoryDynamoModel(**{**base, "peer_history_id": str(uuid.uuid4())})
    deduped = db.dedupe_history([peer1, peer2])
    # Now these are considered duplicates, so only one should remain
    assert len(deduped) == 1


def test_dedupe_history_empty_tags_and_allowed_ips():
    db = DynamoDb.__new__(DynamoDb)
    base = {
        "vpn_name": "vpn1",
        "ip_address": "10.0.0.2",
        "public_key": "pubkey1",
        "private_key": "privkey1",
        "persistent_keepalive": 25,
        "peer_history_id": str(uuid.uuid4()),
        "timestamp": 123456789,
        "vpn_name_ip_addr": "vpn1#10.0.0.2",
        "vpn_name_tag": "vpn1#tag1",
    }
    peer1 = PeerHistoryDynamoModel(**{**base, "allowed_ips": [], "tags": [], "peer_history_id": str(uuid.uuid4())})
    peer2 = PeerHistoryDynamoModel(**{**base, "allowed_ips": [], "tags": [], "peer_history_id": str(uuid.uuid4())})
    deduped = db.dedupe_history([peer1, peer2])
    assert len(deduped) == 1


def test_dedupe_history_mixed_types_and_duplicates():
    db = DynamoDb.__new__(DynamoDb)
    peer1 = PeerHistoryDynamoModel(
        vpn_name="vpn1",
        ip_address="10.0.0.2",
        public_key="pubkey1",
        private_key="privkey1",
        persistent_keepalive=25,
        allowed_ips=["10.0.0.2/32"],
        peer_history_id=str(uuid.uuid4()),
        timestamp=123456789,
        vpn_name_ip_addr="vpn1#10.0.0.2",
        vpn_name_tag="vpn1#tag1",
        tags=["tag1"],
    )
    peer2 = PeerHistoryDynamoModel(
        vpn_name="vpn1",
        ip_address="10.0.0.2",
        public_key="pubkey1",
        private_key="privkey1",
        persistent_keepalive=25,
        allowed_ips=["10.0.0.2/32"],
        peer_history_id=str(uuid.uuid4()),
        timestamp=123456789,
        vpn_name_ip_addr="vpn1#10.0.0.2",
        vpn_name_tag="vpn1#tag1",
        tags=["tag1"],
    )
    peer3 = PeerHistoryDynamoModel(
        vpn_name="vpn2",
        ip_address="10.0.0.3",
        public_key="pubkey2",
        private_key="privkey2",
        persistent_keepalive=30,
        allowed_ips=["10.0.0.3/32"],
        peer_history_id=str(uuid.uuid4()),
        timestamp=987654321,
        vpn_name_ip_addr="vpn2#10.0.0.3",
        vpn_name_tag="vpn2#tag2",
        tags=["tag2"],
    )
    deduped = db.dedupe_history([peer1, peer2, peer3])
    assert len(deduped) == 2
    ip_addresses = {p.ip_address for p in deduped}
    assert "10.0.0.2" in ip_addresses
    assert "10.0.0.3" in ip_addresses


def test_dedupe_history_three_identical():
    db = DynamoDb.__new__(DynamoDb)
    base = {
        "vpn_name": "vpn1",
        "ip_address": "10.0.0.2",
        "public_key": "pubkey1",
        "private_key": "privkey1",
        "persistent_keepalive": 25,
        "allowed_ips": ["10.0.0.2/32"],
        "peer_history_id": str(uuid.uuid4()),
        "timestamp": 123456789,
        "vpn_name_ip_addr": "vpn1#10.0.0.2",
        "vpn_name_tag": "vpn1#tag1",
        "tags": ["tag1"],
    }
    peer1 = PeerHistoryDynamoModel(**{**base, "peer_history_id": str(uuid.uuid4())})
    peer2 = PeerHistoryDynamoModel(**{**base, "peer_history_id": str(uuid.uuid4())})
    peer3 = PeerHistoryDynamoModel(**{**base, "peer_history_id": str(uuid.uuid4())})
    deduped = db.dedupe_history([peer1, peer2, peer3])
    assert len(deduped) == 1
    assert deduped[0].ip_address == "10.0.0.2"
