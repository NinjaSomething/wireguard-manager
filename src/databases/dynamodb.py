import logging
import time
from copy import deepcopy
from itertools import groupby
from uuid import uuid4

import boto3
from typing import Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ParamValidationError, ClientError
from pydantic import BaseModel, ValidationError

from models.vpn import WireguardModel, VpnModel
from models.peers import PeerDbModel
from models.connection import ConnectionType
from models.connection import build_wireguard_connection_model, ConnectionModel
from databases.in_mem_db import InMemoryDataStore
from environment import Environment

logger = logging.getLogger(__name__)


class VpnDynamoModel(BaseModel):
    name: str
    description: str
    wireguard_ip_address: str
    wireguard_ip_network: str
    wireguard_interface: str
    wireguard_public_key: str
    wireguard_private_key: str
    wireguard_listen_port: int
    connection_info: dict | None


class PeerBaseModel(BaseModel):
    vpn_name: str
    ip_address: str
    public_key: str
    private_key: Optional[str] = None
    persistent_keepalive: int
    allowed_ips: str
    tags: list[str] = []


class PeerDynamoModel(PeerBaseModel):
    peer_id: str


class PeerHistoryDynamoModel(PeerBaseModel):
    peer_history_id: str
    timestamp: int
    vpn_name_ip_addr: str
    vpn_name_tag: str


class DynamoDb(InMemoryDataStore):
    """
    This wraps around the InMemoryDataStore class and uses DynamoDB as the backend.  It will fetch all the Wireguard
    servers and their peers during startup and store it in memory.  Requests for data from the DB will use the in-memory
    datastore as a cache.  Changes made to the DB will first be done to DynamoDB and then to the in-memory datastore.
    """

    def __init__(self, environment: Environment, dynamodb_endpoint_url: str, aws_region: str = "us-west-2"):
        dynamodb = None
        match environment:
            case environment.DEV:
                dynamodb = boto3.resource("dynamodb", region_name=aws_region, endpoint_url=dynamodb_endpoint_url)
            case environment.STAGING:
                dynamodb = boto3.resource("dynamodb", region_name=aws_region)
            case environment.PRODUCTION:
                dynamodb = boto3.resource("dynamodb", region_name=aws_region)
        self.vpn_table = dynamodb.Table(f"wireguard-manager-vpn-servers-{environment.value}")
        self.peer_table = dynamodb.Table(f"wireguard-manager-peers-{environment.value}")
        self.peer_history_table = dynamodb.Table(f"wireguard-manager-peers-history-{environment.value}")
        super().__init__()

    def _get_all_vpn_from_server(self) -> list[VpnModel]:
        """Get all VPN networks from the database."""
        response = self.vpn_table.scan()
        data = response["Items"]
        while "LastEvaluatedKey" in response:
            response = self.vpn_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            data.extend(response["Items"])

        all_vpns = []
        for dynamo_vpn in data:
            connection_info = build_wireguard_connection_model(dynamo_vpn["connection_info"])
            vpn = VpnModel(
                name=dynamo_vpn["name"],
                description=dynamo_vpn["description"],
                wireguard=WireguardModel(
                    ip_address=dynamo_vpn["wireguard_ip_address"],
                    ip_network=dynamo_vpn["wireguard_ip_network"],
                    interface=dynamo_vpn["wireguard_interface"],
                    public_key=dynamo_vpn["wireguard_public_key"],
                    private_key=dynamo_vpn["wireguard_private_key"],
                    listen_port=dynamo_vpn["wireguard_listen_port"],
                ),
                connection_info=connection_info,
            )
            all_vpns.append(vpn)
        return all_vpns

    def _get_all_peers_from_server(self) -> dict[str, list[PeerDbModel]]:
        """
        Get all peers from the database.
        dict key: vpn_name
        """
        vpn_peers = {}
        response = self.peer_table.scan()
        data = response["Items"]
        while "LastEvaluatedKey" in response:
            response = self.vpn_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            data.extend(response["Items"])

        for dynamo_peer in data:
            peer = PeerDbModel(
                peer_id=dynamo_peer["peer_id"],
                ip_address=dynamo_peer["ip_address"],
                public_key=dynamo_peer["public_key"],
                private_key=dynamo_peer["private_key"],
                persistent_keepalive=dynamo_peer["persistent_keepalive"],
                allowed_ips=dynamo_peer["allowed_ips"],
                tags=dynamo_peer["tags"],
            )
            if dynamo_peer["vpn_name"] not in vpn_peers:
                vpn_peers[dynamo_peer["vpn_name"]] = []
            vpn_peers[dynamo_peer["vpn_name"]].append(peer)
        return vpn_peers

    def add_vpn(self, new_vpn: VpnModel):
        """Add a new VPN network to the database.  If it already exists, raise a ValueError exception."""
        vpn_dynamo = VpnDynamoModel(
            name=new_vpn.name,
            description=new_vpn.description,
            wireguard_ip_address=new_vpn.wireguard.ip_address,
            wireguard_ip_network=new_vpn.wireguard.ip_network,
            wireguard_interface=new_vpn.wireguard.interface,
            wireguard_public_key=new_vpn.wireguard.public_key,
            wireguard_private_key=new_vpn.wireguard.private_key,
            wireguard_listen_port=new_vpn.wireguard.listen_port,
            connection_info=new_vpn.connection_info.model_dump() if new_vpn.connection_info else None,
        )
        if new_vpn.connection_info is not None and new_vpn.connection_info.type == ConnectionType.SSH:
            # Get the secret value for the SSH key and password
            vpn_dynamo.connection_info["data"]["key"] = new_vpn.connection_info.data.key
            if new_vpn.connection_info.data.key_password is not None:
                vpn_dynamo.connection_info["data"]["key_password"] = new_vpn.connection_info.data.key_password
        elif new_vpn.connection_info is not None and new_vpn.connection_info.type == ConnectionType.SSM:
            # Get the secret value for the AWS aws_access_key_id and aws_secret_access_key
            vpn_dynamo.connection_info["data"]["aws_access_key_id"] = new_vpn.connection_info.data.aws_access_key_id
            vpn_dynamo.connection_info["data"][
                "aws_secret_access_key"
            ] = new_vpn.connection_info.data.aws_secret_access_key

        self.vpn_table.put_item(Item=vpn_dynamo.model_dump())
        # TODO: Handle failure response
        super().add_vpn(new_vpn)  # Add the VPN to the in-memory datastore

    def delete_vpn(self, name: str):
        """Remove a VPN network from the database."""
        self.vpn_table.delete_item(Key={"name": name})
        # TODO: Handle failure response
        super().delete_vpn(name)  # Remove the VPN from the in-memory datastore

    def add_peer(self, vpn_name: str, peer: PeerDbModel):
        peer_dynamo = PeerDynamoModel(
            vpn_name=vpn_name,
            peer_id=peer.peer_id,
            ip_address=peer.ip_address,
            public_key=peer.public_key,
            private_key=peer.private_key if peer.private_key else None,
            persistent_keepalive=peer.persistent_keepalive,
            allowed_ips=peer.allowed_ips,
            tags=peer.tags,
        )
        self.peer_table.put_item(Item=peer_dynamo.model_dump())
        # TODO: Handle failure response
        super().add_peer(vpn_name, peer)  # Add the peer to the in-memory datastore
        # Write the peer history
        self.write_peers_history(vpn_name, peer)

    def delete_peer(self, vpn_name: str, peer: PeerDbModel):
        # Prevent overwriting original object, in case it's reused later
        temp_peer = deepcopy(peer)
        temp_peer.allowed_ips = ""
        temp_peer.public_key = ""
        temp_peer.private_key = None
        temp_peer.persistent_keepalive = 0
        # Write history before deleting
        self.write_peers_history(vpn_name, temp_peer)

        # Delete the peer from the DynamoDB table
        self.peer_table.delete_item(Key={"peer_id": peer.peer_id})
        # TODO: Handle failure response
        # Remove the peer from the in-memory datastore
        super().delete_peer(vpn_name, peer)

    def add_tag_to_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Add a tag to a peer."""
        peer = self.get_peer(vpn_name, peer_ip)
        if peer is not None and tag not in peer.tags:
            peer.tags.append(tag)

            # Write the peer history
            self.write_peers_history(vpn_name, peer)

            # Update the peer in the DynamoDB table
            self.peer_table.update_item(
                Key={"peer_id": peer.peer_id},
                UpdateExpression="set tags=:newTags",
                ExpressionAttributeValues={":newTags": peer.tags + [tag]},
                ReturnValues="UPDATED_NEW",
            )
            # TODO: Handle failure response
            # Add the tag to the in-memory datastore
            super().add_tag_to_peer(vpn_name, peer_ip, tag)

    def delete_tag_from_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Delete tag from a peer."""
        peer = self.get_peer(vpn_name, peer_ip)
        if peer is not None and tag in peer.tags:
            peer.tags.remove(tag)

            # Write the peer history
            self.write_peers_history(vpn_name, peer)

            # Update the peer in the DynamoDB table
            self.peer_table.update_item(
                Key={"peer_id": peer.peer_id},
                UpdateExpression="set tags=:newTags",
                ExpressionAttributeValues={":newTags": peer.tags},
                ReturnValues="UPDATED_NEW",
            )

            # TODO: Handle failure response
            # Remove the tag from the in-memory datastore
            super().delete_tag_from_peer(vpn_name, peer_ip, tag)

    def update_connection_info(self, vpn_name: str, connection_info: ConnectionModel):
        """Update the connection info"""
        connection_info_dict = None
        if connection_info is not None:
            connection_info_dict = connection_info.model_dump()
            if connection_info.type == ConnectionType.SSH:
                # Get the secret value for the SSH key and password
                connection_info_dict["data"]["key"] = connection_info.data.key
                if connection_info.data.key_password is not None:
                    connection_info_dict["data"]["key_password"] = connection_info.data.key_password

        self.vpn_table.update_item(
            Key={"name": vpn_name},
            UpdateExpression="set connection_info=:newConnectionInfo",
            ExpressionAttributeValues={":newConnectionInfo": connection_info_dict},
            ReturnValues="UPDATED_NEW",
        )
        # TODO: Handle failure response
        super().update_connection_info(vpn_name, connection_info)  # Update the in-memory datastore

    def write_peer_history_db(self, peer: PeerHistoryDynamoModel):
        """
        Write a tag-flattened peer history to the peer history table.
        """
        item = peer.model_dump()
        try:
            self.peer_history_table.put_item(Item=item)
        except ParamValidationError as e:
            # e.g. invalid types or missing required fields
            logger.exception("Invalid item payload for DynamoDB: %r", item)
            raise ValueError("Peer model has invalid data") from e
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"]["Message"]
            logger.error("DynamoDB ClientError %s: %s", code, msg)
            raise
        except Exception as e:
            # catch anything else (network issue, etc.)
            logger.exception("Unexpected error writing to DynamoDB")
            raise

    def get_peer_history(
        self, vpn_name: str, ip_address: str, start_time: Optional[str] = None, end_time: Optional[str] = None
    ) -> list[PeerHistoryDynamoModel]:
        """
        Hit the peer history table and return the peer history based on ip_address.
        """
        key = f"{vpn_name}#{ip_address}"
        if start_time is not None and end_time is not None:
            resp = self.peer_history_table.query(
                IndexName="GSI-byIp",
                KeyConditionExpression=Key("vpn_name_ip_addr").eq(key) & Key("timestamp").between(start_time, end_time),
                ScanIndexForward=False,
            )
        else:
            resp = self.peer_history_table.query(
                IndexName="GSI-byIp", KeyConditionExpression=Key("vpn_name_ip_addr").eq(key), ScanIndexForward=False
            )
        db_items = resp.get("Items", [])

        peers_history = []
        try:
            for item in db_items:
                peer_history = PeerHistoryDynamoModel.model_validate(item)
                peers_history.append(peer_history)
        except ValidationError as e:
            logger.error("Validation error while processing peer history items: %s", e)
            raise ValueError("Peer history items have invalid data") from e
        return peers_history

    def get_tag_history(
        self, vpn_name: str, tag: str, start_time: Optional[str] = None, end_time: Optional[str] = None
    ) -> dict[str, list[PeerHistoryDynamoModel]]:
        """
        Hit the peer history table. Group peers together and return combined peer history based on tag.
        """
        key = f"{vpn_name}#{tag}"

        if start_time is not None and end_time is not None:
            # Add time range filtering if provided
            resp = self.peer_history_table.query(
                IndexName="GSI-byTag",
                KeyConditionExpression=Key("vpn_name_tag").eq(key) & Key("timestamp").between(start_time, end_time),
                ScanIndexForward=False,
            )
        else:
            resp = self.peer_history_table.query(
                IndexName="GSI-byTag", KeyConditionExpression=Key("vpn_name_tag").eq(key), ScanIndexForward=False
            )
        db_items = resp.get("Items", [])

        peers_tag_history = []
        try:
            for item in db_items:
                peer_tag_history = PeerHistoryDynamoModel.model_validate(item)
                peers_tag_history.append(peer_tag_history)
        except ValidationError as e:
            logger.error("Validation error while processing peer tag history items: %s", e)
            raise ValueError("Peer history items have invalid data") from e

        grouped_peers_tag_history = {
            ip: sorted(
                [obj for obj in peers_tag_history if obj.ip_address == ip], key=lambda x: x.timestamp, reverse=True
            )
            for ip in {peer_tag_history.ip_address for peer_tag_history in peers_tag_history}
        }

        return grouped_peers_tag_history

    def write_peers_history(self, vpn_name: str, peer: PeerDbModel):
        """
        Write the peer history to the peer history table. Flatten the tags into individual entries.
        If the peer has no tags, write a single entry with an empty tag.
        """
        timestamp = int(time.time_ns())
        if len(peer.tags) > 0:
            for tag in peer.tags:
                peer_history = PeerHistoryDynamoModel(
                    vpn_name=vpn_name,
                    ip_address=peer.ip_address,
                    public_key=peer.public_key,
                    private_key=peer.private_key,
                    persistent_keepalive=peer.persistent_keepalive,
                    allowed_ips=peer.allowed_ips,
                    peer_history_id=uuid4().hex,
                    timestamp=timestamp,
                    vpn_name_ip_addr=f"{vpn_name}#{peer.ip_address}",
                    vpn_name_tag=f"{vpn_name}#{tag}",
                    tags=peer.tags,
                )
                self.write_peer_history_db(peer_history)
        else:
            peer_history = PeerHistoryDynamoModel(
                vpn_name=vpn_name,
                ip_address=peer.ip_address,
                public_key=peer.public_key,
                private_key=peer.private_key,
                persistent_keepalive=peer.persistent_keepalive,
                allowed_ips=peer.allowed_ips,
                peer_history_id=uuid4().hex,
                timestamp=timestamp,
                vpn_name_ip_addr=f"{vpn_name}#{peer.ip_address}",
                vpn_name_tag=f"{vpn_name}#",
            )
            self.write_peer_history_db(peer_history)
