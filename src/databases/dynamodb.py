import logging
import time
from copy import deepcopy
from typing import Optional
from uuid import uuid4

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError, ParamValidationError
from pydantic import BaseModel, ValidationError, field_validator

from databases.in_mem_db import InMemoryDataStore
from models.connection import ConnectionModel, ConnectionType, build_wireguard_connection_model
from models.peers import PeerDbModel
from models.vpn import VpnModel, WireguardModel
from models.exceptions import (
    DynamoUpdatePeerException,
    DynamoAddPeerException,
    DynamoUpdateConnectionInfoException,
    DynamoDeletePeerException,
    DynamoDeleteVpnException,
    DynamoAddVpnException,
    DynamoRecordHistoryException,
)

log = logging.getLogger(__name__)

UNKNOWN_USER_STRING = "[Unknown]"


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
    allowed_ips: list[str] | str
    tags: list[str] = []

    @field_validator("allowed_ips", mode="before")
    def transform_allowed_ips(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return value.split(",")
        else:
            return value


class PeerDynamoModel(PeerBaseModel):
    peer_id: str


class PeerHistoryDynamoModel(PeerBaseModel):
    peer_history_id: str
    timestamp: int
    vpn_name_ip_addr: str
    vpn_name_tag: str
    changed_by: str = UNKNOWN_USER_STRING
    message: str = ""


class DynamoDb(InMemoryDataStore):
    """
    This wraps around the InMemoryDataStore class and uses DynamoDB as the backend.  It will fetch all the Wireguard
    servers and their peers during startup and store it in memory.  Requests for data from the DB will use the in-memory
    datastore as a cache.  Changes made to the DB will first be done to DynamoDB and then to the in-memory datastore.
    """

    def __init__(self, environment: str, dynamodb_endpoint_url: str | None, aws_region: str = "us-west-2"):
        if dynamodb_endpoint_url is not None:
            dynamodb = boto3.resource("dynamodb", region_name=aws_region, endpoint_url=dynamodb_endpoint_url)
        else:
            dynamodb = boto3.resource("dynamodb", region_name=aws_region)
        self.vpn_table = dynamodb.Table(f"wireguard-manager-vpn-servers-{environment}")
        self.peer_table = dynamodb.Table(f"wireguard-manager-peers-{environment}")
        self.peer_history_table = dynamodb.Table(f"wireguard-manager-peers-history-{environment}")
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
                # Default these values if they don't exist in the record
                changed_by=dynamo_peer.get("changed_by", UNKNOWN_USER_STRING),
                message=dynamo_peer.get("message", ""),
            )
            if dynamo_peer["vpn_name"] not in vpn_peers:
                vpn_peers[dynamo_peer["vpn_name"]] = []
            vpn_peers[dynamo_peer["vpn_name"]].append(peer)
        return {k: sorted(v, key=lambda p: p.ip_address) for k, v in vpn_peers.items()}

    def add_vpn(self, new_vpn: VpnModel):
        """Add a new VPN network to the database.  If it already exists, raise a ValueError exception."""
        try:
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
        except Exception as err:
            # This will trigger a rollback in the event we introduce a regression here.  It is intentionally broad.
            msg = f"Failed to add VPN {new_vpn.name} in DynamoDB: {err}"
            raise DynamoAddVpnException(msg)

        try:
            self.vpn_table.put_item(Item=vpn_dynamo.model_dump())
        except ClientError as err:
            log.error("Error Code: {}".format(err.response["Error"]["Code"]))
            log.error("Error Message: {}".format(err.response["Error"]["Message"]))
            log.error("Http Code: {}".format(err.response["ResponseMetadata"]["HTTPStatusCode"]))
            log.error("Request ID: {}".format(err.response["ResponseMetadata"]["RequestId"]))

            if err.response["Error"]["Code"] in ("ProvisionedThroughputExceededException", "ThrottlingException"):
                log.warning("Received a throttle")
            elif err.response["Error"]["Code"] == "InternalServerError":
                log.error("Received a server error")
            msg = f"Failed to add VPN {new_vpn.name} in DynamoDB: {err}"
            raise DynamoAddVpnException(msg)

        super().add_vpn(new_vpn)  # Add the VPN to the in-memory datastore

    def delete_vpn(self, name: str):
        """Remove a VPN network from the database."""
        try:
            self.vpn_table.delete_item(Key={"name": name})
        except ClientError as err:
            log.error("Error Code: {}".format(err.response["Error"]["Code"]))
            log.error("Error Message: {}".format(err.response["Error"]["Message"]))
            log.error("Http Code: {}".format(err.response["ResponseMetadata"]["HTTPStatusCode"]))
            log.error("Request ID: {}".format(err.response["ResponseMetadata"]["RequestId"]))

            if err.response["Error"]["Code"] in ("ProvisionedThroughputExceededException", "ThrottlingException"):
                log.warning("Received a throttle")
            elif err.response["Error"]["Code"] == "InternalServerError":
                log.error("Received a server error")
            msg = f"Failed to delete VPN {name} in DynamoDB: {err}"
            raise DynamoDeleteVpnException(msg)

        super().delete_vpn(name)  # Remove the VPN from the in-memory datastore

    def add_peer(self, vpn_name: str, peer: PeerDbModel, changed_by: str):
        try:
            peer_dynamo = PeerDynamoModel(
                vpn_name=vpn_name,
                peer_id=peer.peer_id,
                ip_address=peer.ip_address,
                public_key=peer.public_key,
                private_key=peer.private_key if peer.private_key else None,
                persistent_keepalive=peer.persistent_keepalive,
                allowed_ips=",".join(peer.allowed_ips),
                tags=peer.tags,
            )
        except Exception as err:
            # This will trigger a rollback in the event we introduce a regression here.  It is intentionally broad.
            msg = f"Failed to add peer {peer.ip_address} [{peer.peer_id}] in DynamoDB: {err}"
            raise DynamoAddPeerException(msg)

        try:
            self.peer_table.put_item(Item=peer_dynamo.model_dump())
        except ClientError as err:
            log.error("Error Code: {}".format(err.response["Error"]["Code"]))
            log.error("Error Message: {}".format(err.response["Error"]["Message"]))
            log.error("Http Code: {}".format(err.response["ResponseMetadata"]["HTTPStatusCode"]))
            log.error("Request ID: {}".format(err.response["ResponseMetadata"]["RequestId"]))

            if err.response["Error"]["Code"] in ("ProvisionedThroughputExceededException", "ThrottlingException"):
                log.warning("Received a throttle")
            elif err.response["Error"]["Code"] == "InternalServerError":
                log.error("Received a server error")
            msg = f"Failed to add peer {peer.ip_address} [{peer.peer_id}] in DynamoDB: {err}"
            raise DynamoAddPeerException(msg)

        # Add the peer to the in-memory datastore
        super().add_peer(vpn_name, peer, changed_by)

        # Write the peer history
        try:
            self.write_peers_history(vpn_name, peer, changed_by)
        except DynamoRecordHistoryException as err:
            # Don't raise an exception here.  Failing to record the history doesn't need to trigger a rollback.
            log.error(
                f"Failed to record the deletion history for {peer.ip_address} [{peer.message}] in DynamoDB: {err}"
            )

    def delete_peer(self, vpn_name: str, peer: PeerDbModel, changed_by: str):
        try:
            # Prevent overwriting original object, in case it's reused later
            temp_peer = deepcopy(peer)
            temp_peer.allowed_ips = ""
            temp_peer.public_key = ""
            temp_peer.private_key = None
            temp_peer.persistent_keepalive = 0
            # Write history before deleting
            self.write_peers_history(vpn_name, temp_peer, changed_by)
        except DynamoRecordHistoryException as err:
            # Don't raise an exception here.  Failing to record the history doesn't need to trigger a rollback.
            log.error(
                f"Failed to record the deletion history for {peer.ip_address} [{peer.message}] in DynamoDB: {err}"
            )

        # Delete the peer from the DynamoDB table
        try:
            self.peer_table.delete_item(Key={"peer_id": peer.peer_id})
        except ClientError as err:
            log.error("Error Code: {}".format(err.response["Error"]["Code"]))
            log.error("Error Message: {}".format(err.response["Error"]["Message"]))
            log.error("Http Code: {}".format(err.response["ResponseMetadata"]["HTTPStatusCode"]))
            log.error("Request ID: {}".format(err.response["ResponseMetadata"]["RequestId"]))

            if err.response["Error"]["Code"] in ("ProvisionedThroughputExceededException", "ThrottlingException"):
                log.warning("Received a throttle")
            elif err.response["Error"]["Code"] == "InternalServerError":
                log.error("Received a server error")
            msg = f"Failed to delete peer {peer.ip_address} [{peer.peer_id}] in DynamoDB: {err}"
            raise DynamoDeletePeerException(msg)

        # Remove the peer from the in-memory datastore
        super().delete_peer(vpn_name, peer, changed_by)

    def update_peer(self, vpn_name: str, updated_peer: PeerDbModel, changed_by: str):
        """Update an existing peer."""
        # Update the peer in the DynamoDB table
        try:
            response = self.peer_table.update_item(
                Key={"peer_id": updated_peer.peer_id},
                UpdateExpression="set tags=:newTags, allowed_ips=:newAllowedIps, public_key=:newPublicKey, private_key=:newPrivateKey, persistent_keepalive=:newPersistentKeepalive",
                ExpressionAttributeValues={
                    ":newTags": updated_peer.tags,
                    ":newAllowedIps": updated_peer.allowed_ips,
                    ":newPublicKey": updated_peer.public_key,
                    ":newPrivateKey": updated_peer.private_key,
                    ":newPersistentKeepalive": updated_peer.persistent_keepalive,
                },
                ReturnValues="UPDATED_NEW",
            )
            log.info(f"Updated peer in DynamoDB: {response.get('Attributes')}")
        except ClientError as err:
            log.error("Error Code: {}".format(err.response["Error"]["Code"]))
            log.error("Error Message: {}".format(err.response["Error"]["Message"]))
            log.error("Http Code: {}".format(err.response["ResponseMetadata"]["HTTPStatusCode"]))
            log.error("Request ID: {}".format(err.response["ResponseMetadata"]["RequestId"]))

            if err.response["Error"]["Code"] in ("ProvisionedThroughputExceededException", "ThrottlingException"):
                log.warning("Received a throttle")
            elif err.response["Error"]["Code"] == "InternalServerError":
                log.error("Received a server error")
            msg = f"Failed to update peer {updated_peer.ip_address} [{updated_peer.peer_id}] in DynamoDB: {err}"
            raise DynamoUpdatePeerException(msg)

        # Update the in-memory datastore
        super().update_peer(vpn_name, updated_peer, changed_by)

        # Write the peer history
        try:
            self.write_peers_history(vpn_name, updated_peer, changed_by)
        except DynamoRecordHistoryException as err:
            # Don't raise an exception here.  Failing to record the history doesn't need to trigger a rollback.
            log.error(
                f"Failed to record the deletion history for {updated_peer.ip_address} [{updated_peer.message}] in DynamoDB: {err}"
            )

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

        try:
            response = self.vpn_table.update_item(
                Key={"name": vpn_name},
                UpdateExpression="set connection_info=:newConnectionInfo",
                ExpressionAttributeValues={":newConnectionInfo": connection_info_dict},
                ReturnValues="UPDATED_NEW",
            )
            log.info(f"Updated connection_info in DynamoDB: {response.get('Attributes')}")
        except ClientError as err:
            log.error("Error Code: {}".format(err.response["Error"]["Code"]))
            log.error("Error Message: {}".format(err.response["Error"]["Message"]))
            log.error("Http Code: {}".format(err.response["ResponseMetadata"]["HTTPStatusCode"]))
            log.error("Request ID: {}".format(err.response["ResponseMetadata"]["RequestId"]))

            if err.response["Error"]["Code"] in ("ProvisionedThroughputExceededException", "ThrottlingException"):
                log.warning("Received a throttle")
            elif err.response["Error"]["Code"] == "InternalServerError":
                log.error("Received a server error")
            msg = f"Failed to update connection info in dynamodb {vpn_name}: {err}"
            raise DynamoUpdateConnectionInfoException(msg)
        super().update_connection_info(vpn_name, connection_info)  # Update the in-memory datastore

    def write_peer_history_db(self, peer: PeerHistoryDynamoModel):
        """
        Write a tag-flattened peer history to the peer history table.
        """
        item = peer.model_dump()
        try:
            self.peer_history_table.put_item(Item=item)
        except ClientError as err:
            log.error("Error Code: {}".format(err.response["Error"]["Code"]))
            log.error("Error Message: {}".format(err.response["Error"]["Message"]))
            log.error("Http Code: {}".format(err.response["ResponseMetadata"]["HTTPStatusCode"]))
            log.error("Request ID: {}".format(err.response["ResponseMetadata"]["RequestId"]))

            if err.response["Error"]["Code"] in ("ProvisionedThroughputExceededException", "ThrottlingException"):
                log.warning("Received a throttle")
            elif err.response["Error"]["Code"] == "InternalServerError":
                log.error("Received a server error")
            raise DynamoRecordHistoryException(err)

    def dedupe_history(self, peers_history: list[PeerHistoryDynamoModel]) -> list[PeerHistoryDynamoModel]:
        """
        Deduplicate history items.
        Returns a list of unique PeerHistoryDynamoModel objects.
        Ignores peer_history_id in the comparison.
        """

        # Convert non-hashable dicts to hashable tuples for deduplication
        # This is necessary because lists are not hashable by default
        def make_hashable(d):
            # Exclude peer_history_id from the hashable tuple; Exclude vpn_name_tag and vpn_name_ip_addr as well since they're just for indexing purposes
            return tuple(
                (k, tuple(v) if isinstance(v, list) else v)
                for k, v in sorted(d.items())
                if (k != "peer_history_id" and k != "vpn_name_tag" and k != "vpn_name_ip_addr")
            )

        # Store hashable object as key, and the peer_history as value. Use key to deduplicate and convert back into the deduped list.
        unique = list({make_hashable(p.model_dump()): p for p in peers_history}.values())
        return unique

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
            log.error("Validation error while processing peer history items: %s", e)
            raise ValueError("Peer history items have invalid data") from e
        return self.dedupe_history(peers_history)

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
            log.error("Validation error while processing peer tag history items: %s", e)
            raise ValueError("Peer history items have invalid data") from e

        peers_tag_history = self.dedupe_history(peers_tag_history)
        grouped_peers_tag_history = {
            ip: sorted(
                [obj for obj in peers_tag_history if obj.ip_address == ip], key=lambda x: x.timestamp, reverse=True
            )
            for ip in {peer_tag_history.ip_address for peer_tag_history in peers_tag_history}
        }

        return grouped_peers_tag_history

    def write_peers_history(self, vpn_name: str, peer: PeerDbModel, changed_by: str):
        """
        Write the peer history to the peer history table. Flatten the tags into individual entries.
        If the peer has no tags, write a single entry with an empty tag.
        """
        timestamp = int(time.time_ns())
        _tags = peer.tags if len(peer.tags) > 0 else [""]
        for tag in _tags:
            peer_history = PeerHistoryDynamoModel(
                vpn_name=vpn_name,
                ip_address=peer.ip_address,
                public_key=peer.public_key,
                private_key=peer.private_key,
                persistent_keepalive=peer.persistent_keepalive,
                allowed_ips=",".join(peer.allowed_ips),
                peer_history_id=uuid4().hex,
                timestamp=timestamp,
                vpn_name_ip_addr=f"{vpn_name}#{peer.ip_address}",
                vpn_name_tag=f"{vpn_name}#{tag}",
                tags=peer.tags,
                changed_by=changed_by,
                message=peer.message,
            )
            self.write_peer_history_db(peer_history)
