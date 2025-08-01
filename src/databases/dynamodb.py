import boto3
from typing import Optional

from pydantic import BaseModel
from models.vpn import WireguardModel, VpnModel
from models.peers import PeerDbModel
from models.connection import ConnectionType
from vpn_manager.vpn import VpnServer
from models.connection import build_connection_model, ConnectionModel
from databases.in_mem_db import InMemoryDataStore
from environment import Environment


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


class PeerDynamoModel(BaseModel):
    peer_id: str
    vpn_name: str
    ip_address: str
    public_key: str
    private_key: Optional[str] = None
    persistent_keepalive: int
    allowed_ips: str
    tags: list[str]


class DynamoDb(InMemoryDataStore):
    """
    This wraps around the InMemoryDataStore class and uses DynamoDB as the backend.  It will fetch all the Wireguard
    servers and their peers during startup and store it in memory.  Requests for data from the DB will use the in-memory
    datastore.  Changes made to the DB will first be done to DynamoDB and then to the in-memory datastore.
    """

    def __init__(self, environment: Environment, dynamodb_endpoint_url: str, aws_region: str = "us-west-2"):
        super().__init__()
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
        self._init_vpn_from_db()
        self._init_peers_from_db()

    def _init_vpn_from_db(self):
        """Get existing VPNs from DynamoDb and add them to the in-memory datastore."""
        all_vpns = self.get_all_vpns()
        for vpn in all_vpns:
            self._vpn_networks[vpn.name] = vpn
            self._vpn_peers[vpn.name] = []

    def _init_peers_from_db(self):
        """Get existing Peers from DynamoDb and add them to the in-memory datastore."""
        self._vpn_peers = self.get_all_peers()

    def get_all_vpns(self) -> list[VpnModel]:
        """Get all VPN networks from the database."""
        response = self.vpn_table.scan()
        data = response["Items"]
        while "LastEvaluatedKey" in response:
            response = self.vpn_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            data.extend(response["Items"])

        all_vpns = []
        for dynamo_vpn in data:
            connection_info = build_connection_model(dynamo_vpn["connection_info"])
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

    def get_all_peers(self) -> dict[str, list[PeerDbModel]]:
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

    def add_vpn(self, new_vpn: VpnServer):
        """Add a new VPN network to the database.  If it already exists, raise a ValueError exception."""
        vpn_dynamo = VpnDynamoModel(
            name=new_vpn.name,
            description=new_vpn.description,
            wireguard_ip_address=new_vpn.ip_address,
            wireguard_ip_network=new_vpn.ip_network,
            wireguard_interface=new_vpn.interface,
            wireguard_public_key=new_vpn.public_key,
            wireguard_private_key=new_vpn.private_key,
            wireguard_listen_port=new_vpn.listen_port,
            connection_info=new_vpn.connection_info.model_dump() if new_vpn.connection_info else None,
        )
        if new_vpn.connection_info is not None and new_vpn.connection_info.type == ConnectionType.SSH:
            # Get the secret value for the SSH key and password
            vpn_dynamo.connection_info["data"]["key"] = new_vpn.connection_info.data.key
            if new_vpn.connection_info.data.key_password is not None:
                vpn_dynamo.connection_info["data"]["key_password"] = new_vpn.connection_info.data.key_password

        response = self.vpn_table.put_item(Item=vpn_dynamo.model_dump())
        # TODO: Handle failure response
        super().add_vpn(new_vpn)

    def delete_vpn(self, name: str):
        """Remove a VPN network from the database."""
        response = self.vpn_table.delete_item(Key={"name": name})
        # TODO: Handle failure response
        super().delete_vpn(name)

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
        response = self.peer_table.put_item(Item=peer_dynamo.dict())
        # TODO: Handle failure response
        super().add_peer(vpn_name, peer)

    def delete_peer(self, vpn_name: str, peer: PeerDbModel):
        response = self.peer_table.delete_item(Key={"peer_id": peer.peer_id})
        # TODO: Handle failure response
        super().delete_peer(vpn_name, peer)

    def add_tag_to_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Add a tag to a peer."""
        peer = self.get_peer(vpn_name, peer_ip)
        if peer is not None and tag not in peer.tags:
            super().add_tag_to_peer(vpn_name, peer_ip, tag)
            response = self.peer_table.update_item(
                Key={"peer_id": peer.peer_id},
                UpdateExpression="set tags=:newTags",
                ExpressionAttributeValues={":newTags": peer.tags},
                ReturnValues="UPDATED_NEW",
            )
            # TODO: Handle failure response

    def delete_tag_from_peer(self, vpn_name: str, peer_ip: str, tag: str):
        """Delete tag from a peer."""
        peer = self.get_peer(vpn_name, peer_ip)
        if peer is not None and tag in peer.tags:
            super().delete_tag_from_peer(vpn_name, peer_ip, tag)
            response = self.peer_table.update_item(
                Key={"peer_id": peer.peer_id},
                UpdateExpression="set tags=:newTags",
                ExpressionAttributeValues={":newTags": peer.tags},
                ReturnValues="UPDATED_NEW",
            )
            # TODO: Handle failure response

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

        super().update_connection_info(vpn_name, connection_info)
        response = self.vpn_table.update_item(
            Key={"name": vpn_name},
            UpdateExpression="set connection_info=:newConnectionInfo",
            ExpressionAttributeValues={":newConnectionInfo": connection_info_dict},
            ReturnValues="UPDATED_NEW",
        )
        # TODO: Handle failure response
