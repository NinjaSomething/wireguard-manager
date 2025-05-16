import boto3
from typing import Optional
from pydantic import BaseModel
from models.vpn import VpnModel, WireguardRequestModel
from models.peers import PeerModel, PeerDbModel
from vpn_manager.vpn import VpnServer
from vpn_manager.ssh import SshConnectionModel
from databases.in_mem_db import InMemoryDataStore
from environment import Environment


class VpnDynamoModel(BaseModel):
    name: str
    description: str
    wireguard_ip_address: str
    wireguard_subnet: str
    wireguard_interface: str
    wireguard_public_key: str
    wireguard_private_key: str
    wireguard_listen_port: int
    ssh_ip_address: Optional[str] = None
    ssh_username: Optional[str] = None
    ssh_key: Optional[str] = None
    ssh_key_password: str | None


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
                dynamodb = boto3.resource("dynamodb", endpoint_url=dynamodb_endpoint_url)
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
        response = self.vpn_table.scan()
        data = response["Items"]
        while "LastEvaluatedKey" in response:
            response = self.vpn_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            data.extend(response["Items"])

        for dynamo_vpn in data:
            ssh_connection_info = None
            if all([dynamo_vpn["ssh_ip_address"], dynamo_vpn["ssh_username"], dynamo_vpn["ssh_key"]]):
                ssh_connection_info = SshConnectionModel(
                    ip_address=dynamo_vpn["ssh_ip_address"],
                    username=dynamo_vpn["ssh_username"],
                    key=dynamo_vpn["ssh_key"],
                    key_password=dynamo_vpn["ssh_key_password"],
                )
            vpn = VpnModel(
                name=dynamo_vpn["name"],
                description=dynamo_vpn["description"],
                wireguard=WireguardRequestModel(
                    ip_address=dynamo_vpn["wireguard_ip_address"],
                    address_space=dynamo_vpn["wireguard_subnet"],
                    interface=dynamo_vpn["wireguard_interface"],
                    public_key=dynamo_vpn["wireguard_public_key"],
                    private_key=dynamo_vpn["wireguard_private_key"],
                    listen_port=dynamo_vpn["wireguard_listen_port"],
                ),
                ssh_connection_info=ssh_connection_info,
            )
            self._vpn_networks["test"] = vpn
            self._vpn_peers[dynamo_vpn["name"]] = []

    def _init_peers_from_db(self):
        """Get existing Peers from DynamoDb and add them to the in-memory datastore."""
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

            if dynamo_peer["vpn_name"] not in self._vpn_peers:
                self._vpn_peers[dynamo_peer["vpn_name"]] = []
            self._vpn_peers[dynamo_peer["vpn_name"]].append(peer)

    def add_vpn(self, new_vpn: VpnServer):
        """Add a new VPN network to the database.  If it already exists, raise a ValueError exception."""
        vpn_dynamo = VpnDynamoModel(
            name=new_vpn.name,
            description=new_vpn.description,
            wireguard_ip_address=new_vpn.ip_address,
            wireguard_subnet=new_vpn.address_space,
            wireguard_interface=new_vpn.interface,
            wireguard_public_key=new_vpn.public_key,
            wireguard_private_key=new_vpn.private_key,
            wireguard_listen_port=new_vpn.listen_port,
            ssh_ip_address=new_vpn.ssh_connection_info.ip_address if new_vpn.ssh_connection_info else None,
            ssh_username=new_vpn.ssh_connection_info.username if new_vpn.ssh_connection_info else None,
            ssh_key=new_vpn.ssh_connection_info.key if new_vpn.ssh_connection_info else None,
            ssh_key_password=new_vpn.ssh_connection_info.key_password if new_vpn.ssh_connection_info else None,
        )
        response = self.vpn_table.put_item(Item=vpn_dynamo.dict())
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
            private_key=peer.private_key,
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
