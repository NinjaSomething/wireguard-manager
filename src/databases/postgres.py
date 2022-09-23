import psycopg2
from models.vpn import VpnDbModel, SshConnectionModel, PeerDbModel
from typing import List


class PgStuff:
    def __init__(self, host, port, user, password):
        self.host = host
        self.port = port
        self.user = user
        self.password = password

    def connect(self, db: str = None):
        # Connect to the database
        connection_string = (
            f"host={self.host} port={self.port} user={self.user} password={self.password} "
            f"options='-c statement_timeout=10s'"
        )
        if db is not None:
            connection_string += f" dbname={db}"
        conn = psycopg2.connect(connection_string)
        return conn

    def create_wg_vpn_table(self):
        conn = self.connect()
        cur = conn.cursor()
        # TODO: Update this!
        _query = (
            "CREATE SEQUENCE IF NOT EXISTS public.wg_vpn_id_seq "
            "    INCREMENT 1 "
            "    START 1 "
            "    MINVALUE 1 "
            "    MAXVALUE 2147483647 "
            "    CACHE 1; "
            "CREATE TABLE IF NOT EXISTS public.wg_vpn "
            "("
            "    id integer NOT NULL DEFAULT nextval('wg_vpn_id_seq'::regclass), "
            '    interface character varying(10) COLLATE pg_catalog."default" NOT NULL, '
            '    public_key character varying COLLATE pg_catalog."default" NOT NULL, '
            '    private_key character varying COLLATE pg_catalog."default", '
            "    listen_port integer NOT NULL, "
            '    name character varying COLLATE pg_catalog."default", '
            '    description character varying COLLATE pg_catalog."default", '
            '    wg_ip_address character varying(15) COLLATE pg_catalog."default" NOT NULL, '
            '    ssh_ip_address character varying(15) COLLATE pg_catalog."default" NOT NULL, '
            '    ssh_username character varying COLLATE pg_catalog."default" NOT NULL, '
            '    ssh_pem_filename character varying COLLATE pg_catalog."default" NOT NULL, '
            "    CONSTRAINT wg_vpn_pkey PRIMARY KEY (id) "
            ") "
            "TABLESPACE pg_default; "
            "ALTER SEQUENCE public.wg_vpn_id_seq "
            "   OWNED BY wg_vpn.id;"
            "ALTER SEQUENCE public.wg_vpn_id_seq "
            "   OWNER TO postgres;"
            "ALTER TABLE IF EXISTS public.wg_vpn "
            "    OWNER to postgres; "
        )
        cur.execute(_query)
        conn.commit()
        conn.close()
        print("Created wg_vpn table")

    def tables_exist(self):
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
        list_tables = cur.fetchall()
        conn.close()
        # Unpack the list of tuples
        list_tables = list(list_tables.pop())

        if "wg_vpn" not in list_tables:
            self.create_wg_vpn_table()

    def get_peers(self, wg_vpn_id: int) -> List[PeerDbModel]:
        conn = self.connect()
        cur = conn.cursor()
        # TODO: Protect against key injection
        f"  (, "
        f"   , wg_vpn_id) VALUES "
        query = (
            "SELECT wg_ip_address, public_key, private_key, preshared_key, persistent_keepalive, name, description, "
            "       machine_id "
            "FROM wg_peers "
            "WHERE "
            f"  wg_vpn_id = '{wg_vpn_id}' "
        )
        cur.execute(query)
        list_peers = cur.fetchall()
        conn.close()
        db_peers = []
        for peer in list_peers:
            db_peers.append(
                PeerDbModel(
                    wg_ip_address=peer[0],
                    public_key=peer[1],
                    private_key=peer[2],
                    preshared_key=peer[3],
                    persistent_keepalive=peer[4],
                    name=peer[5],
                    description=peer[6],
                    machine_id=peer[7],
                )
            )
        return db_peers

    def get_interfaces(self):
        conn = self.connect()
        cur = conn.cursor()
        query = (
            "SELECT interface, public_key, private_key, listen_port, name, description, wg_ip_address, "
            "       ssh_username, ssh_pem_filename, ssh_ip_address, id "
            "FROM wg_vpn "
        )
        cur.execute(query)
        list_interfaces = cur.fetchall()
        conn.close()
        vpn_models = []
        for interface in list_interfaces:
            vpn_model = VpnDbModel(
                interface=interface[0],
                public_key=interface[1],
                private_key=interface[2],
                listen_port=interface[3],
                name=interface[4],
                description=interface[5],
                wg_ip_address=interface[6],
                ssh_connection_info=SshConnectionModel(
                    ssh_username=interface[7], ssh_pem_filename=interface[8], ssh_ip_address=interface[9]
                ),
            )
            wg_vpn_id = interface[10]
            vpn_model.peers = self.get_peers(wg_vpn_id)
            vpn_models.append(vpn_model)
            # TODO: Get Peers
        return vpn_models

    def get_interface(self, name) -> VpnDbModel:
        conn = self.connect()
        cur = conn.cursor()
        # TODO: Protect against key injection
        query = (
            "SELECT interface, public_key, private_key, listen_port, name, description, wg_ip_address, "
            "       ssh_username, ssh_pem_filename, ssh_ip_address, id "
            "FROM wg_vpn "
            "WHERE "
            f"  name = '{name}' "
        )
        cur.execute(query)
        list_interfaces = cur.fetchall()
        conn.close()
        vpn_model = None
        for interface in list_interfaces:
            vpn_model = VpnDbModel(
                interface=interface[0],
                public_key=interface[1],
                private_key=interface[2],
                listen_port=interface[3],
                name=interface[4],
                description=interface[5],
                wg_ip_address=interface[6],
                ssh_connection_info=SshConnectionModel(
                    ssh_username=interface[7], ssh_pem_filename=interface[8], ssh_ip_address=interface[9]
                ),
            )
            wg_vpn_id = interface[10]
            vpn_model.peers = self.get_peers(wg_vpn_id)
        return vpn_model

    def add_peers(self, vpn_id, peers: List[PeerDbModel], cursor=None):
        conn = None
        if cursor is None:
            conn = self.connect()
            cursor = conn.cursor()

        # TODO: Protect against key injection
        # TODO: Don't write values that are None
        for peer in peers:
            query = (
                f"INSERT INTO wg_peers "
                f"  (wg_ip_address, public_key, private_key, preshared_key, persistent_keepalive, name, description, "
                f"   machine_id, wg_vpn_id) VALUES "
                f"  ('{peer.wg_ip_address}', '{peer.public_key}', '{peer.private_key}', '{peer.preshared_key}', "
                f"    {peer.persistent_keepalive}, '{peer.name}', '{peer.description}', '{peer.machine_id}', "
                f"    {vpn_id})"
            )
            cursor.execute(query)

        if conn is not None:
            conn.commit()

    def add_interface(self, new_vpn: VpnDbModel):
        conn = self.connect()
        cur = conn.cursor()
        # TODO: Protect against key injection
        # TODO: Don't write values that are None
        query = (
            f"INSERT INTO wg_vpn "
            f"  (interface, public_key, private_key, listen_port, name, description, ssh_ip_address, ssh_username, "
            f"   ssh_pem_filename, wg_ip_address) VALUES "
            f"  ('{new_vpn.interface}', '{new_vpn.public_key}', '{new_vpn.private_key}', '{new_vpn.listen_port}', "
            f"   '{new_vpn.name}', '{new_vpn.description}', '{new_vpn.ssh_connection_info.ssh_ip_address}', "
            f"   '{new_vpn.ssh_connection_info.ssh_username}', '{new_vpn.ssh_connection_info.ssh_pem_filename}', "
            f"   '{new_vpn.wg_ip_address}')"
            f"RETURNING wg_vpn.id"
        )
        cur.execute(query)
        vpn_id = cur.fetchone()[0]
        self.add_peers(vpn_id, new_vpn.peers, cur)
        conn.commit()
        conn.close()

    def update_interface(self, updated_vpn: VpnDbModel):
        conn = self.connect()
        cur = conn.cursor()
        # TODO: Protect against key injection
        # TODO: Don't write values that are None
        query = (
            f"UPDATE wg_vpn "
            f"SET "
            f"  name = '{updated_vpn.name}', "
            f"  description = '{updated_vpn.description}', "
            f"  public_key = '{updated_vpn.public_key}', "
            f"  private_key = '{updated_vpn.private_key}', "
            f"  listen_port = '{updated_vpn.listen_port}', "
            f"  ssh_ip_address = '{updated_vpn.ssh_connection_info.ssh_ip_address}', "
            f"  ssh_username = '{updated_vpn.ssh_connection_info.ssh_username}', "
            f"  ssh_pem_filename = '{updated_vpn.ssh_connection_info.ssh_pem_filename}', "
            f"  wg_ip_address = '{updated_vpn.wg_ip_address}'"
        )
        cur.execute(query)
        conn.commit()
        conn.close()

    def delete_interface(self, name: str):
        conn = self.connect()
        cur = conn.cursor()
        # TODO: Protect against key injection
        query = f"SELECT id from wg_vpn WHERE name = '{name}'"
        cur.execute(query)
        wg_vpn_id = cur.fetchone()[0]
        query = f"DELETE FROM wg_vpn WHERE name = '{name}' "
        cur.execute(query)
        query = f"DELETE FROM wg_peers WHERE wg_vpn_id = {wg_vpn_id}"
        cur.execute(query)
        conn.commit()
        conn.close()
