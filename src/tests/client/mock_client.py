import parse

from models.wg_server import WgServerModel, WgServerPeerModel


class MockCommand:
    """
    This module contains the generic mocks that allow the behaviour of the commanding method for testing purposes.  Specifically, it will
    simulate adding/removing a peer from the WireGuard server, and dumping the WireGuard configuration in the expected
    format.
    """

    def __init__(self, server: WgServerModel, peers: list[WgServerPeerModel]):
        self._server = server
        self._peers = peers or []

    @property
    def server(self) -> WgServerModel:
        return self._server

    @server.setter
    def server(self, value: WgServerModel):
        """This allows the test to change the server model to something different if needed."""
        self._server = value

    def _dump(self):
        """
        The following defines the dump format:
        Several lines are returned; the first contains in order separated by tab:
          private-key, public-key, listen-port, fwmark.

        Subsequent lines are printed for each peer and contain in order separated by tab:
          public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx,
          persistent-keepalive.
        """
        return_value = [
            f"{self._server.private_key.get_secret_value()}\t{self._server.public_key}\t{self._server.listen_port}\t{self._server.fw_mark}"
        ]
        for peer in self._peers:
            return_value.append(
                f"{peer.public_key}\t{peer.preshared_key or '(none)'}\t{peer.endpoint or '(none)'}\t{peer.wg_ip_address}\t{peer.latest_handshake}\t{peer.transfer_rx}\t{peer.transfer_tx}\t{peer.persistent_keepalive}"
            )
        return return_value

    def _add_peer(self, command: str):
        """
        This will add a new peer to the mock WireGuard server.
        """
        add_dict = parse.parse(
            "sudo wg set {interface} peer {public_key} persistent-keepalive {persistent_keepalive} allowed-ips {ip_address} && sudo wg-quick save wg0",
            command,
        )
        if add_dict:
            self._peers.append(
                WgServerPeerModel(
                    public_key=add_dict["public_key"],
                    persistent_keepalive=add_dict["persistent_keepalive"],
                    wg_ip_address=add_dict["ip_address"],
                    preshared_key=None,
                    endpoint="(none)",
                    latest_handshake=0,
                    transfer_rx=0,
                    transfer_tx=0,
                )
            )

    def _remove_peer(self, command: str):
        """
        This will remove a peer from the mock WireGuard server.
        """
        rm_dict = parse.parse("sudo wg set {interface} peer {public_key} remove && sudo wg-quick save wg0", command)
        if rm_dict:
            remove_peer = None
            for peer in self._peers:
                if rm_dict["public_key"] == peer.public_key:
                    remove_peer = peer
                    break
            if remove_peer:
                self._peers.remove(remove_peer)
