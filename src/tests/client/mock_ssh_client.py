import parse
from unittest.mock import MagicMock

from interfaces.peers import peer_router
from models.wg_server import WgServerModel, WgServerPeerModel
from tests.client.mock_client import MockCommand


class MockSshCommand(MockCommand):
    """
    This will mock out the behaviour of the exec_command method for testing purposes.
    """

    def __init__(self, server: WgServerModel, peers: list[WgServerPeerModel] = None):
        super().__init__(server, peers)
        self._connection_failure = False
        self.stdin = MagicMock()
        self.stdout = MagicMock()
        self.stderr = MagicMock()

    def command(self, command, bufsize=-1, timeout=None, get_pty=False, environment=None):
        self.stdout.channel.recv_exit_status.return_value = 0
        if f"wg show " in command and "dump" in command:
            dump_dict = parse.parse("sudo wg show {wg_interface} dump", command)
            if dump_dict["wg_interface"] == self._server.interface:
                self.stdout.readlines.return_value = self._dump()
            else:
                # This simulates trying to dump an interface that does not exist.
                self.stderr.readlines.return_value = ["Error: Interface not found"]
                self.stdout.readlines.return_value = []
                self.stdout.channel.recv_exit_status.return_value = 1
        elif "remove" in command and "wg set" in command:
            self._remove_peer(command)
        elif "wg set" in command:
            self._add_peer(command)
        return self.stdin, self.stdout, self.stderr
