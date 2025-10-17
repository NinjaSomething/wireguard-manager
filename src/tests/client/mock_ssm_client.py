from unittest.mock import MagicMock

from models.wg_server import WgServerModel, WgServerPeerModel
from tests.client.mock_client import MockCommand
import parse


class MockSsmCommand(MockCommand):
    """
    This will mock out the behaviour of the exec_command method for testing purposes.
    """

    def __init__(self, server: WgServerModel, peers: list[WgServerPeerModel] = None):
        super().__init__(server, peers)
        self.standard_output_content = MagicMock()
        self.standard_error_content = MagicMock()
        self.cmd = None

    def send_command(
        self, InstanceIds: list[str], DocumentName: str, Parameters: dict[str : list[str]], TimeoutSeconds: int
    ):
        self.cmd = Parameters["commands"][0]
        return {"Command": {"CommandId": "mock-cmd-id"}}

    def command(self, CommandId: str, InstanceId=str, PluginName=str):
        return_dict = {}
        if f"wg show " in self.cmd:
            if "dump" in self.cmd:
                dump_dict = parse.parse("sudo wg show {wg_interface} dump", self.cmd)
            elif "public-key" in self.cmd:
                dump_dict = parse.parse("sudo wg show {wg_interface} public-key", self.cmd)
            else:
                raise Exception(f"Unknown wg show command: {self.cmd}")

            if dump_dict["wg_interface"] == self._server.interface:
                if "dump" in self.cmd:
                    self.standard_output_content.splitlines.return_value = self._dump()
                else:
                    self.standard_output_content.splitlines.return_value = self._show_public_key()
                return_dict["StandardOutputContent"] = self.standard_output_content
                return_dict["Status"] = "Success"
            else:
                # This simulates trying to dump an interface that does not exist.
                self.standard_error_content = "Error: Interface not found"
                return_dict["StandardErrorContent"] = self.standard_error_content
                return_dict["StandardOutputContent"] = self.standard_output_content
                return_dict["Status"] = "Failed"
        elif "remove" in self.cmd and "wg set" in self.cmd:
            self._remove_peer(self.cmd)
            return_dict["StandardOutputContent"] = ""
            return_dict["Status"] = "Success"
        elif "wg set" in self.cmd:
            self._add_peer(self.cmd)
            return_dict["StandardOutputContent"] = ""
            return_dict["Status"] = "Success"
        return return_dict
