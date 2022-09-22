from fastapi import APIRouter, Response, HTTPException
from http import HTTPStatus
from srv_manager.ssh import get_vpn_config, extract_wg_server_config, VpnModel, VpnRequestModel


class VpnAPIRouter(APIRouter):
    """
    An extension to the base FastAPI router, that adds a params_manager property. It is expected that you set
    this property at app startup, so that the endpoints within the router will have access to the ParamsManager.
    """

    def __init__(self):
        super().__init__()
        self._ssh_key_path = None

    @property
    def ssh_key_path(self):
        if self._ssh_key_path is None:
            raise Exception("ssh_key_path has not been configured in APIRouter, set it before use")
        else:
            return self._ssh_key_path

    @ssh_key_path.setter
    def ssh_key_path(self, value: str):
        self._ssh_key_path = value


vpn_router = VpnAPIRouter()


@vpn_router.post("/v1/vpn", tags=["wg-manager"])
def new_vpn(vpn: VpnRequestModel) -> Response:
    # TODO: Check if the VPN already exists
    wg_config = get_vpn_config(vpn, vpn_router.ssh_key_path)
    result = extract_wg_server_config(wg_config, vpn)
    if not result:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=f"Unable to connect to the WireGuard server {vpn.name} via SSH"
        )
    print(str(result))
    return Response(status_code=HTTPStatus.OK)
