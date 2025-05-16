from fastapi import APIRouter


class WgAPIRouter(APIRouter):
    """
    An extension to the base FastAPI router, that adds a params_manager property. It is expected that you set
    this property at app startup, so that the endpoints within the router will have access to the ParamsManager.
    """

    def __init__(self):
        super().__init__()
        self._vpn_manager = None

    @property
    def vpn_manager(self):
        if self._vpn_manager is None:
            raise Exception("vpn_manager has not been configured in APIRouter, set it before use")
        else:
            return self._vpn_manager

    @vpn_manager.setter
    def vpn_manager(self, value):
        self._vpn_manager = value
