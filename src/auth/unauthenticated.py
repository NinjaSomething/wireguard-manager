from fastapi import FastAPI


class WireguardAPI(FastAPI):

    def __init__(self, **kwargs):
        """
        Instantiate the FastAPI app, passing in any kwargs to the
        FastAPI constructor.
        """
        super().__init__(
            openapi_url="/spec", title="Wireguard Manager", description="API for managing wireguard clients", **kwargs
        )
