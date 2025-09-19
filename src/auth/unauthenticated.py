from fastapi import Depends, FastAPI, Request


class WireguardManagerAPI(FastAPI):

    def __init__(self, **kwargs):
        """
        Instantiate the FastAPI app, passing in any kwargs to the
        FastAPI constructor.
        """
        if "dependencies" in kwargs:
            dependencies = kwargs.pop("dependencies")
            dependencies.append(Depends(self._set_user_state))
        else:
            dependencies = [Depends(self._set_user_state)]

        super().__init__(
            openapi_url="/spec",
            title="Wireguard Manager",
            description="API for managing wireguard clients",
            dependencies=dependencies,
            **kwargs
        )

    def _set_user_state(self, request: Request):
        """Set the user state to unauthenticated if not already set."""
        if not hasattr(request.state, "user"):
            request.state.user = "unauthenticated"
