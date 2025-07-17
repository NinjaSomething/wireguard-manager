from pydantic import BaseModel, PrivateAttr


class OpaqueModel(BaseModel):
    """
    This is a shared model for anything that uses SecretStr.  It can be used to automate whether the secret is visible.
    """

    _opaque: bool = PrivateAttr(default=True)

    @property
    def opaque(self):
        return self._opaque

    @opaque.setter
    def opaque(self, value: bool) -> None:
        # here you can implement custom logic, like propagating to children models for example (my case)
        self._opaque = value
