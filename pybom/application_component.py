from pybom.application_layer import ApplicationLayer


class ApplicationComponent:
    """
    A component of the application, either a python package or component
    identified in a docker image.
    """

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, f"_{k}", v)

    @property
    def name(self) -> str:
        return self._name

    @property
    def project(self):
        return self._project

    @property
    def package_manager(self):
        return self._package_manager

    @property
    def version(self) -> str:
        return self._version

    @property
    def layer(self) -> ApplicationLayer:
        return self._layer

    @property
    def license(self) -> str:
        return self._license

    @property
    def vulnerability_count(self):
        return self._vulnerability_count
