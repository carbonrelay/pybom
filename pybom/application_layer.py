from enum import Enum


class ApplicationLayer(Enum):
    """The parts of an application in which vulnerabilities can exist."""

    APPLICATION_CODE = 1
    PYTHON_DEPENDENCY = 2
    DOCKER_IMAGE = 3

    def __str__(self):
        return str.lower(self.name)
