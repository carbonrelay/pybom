from typing import List

from pybom.application_component import ApplicationComponent
from pybom.application_layer import ApplicationLayer
from pybom.github import GithubClient
from pybom.pypi import get_package_license
from pybom.vulnerability import Vulnerability


def get_components(repo_name: str, owner: str) -> List[ApplicationComponent]:
    """Get a list of python packages used in the specified repository."""
    client = GithubClient()
    dependencies = client.get_repo_dependencies(repo_name, owner)
    for d in dependencies:
        d["license"] = get_package_license(d["name"], d["version"])
        d["layer"] = ApplicationLayer.PYTHON_DEPENDENCY

    return [ApplicationComponent(**d) for d in dependencies]


def get_vulnerabilities(repo_name: str, owner: str) -> List[Vulnerability]:
    """Get a list of vulnerabilities detected in this repository's dependencies.
    """
    client = GithubClient()
    vulnerabilities = client.get_repo_vulnerabilities(repo_name, owner)

    for v in vulnerabilities:
        v["project"] = repo_name

    return [Vulnerability(**v) for v in vulnerabilities]
