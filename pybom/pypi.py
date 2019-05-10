import re
import requests


PYPI_UNREACHABLE = "Could not reach PyPI"
NO_PYPI_PACKAGE = "Package not found on PyPI"
NO_LICENSE = "License not found"


_version_matcher = re.compile(r"\d.*$")


def _extract_version(requirement: str) -> str:
    """Given a requirement in the form '= 1.2.3', extract the version.
    """

    return _version_matcher.search(requirement).group()


def _get_package_info(name: str, version: str) -> dict:
    """Get package information from PyPI. If no version is specified,
    the information will be for the latest version."""
    package_url_segments = ["https://pypi.org/pypi", name]

    if version is not None:
        package_url_segments.append(version)

    package_url_segments.append("json")

    url = "/".join(package_url_segments)

    response = requests.get(url)

    if response.status_code == 404:
        return None

    return response.json()


def get_package_license(name: str, version_requirement: str):
    """Get package license from the PyPI API. Returns str or None.

    Package is chosen from package data with the following order of priority:
    1. The license specified in the package's metadata (.info.license)
    2. The license(s) specified in the package's classifier (see https://pypi.org/classifiers/)
    3. None (if no license could be found)
    TODO: Update these ^^
    """
    try:
        package_info = _get_package_info(name, _extract_version(version_requirement))
    except ConnectionError as e:
        raise ConnectionError(PYPI_UNREACHABLE) from e

    # todo: sort out cases for this. package DNE, license not listed, or license.
    if package_info is None:
        return NO_PYPI_PACKAGE
    if package_info["info"]["license"] == "":
        return _license_str_from_classifiers(package_info["info"]["classifiers"])
    else:
        return package_info["info"]["license"]


def _license_str_from_classifiers(classifiers: list):
    """Returns str or None"""

    license_classifiers = [
        c.replace("License :: ", "") for c in classifiers if c.startswith("License")
    ]

    return ", ".join(license_classifiers) if len(license_classifiers) else NO_LICENSE
