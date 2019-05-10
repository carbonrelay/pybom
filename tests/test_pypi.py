import pytest
from unittest.mock import Mock

import requests

from pybom.pypi import get_package_license, NO_PYPI_PACKAGE, PYPI_UNREACHABLE


def _raise_error(error):
    """Lambdas can only include expressions, and `raise` is a statement.
    Use this wrapper to raise exceptions from within a lambda.
    """
    raise error


def test_get_package_license_package_dne(monkeypatch):
    with monkeypatch.context() as m:
        mock_response = Mock()
        mock_response.status_code = 404
        m.setattr(requests, "get", lambda x: mock_response)

        assert get_package_license("abc", "1.2") == NO_PYPI_PACKAGE


def test_get_package_license_pypi_unreachable(monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(requests, "get", lambda x: _raise_error(ConnectionError))

        with pytest.raises(ConnectionError) as e:
            get_package_license("abc", "1.2")
            assert type(e) is ConnectionError
            assert e.value == PYPI_UNREACHABLE


def test_get_package_license_license_in_info():
    pass


def test_get_package_license_license_in_classifier():
    pass


def test_get_package_license_no_version():
    pass


def test_get_package_license_():
    pass
