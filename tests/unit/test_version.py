"""Tests fuer die zentrale Anwendungsversion."""

import tomllib

from app.api.routes_version import version as version_endpoint
from app.utils.version import PYPROJECT, get_app_version


def test_version_endpoint_uses_pyproject_version() -> None:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    get_app_version.cache_clear()

    response = version_endpoint()

    assert response["name"] == project["name"]
    assert response["version"] == project["version"]
