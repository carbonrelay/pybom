import json
import os
import pytest
from unittest.mock import Mock

import pybom.github
from pybom.github import GITHUB_ENVVAR_NAME, github_token_from_environ, GithubClient


def test_github_token_from_environ_tokenexists():
    previous_envvar = None
    if os.environ.get(GITHUB_ENVVAR_NAME) is not None:
        previous_envvar = os.environ[GITHUB_ENVVAR_NAME]

    token_val = "githubtoken"
    os.environ[GITHUB_ENVVAR_NAME] = token_val
    token = github_token_from_environ()

    assert token == token_val

    if previous_envvar is not None:
        os.environ[GITHUB_ENVVAR_NAME] = previous_envvar


def test_github_token_from_environ_notoken():
    previous_envvar = None
    if os.environ.get(GITHUB_ENVVAR_NAME) is not None:
        previous_envvar = os.environ[GITHUB_ENVVAR_NAME]

    del os.environ[GITHUB_ENVVAR_NAME]

    with pytest.raises(EnvironmentError):
        github_token_from_environ()

    if previous_envvar is not None:
        os.environ[GITHUB_ENVVAR_NAME] = previous_envvar


def test_githubclient_get_repo_dependencies():
    client = GithubClient()
    client.gql_client = Mock()
    client.gql_client.execute.return_value = """
{
    "data": {
        "repository": {
            "dependencyGraphManifests": {
                "nodes": [
                    {
                        "dependenciesCount": 1,
                        "exceedsMaxSize": false,
                        "dependencies": {
                            "nodes": [
                                {
                                    "packageName": "jinja2",
                                    "packageManager": "PIP",
                                    "requirements": "= 2.10"
                                }
                            ]
                        }
                    }
                ]
            }
        }
    }
}
    """

    repo_name = "fakename"
    repo_owner = "fakeorg"

    query_vars = {"repository_name": repo_name, "repository_owner": repo_owner}

    result = client.get_repo_dependencies(repo_name, repo_owner)

    client.gql_client.execute.assert_called_with(
        pybom.github._repo_dependencies_query, json.dumps(query_vars)
    )

    assert type(result) is list
    assert len(result) == 1
    assert type(result[0]) is dict
    assert result[0]["name"] == "jinja2"


def test_githubclient_get_repo_vuln_alerts():
    client = GithubClient()
    client.gql_client = Mock()
    client.gql_client.execute.return_value = """
{
    "data": {
        "repository": {
            "vulnerabilityAlerts": {
                "nodes": [
                    {
                        "securityAdvisory": {
                            "identifiers": [
                                {
                                    "type": "GHSA",
                                    "value": "GHSA-462w-v97r-4m45"
                                },
                                {
                                    "type": "CVE",
                                    "value": "CVE-2019-10906"
                                }
                            ],
                            "summary": "High severity vulnerability that affects Jinja2",
                            "description": "In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.",
                            "severity": "HIGH",
                            "publishedAt": "2019-04-10T14:30:24Z",
                            "updatedAt": "2019-04-12T18:36:15Z"
                        },
                        "securityVulnerability": {
                            "package": {
                                "name": "Jinja2",
                                "ecosystem": "PIP"
                            },
                            "vulnerableVersionRange": "< 2.10.1"
                        },
                        "dismissedAt": null,
                        "vulnerableManifestPath": "requirements.txt",
                        "vulnerableRequirements": "= 2.10"
                    }
                ]
            }
        }
    }
}
    """

    repo_name = "fakename"
    repo_owner = "fakeorg"

    query_vars = {"repository_name": repo_name, "repository_owner": repo_owner}

    result = client.get_repo_vuln_alerts(repo_name, repo_owner)

    client.gql_client.execute.assert_called_with(
        pybom.github._repo_vulnerabilities_query, json.dumps(query_vars)
    )

    assert type(result) is list
    assert len(result) == 1
    assert type(result[0]) is dict
    assert result[0]["component_name"] == "Jinja2"


def test_githubclient_get_repo_dependencies_many():
    client = GithubClient()
    client.gql_client = Mock()
    client.gql_client.execute.return_value = """
{
    "data": {
        "repository": {
            "dependencyGraphManifests": {
                "nodes": [
                    {
                        "dependenciesCount": 1,
                        "exceedsMaxSize": false,
                        "dependencies": {
                            "nodes": [
                                {
                                    "packageName": "jinja2",
                                    "packageManager": "PIP",
                                    "requirements": "= 2.10"
                                },
                                {
                                    "packageName": "urllib3",
                                    "packageManager": "PIP",
                                    "requirements": "= 1.23"
                                }
                            ]
                        }
                    }
                ]
            }
        }
    }
}
    """

    repo_name = "fakename"
    repo_owner = "fakeorg"

    query_vars = {"repository_name": repo_name, "repository_owner": repo_owner}

    result = client.get_repo_dependencies(repo_name, repo_owner)

    client.gql_client.execute.assert_called_with(
        pybom.github._repo_dependencies_query, json.dumps(query_vars)
    )

    assert type(result) is list
    assert len(result) == 2
    assert type(result[0]) is dict


def test_githubclient_get_repo_vuln_alerts_many():
    client = GithubClient()
    client.gql_client = Mock()
    client.gql_client.execute.return_value = """
{
    "data": {
        "repository": {
            "vulnerabilityAlerts": {
                "nodes": [
                    {
                        "securityAdvisory": {
                            "identifiers": [
                                {
                                    "type": "GHSA",
                                    "value": "GHSA-462w-v97r-4m45"
                                },
                                {
                                    "type": "CVE",
                                    "value": "CVE-2019-10906"
                                }
                            ],
                            "summary": "High severity vulnerability that affects Jinja2",
                            "description": "In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.",
                            "severity": "HIGH",
                            "publishedAt": "2019-04-10T14:30:24Z",
                            "updatedAt": "2019-04-12T18:36:15Z"
                        },
                        "securityVulnerability": {
                            "package": {
                                "name": "Jinja2",
                                "ecosystem": "PIP"
                            },
                            "vulnerableVersionRange": "< 2.10.1"
                        },
                        "dismissedAt": null,
                        "vulnerableManifestPath": "requirements.txt",
                        "vulnerableRequirements": "= 2.10"
                    },
                    {
                        "securityAdvisory": {
                            "identifiers": [
                                {
                                    "type": "GHSA",
                                    "value": "GHSA-mh33-7rrq-662w"
                                },
                                {
                                    "type": "CVE",
                                    "value": "CVE-2019-11324"
                                }
                            ],
                            "summary": "High severity vulnerability that affects urllib3",
                            "description": "The urllib3 library before 1.24.2 for Python mishandles certain cases where the desired set of CA certificates is different from the OS store of CA certificates, which results in SSL connections succeeding in situations where a verification failure is the correct outcome. This is related to use of the ssl_context, ca_certs, or ca_certs_dir argument.",
                            "severity": "HIGH",
                            "publishedAt": "2019-04-19T16:55:10Z",
                            "updatedAt": "2019-04-19T16:55:10Z"
                        },
                        "securityVulnerability": {
                            "package": {
                                "name": "urllib3",
                                "ecosystem": "PIP"
                            },
                            "vulnerableVersionRange": "< 1.24.2"
                        },
                        "dismissedAt": null,
                        "vulnerableManifestPath": "requirements.txt",
                        "vulnerableRequirements": "= 1.23"
                    }
                ]
            }
        }
    }
}
    """

    repo_name = "fakename"
    repo_owner = "fakeorg"

    query_vars = {"repository_name": repo_name, "repository_owner": repo_owner}

    result = client.get_repo_vuln_alerts(repo_name, repo_owner)

    client.gql_client.execute.assert_called_with(
        pybom.github._repo_vulnerabilities_query, json.dumps(query_vars)
    )

    assert type(result) is list
    assert len(result) == 2
    assert type(result[0]) is dict
