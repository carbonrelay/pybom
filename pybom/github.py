"""Code for interacting with the GitHub GraphQL API.

This is separate from repository.py in case other git providers are
added in the future.
"""
import json
import os

from pybom.graphqlclient import GraphQLClient

GITHUB_ENVVAR_NAME = "GITHUB_PERSONAL_ACCESS_TOKEN"
GITHUB_API_ENDPOINT = "https://api.github.com/graphql"

_repo_vulnerabilities_query = """
query RepositoryVulnerabilities($repository_owner: String!, $repository_name: String!) {
    repository(owner: $repository_owner, name: $repository_name) {
        vulnerabilityAlerts(first:100) {
            nodes {
                securityAdvisory {
                    identifiers {
                        type
                        value
                    }
                    summary
                    description
                    severity
                    publishedAt
                    updatedAt
                }
                securityVulnerability {
                    package {
                        name
                        ecosystem
                    }
                    vulnerableVersionRange
                }
                dismissedAt
                vulnerableManifestPath
                vulnerableRequirements
            }
        }
    }
}
"""
# todo: add checks to get all pages. pass in as graphql variable?


_repo_dependencies_query = """
query RepositoryDependencies($repository_owner: String!, $repository_name: String!) {
    repository(owner: $repository_owner, name: $repository_name) {
        dependencyGraphManifests(first: 100) {
            nodes {
                dependenciesCount
                exceedsMaxSize
                dependencies(first: 100) {
                    nodes {
                        packageName
                        packageManager
                        requirements
                    }
                }
            }
        }
    }
}
"""


def github_token_from_environ() -> str:
    token = os.environ.get(GITHUB_ENVVAR_NAME)
    if token is None:
        raise EnvironmentError(
            "Could not find environment variable {}. See ".format(GITHUB_ENVVAR_NAME)
            + "https://help.github.com/en/articles/creating-a-personal-access-token-"
            "for-the-command-line for instructions on creating a token. Create the "
            "token with Repo permissions and set it as an environment variable."
        )
    return token


class GithubClient:
    def __init__(self, github_pat: str = None):
        """Initialize with an optional Github Personal Access Token (PAT).

        If no PAT is specified, the client will check for environment variable
        GITHUB_PERSONAL_ACCESS_TOKEN. If this is not set, an exception is raised.
        """
        personal_access_token = (
            github_pat if github_pat else github_token_from_environ()
        )
        self.gql_client = GraphQLClient(GITHUB_API_ENDPOINT)
        self.gql_client.inject_token(personal_access_token)

    def get_repo_dependencies(self, repo_name: str, repo_owner: str):
        """Get all dependencies for a repository."""
        client = self.gql_client

        query_vars = {"repository_name": repo_name, "repository_owner": repo_owner}

        response = client.execute(_repo_dependencies_query, json.dumps(query_vars))

        r = json.loads(response)

        return [
            {
                "name": p["packageName"],
                "package_manager": p["packageManager"],
                "version": p["requirements"],
                "project": repo_name,
            }
            for p in r["data"]["repository"]["dependencyGraphManifests"]["nodes"][0][
                "dependencies"
            ]["nodes"]
            if p["packageManager"] == "PIP"
        ]

    def get_repo_vuln_alerts(self, repo_name: str, repo_owner: str):
        """Get all vulnerability alerts from Github for the given repository."""
        client = self.gql_client

        query_vars = {"repository_name": repo_name, "repository_owner": repo_owner}

        response = client.execute(_repo_vulnerabilities_query, json.dumps(query_vars))

        rj = json.loads(response)

        return [
            {
                "component_name": v["securityVulnerability"]["package"]["name"],
                "ecosystem": v["securityVulnerability"]["package"]["ecosystem"],
                "cve_id": next(
                    ident["value"]
                    for ident in v["securityAdvisory"]["identifiers"]
                    if ident["type"] == "CVE"
                ),
                "summary": v["securityAdvisory"]["summary"],
                "description": v["securityAdvisory"]["description"],
                "severity": v["securityAdvisory"]["severity"],
                "vulnerable_version_range": v["securityVulnerability"][
                    "vulnerableVersionRange"
                ],
                "vulnerable_manifest_path": v["vulnerableManifestPath"],
                "published_at": v["securityAdvisory"]["publishedAt"],
                "updated_at": v["securityAdvisory"]["updatedAt"],
            }
            for v in rj["data"]["repository"]["vulnerabilityAlerts"]["nodes"]
        ]
