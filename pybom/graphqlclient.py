from six.moves import urllib
import json


class GraphQLClient:
    """
    Simple GraphQL client, based on: https://github.com/prisma/python-graphql-client
    Usage permitted under the above's included MIT license.
    """

    def __init__(self, endpoint: str):
        """
        """
        self.endpoint = endpoint
        self.token = None
        self.headername = None

    def execute(self, query, variables=None):
        return self._send(query, variables)

    def inject_token(self, token, headername="Authorization"):
        self.token = token
        self.headername = headername

    def include_header(self, headername, headervalue):
        """Include the given header in all requests sent by this client."""
        self.headers[headername] = headervalue

    def _send(self, query, variables):
        data = {"query": query, "variables": variables}

        # headers are specific to GitHub's vulnerability and dependency graph
        # connections which are in preview.
        headers = {
            "Accept": "application/vnd.github.hawkgirl-preview+json, "
            "application/vnd.github.vixen-preview",
            "Content-Type": "application/json",
        }

        if self.token is not None:
            headers[self.headername] = "bearer {}".format(self.token)

        req = urllib.request.Request(
            self.endpoint, json.dumps(data).encode("utf-8"), headers
        )

        try:
            response = urllib.request.urlopen(req)
            return response.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            print((e.read()))
            print("")
            raise e
