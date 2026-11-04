"""Finding the token endpoint from the agent gateway's URL.

An agent that knows only the gateway it calls can find where to ask for
tokens the way an MCP client does: the gateway's protected resource metadata
(RFC 9728) names its authorization server, and that server's metadata
(RFC 8414) names its token endpoint.

    token_url = discover_token_endpoint("https://acme.mcp.example.com")

Each document is checked against what was asked for (RFC 9728 section 3.3,
RFC 8414 section 3.3), so metadata served for another resource or issuer is
never used. Redirects are not followed, and plain http is accepted only on a
loopback host.

An Andromeda gateway can name an issuer of its own, which an assertion made
for it names as the audience; discover_authorization_server returns the
issuer along with the token endpoint for that.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

PROTECTED_RESOURCE_WELL_KNOWN = "/.well-known/oauth-protected-resource"
AUTHORIZATION_SERVER_WELL_KNOWN = "/.well-known/oauth-authorization-server"
OPENID_CONFIGURATION_WELL_KNOWN = "/.well-known/openid-configuration"

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class DiscoveryError(Exception):
    """The gateway's or the authorization server's metadata could not be used."""


@dataclass(frozen=True)
class AuthorizationServer:
    """The authorization server that protects a gateway."""

    # Its issuer identifier (RFC 8414 section 2), the audience a client
    # assertion for it names (RFC 7523bis).
    issuer: str
    token_endpoint: str


def discover_token_endpoint(resource: str, *, client: httpx.Client | None = None, timeout: float = 10.0) -> str:
    """Return the token endpoint of the authorization server that protects
    resource, the agent gateway's URL (the value an agent sends as resource)."""
    return discover_authorization_server(resource, client=client, timeout=timeout).token_endpoint


def discover_authorization_server(
    resource: str, *, client: httpx.Client | None = None, timeout: float = 10.0
) -> AuthorizationServer:
    """Return the issuer and token endpoint of the authorization server that
    protects resource, the agent gateway's URL.

    When the gateway's metadata names several authorization servers, the first
    is used."""
    resource_url = _checked_url(resource, "resource")
    owned = client is None
    client = client or httpx.Client(timeout=timeout)
    try:
        expected = resource
        try:
            prm = _get_json(client, _well_known(resource_url, PROTECTED_RESOURCE_WELL_KNOWN))
        except _NotFound:
            # A gateway that serves its metadata only at its root, for the
            # origin, as MCP clients fall back to when given an endpoint URL.
            if not resource_url.path.strip("/"):
                raise
            origin = resource_url.copy_with(path="/", query=None)
            expected = str(origin).rstrip("/")
            prm = _get_json(client, _well_known(origin, PROTECTED_RESOURCE_WELL_KNOWN))
        if _strip_slash(str(prm.get("resource", ""))) != _strip_slash(expected):
            raise DiscoveryError(f"the gateway's metadata is for {prm.get('resource')!r}, not {expected!r}")
        servers = prm.get("authorization_servers")
        if not isinstance(servers, list) or not servers or not isinstance(servers[0], str):
            raise DiscoveryError("the gateway's metadata names no authorization server")
        issuer = servers[0]
        issuer_url = _checked_url(issuer, "authorization server")

        metadata = _authorization_server_metadata(client, issuer_url)
        if _strip_slash(str(metadata.get("issuer", ""))) != _strip_slash(issuer):
            raise DiscoveryError(f"the authorization server's metadata is for {metadata.get('issuer')!r}, not {issuer!r}")
        # RFC 8414 section 2: an omitted list means its default, which names
        # neither of these.
        _require_supported(metadata, "grant_types_supported", "client_credentials", ["authorization_code", "implicit"])
        _require_supported(metadata, "token_endpoint_auth_methods_supported", "private_key_jwt", ["client_secret_basic"])
        token_endpoint = metadata.get("token_endpoint")
        if not isinstance(token_endpoint, str) or not token_endpoint:
            raise DiscoveryError("the authorization server's metadata names no token_endpoint")
        _checked_url(token_endpoint, "token_endpoint")
        return AuthorizationServer(issuer=str(metadata["issuer"]), token_endpoint=token_endpoint)
    finally:
        if owned:
            client.close()


def _authorization_server_metadata(client: httpx.Client, issuer: httpx.URL) -> dict:
    """RFC 8414 metadata, or OpenID Connect discovery for a server that only
    serves that."""
    try:
        return _get_json(client, _well_known(issuer, AUTHORIZATION_SERVER_WELL_KNOWN))
    except _NotFound:
        path = issuer.path.rstrip("/")
        return _get_json(client, issuer.copy_with(path=path + OPENID_CONFIGURATION_WELL_KNOWN, query=None))


class _NotFound(DiscoveryError):
    pass


def _well_known(url: httpx.URL, suffix: str) -> httpx.URL:
    """The well-known URL for url: suffix goes between the host and the path
    (RFC 9728 section 3.1, RFC 8414 section 3.1)."""
    path = url.path.rstrip("/")
    return url.copy_with(path=suffix + path if path else suffix)


def _get_json(client: httpx.Client, url: httpx.URL) -> dict:
    try:
        response = client.get(url, headers={"Accept": "application/json"}, follow_redirects=False)
    except httpx.HTTPError as e:
        raise DiscoveryError(f"fetching {url}: {e}") from e
    if response.status_code in (404, 405):
        raise _NotFound(f"{url} answered {response.status_code}")
    if response.status_code != 200:
        raise DiscoveryError(f"{url} answered {response.status_code}")
    try:
        body = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise DiscoveryError(f"{url} is not JSON") from e
    if not isinstance(body, dict):
        raise DiscoveryError(f"{url} is not a JSON object")
    return body


def _checked_url(value: str, what: str) -> httpx.URL:
    try:
        url = httpx.URL(value)
    except httpx.InvalidURL as e:
        raise DiscoveryError(f"{what} {value!r} is not a URL") from e
    if url.scheme not in ("https", "http") or not url.host or url.fragment:
        raise DiscoveryError(f"{what} {value!r} must be an absolute https URL without a fragment")
    if url.scheme == "http" and url.host not in _LOOPBACK_HOSTS:
        raise DiscoveryError(f"{what} {value!r} must use https")
    return url


def _require_supported(metadata: dict, field: str, value: str, default: list[str]) -> None:
    listed = metadata.get(field, default)
    if not isinstance(listed, list) or value not in listed:
        raise DiscoveryError(f"the authorization server does not list {value} in {field}")


def _strip_slash(url: str) -> str:
    return url.removesuffix("/")
