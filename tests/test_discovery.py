import json
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from conftest import b64d

from andromeda_agent_auth import (
    AgentAuth,
    AuthorizationServer,
    DiscoveryError,
    cli,
    discover_authorization_server,
    discover_token_endpoint,
    keys,
)

GATEWAY = "https://acme.mcp.example.com"
ISSUER = "https://api.example.com"
TOKEN_URL = "https://api.example.com/oauth/token"


def gateway_metadata(resource=GATEWAY, servers=(ISSUER,)):
    return httpx.Response(200, json={"resource": resource, "authorization_servers": list(servers)})


def server_metadata(issuer=ISSUER, **extra):
    body = {
        "issuer": issuer,
        "token_endpoint": TOKEN_URL,
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
    }
    body.update(extra)
    return httpx.Response(200, json=body)


@respx.mock
def test_gateway_to_token_endpoint():
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata())
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server").mock(return_value=server_metadata())
    assert discover_token_endpoint(GATEWAY) == TOKEN_URL
    assert discover_token_endpoint(GATEWAY + "/") == TOKEN_URL


@respx.mock
def test_well_known_goes_between_host_and_path():
    resource = f"{GATEWAY}/mcp"
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource/mcp").mock(return_value=gateway_metadata(resource))
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server").mock(return_value=server_metadata())
    assert discover_token_endpoint(resource) == TOKEN_URL


@respx.mock
def test_root_metadata_when_given_the_mcp_endpoint():
    # The gateway serves its metadata only at its root, for the origin.
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource/mcp").mock(return_value=httpx.Response(405))
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata())
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server").mock(return_value=server_metadata())
    assert discover_token_endpoint(f"{GATEWAY}/mcp") == TOKEN_URL


@respx.mock
def test_omitted_support_lists_mean_their_defaults():
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata())
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server").mock(
        return_value=httpx.Response(200, json={"issuer": ISSUER, "token_endpoint": TOKEN_URL})
    )
    with pytest.raises(DiscoveryError, match="client_credentials"):
        discover_token_endpoint(GATEWAY)


@respx.mock
def test_metadata_for_another_resource_is_refused():
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata("https://other.example.com"))
    with pytest.raises(DiscoveryError, match="not 'https://acme.mcp.example.com'"):
        discover_token_endpoint(GATEWAY)


@respx.mock
def test_metadata_for_another_issuer_is_refused():
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata())
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server").mock(
        return_value=server_metadata(issuer="https://evil.example.com")
    )
    with pytest.raises(DiscoveryError, match="is for 'https://evil.example.com'"):
        discover_token_endpoint(GATEWAY)


@respx.mock
def test_server_that_does_not_take_private_key_jwt_is_refused():
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata())
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server").mock(
        return_value=server_metadata(token_endpoint_auth_methods_supported=["client_secret_basic"])
    )
    with pytest.raises(DiscoveryError, match="private_key_jwt"):
        discover_token_endpoint(GATEWAY)


@respx.mock
def test_openid_configuration_is_the_fallback():
    issuer = f"{ISSUER}/tenant"
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata(servers=[issuer]))
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server/tenant").mock(return_value=httpx.Response(404))
    respx.get(f"{issuer}/.well-known/openid-configuration").mock(return_value=server_metadata(issuer=issuer))
    assert discover_token_endpoint(GATEWAY) == TOKEN_URL


@respx.mock
def test_redirects_are_not_followed():
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.example.com/prm"})
    )
    with pytest.raises(DiscoveryError, match="answered 302"):
        discover_token_endpoint(GATEWAY)


@pytest.mark.parametrize(
    "resource",
    ["http://acme.mcp.example.com", "ftp://acme.mcp.example.com", "acme.mcp.example.com", f"{GATEWAY}#frag"],
)
def test_resource_must_be_https(resource):
    with pytest.raises(DiscoveryError):
        discover_token_endpoint(resource)


@respx.mock
def test_plain_http_only_on_loopback():
    respx.get("http://localhost:18180/.well-known/oauth-protected-resource").mock(
        return_value=gateway_metadata("http://localhost:18180", servers=["http://localhost:8080"])
    )
    respx.get("http://localhost:8080/.well-known/oauth-authorization-server").mock(
        return_value=server_metadata(issuer="http://localhost:8080", token_endpoint="http://localhost:8080/oauth/token")
    )
    assert discover_token_endpoint("http://localhost:18180") == "http://localhost:8080/oauth/token"


@respx.mock
def test_for_resource_sends_the_resource_to_the_discovered_endpoint():
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata())
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server").mock(return_value=server_metadata())
    token_route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "token_type": "DPoP", "expires_in": 3600})
    )
    auth = AgentAuth.for_resource("https://agents.example/bot.json", GATEWAY, keys.generate("EdDSA"))
    assert str(auth.token_url) == TOKEN_URL and auth.resource == GATEWAY
    assert auth.fetch_token().access_token == "tok"
    assert parse_qs(token_route.calls.last.request.content.decode())["resource"] == [GATEWAY]


@respx.mock
def test_cli_token_without_token_url(tmp_path, capsys):
    key_file = tmp_path / "agent-key.pem"
    key_file.write_bytes(keys.generate("EdDSA").private_pem())
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata())
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server").mock(return_value=server_metadata())
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "tok", "token_type": "Bearer"}))
    code = cli.main(["token", "--client-id", "https://agents.example/bot.json", "--key", str(key_file), "--resource", GATEWAY])
    out = capsys.readouterr()
    assert code == 0, out.err
    assert json.loads(out.out)["access_token"] == "tok"
    assert f"token endpoint: {TOKEN_URL}" in out.err


def test_cli_token_needs_a_token_url_or_a_resource(tmp_path, capsys):
    key_file = tmp_path / "agent-key.pem"
    key_file.write_bytes(keys.generate("EdDSA").private_pem())
    assert cli.main(["token", "--client-id", "client-1", "--key", str(key_file)]) == 2
    assert "--resource" in capsys.readouterr().err


GATEWAY_ISSUER = "https://api.example.com/oauth/gateway/acme.mcp.example.com"
GATEWAY_TOKEN_URL = f"{GATEWAY_ISSUER}/token"


def mock_gateway_issuer():
    respx.get(f"{GATEWAY}/.well-known/oauth-protected-resource").mock(return_value=gateway_metadata(servers=[GATEWAY_ISSUER]))
    respx.get(f"{ISSUER}/.well-known/oauth-authorization-server/oauth/gateway/acme.mcp.example.com").mock(
        return_value=server_metadata(issuer=GATEWAY_ISSUER, token_endpoint=GATEWAY_TOKEN_URL)
    )


@respx.mock
def test_a_gateway_issuer_is_found_at_its_path_inserted_metadata():
    mock_gateway_issuer()
    server = discover_authorization_server(GATEWAY)
    assert server == AuthorizationServer(issuer=GATEWAY_ISSUER, token_endpoint=GATEWAY_TOKEN_URL)
    assert discover_token_endpoint(GATEWAY) == GATEWAY_TOKEN_URL


def assertion_audience(request: httpx.Request) -> str:
    assertion = parse_qs(request.content.decode())["client_assertion"][0]
    return json.loads(b64d(assertion.split(".")[1]))["aud"]


@respx.mock
def test_for_resource_signs_the_assertion_for_the_issuer():
    mock_gateway_issuer()
    token_route = respx.post(GATEWAY_TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "token_type": "DPoP", "expires_in": 3600})
    )
    auth = AgentAuth.for_resource("client-1", GATEWAY, keys.generate("EdDSA"))
    auth.fetch_token()
    assert assertion_audience(token_route.calls.last.request) == GATEWAY_ISSUER

    explicit = AgentAuth.for_resource("client-1", GATEWAY, keys.generate("EdDSA"), audience=GATEWAY_TOKEN_URL)
    explicit.fetch_token()
    assert assertion_audience(token_route.calls.last.request) == GATEWAY_TOKEN_URL, "an explicit audience wins"


@respx.mock
def test_cli_token_signs_for_the_discovered_issuer(tmp_path, capsys):
    key_file = tmp_path / "agent-key.pem"
    key_file.write_bytes(keys.generate("EdDSA").private_pem())
    mock_gateway_issuer()
    token_route = respx.post(GATEWAY_TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "token_type": "Bearer"})
    )
    code = cli.main(["token", "--client-id", "client-1", "--key", str(key_file), "--resource", GATEWAY, "--no-dpop"])
    assert code == 0, capsys.readouterr().err
    assert assertion_audience(token_route.calls.last.request) == GATEWAY_ISSUER
