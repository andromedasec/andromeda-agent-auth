import email.utils
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from conftest import verify_jws

from andromeda_agent_auth import AgentAuth, TokenError, keys
from andromeda_agent_auth.auth import CLIENT_ASSERTION_TYPE
from andromeda_agent_auth.jws import access_token_hash

TOKEN_URL = "https://api.example/oauth/token"
MCP_URL = "https://gw.example/mcp"


def bound(token="tok-1", expires_in=3600):
    return httpx.Response(200, json={"access_token": token, "token_type": "DPoP", "expires_in": expires_in})


@pytest.fixture
def client_key():
    return keys.generate("EdDSA")


def form(request: httpx.Request) -> dict:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


@respx.mock
def test_bound_token_and_proof_on_every_request(client_key):
    token_route = respx.post(TOKEN_URL).mock(return_value=bound())
    mcp_route = respx.post(MCP_URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    auth = AgentAuth("client-1", TOKEN_URL, client_key)

    with httpx.Client(auth=auth) as c:
        assert c.post(MCP_URL + "?session=a", json={"m": 1}).status_code == 200
        assert c.post(MCP_URL, json={"m": 2}).status_code == 200

    assert token_route.call_count == 1, "the token is reused until it nears expiry"
    token_req = token_route.calls[0].request
    body = form(token_req)
    assert body["grant_type"] == "client_credentials"
    assert body["client_assertion_type"] == CLIENT_ASSERTION_TYPE
    assert "client_secret" not in body
    header, claims = verify_jws(body["client_assertion"], client_key.public_jwk())
    assert header["kid"] == client_key.kid
    assert claims["iss"] == claims["sub"] == "client-1" and claims["aud"] == TOKEN_URL

    _, token_proof = verify_jws(token_req.headers["DPoP"])
    assert token_proof["htm"] == "POST" and token_proof["htu"] == TOKEN_URL
    assert "ath" not in token_proof, "no token exists yet at the token endpoint"

    jtis = set()
    for call in mcp_route.calls:
        req = call.request
        assert req.headers["Authorization"] == "DPoP tok-1"
        proof_header, proof = verify_jws(req.headers["DPoP"])
        assert keys.thumbprint(proof_header["jwk"]) == auth.dpop_jkt
        assert proof_header["jwk"] != client_key.public_jwk(), "the DPoP key is separate from the client key"
        assert proof["htm"] == "POST" and proof["htu"] == MCP_URL
        assert proof["ath"] == access_token_hash("tok-1")
        jtis.add(proof["jti"])
    assert len(jtis) == 2, "each request carries a fresh proof"


@respx.mock
def test_server_returning_a_bearer_token_gets_bearer_calls(client_key):
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "b", "token_type": "Bearer", "expires_in": 120})
    )
    mcp_route = respx.get(MCP_URL).mock(return_value=httpx.Response(200))
    httpx.get(MCP_URL, auth=AgentAuth("client-1", TOKEN_URL, client_key))
    req = mcp_route.calls[0].request
    assert req.headers["Authorization"] == "Bearer b"
    assert "DPoP" not in req.headers


@respx.mock
def test_dpop_off_sends_no_proofs(client_key):
    token_route = respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "b", "token_type": "Bearer"}))
    mcp_route = respx.get(MCP_URL).mock(return_value=httpx.Response(200))
    httpx.get(MCP_URL, auth=AgentAuth("client-1", TOKEN_URL, client_key, dpop=False))
    assert "DPoP" not in token_route.calls[0].request.headers
    assert "DPoP" not in mcp_route.calls[0].request.headers


@respx.mock
def test_invalid_token_gets_a_new_token_and_one_retry(client_key):
    token_route = respx.post(TOKEN_URL).mock(side_effect=[bound("tok-1"), bound("tok-2")])
    mcp_route = respx.get(MCP_URL).mock(
        side_effect=[
            httpx.Response(401, headers={"WWW-Authenticate": 'DPoP algs="ES256 EdDSA", error="invalid_token"'}),
            httpx.Response(200),
        ]
    )
    resp = httpx.get(MCP_URL, auth=AgentAuth("client-1", TOKEN_URL, client_key))
    assert resp.status_code == 200
    assert token_route.call_count == 2
    assert mcp_route.calls[1].request.headers["Authorization"] == "DPoP tok-2"


@respx.mock
def test_a_refusal_a_retry_cannot_fix_is_returned(client_key):
    respx.post(TOKEN_URL).mock(return_value=bound())
    mcp_route = respx.get(MCP_URL).mock(return_value=httpx.Response(401, headers={"WWW-Authenticate": 'DPoP algs="ES256 EdDSA"'}))
    resp = httpx.get(MCP_URL, auth=AgentAuth("client-1", TOKEN_URL, client_key))
    assert resp.status_code == 401
    assert mcp_route.call_count == 1


@respx.mock
def test_resource_nonce_is_used_on_retry_and_after(client_key):
    respx.post(TOKEN_URL).mock(return_value=bound())
    mcp_route = respx.get(MCP_URL).mock(
        side_effect=[
            httpx.Response(401, headers={"WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "n-1"}),
            httpx.Response(200),
            httpx.Response(200),
        ]
    )
    auth = AgentAuth("client-1", TOKEN_URL, client_key)
    with httpx.Client(auth=auth) as c:
        assert c.get(MCP_URL).status_code == 200
        c.get(MCP_URL)
    nonces = [verify_jws(call.request.headers["DPoP"])[1].get("nonce") for call in mcp_route.calls]
    assert nonces == [None, "n-1", "n-1"]


@respx.mock
def test_token_endpoint_nonce(client_key):
    token_route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "as-1"}),
            bound(),
        ]
    )
    respx.get(MCP_URL).mock(return_value=httpx.Response(200))
    httpx.get(MCP_URL, auth=AgentAuth("client-1", TOKEN_URL, client_key))
    assert token_route.call_count == 2
    assert verify_jws(token_route.calls[1].request.headers["DPoP"])[1]["nonce"] == "as-1"


@respx.mock
def test_token_endpoint_refusal_raises(client_key):
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(401, json={"error": "invalid_client"}))
    mcp_route = respx.get(MCP_URL).mock(return_value=httpx.Response(200))
    with pytest.raises(TokenError) as e:
        httpx.get(MCP_URL, auth=AgentAuth("client-1", TOKEN_URL, client_key))
    assert e.value.error == "invalid_client" and e.value.status_code == 401
    assert mcp_route.call_count == 0


@respx.mock
def test_token_is_renewed_before_it_expires(client_key, monkeypatch):
    import andromeda_agent_auth.auth as auth_mod

    now = [1_000_000.0]
    monkeypatch.setattr(auth_mod.time, "time", lambda: now[0])
    token_route = respx.post(TOKEN_URL).mock(side_effect=[bound("tok-1", 3600), bound("tok-2", 3600)])
    respx.get(MCP_URL).mock(return_value=httpx.Response(200))
    auth = AgentAuth("client-1", TOKEN_URL, client_key)
    with httpx.Client(auth=auth) as c:
        c.get(MCP_URL)
        now[0] += 3600 - 61
        c.get(MCP_URL)
        assert token_route.call_count == 1
        now[0] += 2
        c.get(MCP_URL)
        assert token_route.call_count == 2, "renewed within a minute of expiry"


def test_fetch_token(client_key):
    with respx.mock:
        respx.post(TOKEN_URL).mock(return_value=bound("tok-9"))
        token = AgentAuth("client-1", TOKEN_URL, client_key).fetch_token()
    assert token.access_token == "tok-9" and token.bound


@respx.mock
async def test_async_client(client_key):
    token_route = respx.post(TOKEN_URL).mock(return_value=bound())
    mcp_route = respx.post(MCP_URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    auth = AgentAuth("client-1", TOKEN_URL, client_key)
    async with httpx.AsyncClient(auth=auth) as c:
        assert (await c.post(MCP_URL, json={})).status_code == 200
        assert (await c.post(MCP_URL, json={})).status_code == 200
    assert token_route.call_count == 1
    assert mcp_route.calls[1].request.headers["Authorization"] == "DPoP tok-1"


@respx.mock
async def test_streamed_response_is_left_unread(client_key):
    respx.post(TOKEN_URL).mock(return_value=bound())
    respx.get(MCP_URL).mock(return_value=httpx.Response(200, stream=httpx.ByteStream(b"event: message\ndata: {}\n\n")))
    async with httpx.AsyncClient(auth=AgentAuth("client-1", TOKEN_URL, client_key)) as c, c.stream("GET", MCP_URL) as resp:
        assert not resp.is_stream_consumed, "an event stream must reach the caller unread"
        assert b"event: message" in await resp.aread()


@respx.mock
@pytest.mark.parametrize(
    ("token_url", "audience"),
    [
        ("https://api.example/oauth/gateway/acme.mcp.example/token", "https://api.example/oauth/gateway/acme.mcp.example"),
        ("http://localhost:8080/oauth/gateway/gw.local/token", "http://localhost:8080/oauth/gateway/gw.local"),
        (TOKEN_URL, TOKEN_URL),
    ],
)
def test_assertion_audience_defaults_to_the_gateway_issuer(client_key, token_url, audience):
    route = respx.post(token_url).mock(return_value=bound())
    AgentAuth("client-1", token_url, client_key).fetch_token()
    claims = verify_jws(form(route.calls.last.request)["client_assertion"], client_key.public_jwk())[1]
    assert claims["aud"] == audience


def test_retry_after_forms():
    from andromeda_agent_auth.auth import _retry_after

    assert _retry_after(httpx.Response(429, headers={"Retry-After": "7"})) == 7
    assert _retry_after(httpx.Response(429)) is None
    assert _retry_after(httpx.Response(429, headers={"Retry-After": "soon"})) is None
    assert _retry_after(httpx.Response(503, headers={"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})) == 0
    assert _retry_after(httpx.Response(429, headers=[(b"Retry-After", "²".encode())])) is None
    soon = email.utils.format_datetime(datetime.now(timezone.utc) + timedelta(seconds=100)).replace("+0000", "-0000")
    assert 90 < _retry_after(httpx.Response(429, headers={"Retry-After": soon})) <= 100
