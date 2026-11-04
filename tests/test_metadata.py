import json

import httpx
import pytest
import respx

from andromeda_agent_auth import AgentAuth, RegistrationPending, TokenError, cli, client_metadata, jwk_set, keys
from andromeda_agent_auth.metadata import check_client_id

CLIENT_ID = "https://agents.acme.com/bots/invoice.json"
TOKEN_URL = "https://api.example/oauth/token"
GATEWAY = "https://acme.global.mcp.andromeda.com"


@pytest.fixture
def signer():
    return keys.generate("EdDSA")


def test_document_with_inline_keys(signer):
    doc = client_metadata(
        CLIENT_ID, keys=[signer], client_name="Invoice bot", software_version="2.4.1", contacts=["ops@acme.com"]
    )
    assert doc["client_id"] == CLIENT_ID
    assert doc["token_endpoint_auth_method"] == "private_key_jwt"
    assert doc["grant_types"] == ["client_credentials"]
    assert "jwks_uri" not in doc and "client_secret" not in doc
    (jwk,) = doc["jwks"]["keys"]
    assert jwk["kid"] == signer.kid and jwk["alg"] == "EdDSA" and jwk["use"] == "sig"
    assert "d" not in jwk, "only the public key is published"
    assert doc["client_name"] == "Invoice bot" and doc["contacts"] == ["ops@acme.com"]
    assert "client_uri" not in doc, "unset fields are left out"


def test_document_with_jwks_uri(signer):
    doc = client_metadata(CLIENT_ID, jwks_uri="https://agents.acme.com/bots/jwks.json")
    assert doc["jwks_uri"] == "https://agents.acme.com/bots/jwks.json" and "jwks" not in doc
    with pytest.raises(ValueError, match="same origin"):
        client_metadata(CLIENT_ID, jwks_uri="https://keys.other.com/jwks.json")
    with pytest.raises(ValueError, match="same origin"):
        client_metadata(CLIENT_ID, jwks_uri="https://agents.acme.com:8443/jwks.json")
    with pytest.raises(ValueError, match="exactly one"):
        client_metadata(CLIENT_ID)
    with pytest.raises(ValueError, match="exactly one"):
        client_metadata(CLIENT_ID, keys=[signer], jwks_uri="https://agents.acme.com/jwks.json")
    with pytest.raises(ValueError, match="empty"):
        client_metadata(CLIENT_ID, keys=[])


@pytest.mark.parametrize(
    "bad",
    [
        "http://agents.acme.com/bot.json",
        "https:///bot.json",
        "https://agents.acme.com",
        "https://agents.acme.com/",
        "https://u:p@agents.acme.com/bot.json",
        "https://agents.acme.com/bot.json?v=1",
        "https://agents.acme.com/bot.json#x",
        "https://agents.acme.com/a/../bot.json",
    ],
)
def test_client_id_rules(bad):
    with pytest.raises(ValueError):
        check_client_id(bad)


def test_jwk_set_names_every_key():
    a, b = keys.generate("EdDSA"), keys.generate("ES256")
    assert [k["kid"] for k in jwk_set([a, b])["keys"]] == [a.kid, b.kid]


def pending():
    return httpx.Response(
        400,
        json={"error": "unauthorized_client", "error_description": "waiting for approval", "registration_status": "pending"},
    )


@respx.mock
def test_authorization_pending_from_an_older_server_is_still_pending(signer):
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(400, json={"error": "authorization_pending"}))
    with pytest.raises(RegistrationPending):
        AgentAuth(CLIENT_ID, TOKEN_URL, signer, resource=GATEWAY).fetch_token()


@respx.mock
def test_resource_is_sent_and_pending_is_typed(signer):
    route = respx.post(TOKEN_URL).mock(return_value=pending())
    auth = AgentAuth(CLIENT_ID, TOKEN_URL, signer, resource=GATEWAY)
    with pytest.raises(RegistrationPending) as err:
        auth.fetch_token()
    assert isinstance(err.value, TokenError)
    assert err.value.description == "waiting for approval" and err.value.registration_status == "pending"
    body = httpx.QueryParams(route.calls[0].request.content.decode())
    assert body["resource"] == GATEWAY


@respx.mock
def test_no_resource_unless_given(signer):
    route = respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "t", "token_type": "Bearer"}))
    AgentAuth("client-1", TOKEN_URL, signer).fetch_token()
    assert "resource" not in httpx.QueryParams(route.calls[0].request.content.decode())


@respx.mock
def test_wait_for_approval_polls_until_approved(signer):
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            pending(),
            pending(),
            httpx.Response(200, json={"access_token": "t", "token_type": "DPoP", "expires_in": 3600}),
        ]
    )
    slept = []
    token = AgentAuth(CLIENT_ID, TOKEN_URL, signer, resource=GATEWAY).wait_for_approval(
        timeout=600, interval=30, sleep=slept.append
    )
    assert token.access_token == "t"
    assert route.call_count == 3 and slept == [30, 30]
    assertions = {httpx.QueryParams(c.request.content.decode())["client_assertion"] for c in route.calls}
    assert len(assertions) == 3, "every attempt signs a fresh assertion"


@respx.mock
def test_wait_for_approval_gives_up_and_stops_on_refusal(signer):
    respx.post(TOKEN_URL).mock(return_value=pending())
    with pytest.raises(RegistrationPending):
        AgentAuth(CLIENT_ID, TOKEN_URL, signer).wait_for_approval(timeout=50, interval=30, sleep=lambda _: None)

    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            401, json={"error": "invalid_client", "error_description": "rejected", "registration_status": "rejected"}
        )
    )
    slept = []
    with pytest.raises(TokenError) as err:
        AgentAuth(CLIENT_ID, TOKEN_URL, signer).wait_for_approval(sleep=slept.append)
    assert not isinstance(err.value, RegistrationPending) and slept == []
    assert err.value.registration_status == "rejected"

    # unauthorized_client alone is a refusal, not a wait.
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(400, json={"error": "unauthorized_client"}))
    with pytest.raises(TokenError) as err:
        AgentAuth(CLIENT_ID, TOKEN_URL, signer).wait_for_approval(sleep=slept.append)
    assert not isinstance(err.value, RegistrationPending) and slept == []


def test_cli_metadata(tmp_path, capsys, signer):
    key_file = tmp_path / "agent-key.pem"
    key_file.write_bytes(signer.private_pem())
    assert cli.main(["metadata", "--client-id", CLIENT_ID, "--key", str(key_file), "--name", "Invoice bot"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["client_id"] == CLIENT_ID and doc["jwks"]["keys"][0]["kid"] == signer.kid
    assert cli.main(["metadata", "--client-id", "http://x/y.json", "--key", str(key_file)]) == 2
    assert cli.main(["jwks", str(key_file)]) == 0
    assert json.loads(capsys.readouterr().out)["keys"][0]["kid"] == signer.kid


@respx.mock
def test_cli_token_reports_pending(tmp_path, capsys, signer):
    key_file = tmp_path / "agent-key.pem"
    key_file.write_bytes(signer.private_pem())
    respx.post(TOKEN_URL).mock(return_value=pending())
    code = cli.main(["token", "--token-url", TOKEN_URL, "--client-id", CLIENT_ID, "--key", str(key_file), "--resource", GATEWAY])
    assert code == 3
    assert "ask an administrator to approve it" in capsys.readouterr().err


def test_document_size_is_bounded():
    from andromeda_agent_auth.metadata import MAX_DOCUMENT_BYTES, encode

    signers = [keys.generate("EdDSA") for _ in range(20)]
    with pytest.raises(ValueError, match="larger than 5120 bytes"):
        client_metadata(CLIENT_ID, keys=signers, contacts=[f"{'o' * 300}{i}@acme.com" for i in range(10)])
    # A document that fits compact but not indented is served compact, with a
    # byte left for the newline a file usually ends with.
    for length in range(1, 300):
        doc = client_metadata(CLIENT_ID, keys=signers, contacts=[f"{'o' * length}{i}@acme.com" for i in range(10)])
        if len(json.dumps(doc, indent=2)) + 1 > MAX_DOCUMENT_BYTES:
            break
    served = encode(doc)
    assert len(served) + 1 <= MAX_DOCUMENT_BYTES and b"\n" not in served
    assert json.loads(served) == doc


def test_document_limits_match_the_server(signer):
    with pytest.raises(ValueError, match="at most 20 keys"):
        client_metadata(CLIENT_ID, keys=[keys.generate("EdDSA") for _ in range(21)])
    with pytest.raises(ValueError, match="at most 10 contacts"):
        client_metadata(CLIENT_ID, keys=[signer], contacts=[f"ops{i}@acme.com" for i in range(11)])
    with pytest.raises(ValueError, match="client_name must be at most 200"):
        client_metadata(CLIENT_ID, keys=[signer], client_name="x" * 201)
    # The token endpoint counts UTF-8 bytes: 101 two-byte characters are too many.
    with pytest.raises(ValueError, match="client_name must be at most 200 bytes"):
        client_metadata(CLIENT_ID, keys=[signer], client_name="é" * 101)
    assert client_metadata(CLIENT_ID, keys=[signer], client_name="é" * 100)["client_name"] == "é" * 100
    with pytest.raises(ValueError, match="a contact must be at most 320 bytes"):
        client_metadata(CLIENT_ID, keys=[signer], contacts=["ü" * 161])
    for bad in ("https://agents.acme.com/jwks.json#k", "https://u:p@agents.acme.com/jwks.json"):
        with pytest.raises(ValueError, match="credentials or a fragment"):
            client_metadata(CLIENT_ID, jwks_uri=bad)
    with pytest.raises(ValueError, match="dot path segments"):
        check_client_id("https://agents.acme.com/a/%2e%2e/bot.json")
    with pytest.raises(ValueError, match="at most 2048"):
        check_client_id("https://agents.acme.com/" + "a" * 2048 + ".json")


@respx.mock
def test_wait_for_approval_honors_retry_after_and_rides_out_an_outage(signer):
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(429, json={"error": "temporarily_unavailable"}, headers={"Retry-After": "90"}),
            httpx.Response(429, json={"error": "temporarily_unavailable"}, headers={"Retry-After": "1"}),
            httpx.ConnectError("apiserver restarting"),
            pending(),
            httpx.Response(200, json={"access_token": "t", "token_type": "DPoP", "expires_in": 3600}),
        ]
    )
    slept = []
    token = AgentAuth(CLIENT_ID, TOKEN_URL, signer, resource=GATEWAY).wait_for_approval(
        timeout=600, interval=30, sleep=slept.append
    )
    assert token.access_token == "t" and route.call_count == 5
    assert slept == [90, 30, 30, 30], "a Retry-After longer than the interval is waited out, a shorter one is not"

    # A Retry-After past the deadline ends the wait.
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(429, json={"error": "temporarily_unavailable"}, headers={"Retry-After": "900"})
    )
    with pytest.raises(TokenError) as err:
        AgentAuth(CLIENT_ID, TOKEN_URL, signer).wait_for_approval(timeout=600, interval=30, sleep=lambda _: None)
    assert err.value.status_code == 429 and err.value.retry_after == 900
    with pytest.raises(ValueError):
        AgentAuth(CLIENT_ID, TOKEN_URL, signer).wait_for_approval(interval=0)


def test_cli_metadata_reports_an_unreadable_key(tmp_path, capsys):
    assert cli.main(["metadata", "--client-id", CLIENT_ID, "--key", str(tmp_path / "missing.pem")]) == 2
    assert "missing.pem" in capsys.readouterr().err


@respx.mock
def test_wait_for_approval_rides_out_a_failing_token_endpoint(signer):
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(503, text="upstream connect error"),
            httpx.Response(500, json={"error": "server_error"}),
            httpx.Response(400, json={"error": "temporarily_unavailable"}),
            pending(),
            httpx.Response(200, json={"access_token": "t", "token_type": "DPoP", "expires_in": 3600}),
        ]
    )
    slept = []
    token = AgentAuth(CLIENT_ID, TOKEN_URL, signer, resource=GATEWAY).wait_for_approval(
        timeout=600, interval=30, sleep=slept.append
    )
    assert token.access_token == "t" and route.call_count == 5
    assert slept == [30, 30, 30, 30]

    # A failing endpoint still ends the wait at the deadline.
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(502, text="bad gateway"))
    with pytest.raises(TokenError) as err:
        AgentAuth(CLIENT_ID, TOKEN_URL, signer).wait_for_approval(timeout=50, interval=30, sleep=lambda _: None)
    assert err.value.status_code == 502
