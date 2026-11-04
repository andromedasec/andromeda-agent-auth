import json
import os
import stat

import pytest
from conftest import b64d, verify_jws
from cryptography.hazmat.primitives.asymmetric import ed25519

from andromeda_agent_auth import cli, keys
from andromeda_agent_auth.jws import access_token_hash, client_assertion, dpop_proof, htu


def test_thumbprint_rfc7638_rsa_example():
    jwk = {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs"
        "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91"
        "CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
    }
    assert keys.thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_ed25519_rfc8037_vectors():
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(b64d("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"))
    signer = keys.LocalSigner(priv)
    assert signer.public_jwk() == {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    assert signer.kid == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    signing_input = b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
    assert keys.b64url(signer.sign(signing_input)) == (
        "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
    )


@pytest.mark.parametrize("alg", ["EdDSA", "ES256"])
def test_client_assertion_claims(alg):
    signer = keys.generate(alg)
    token = client_assertion(signer, "client-1", "https://api.example/oauth/token", now=1_700_000_000)
    header, claims = verify_jws(token, signer.public_jwk())
    assert header == {"typ": "JWT", "kid": signer.kid, "alg": alg}
    assert claims["iss"] == claims["sub"] == "client-1"
    assert claims["aud"] == "https://api.example/oauth/token"
    assert claims["exp"] - claims["iat"] == 60
    assert claims["jti"]
    assert client_assertion(signer, "client-1", "aud") != client_assertion(signer, "client-1", "aud"), "fresh jti each time"


def test_dpop_proof_claims():
    signer = keys.generate("ES256")
    proof = dpop_proof(signer, "post", "https://GW.example:443/mcp?x=1#frag", access_token="tok", nonce="n-1", now=1_700_000_000)
    header, claims = verify_jws(proof)
    assert header["typ"] == "dpop+jwt" and header["alg"] == "ES256"
    assert keys.thumbprint(header["jwk"]) == signer.kid
    assert "d" not in header["jwk"], "only the public key travels"
    assert claims["htm"] == "POST"
    assert claims["htu"] == "https://gw.example/mcp"
    assert claims["ath"] == access_token_hash("tok")
    assert claims["nonce"] == "n-1"
    assert claims["iat"] == 1_700_000_000


def test_dpop_proof_refuses_rsa():
    from cryptography.hazmat.primitives.asymmetric import rsa

    signer = keys.LocalSigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "PS256")
    with pytest.raises(ValueError):
        dpop_proof(signer, "GET", "https://gw.example/mcp")


def test_htu_strips_query_and_fragment():
    assert htu("https://gw.example/a/b?c=d#e") == "https://gw.example/a/b"


def test_load_pem_round_trip_and_env(monkeypatch, tmp_path):
    signer = keys.generate("EdDSA")
    path = tmp_path / "k.pem"
    path.write_bytes(signer.private_pem())
    assert keys.load_file(path).kid == signer.kid
    monkeypatch.setenv("ANDROMEDA_AGENT_PRIVATE_KEY_FILE", str(path))
    assert keys.load_env().kid == signer.kid
    monkeypatch.setenv("ANDROMEDA_AGENT_PRIVATE_KEY", signer.private_pem().decode())
    assert keys.load_env().kid == signer.kid


def test_mismatched_alg_is_refused():
    with pytest.raises(ValueError):
        keys.LocalSigner(ed25519.Ed25519PrivateKey.generate(), "ES256")


def test_cli_keygen_and_jwk(tmp_path, capsys):
    out = tmp_path / "agent.pem"
    assert cli.main(["keygen", "--out", str(out)]) == 0
    generated = json.loads(capsys.readouterr().out)
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert cli.main(["jwk", str(out)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == generated
    assert printed["kid"] == keys.thumbprint(printed["public_jwk"])
    with pytest.raises(FileExistsError):
        cli.main(["keygen", "--out", str(out)])
