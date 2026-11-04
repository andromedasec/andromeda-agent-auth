"""Compact JWS signing, and the two JWTs an agent signs.

- the client assertion that authenticates it at the token endpoint
  (private_key_jwt, RFC 7523 section 2.2, as profiled by OIDC Core 9)
- the DPoP proof sent with every request (RFC 9449 section 4.2)
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid

import httpx

from .keys import DPOP_ALGS, Signer, b64url, thumbprint

# RFC 7523 recommends a short life; the token endpoint refuses more than five
# minutes.
ASSERTION_LIFETIME = 60


def sign(signer: Signer, header: dict, claims: dict) -> str:
    header = {**header, "alg": signer.alg}
    enc = lambda v: b64url(json.dumps(v, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{enc(header)}.{enc(claims)}"
    return f"{signing_input}.{b64url(signer.sign(signing_input.encode('ascii')))}"


def client_assertion(signer: Signer, client_id: str, audience: str, now: float | None = None) -> str:
    """A private_key_jwt client assertion: iss and sub are the client id, aud
    the token endpoint, and the header kid names the registered key."""
    now = int(now if now is not None else time.time())
    return sign(
        signer,
        {"typ": "JWT", "kid": thumbprint(signer.public_jwk())},
        {
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "iat": now,
            "exp": now + ASSERTION_LIFETIME,
            "jti": str(uuid.uuid4()),
        },
    )


def htu(url: str | httpx.URL) -> str:
    """The proof's htu: the request URL without query and fragment."""
    return str(httpx.URL(url).copy_with(query=None, fragment=None))


def access_token_hash(access_token: str) -> str:
    """The proof's ath: base64url SHA-256 of the access token."""
    return b64url(hashlib.sha256(access_token.encode("ascii")).digest())


def dpop_proof(
    signer: Signer,
    method: str,
    url: str | httpx.URL,
    access_token: str | None = None,
    nonce: str | None = None,
    now: float | None = None,
) -> str:
    """A DPoP proof for one request. Each proof has a fresh jti, so it is
    accepted once."""
    if signer.alg not in DPOP_ALGS:
        raise ValueError(f"DPoP proofs are signed with {' or '.join(DPOP_ALGS)}, not {signer.alg}")
    claims: dict = {
        "jti": str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": htu(url),
        "iat": int(now if now is not None else time.time()),
    }
    if access_token is not None:
        claims["ath"] = access_token_hash(access_token)
    if nonce is not None:
        claims["nonce"] = nonce
    return sign(signer, {"typ": "dpop+jwt", "jwk": signer.public_jwk()}, claims)
