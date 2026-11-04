"""Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).

An autonomous agent can identify itself by the HTTPS URL of a JSON document its
operator publishes, instead of a client id an administrator registered for it.
The document is the agent's client metadata: it says the agent authenticates
with private_key_jwt and carries its public keys (jwks) or points at them
(jwks_uri). The agent then uses that URL as its client_id:

    doc = client_metadata("https://agents.acme.com/invoice-bot.json", keys=[signer])
    # publish json.dumps(doc) at that URL, served as application/json
    auth = AgentAuth("https://agents.acme.com/invoice-bot.json", token_url, signer,
                     resource="https://acme.global.mcp.andromeda.com")

The first token request registers the agent and waits for an administrator's
approval; see AgentAuth.wait_for_approval.
"""

from __future__ import annotations

import json
from urllib.parse import unquote, urlsplit

from .keys import Signer, thumbprint

AUTH_METHOD = "private_key_jwt"
GRANT_TYPE = "client_credentials"

# The largest document the Andromeda token endpoint reads, after the draft's
# 5 KB guidance. A larger one never registers.
MAX_DOCUMENT_BYTES = 5120

# The token endpoint's other limits. It refuses a document with more keys, and
# would cut longer text and extra contacts, so they are refused here instead.
# Lengths are in UTF-8 bytes, as the token endpoint counts them.
MAX_URL_LENGTH = 2048
MAX_KEYS = 20
MAX_CONTACTS = 10
MAX_TEXT_LENGTH = 200
MAX_CONTACT_LENGTH = 320


def _too_long(value: str, limit: int) -> bool:
    """Whether value is longer than limit UTF-8 bytes."""
    return len(value.encode()) > limit


def _fits(text: bytes) -> bool:
    """Whether a served document fits, leaving a byte for the newline a file
    usually ends with."""
    return len(text) + 1 <= MAX_DOCUMENT_BYTES


def check_client_id(client_id: str) -> None:
    """Raise ValueError unless client_id is a usable client identifier URL:
    https, a host, a path other than "/", and no credentials, query, fragment
    or dot segments (the draft's section 3, plus the server's refusal of a
    query)."""
    if _too_long(client_id, MAX_URL_LENGTH):
        raise ValueError(f"client_id must be at most {MAX_URL_LENGTH} bytes")
    parts = urlsplit(client_id)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("client_id must be an https URL with a host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("client_id must not contain credentials")
    if parts.query or "?" in client_id:
        raise ValueError("client_id must not contain a query")
    if parts.fragment or "#" in client_id:
        raise ValueError("client_id must not contain a fragment")
    if parts.path in ("", "/"):
        raise ValueError("client_id must contain a path")
    # The server decodes each segment first, so %2e%2e counts as "..".
    if any(unquote(seg) in (".", "..") for seg in parts.path.split("/")):
        raise ValueError("client_id must not contain dot path segments")


def jwk_set(signers: list[Signer]) -> dict:
    """A JWK Set (RFC 7517) of the signers' public keys, each with its kid
    (RFC 7638 thumbprint), alg and use, as a jwks_uri should serve it."""
    keys = []
    for s in signers:
        jwk = dict(s.public_jwk())
        jwk.update({"kid": thumbprint(jwk), "alg": s.alg, "use": "sig"})
        keys.append(jwk)
    return {"keys": keys}


def client_metadata(
    client_id: str,
    *,
    keys: list[Signer] | None = None,
    jwks_uri: str | None = None,
    client_name: str | None = None,
    client_uri: str | None = None,
    software_id: str | None = None,
    software_version: str | None = None,
    contacts: list[str] | None = None,
) -> dict:
    """The client ID metadata document for an agent that runs without a user.

    Exactly one of keys (published inline as jwks) and jwks_uri must be given.
    A jwks_uri must be on the same origin as client_id, which the Andromeda
    token endpoint requires. The document names no secret: a client ID
    metadata document may not.
    """
    check_client_id(client_id)
    if (keys is None) == (jwks_uri is None):
        raise ValueError("give exactly one of keys and jwks_uri")
    doc: dict = {
        "client_id": client_id,
        "token_endpoint_auth_method": AUTH_METHOD,
        "grant_types": [GRANT_TYPE],
    }
    if keys is not None:
        if not keys:
            raise ValueError("keys must not be empty")
        if len(keys) > MAX_KEYS:
            raise ValueError(f"a document carries at most {MAX_KEYS} keys; use jwks_uri for more")
        doc["jwks"] = jwk_set(keys)
    else:
        if _too_long(jwks_uri, MAX_URL_LENGTH):
            raise ValueError(f"jwks_uri must be at most {MAX_URL_LENGTH} bytes")
        client, uri = urlsplit(client_id), urlsplit(jwks_uri)
        if uri.username is not None or uri.password is not None or uri.fragment or "#" in jwks_uri:
            raise ValueError("jwks_uri must not contain credentials or a fragment")
        if (uri.scheme, (uri.hostname or "").lower(), uri.port) != (client.scheme, (client.hostname or "").lower(), client.port):
            raise ValueError("jwks_uri must be on the same origin as client_id")
        doc["jwks_uri"] = jwks_uri
    for name, value in (
        ("client_name", client_name),
        ("client_uri", client_uri),
        ("software_id", software_id),
        ("software_version", software_version),
    ):
        if value:
            if _too_long(value, MAX_TEXT_LENGTH):
                raise ValueError(f"{name} must be at most {MAX_TEXT_LENGTH} bytes")
            doc[name] = value
    if contacts:
        if len(contacts) > MAX_CONTACTS:
            raise ValueError(f"a document names at most {MAX_CONTACTS} contacts")
        if any(_too_long(c, MAX_CONTACT_LENGTH) for c in contacts):
            raise ValueError(f"a contact must be at most {MAX_CONTACT_LENGTH} bytes")
        doc["contacts"] = list(contacts)
    if not _fits(encode(doc, indent=None)):
        raise ValueError(
            f"the document is larger than {MAX_DOCUMENT_BYTES} bytes, the most the token endpoint reads; "
            "name fewer keys, or use jwks_uri"
        )
    return doc


def encode(doc: dict, indent: int | None = 2) -> bytes:
    """The document as it should be served: indented when that still fits in
    MAX_DOCUMENT_BYTES, compact otherwise."""
    if indent is not None:
        text = json.dumps(doc, indent=indent).encode()
        if _fits(text):
            return text
    return json.dumps(doc, separators=(",", ":")).encode()
