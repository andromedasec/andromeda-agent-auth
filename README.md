# andromeda-agent-auth

Key-bound OAuth for autonomous agents that call tools through the Andromeda
Agent Gateway. The agent authenticates with a private key instead of a shared
client secret, and every call it makes proves it still holds a key, so a token
copied out of a log or a trace is useless on its own.

It uses two IETF standards and nothing else:

- **`private_key_jwt`** ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)): at the
  token endpoint the agent signs a short JWT with its registered key, in place of
  a `client_secret`.
- **DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)): the token it gets
  back is bound to a second key (`cnf.jkt`), and each request carries a fresh proof
  signed with that key for that method and URL.

The package is one `httpx.Auth`, so it works anywhere httpx does, including the
MCP Python SDK and `langchain-mcp-adapters`.

## 1. Make a key and register it

```bash
pip install andromeda-agent-auth
andromeda-agent-auth keygen --out agent-key.pem
```

`keygen` writes the private key (mode 0600) and prints the public JWK and its
`kid` (the RFC 7638 thumbprint). Register the public JWK on the agent's client:
in the console (the agent's **Keys** tab), or with `POST /agentclientkeys`:

```json
{"client_kind": "REGISTERED_AGENT", "credential_ref_id": "<agent id>",
 "name": "support-triage prod", "public_key": "<public JWK or PEM>"}
```

Use `"client_kind": "AGENT_BLUEPRINT"` and the blueprint id for agents minted
under a blueprint, which share its client.

Register one key per deployment or per instance; each has its own `kid`, can be
disabled on its own, and shows up by `kid` in gateway events. To rotate, register
the new key, roll the agent, then disable the old key. An operator who would
rather publish keys than call the API can set a `jwks_uri` on the client instead;
a key taken out of that set is revoked the next time the token endpoint fetches it.

Once the agent authenticates with its key, the client's settings can refuse the
shared secret (`keys_only`) and require a DPoP proof on every gateway call
(`require_proof_of_possession`).

## 2. Use it

```python
import httpx
from andromeda_agent_auth import AgentAuth, keys

auth = AgentAuth.for_resource(
    client_id="<the agent's OAuth client id>",
    resource="https://<gateway>",
    key=keys.load_file("agent-key.pem"),   # or keys.load_env()
)

with httpx.Client(auth=auth) as client:
    client.post("https://<gateway>/mcp", json={...})
```

A key authenticates only at the token endpoint of the agent's gateway,
`https://<apiserver>/oauth/gateway/<gateway host>/token`, which `for_resource`
finds from the gateway's metadata (see section 3). An agent that is given the
endpoint instead passes it as `token_url` to `AgentAuth(...)`. Either way the
client assertion names the gateway's issuer, the endpoint without its final
`/token`, as its audience
([RFC 7523bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/));
the token endpoint refuses any other `aud`, the token endpoint URL included.

`AgentAuth` gets a token on first use and again a minute before it expires,
generates the DPoP key in memory (it never touches disk), and signs a new proof
for every request. It retries a request once when the gateway answers 401 with
`invalid_token` (it gets a new token), `invalid_dpop_proof` or `use_dpop_nonce`;
any other refusal is returned to the caller. A refusal from the token endpoint
raises `TokenError`. One that limits requests answers 429 with a `Retry-After`,
which `TokenError.retry_after` carries; `fetch_token` does not wait it out, so a
caller that retries sleeps that long first.

## 3. Or let the agent register itself (client ID metadata document)

An agent nobody registered in advance can identify itself by the HTTPS URL of a
JSON document its operator publishes, a
[client ID metadata document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/).
The URL is its `client_id`; the document says it authenticates with
`private_key_jwt` and carries its public keys. Print one for a key:

```bash
andromeda-agent-auth metadata --client-id https://agents.acme.com/invoice-bot.json \
    --key agent-key.pem --name "Invoice bot" > invoice-bot.json
```

Publish it at exactly that URL, served as `application/json`. Instead of inline
keys, `--jwks-uri https://agents.acme.com/invoice-bot/jwks.json` points at a JWK
Set on the same origin (print one with `andromeda-agent-auth jwks agent-key.pem`),
so keys rotate without touching the document.

The tenant's admin must allow the document's host (Tenant Settings, Agent). The
agent then asks the token endpoint of the gateway it calls: each gateway has an
authorization server issuer of its own,
`https://<apiserver>/oauth/gateway/<gateway host>`, and the client assertion
names it as the audience, so what the agent signs says which tenant it is
asking. The agent also sends the gateway as the `resource`
([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)):

```python
from andromeda_agent_auth import AgentAuth, keys

auth = AgentAuth.for_resource(
    client_id="https://agents.acme.com/invoice-bot.json",
    resource="https://<gateway host>",
    key=keys.load_file("agent-key.pem"),
)
auth.wait_for_approval(timeout=3600)   # polls every 30 s while an admin decides
```

The gateway's URL is all the agent needs from Andromeda: `for_resource` finds
the token endpoint the way an MCP client does, from the gateway's protected
resource metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) and its
authorization server's metadata
([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)), checking that each
document is for the resource and the issuer asked about, and signs its client
assertion for that issuer. The CLI does the same when `token` gets `--resource`
without `--token-url`. To skip discovery, pass the gateway issuer's token
endpoint (the console shows it in the agent's connection settings):
`AgentAuth(client_id, token_url, key, resource=...)`.

The first request registers the agent and answers `unauthorized_client` with
`"registration_status": "pending"` (`RegistrationPending`, a `TokenError`); a
rejected registration answers `invalid_client` with `"registration_status":
"rejected"`. No token is issued until an admin
approves the registration in the console (Agents, Registrations,
Self-registered) or through the API
(`POST /agentclientregistrations/{id}/approve`, naming the `metadata_hash` of
the document they reviewed). After that the same `AgentAuth`
works as in section 2. If the document later adds a key or changes its
`jwks_uri`, the registration goes back to pending, and the agent gets no token,
until an admin approves the change. Removing a key needs no approval: the key is
revoked at once, so tokens already issued with it stop working at the gateway
too. Keys behind a `jwks_uri` rotate without approvals, and one taken out of the
set is revoked the same way the next time the token endpoint fetches it.

The token endpoint reads at most 5120 bytes of the document, so
`client_metadata` refuses a larger one; name fewer keys, or use `jwks_uri`.

The token endpoint caches the document as its `Cache-Control` says (five
minutes without one, a day at most). When the host serving it fails, an
approved agent keeps getting tokens on the last copy only if the response
allowed that with `stale-if-error`
([RFC 5861](https://www.rfc-editor.org/rfc/rfc5861)), for at most an hour after
the copy went stale. To ride out a brief outage, serve it with, for example,
`Cache-Control: max-age=300, stale-if-error=3600`.

### LangGraph with MCP tools

```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "gateway": {
        "transport": "streamable_http",
        "url": "https://<gateway>/mcp",
        "auth": auth,
    }
})
tools = await client.get_tools()
```

A full agent, `examples/langgraph_agent.py`, ships in the source distribution.

### Keys in a KMS or HSM

`AgentAuth` takes any object with an `alg` property, a `public_jwk()` method and
a `sign(data) -> bytes` method (the `Signer` protocol), so the client key can stay
in AWS KMS, Google Cloud KMS or an HSM. ES256 signatures must be raw `r||s`
(64 bytes), as JWS requires, not DER.

### Environment

`keys.load_env()` reads `ANDROMEDA_AGENT_PRIVATE_KEY` (the PEM) or
`ANDROMEDA_AGENT_PRIVATE_KEY_FILE` (a path), and `ANDROMEDA_AGENT_KEY_ALG`
(`RS256` or `PS256`) for an RSA key.

## Algorithms

| | Client key (assertion) | DPoP key (proofs) |
|---|---|---|
| Ed25519 (`EdDSA`) | yes, the default | yes, the default |
| P-256 (`ES256`) | yes | yes |
| RSA 2048+ (`PS256`, `RS256`) | yes | no |

## TypeScript

No SDK is needed. The MCP TypeScript SDK accepts a custom `fetch`; sign the
assertion and proofs with [`jose`](https://github.com/panva/jose):

```ts
import { SignJWT, importPKCS8, generateKeyPair, exportJWK } from "jose";
import { createHash, randomUUID } from "node:crypto";

const clientKey = await importPKCS8(process.env.ANDROMEDA_AGENT_PRIVATE_KEY!, "EdDSA");
const kid = process.env.ANDROMEDA_AGENT_KEY_ID!;           // printed by `keygen`
const dpop = await generateKeyPair("EdDSA");
const dpopJwk = await exportJWK(dpop.publicKey);

const proof = (htm: string, htu: string, token?: string) =>
  new SignJWT({
    htm, htu: htu.split(/[?#]/)[0], jti: randomUUID(),
    ...(token && { ath: createHash("sha256").update(token).digest("base64url") }),
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: dpopJwk })
    .setIssuedAt()
    .sign(dpop.privateKey);

// tokenUrl is https://<apiserver>/oauth/gateway/<gateway host>/token; the
// assertion's audience is the issuer, that URL without its final /token.
async function getToken(clientId: string, tokenUrl: string) {
  const issuer = tokenUrl.replace(/\/token$/, "");
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid })
    .setIssuer(clientId).setSubject(clientId).setAudience(issuer)
    .setIssuedAt().setExpirationTime("60s").setJti(randomUUID())
    .sign(clientKey);
  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: await proof("POST", tokenUrl) },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion,
    }),
  });
  return (await res.json()).access_token as string;
}

// Each gateway request: Authorization: DPoP <token>, DPoP: await proof(method, url, token)
```

## Development

```bash
pip install -e '.[test]'
pytest
```
