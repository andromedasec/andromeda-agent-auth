"""AgentAuth: an httpx.Auth that authenticates an autonomous agent with its
registered key and proves possession of a DPoP key on every request.

    auth = AgentAuth(client_id, token_url, keys.load_file("agent-key.pem"))
    httpx.get("https://gateway.example/mcp", auth=auth)

At first use, and again shortly before the token expires, it calls the token
endpoint with the client_credentials grant, authenticated by a client
assertion signed with the registered key (RFC 7523) and carrying a DPoP proof
(RFC 9449), so the token it gets back is bound to the DPoP key. Every request
then carries the token in the DPoP scheme plus a fresh proof for that method
and URL. The DPoP key is generated in memory and never leaves the process.

The same object works with httpx.Client and httpx.AsyncClient, so it can be
handed to any library built on httpx, such as the MCP Python SDK or
langchain-mcp-adapters.
"""

from __future__ import annotations

import email.utils
import json
import re
import time
from collections.abc import Generator
from dataclasses import dataclass
from datetime import timezone

import httpx

from .discovery import discover_authorization_server
from .jws import client_assertion, dpop_proof
from .keys import Signer, generate, thumbprint

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

_CHALLENGE_ERROR = re.compile(r'error="([^"]*)"')

# An Andromeda gateway's token endpoint is its issuer followed by /token.
_GATEWAY_TOKEN_PATH = re.compile(r"^(.*/oauth/gateway/[^/]+)/token$")


class TokenError(Exception):
    """The token endpoint refused the request.

    registration_status is what it said of a client registered through its
    client ID metadata document ("pending" or "rejected"), and retry_after the
    seconds its Retry-After asked to wait, when it sent one."""

    def __init__(
        self,
        status_code: int,
        error: str,
        description: str = "",
        *,
        registration_status: str = "",
        retry_after: float | None = None,
    ):
        self.status_code = status_code
        self.error = error
        self.description = description
        self.registration_status = registration_status
        self.retry_after = retry_after
        super().__init__(f"token endpoint returned {status_code} {error}" + (f": {description}" if description else ""))


def _server_failing(e: TokenError) -> bool:
    """Whether the token endpoint failed on its side or is limiting requests,
    which asking again later can outlast."""
    return e.status_code == 429 or e.status_code >= 500 or e.error == "temporarily_unavailable"


class RegistrationPending(TokenError):
    """The client registered itself through its client ID metadata document and
    is waiting for an administrator's approval (registration_status
    "pending"). Asking again later is the expected next step; see
    AgentAuth.wait_for_approval."""


@dataclass(frozen=True)
class Token:
    access_token: str
    token_type: str
    expires_at: float
    scope: str = ""

    @property
    def bound(self) -> bool:
        """Whether the token is DPoP-bound (token_type DPoP)."""
        return self.token_type.lower() == "dpop"


# A step of the request flow: the request to send, and whether its response
# body has to be read before the flow sees it (only the token response does;
# reading a gateway response would drain an event stream).
_Step = tuple[httpx.Request, bool]


class AgentAuth(httpx.Auth):
    def __init__(
        self,
        client_id: str,
        token_url: str,
        key: Signer,
        *,
        scope: str | None = None,
        dpop: bool = True,
        dpop_key: Signer | None = None,
        audience: str | None = None,
        refresh_before: float = 60.0,
        resource: str | None = None,
    ):
        """
        client_id: the agent's OAuth client id.
        token_url: the authorization server's token endpoint.
        key: the registered client key that signs the client assertion.
        scope: optional scope to request.
        dpop: ask for a DPoP-bound token (the default). False gets a bearer
            token, which a client that requires proof of possession cannot use.
        dpop_key: the key DPoP proofs are signed with. Defaults to a fresh
            in-memory Ed25519 key per AgentAuth.
        audience: the client assertion's aud, the authorization server's
            issuer (RFC 7523bis). Defaults to the issuer of the Andromeda
            gateway whose token endpoint token_url is (the URL without its
            final /token), and to token_url for any other server.
        refresh_before: get a new token this many seconds before the current
            one expires (at most half its life).
        resource: the resource the token is for (RFC 8707), the agent
            gateway's URL. Optional at an Andromeda gateway's own issuer,
            which already names the gateway, and must be that gateway when
            sent.
        """
        self.client_id = client_id
        self.token_url = httpx.URL(token_url)
        self.scope = scope
        self._key = key
        self._dpop_key = (dpop_key or generate("EdDSA")) if dpop else None
        self._audience = audience or _default_audience(self.token_url)
        self._refresh_before = refresh_before
        self.resource = resource
        self._token: Token | None = None
        # The latest DPoP-Nonce each server sent (RFC 9449 section 8), by origin.
        self._nonces: dict[str, str] = {}

    @classmethod
    def for_resource(
        cls,
        client_id: str,
        resource: str,
        key: Signer,
        *,
        client: httpx.Client | None = None,
        **kwargs,
    ) -> AgentAuth:
        """An AgentAuth for an agent that knows only the gateway it calls: the
        authorization server is found now, once, from the gateway's metadata
        (see discovery.discover_authorization_server), its issuer is the
        client assertion's audience unless audience is given, and resource is
        sent with every token request. Raises DiscoveryError when it cannot be
        found. Other keyword arguments are AgentAuth's."""
        server = discover_authorization_server(resource, client=client)
        kwargs.setdefault("audience", server.issuer)
        return cls(client_id, server.token_endpoint, key, resource=resource, **kwargs)

    @property
    def dpop_jkt(self) -> str | None:
        """The thumbprint a bound token's cnf.jkt names."""
        if self._dpop_key is None:
            return None
        return thumbprint(self._dpop_key.public_jwk())

    # httpx drives these. The flow itself is shared; only reading a token
    # response's body differs between the sync and async clients.

    def sync_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        flow = self._flow(request)
        outgoing, needs_body = next(flow)
        while True:
            response = yield outgoing
            if needs_body:
                response.read()
            try:
                outgoing, needs_body = flow.send(response)
            except StopIteration:
                return

    async def async_auth_flow(self, request: httpx.Request):
        flow = self._flow(request)
        outgoing, needs_body = next(flow)
        while True:
            response = yield outgoing
            if needs_body:
                await response.aread()
            try:
                outgoing, needs_body = flow.send(response)
            except StopIteration:
                return

    def fetch_token(self, client: httpx.Client | None = None) -> Token:
        """Get a new token now, outside any request."""
        owned = client is None
        client = client or httpx.Client()
        try:
            flow = self._mint()
            outgoing, _ = next(flow)
            while True:
                response = client.send(outgoing)
                response.read()
                try:
                    outgoing, _ = flow.send(response)
                except StopIteration as done:
                    return done.value
        finally:
            if owned:
                client.close()

    def wait_for_approval(
        self,
        timeout: float = 3600.0,
        interval: float = 30.0,
        client: httpx.Client | None = None,
        sleep=time.sleep,
    ) -> Token:
        """Get a token, asking again every interval seconds while the client's
        registration waits for an administrator's approval, for up to timeout
        seconds. A token endpoint briefly out of reach, failing (a 5xx answer,
        or temporarily_unavailable) or limiting requests (429) does not end the
        wait, and a Retry-After longer than the interval is waited out.
        Raises RegistrationPending (or the last error) if it is still waiting
        then, and any other TokenError at once (a rejected registration among
        them)."""
        if interval <= 0:
            raise ValueError("interval must be positive")
        deadline = time.monotonic() + timeout
        while True:
            wait = interval
            try:
                return self.fetch_token(client)
            except TokenError as e:
                if not (isinstance(e, RegistrationPending) or _server_failing(e)):
                    raise
                wait = max(interval, e.retry_after or 0)
                if time.monotonic() + wait > deadline:
                    raise
            except httpx.TransportError:
                if time.monotonic() + wait > deadline:
                    raise
            sleep(wait)

    def _flow(self, request: httpx.Request) -> Generator[_Step, httpx.Response, None]:
        token = self._current()
        if token is None:
            token = yield from self._mint()
        response = yield self._authorize(request, token), False
        self._remember_nonce(request.url, response)
        if response.status_code != 401:
            return
        # One retry, for the failures a retry can fix (RFC 9449 sections 7.1
        # and 9): a nonce the server now wants, a proof it refused, or a token
        # it no longer accepts. Anything else is returned to the caller.
        error = _challenge_error(response)
        nonce_wanted = error == "use_dpop_nonce" and _origin(request.url) in self._nonces
        proof_refused = error == "invalid_dpop_proof" and token.bound
        if nonce_wanted or proof_refused:
            yield self._authorize(request, token), False
        elif error == "invalid_token":
            self._token = None
            token = yield from self._mint()
            yield self._authorize(request, token), False

    def _current(self) -> Token | None:
        token = self._token
        if token is None:
            return None
        return token if time.time() < token.expires_at else None

    def _mint(self) -> Generator[_Step, httpx.Response, Token]:
        for attempt in (1, 2):
            response = yield self._token_request(), True
            self._remember_nonce(self.token_url, response)
            if (
                attempt == 1
                and response.status_code == 400
                and _json_error(response) == "use_dpop_nonce"
                and _origin(self.token_url) in self._nonces
            ):
                continue
            token = self._parse_token(response)
            self._token = token
            return token
        raise AssertionError("unreachable")

    def _token_request(self) -> httpx.Request:
        data = {
            "grant_type": "client_credentials",
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion(self._key, self.client_id, self._audience),
        }
        if self.scope:
            data["scope"] = self.scope
        if self.resource:
            data["resource"] = self.resource
        headers = {"Accept": "application/json"}
        if self._dpop_key is not None:
            headers["DPoP"] = dpop_proof(self._dpop_key, "POST", self.token_url, nonce=self._nonces.get(_origin(self.token_url)))
        return httpx.Request("POST", self.token_url, data=data, headers=headers)

    def _parse_token(self, response: httpx.Response) -> Token:
        try:
            body = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {}
        if not isinstance(body, dict):
            body = {}
        if response.status_code != 200 or not body.get("access_token"):
            registration_status = str(body.get("registration_status", ""))
            error = str(body.get("error", "invalid_response"))
            # authorization_pending is how servers without registration_status
            # said the same; kept for one release.
            pending = registration_status == "pending" or error == "authorization_pending"
            refusal = RegistrationPending if pending else TokenError
            raise refusal(
                response.status_code,
                error,
                str(body.get("error_description", "")),
                registration_status=registration_status,
                retry_after=_retry_after(response),
            )
        token_type = str(body.get("token_type", "Bearer"))
        if self._dpop_key is None and token_type.lower() == "dpop":
            raise TokenError(response.status_code, "invalid_response", "got a DPoP-bound token without sending a proof")
        lifetime = float(body.get("expires_in") or 60)
        early = min(self._refresh_before, lifetime / 2)
        return Token(
            access_token=body["access_token"],
            token_type=token_type,
            expires_at=time.time() + lifetime - early,
            scope=str(body.get("scope") or ""),
        )

    def _authorize(self, request: httpx.Request, token: Token) -> httpx.Request:
        if token.bound and self._dpop_key is not None:
            request.headers["Authorization"] = f"DPoP {token.access_token}"
            request.headers["DPoP"] = dpop_proof(
                self._dpop_key,
                request.method,
                request.url,
                access_token=token.access_token,
                nonce=self._nonces.get(_origin(request.url)),
            )
        else:
            request.headers["Authorization"] = f"Bearer {token.access_token}"
            request.headers.pop("DPoP", None)
        return request

    def _remember_nonce(self, url: httpx.URL, response: httpx.Response) -> None:
        nonce = response.headers.get("DPoP-Nonce")
        if nonce:
            self._nonces[_origin(url)] = nonce


def _default_audience(token_url: httpx.URL) -> str:
    match = _GATEWAY_TOKEN_PATH.match(token_url.path)
    if match is None:
        return str(token_url)
    return str(token_url.copy_with(path=match.group(1), query=None, fragment=None))


def _retry_after(response: httpx.Response) -> float | None:
    """The seconds a Retry-After header asks to wait (RFC 9110 section
    10.2.3): delay-seconds or an HTTP-date."""
    value = response.headers.get("Retry-After", "").strip()
    if not value:
        return None
    if value.isascii() and value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        # A -0000 zone parses naive; HTTP-dates are in GMT.
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, when.timestamp() - time.time())


def _origin(url: httpx.URL) -> str:
    return f"{url.scheme}://{url.netloc.decode('ascii')}"


def _challenge_error(response: httpx.Response) -> str:
    for challenge in response.headers.get_list("WWW-Authenticate"):
        match = _CHALLENGE_ERROR.search(challenge)
        if match:
            return match.group(1)
    return ""


def _json_error(response: httpx.Response) -> str:
    try:
        body = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ""
    return str(body.get("error", "")) if isinstance(body, dict) else ""
