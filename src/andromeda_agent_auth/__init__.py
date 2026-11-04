"""Key-bound OAuth for autonomous agents: private_key_jwt (RFC 7523) and DPoP
(RFC 9449) as an httpx.Auth, for a registered client or one identified by a
client ID metadata document."""

from . import keys
from .auth import AgentAuth, RegistrationPending, Token, TokenError
from .discovery import AuthorizationServer, DiscoveryError, discover_authorization_server, discover_token_endpoint
from .jws import client_assertion, dpop_proof
from .keys import LocalSigner, Signer, thumbprint
from .metadata import client_metadata, jwk_set

__all__ = [
    "AgentAuth",
    "AuthorizationServer",
    "DiscoveryError",
    "LocalSigner",
    "RegistrationPending",
    "Signer",
    "Token",
    "TokenError",
    "client_assertion",
    "client_metadata",
    "discover_authorization_server",
    "discover_token_endpoint",
    "dpop_proof",
    "jwk_set",
    "keys",
    "thumbprint",
]
