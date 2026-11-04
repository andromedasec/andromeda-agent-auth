"""andromeda-agent-auth: keys, client ID metadata documents and tokens.

    andromeda-agent-auth keygen --out agent-key.pem
    andromeda-agent-auth jwk agent-key.pem
    andromeda-agent-auth metadata --client-id https://agents.example/bot.json --key agent-key.pem
    andromeda-agent-auth jwks agent-key.pem
    andromeda-agent-auth token --token-url https://api.example/oauth/token \\
        --client-id <client id> --key agent-key.pem [--resource <gateway URL>] [--wait 600]
    andromeda-agent-auth token --resource <gateway URL> --client-id <client id> --key agent-key.pem
        (no --token-url: the token endpoint is found from the gateway's metadata)
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import httpx

from . import keys
from .auth import AgentAuth, RegistrationPending, TokenError
from .discovery import DiscoveryError, discover_authorization_server
from .metadata import client_metadata, encode, jwk_set


def _keygen(args: argparse.Namespace) -> int:
    signer = keys.generate(args.alg)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(signer.private_pem())
    print(json.dumps({"kid": signer.kid, "alg": signer.alg, "public_jwk": signer.public_jwk()}, indent=2))
    print(f"private key written to {args.out}; register the public_jwk above on the agent's client", file=sys.stderr)
    return 0


def _jwk(args: argparse.Namespace) -> int:
    signer = keys.load_file(args.key, alg=args.alg)
    print(json.dumps({"kid": signer.kid, "alg": signer.alg, "public_jwk": signer.public_jwk()}, indent=2))
    return 0


def _metadata(args: argparse.Namespace) -> int:
    try:
        signers = [keys.load_file(k) for k in args.key] if args.key else None
        doc = client_metadata(
            args.client_id,
            keys=signers,
            jwks_uri=args.jwks_uri,
            client_name=args.name,
            client_uri=args.client_uri,
            software_id=args.software_id,
            software_version=args.software_version,
            contacts=args.contact,
        )
    except (OSError, TypeError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 2
    print(encode(doc).decode())
    print(f"publish this at {args.client_id}, served as application/json", file=sys.stderr)
    return 0


def _jwks(args: argparse.Namespace) -> int:
    print(json.dumps(jwk_set([keys.load_file(k) for k in args.key]), indent=2))
    return 0


def _token(args: argparse.Namespace) -> int:
    signer = keys.load_file(args.key, alg=args.alg) if args.key else keys.load_env()
    token_url, audience = args.token_url, None
    if not token_url:
        if not args.resource:
            print("pass --token-url, or --resource to find the token endpoint from the gateway's metadata", file=sys.stderr)
            return 2
        try:
            server = discover_authorization_server(args.resource)
        except DiscoveryError as e:
            print(f"finding the token endpoint from {args.resource}: {e}", file=sys.stderr)
            return 1
        token_url, audience = server.token_endpoint, server.issuer
        print(f"token endpoint: {token_url}", file=sys.stderr)
    auth = AgentAuth(
        args.client_id, token_url, signer, scope=args.scope, dpop=not args.no_dpop, audience=audience, resource=args.resource
    )
    try:
        if args.wait:
            token = auth.wait_for_approval(timeout=args.wait, interval=args.interval)
        else:
            token = auth.fetch_token()
    except RegistrationPending as e:
        hint = f"still not approved after {args.wait:g} s" if args.wait else "try again once it is approved, or pass --wait"
        print(f"{e}\nthe client is registered; ask an administrator to approve it ({hint})", file=sys.stderr)
        return 3
    except TokenError as e:
        print(str(e), file=sys.stderr)
        return 1
    except httpx.TransportError as e:
        print(f"the token endpoint did not answer: {e}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "access_token": token.access_token,
                "token_type": token.token_type,
                "scope": token.scope,
                "dpop_jkt": auth.dpop_jkt if token.bound else None,
            },
            indent=2,
        )
    )
    if token.bound:
        print(
            "the token is bound to a key that existed only in this process; it is useful for inspection, not for calls",
            file=sys.stderr,
        )
    return 0


def _positive(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be more than 0")
    return number


def _non_negative(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="andromeda-agent-auth", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate a private key and print its public JWK")
    p.add_argument("--out", required=True, help="where to write the private key (PEM, mode 0600; must not exist)")
    p.add_argument("--alg", choices=["EdDSA", "ES256"], default="EdDSA")
    p.set_defaults(run=_keygen)

    p = sub.add_parser("jwk", help="print the public JWK and kid of a private key")
    p.add_argument("key", help="PEM private key file")
    p.add_argument("--alg", help="RS256 or PS256 for an RSA key")
    p.set_defaults(run=_jwk)

    p = sub.add_parser("metadata", help="print a client ID metadata document for an agent that runs without a user")
    p.add_argument("--client-id", required=True, help="the https URL the document will be published at")
    keys_or_uri = p.add_mutually_exclusive_group(required=True)
    keys_or_uri.add_argument("--key", action="append", help="PEM private key whose public key goes in jwks (repeatable)")
    keys_or_uri.add_argument("--jwks-uri", help="publish the keys at this URL instead (same origin as --client-id)")
    p.add_argument("--name", help="client_name")
    p.add_argument("--client-uri")
    p.add_argument("--software-id")
    p.add_argument("--software-version")
    p.add_argument("--contact", action="append", help="contacts entry (repeatable)")
    p.set_defaults(run=_metadata)

    p = sub.add_parser("jwks", help="print a JWK Set of private keys' public keys, to serve at a jwks_uri")
    p.add_argument("key", nargs="+", help="PEM private key files")
    p.set_defaults(run=_jwks)

    p = sub.add_parser("token", help="get a token from the token endpoint")
    p.add_argument("--token-url", help="the token endpoint (default: found from --resource's metadata)")
    p.add_argument("--client-id", required=True)
    p.add_argument("--key", help="PEM private key file (default: ANDROMEDA_AGENT_PRIVATE_KEY[_FILE])")
    p.add_argument("--alg", help="RS256 or PS256 for an RSA key")
    p.add_argument("--scope")
    p.add_argument("--no-dpop", action="store_true", help="ask for a bearer token instead of a DPoP-bound one")
    p.add_argument("--resource", help="the agent gateway URL (RFC 8707); required for a client ID metadata document client")
    p.add_argument("--wait", type=_non_negative, default=0, help="seconds to keep asking while the registration awaits approval")
    p.add_argument("--interval", type=_positive, default=30, help="seconds between asks while waiting")
    p.set_defaults(run=_token)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
