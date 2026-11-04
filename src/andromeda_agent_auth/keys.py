"""Signing keys: generation, loading, public JWKs and RFC 7638 thumbprints.

A key is used through the Signer protocol, so a key held in a KMS or HSM can
stand in for a local one: it only has to report its algorithm and public JWK
and sign bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PrivateKey = ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey

# Algorithms the token endpoint accepts for client keys. DPoP proofs at the
# gateway are limited to ES256 and EdDSA.
CLIENT_KEY_ALGS = ("EdDSA", "ES256", "RS256", "PS256")
DPOP_ALGS = ("EdDSA", "ES256")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Signer(Protocol):
    """Anything that can sign a JWS: a local key, or a KMS/HSM-held one."""

    @property
    def alg(self) -> str:
        """The JWS alg this key signs with."""

    def public_jwk(self) -> dict:
        """The public key as a JWK, public members only."""

    def sign(self, data: bytes) -> bytes:
        """The JWS signature over data (raw r||s for ES256)."""


def thumbprint(jwk: dict) -> str:
    """RFC 7638 SHA-256 thumbprint of a public JWK, base64url.

    The registered key's id (kid) and a DPoP-bound token's cnf.jkt are both
    this value.
    """
    kty = jwk.get("kty")
    if kty == "OKP":
        members = {"crv": jwk["crv"], "kty": kty, "x": jwk["x"]}
    elif kty == "EC":
        members = {"crv": jwk["crv"], "kty": kty, "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        members = {"e": jwk["e"], "kty": kty, "n": jwk["n"]}
    else:
        raise ValueError(f"unsupported kty {kty!r}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def _int_bytes(n: int, length: int | None = None) -> bytes:
    length = length or (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


class LocalSigner:
    """A Signer over a private key held in this process."""

    def __init__(self, key: PrivateKey, alg: str | None = None):
        self._key = key
        self._alg = alg or _default_alg(key)
        _check_alg(key, self._alg)
        self._jwk = _public_jwk(key)

    @property
    def alg(self) -> str:
        return self._alg

    @property
    def kid(self) -> str:
        return thumbprint(self._jwk)

    def public_jwk(self) -> dict:
        return dict(self._jwk)

    def sign(self, data: bytes) -> bytes:
        key = self._key
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key.sign(data)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
            return _int_bytes(r, 32) + _int_bytes(s, 32)
        if self._alg == "PS256":
            return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    def private_pem(self) -> bytes:
        """The private key as unencrypted PKCS#8 PEM."""
        return self._key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )


def _default_alg(key: PrivateKey) -> str:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "EdDSA"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ES256"
    if isinstance(key, rsa.RSAPrivateKey):
        return "PS256"
    raise TypeError(f"unsupported key type {type(key).__name__}")


def _check_alg(key: PrivateKey, alg: str) -> None:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        ok = alg == "EdDSA"
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise TypeError("only P-256 EC keys are supported")
        ok = alg == "ES256"
    elif isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise ValueError("RSA keys must be at least 2048 bits")
        ok = alg in ("RS256", "PS256")
    else:
        raise TypeError(f"unsupported key type {type(key).__name__}")
    if not ok:
        raise ValueError(f"alg {alg} does not match a {type(key).__name__}")


def _public_jwk(key: PrivateKey) -> dict:
    pub = key.public_key()
    if isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": b64url(_int_bytes(nums.x, 32)), "y": b64url(_int_bytes(nums.y, 32))}
    nums = pub.public_numbers()
    return {"kty": "RSA", "n": b64url(_int_bytes(nums.n)), "e": b64url(_int_bytes(nums.e))}


def generate(alg: str = "EdDSA") -> LocalSigner:
    """A new key: Ed25519 for EdDSA (the default), P-256 for ES256."""
    if alg == "EdDSA":
        return LocalSigner(ed25519.Ed25519PrivateKey.generate())
    if alg == "ES256":
        return LocalSigner(ec.generate_private_key(ec.SECP256R1()))
    raise ValueError(f"generate supports EdDSA and ES256, not {alg!r}")


def load_pem(pem: bytes | str, password: bytes | None = None, alg: str | None = None) -> LocalSigner:
    """A signer from a PEM private key (PKCS#8, SEC1 or PKCS#1)."""
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    key = serialization.load_pem_private_key(pem, password=password)
    return LocalSigner(key, alg)  # type: ignore[arg-type]


def load_file(path: str | os.PathLike, password: bytes | None = None, alg: str | None = None) -> LocalSigner:
    return load_pem(Path(path).read_bytes(), password, alg)


def load_env(prefix: str = "ANDROMEDA_AGENT") -> LocalSigner:
    """A signer from the environment.

    Reads <prefix>_PRIVATE_KEY (the PEM itself) or <prefix>_PRIVATE_KEY_FILE
    (a path to it), and <prefix>_KEY_ALG when an RSA key should sign RS256.
    """
    alg = os.environ.get(f"{prefix}_KEY_ALG") or None
    pem = os.environ.get(f"{prefix}_PRIVATE_KEY")
    if pem:
        return load_pem(pem, alg=alg)
    path = os.environ.get(f"{prefix}_PRIVATE_KEY_FILE")
    if path:
        return load_file(path, alg=alg)
    raise LookupError(f"set {prefix}_PRIVATE_KEY or {prefix}_PRIVATE_KEY_FILE")
