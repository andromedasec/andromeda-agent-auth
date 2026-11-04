import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_key(jwk: dict):
    if jwk["kty"] == "OKP":
        return ed25519.Ed25519PublicKey.from_public_bytes(b64d(jwk["x"]))
    nums = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64d(jwk["x"]), "big"), int.from_bytes(b64d(jwk["y"]), "big"), ec.SECP256R1()
    )
    return nums.public_key()


def verify_jws(token: str, jwk: dict | None = None) -> tuple[dict, dict]:
    """Verify a compact JWS with jwk (or the jwk in its header) and return its
    header and claims. Raises on a bad signature."""
    h, c, s = token.split(".")
    header = json.loads(b64d(h))
    key = public_key(jwk or header["jwk"])
    sig, data = b64d(s), f"{h}.{c}".encode()
    if header["alg"] == "EdDSA":
        key.verify(sig, data)
    elif header["alg"] == "ES256":
        assert len(sig) == 64, "ES256 signatures are raw r||s"
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        key.verify(der, data, ec.ECDSA(hashes.SHA256()))
    else:
        raise AssertionError(f"unexpected alg {header['alg']}")
    return header, json.loads(b64d(c))
