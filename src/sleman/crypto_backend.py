"""Primitif tanda tangan dan encoding kunci Sleman."""

import base64
import hashlib

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from .errors import FormatError

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
ECDSA = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
SPKI = ser.PublicFormat.SubjectPublicKeyInfo
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey


def generate_key(profile: str) -> PrivateKey:
    if profile == "rsa-pss-sha256":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if profile == "ecdsa-p256-sha256":
        return ec.generate_private_key(ec.SECP256R1())
    if profile == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise FormatError("profil kunci tidak didukung")


def profile_of(key: PublicKey) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size == 3072 and key.public_numbers().e == 65537:
            return "rsa-pss-sha256"
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        return "ecdsa-p256-sha256"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519"
    raise FormatError("tipe atau parameter kunci di luar profil")


def pem_der(data: bytes, label: bytes) -> bytes:
    lines = data.strip().splitlines()
    if (len(lines) < 3 or lines[0] != b"-----BEGIN " + label + b"-----"
            or lines[-1] != b"-----END " + label + b"-----"):
        raise FormatError("label PEM tidak sesuai")
    return base64.b64decode(b"".join(lines[1:-1]), validate=True)


def validate_public_key(public_key_pem: bytes) -> tuple[PublicKey, str, bytes]:
    try:
        der = pem_der(public_key_pem, b"PUBLIC KEY")
        key = ser.load_der_public_key(der)
        profile = profile_of(key)
        # Rebuild the public numbers to enforce the profile's SPKI encoding.
        if isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            key = key.public_numbers().public_key()
        if key.public_bytes(ser.Encoding.DER, SPKI) != der:
            raise FormatError("encoding SPKI di luar profil")
    except (UnsupportedAlgorithm, ValueError, TypeError) as exc:
        raise FormatError("kunci publik SPKI tidak valid") from exc
    return key, profile, der


def load_private_key(data: bytes) -> PrivateKey:
    try:
        pem_der(data, b"PRIVATE KEY")
        key = ser.load_pem_private_key(data, password=None)
        profile_of(key.public_key())
    except (UnsupportedAlgorithm, ValueError, TypeError) as exc:
        raise FormatError("kunci privat PKCS8 tidak valid atau di luar profil") from exc
    return key


def fingerprint(spki_der: bytes) -> str:
    return hashlib.sha256(spki_der).hexdigest()


def sign_message(key: PrivateKey, message: bytes) -> bytes:
    """Tandatangani byte manifest menggunakan kunci yang sudah divalidasi."""
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(message, PSS, hashes.SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        r, s = utils.decode_dss_signature(key.sign(message, ECDSA))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return key.sign(message)


def verify_signature(profile: str, public_key_object: PublicKey,
                     message: bytes, signature: bytes) -> bool:
    key = public_key_object
    try:
        if profile_of(key) != profile:
            return False
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, PSS, hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            if len(signature) != 64:
                return False
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            key.verify(utils.encode_dss_signature(r, s), message, ECDSA)
        else:
            key.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True
