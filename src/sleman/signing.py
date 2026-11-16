"""Penulisan pasangan kunci, manifest canonical, dan bundle."""

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization as ser

from . import crypto_backend as crypto
from .errors import FormatError
from .formats import MAX_BUNDLE_BYTES, serialize_manifest_canonical


def keygen(profile: str, prefix: Path) -> str:
    key = crypto.generate_key(profile)
    public = key.public_key()
    outputs = [
        (Path(f"{prefix}.key.pem"), key.private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())),
        (Path(f"{prefix}.pub.pem"), public.public_bytes(ser.Encoding.PEM, crypto.SPKI)),
    ]
    prefix.parent.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        for path, data in outputs:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return crypto.fingerprint(public.public_bytes(ser.Encoding.DER, crypto.SPKI))


def make_manifest(key: crypto.PrivateKey, artifact: Path, package: str, version: str) -> bytes:
    public = key.public_key()
    digest = hashlib.sha256()
    size = 0
    with artifact.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return serialize_manifest_canonical({
        "schema": "minisign-manifest/v1",
        "package": package,
        "version": version,
        "algorithm": crypto.profile_of(public),
        "keyid": crypto.fingerprint(public.public_bytes(ser.Encoding.DER, crypto.SPKI)),
        "artifact": {"name": artifact.name, "size": size, "sha256": digest.hexdigest()},
    })


def sign_release(artifact: Path, package: str, version: str, key_path: Path, output: Path) -> None:
    key = crypto.load_private_key(key_path.read_bytes())
    manifest = make_manifest(key, artifact, package, version)
    signature = crypto.sign_message(key, manifest)
    bundle = json.dumps({
        "schema": "minisign-bundle/v1",
        "manifest_b64": base64.b64encode(manifest).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }, separators=(",", ":")).encode("ascii")
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise FormatError("bundle melebihi batas ukuran")
    with output.open("xb") as stream:
        try:
            stream.write(bundle)
            stream.flush()
        except OSError:
            stream.close()
            output.unlink(missing_ok=True)
            raise
