"""TLS certificate parsing, validation and CSR generation for Settings → Certificates & Domain.

Validation before activation (all must pass):
* the private key matches the certificate
* the certificate is currently valid (not expired, not yet valid)
* the chain builds to a trusted root: the public roots (certifi), the uploaded *trusted CA bundle*, or a
  self-signed root included in the upload (accepted with a warning: clients must trust that root)
* the SANs cover the configured FQDN (wildcards per RFC 6125)
* key strength: RSA ≥ 2048 bits, ECDSA P-256/P-384/P-521, Ed25519
* no weak signature algorithms (MD5 / SHA-1) anywhere in the chain

Chain building and SAN matching use ``cryptography.x509.verification`` (webpki policy).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

MAX_UPLOAD_BYTES = 1_000_000
_KEY_LABEL = rb"(?:RSA |EC |ENCRYPTED )?PRIVATE KEY"
KEY_BLOCK = re.compile(rb"-----BEGIN " + _KEY_LABEL + rb"-----.+?-----END " + _KEY_LABEL + rb"-----", re.DOTALL)
MAX_CHAIN = 10
WEAK_HASHES = ("md5", "sha1")
KEY_TYPES = {"rsa-2048": ("rsa", 2048), "rsa-3072": ("rsa", 3072), "rsa-4096": ("rsa", 4096),
             "ecdsa-p256": ("ec", ec.SECP256R1), "ecdsa-p384": ("ec", ec.SECP384R1)}


class CertError(ValueError):
    """User-facing problem with an uploaded certificate, key or CSR request."""


@dataclass
class Bundle:
    leaf: x509.Certificate
    chain: list[x509.Certificate]
    key: Any  # private key object (never serialised back to the client)

    def fullchain_pem(self) -> bytes:
        return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in [self.leaf, *self.chain])

    def key_pem(self) -> bytes:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors


# ---- parsing ---------------------------------------------------------------------------------------------

def _size(*parts: bytes | None) -> None:
    if sum(len(p or b"") for p in parts) > MAX_UPLOAD_BYTES:
        raise CertError("upload too large (1 MB maximum)")


def _load_key(pem: bytes, password: bytes | None):
    try:
        return serialization.load_pem_private_key(pem, password=password or None)
    except TypeError as exc:
        raise CertError("the private key is encrypted: provide its password") from exc
    except ValueError as exc:
        raise CertError("could not read the private key (wrong password or not a PEM key)") from exc


def _certs_from_pem(data: bytes) -> list[x509.Certificate]:
    if b"-----BEGIN CERTIFICATE-----" not in data:
        return []
    try:
        return x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        raise CertError("could not parse a PEM certificate") from exc


def _pick_leaf(certs: list[x509.Certificate], key) -> tuple[x509.Certificate, list[x509.Certificate]]:
    if not certs:
        raise CertError("no certificate found")
    if len(certs) > MAX_CHAIN:
        raise CertError(f"too many certificates (maximum {MAX_CHAIN})")
    if key is not None:
        pub = _pub_der(key.public_key())
        for c in certs:
            if _pub_der(c.public_key()) == pub:
                return c, [x for x in certs if x is not c]
        raise CertError("the private key does not match any of the certificates")
    leaves = [c for c in certs if not _is_ca(c)]
    leaf = leaves[0] if leaves else certs[0]
    return leaf, [x for x in certs if x is not leaf]


def parse_pem(cert_pem: bytes, key_pem: bytes | None = None, chain_pem: bytes | None = None,
              key_password: bytes | None = None) -> Bundle:
    """Certificate + key + optional chain as separate files, or one bundle containing all of them."""
    _size(cert_pem, key_pem, chain_pem)
    blob = b"\n".join(p for p in (key_pem, cert_pem, chain_pem) if p)
    m = KEY_BLOCK.search(blob)
    key = _load_key(m.group(0), key_password) if m else None
    certs = _certs_from_pem(cert_pem) + _certs_from_pem(chain_pem or b"")
    if not certs and key_pem:
        certs = _certs_from_pem(key_pem)
    leaf, chain = _pick_leaf(_dedupe(certs), key)
    if key is None:
        raise CertError("no private key provided")
    return Bundle(leaf, _order_chain(leaf, chain), key)


def parse_pkcs12(data: bytes, password: bytes | None) -> Bundle:
    _size(data)
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, password or None)
    except ValueError as exc:
        raise CertError("could not open the PKCS#12 / PFX file (wrong password or corrupt file)") from exc
    if key is None or cert is None:
        raise CertError("the PKCS#12 file must contain the certificate and its private key")
    return Bundle(cert, _order_chain(cert, _dedupe(list(extra or []))), key)


def parse_ca_bundle(data: bytes) -> list[x509.Certificate]:
    _size(data)
    certs = _dedupe(_certs_from_pem(data))
    if not certs:
        raise CertError("no PEM certificates found in the CA bundle")
    for c in certs:
        if not _is_ca(c):
            raise CertError(f"{_cn(c)} is not a CA certificate (basicConstraints CA:TRUE required)")
    return certs


def _dedupe(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    seen, out = set(), []
    for c in certs:
        fp = c.fingerprint(hashes.SHA256())
        if fp not in seen:
            seen.add(fp)
            out.append(c)
    return out


def _order_chain(leaf: x509.Certificate, rest: list[x509.Certificate]) -> list[x509.Certificate]:
    """Leaf → issuer → issuer… (unrelated certificates kept at the end, then flagged by validation)."""
    ordered, pool, cur = [], list(rest), leaf
    while pool:
        nxt = next((c for c in pool if c.subject == cur.issuer and c is not cur), None)
        if nxt is None:
            break
        ordered.append(nxt)
        pool.remove(nxt)
        cur = nxt
    return ordered + pool


# ---- description -----------------------------------------------------------------------------------------

def _pub_der(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _is_ca(c: x509.Certificate) -> bool:
    try:
        return c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        return False


def _cn(c: x509.Certificate) -> str:
    attrs = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else c.subject.rfc4514_string()


def sans(c: x509.Certificate) -> list[str]:
    try:
        ext = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return []
    return [*ext.get_values_for_type(x509.DNSName), *(str(i) for i in ext.get_values_for_type(x509.IPAddress))]


def key_description(pub) -> tuple[str, int | None]:
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA {pub.curve.name}", pub.curve.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    return type(pub).__name__, None


def describe(c: x509.Certificate, now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.UTC)
    ktype, ksize = key_description(c.public_key())
    sig = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "none"
    return {
        "subject": c.subject.rfc4514_string(), "common_name": _cn(c), "issuer": c.issuer.rfc4514_string(),
        "serial": format(c.serial_number, "x"), "sans": sans(c),
        "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(),
        "days_left": (c.not_valid_after_utc - now).days, "key_type": ktype, "key_size": ksize,
        "signature_hash": sig, "fingerprint_sha256": c.fingerprint(hashes.SHA256()).hex(),
        "self_signed": c.issuer == c.subject,
    }


def fingerprint(c: x509.Certificate) -> str:
    return c.fingerprint(hashes.SHA256()).hex()


def san_covers(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in (n.lower().rstrip(".") for n in names):
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:] and not host.startswith("*"):
            return True
    return False


# ---- validation ------------------------------------------------------------------------------------------

def _key_problems(pub) -> list[str]:
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        return [f"RSA key is {pub.key_size} bits; at least 2048 is required"]
    if isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.key_size < 256:
        return [f"ECDSA curve {pub.curve.name} is too weak; use P-256 or stronger"]
    if not isinstance(pub, rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey):
        return [f"unsupported key type {type(pub).__name__}"]
    return []


def public_roots() -> list[x509.Certificate]:
    import certifi

    with open(certifi.where(), "rb") as fh:
        return x509.load_pem_x509_certificates(fh.read())


def validate(bundle: Bundle, fqdn: str | None, *, trusted_roots: list[x509.Certificate] | None = None,
             now: dt.datetime | None = None, include_public_roots: bool = True) -> Report:
    now = now or dt.datetime.now(dt.UTC)
    r = Report(info=describe(bundle.leaf, now))
    leaf = bundle.leaf
    if _pub_der(bundle.key.public_key()) != _pub_der(leaf.public_key()):
        r.errors.append("the private key does not match the certificate")
    if leaf.not_valid_after_utc <= now:
        r.errors.append(f"the certificate expired on {leaf.not_valid_after_utc:%Y-%m-%d}")
    elif leaf.not_valid_before_utc > now:
        r.errors.append(f"the certificate is not valid until {leaf.not_valid_before_utc:%Y-%m-%d}")
    elif (leaf.not_valid_after_utc - now).days < 14:
        r.warnings.append(f"the certificate expires in {(leaf.not_valid_after_utc - now).days} days")
    if _is_ca(leaf):
        r.errors.append("the certificate is a CA certificate, not a server certificate")
    if leaf.issuer == leaf.subject:
        r.errors.append("self-signed server certificates cannot be installed (the self-signed mode is "
                        "automatic); use a certificate signed by your CA")
    r.errors += _key_problems(leaf.public_key())
    for c in [leaf, *bundle.chain]:
        h = c.signature_hash_algorithm
        if h is not None and h.name in WEAK_HASHES:
            r.errors.append(f"{_cn(c)} is signed with {h.name.upper()}, which is not allowed")
    names = sans(leaf)
    if not names:
        r.errors.append("the certificate has no Subject Alternative Names (browsers ignore the CN)")
    if fqdn:
        if not san_covers(fqdn, names):
            r.errors.append(f"the SANs ({', '.join(names) or 'none'}) do not cover {fqdn}")
        r.info["covers_fqdn"] = san_covers(fqdn, names)
    if r.errors:
        return r

    # chain building (webpki): public roots + uploaded trusted CAs + self-signed roots included in the upload
    from cryptography.x509 import verification as v

    supplied_roots = [c for c in bundle.chain if c.issuer == c.subject and _is_ca(c)]
    intermediates = [c for c in bundle.chain if c not in supplied_roots]
    anchors = [*(public_roots() if include_public_roots else []), *(trusted_roots or []), *supplied_roots]
    if not anchors:
        r.errors.append("the chain does not build to a trusted root: no trusted roots are configured")
        return r
    try:
        builder = v.PolicyBuilder().store(v.Store(anchors)).time(now)
        target = fqdn or (names[0] if names else _cn(leaf))
        try:
            subject: Any = v.IPAddress(ipaddress.ip_address(target))
        except ValueError:
            subject = v.DNSName(target)
        path = builder.build_server_verifier(subject).verify(leaf, intermediates)
    except v.VerificationError as exc:
        msg = str(exc)
        if "candidates exhausted" in msg or "no valid" in msg.lower() or "issuer" in msg.lower():
            r.errors.append("the chain does not build to a trusted root: include the intermediate certificate(s), "
                            "or upload your internal root under Trusted CA bundle")
        else:
            r.errors.append(f"chain verification failed: {msg[:200]}")
        return r
    root = path[-1]
    r.info["chain"] = [describe(c, now)["subject"] for c in path]
    if any(root.fingerprint(hashes.SHA256()) == s.fingerprint(hashes.SHA256()) for s in supplied_roots) and not any(
            root.fingerprint(hashes.SHA256()) == t.fingerprint(hashes.SHA256()) for t in (trusted_roots or [])):
        r.warnings.append(f"the chain ends at {_cn(root)}, a root included in the upload: browsers must already "
                          "trust it (internal PKI)")
    unused = [c for c in intermediates if c not in path]
    if unused:
        r.warnings.append(f"{len(unused)} unrelated certificate(s) in the upload will be ignored")
    bundle.chain = [c for c in path[1:] if c.issuer != c.subject]  # serve leaf + intermediates, never the root
    return r


# ---- CSR -------------------------------------------------------------------------------------------------

def generate_key(key_type: str):
    if key_type not in KEY_TYPES:
        raise CertError(f"key type must be one of {', '.join(KEY_TYPES)}")
    kind, param = KEY_TYPES[key_type]
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=param)
    return ec.generate_private_key(param())


def build_csr(key, common_name: str, san_names: list[str], *, organization: str | None = None,
              org_unit: str | None = None, locality: str | None = None, state: str | None = None,
              country: str | None = None, email: str | None = None) -> bytes:
    if not common_name:
        raise CertError("common name is required")
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64])]
    for oid, value, limit in ((NameOID.ORGANIZATION_NAME, organization, 64),
                              (NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit, 64), (NameOID.LOCALITY_NAME, locality, 128),
                              (NameOID.STATE_OR_PROVINCE_NAME, state, 128), (NameOID.EMAIL_ADDRESS, email, 128)):
        if value:
            attrs.append(x509.NameAttribute(oid, value[:limit]))
    if country:
        if len(country) != 2 or not country.isalpha():
            raise CertError("country must be a two-letter ISO code")
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()))
    names: list[x509.GeneralName] = []
    for n in dict.fromkeys([common_name, *san_names]):
        n = n.strip().lower()
        if not n:
            continue
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            names.append(x509.DNSName(n))
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
           .add_extension(x509.SubjectAlternativeName(names), critical=False)
           .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
           .sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def public_key_id(pub) -> str:
    return hashlib.sha256(_pub_der(pub)).hexdigest()
