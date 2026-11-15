"""Certificate validation and CSR generation (Settings → Certificates & Domain), against a generated test PKI."""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from exposurecatalyst.security import certs

NOW = dt.datetime.now(dt.UTC)
FQDN = "excat.corp.example"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn, key, issuer=None, issuer_key=None, path_len=None):
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(issuer.subject if issuer else _name(cn))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - dt.timedelta(days=30)).not_valid_after(NOW + dt.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False, key_agreement=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if issuer is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


def _leaf(issuer, issuer_key, *, names=(FQDN,), key=None, days=(-1, 90), hash_alg=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(names[0] if names else "no-san")).issuer_name(issuer.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW + dt.timedelta(days=days[0])).not_valid_after(NOW + dt.timedelta(days=days[1]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    if names:
        cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    return cert.sign(issuer_key, hash_alg or hashes.SHA256()), key


@pytest.fixture(scope="module")
def pki():
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = _ca("Test Root CA", root_key)
    int_key = ec.generate_private_key(ec.SECP256R1())
    inter = _ca("Test Issuing CA", int_key, root, root_key, path_len=0)
    return {"root": root, "root_key": root_key, "int": inter, "int_key": int_key}


def pem(*items) -> bytes:
    out = b""
    for i in items:
        out += (i.public_bytes(serialization.Encoding.PEM) if isinstance(i, x509.Certificate) else certs.key_pem(i))
    return out


def check(pki, leaf, key, chain=None, fqdn=FQDN, roots=None):
    bundle = certs.parse_pem(pem(leaf), pem(key), pem(*(chain if chain is not None else [pki["int"]])))
    return bundle, certs.validate(bundle, fqdn, trusted_roots=[pki["root"]] if roots is None else roots,
                                  include_public_roots=False)


def test_good_certificate_builds_chain_and_drops_root(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"])
    bundle, r = check(pki, leaf, key, chain=[pki["int"], pki["root"]])
    assert r.ok, r.errors
    assert r.info["covers_fqdn"] and r.info["chain"][-1] == "CN=Test Root CA"
    assert [c.subject for c in bundle.chain] == [pki["int"].subject]  # root not served
    assert bundle.fullchain_pem().count(b"BEGIN CERTIFICATE") == 2


def test_wildcard_covers_single_label_only(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"], names=("*.corp.example",))
    assert check(pki, leaf, key)[1].ok
    assert not check(pki, leaf, key, fqdn="a.b.corp.example")[1].ok


def test_expired_and_not_yet_valid(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"], days=(-100, -1))
    assert any("expired" in e for e in check(pki, leaf, key)[1].errors)
    leaf, key = _leaf(pki["int"], pki["int_key"], days=(5, 100))
    assert any("not valid until" in e for e in check(pki, leaf, key)[1].errors)


def test_soon_expiring_is_a_warning(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"], days=(-1, 5))
    r = check(pki, leaf, key)[1]
    assert r.ok and any("expires in" in w for w in r.warnings)


def test_mismatched_key(pki):
    leaf, _ = _leaf(pki["int"], pki["int_key"])
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(certs.CertError, match="does not match"):
        certs.parse_pem(pem(leaf), pem(other))


def test_incomplete_chain(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"])
    r = check(pki, leaf, key, chain=[])[1]
    assert not r.ok and "does not build to a trusted root" in r.errors[0]


def test_untrusted_root_rejected_unless_supplied_or_uploaded(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"])
    assert not check(pki, leaf, key, roots=[])[1].ok  # root unknown
    _, r = check(pki, leaf, key, chain=[pki["int"], pki["root"]], roots=[])  # root in the upload → warning
    assert r.ok and any("browsers must already trust it" in w for w in r.warnings)


def test_san_mismatch(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"], names=("other.corp.example",))
    r = check(pki, leaf, key)[1]
    assert not r.ok and "do not cover excat.corp.example" in r.errors[0]


def test_no_san_rejected(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"], names=())
    assert any("no Subject Alternative Names" in e for e in check(pki, leaf, key)[1].errors)


def test_weak_key_and_sha1_rejected(pki):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    leaf, key = _leaf(pki["int"], pki["int_key"], key=weak)
    assert any("1024 bits" in e for e in check(pki, leaf, key)[1].errors)
    # cryptography ≥ 44 cannot even create SHA-1 signatures, so a stand-in intermediate reports SHA-1
    class Sha1Intermediate:
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            return getattr(self._real, name)

        signature_hash_algorithm = hashes.SHA1()

    leaf, key = _leaf(pki["int"], pki["int_key"])
    b = certs.Bundle(leaf, [Sha1Intermediate(pki["int"])], key)
    assert any("SHA1" in e for e in certs.validate(b, FQDN, trusted_roots=[pki["root"]]).errors)


def test_self_signed_and_ca_leaf_rejected(pki):
    k = ec.generate_private_key(ec.SECP256R1())
    self_signed, _ = _leaf(_ca(FQDN, k), k, key=k)
    assert any("self-signed" in e for e in certs.validate(certs.Bundle(self_signed, [], k), FQDN).errors)
    assert any("CA certificate" in e for e in certs.validate(certs.Bundle(pki["int"], [], pki["int_key"]), FQDN).errors)


def test_single_bundle_and_encrypted_key(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"])
    enc = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(b"key-pass"))
    with pytest.raises(certs.CertError, match="encrypted"):
        certs.parse_pem(pem(leaf) + enc)
    b = certs.parse_pem(pem(pki["int"]) + enc + pem(leaf), key_password=b"key-pass")  # any order in one file
    assert b.leaf.subject == leaf.subject and certs.validate(b, FQDN, trusted_roots=[pki["root"]],
                                                           include_public_roots=False).ok
    with pytest.raises(certs.CertError, match="no private key"):
        certs.parse_pem(pem(leaf))


def test_pkcs12(pki):
    leaf, key = _leaf(pki["int"], pki["int_key"])
    p12 = pkcs12.serialize_key_and_certificates(b"excat", key, leaf, [pki["int"]],
                                                serialization.BestAvailableEncryption(b"pfx-pass"))
    b = certs.parse_pkcs12(p12, b"pfx-pass")
    assert certs.validate(b, FQDN, trusted_roots=[pki["root"]], include_public_roots=False).ok
    with pytest.raises(certs.CertError, match="wrong password"):
        certs.parse_pkcs12(p12, b"nope")


def test_upload_size_limit():
    with pytest.raises(certs.CertError, match="too large"):
        certs.parse_pem(b"x" * (certs.MAX_UPLOAD_BYTES + 1))


def test_ca_bundle_requires_ca_certs(pki):
    assert len(certs.parse_ca_bundle(pem(pki["root"], pki["int"]))) == 2
    leaf, _ = _leaf(pki["int"], pki["int_key"])
    with pytest.raises(certs.CertError, match="not a CA"):
        certs.parse_ca_bundle(pem(leaf))


@pytest.mark.parametrize("key_type,expect", [("rsa-2048", ("RSA", 2048)), ("rsa-3072", ("RSA", 3072)),
                                             ("ecdsa-p256", ("ECDSA secp256r1", 256)),
                                             ("ecdsa-p384", ("ECDSA secp384r1", 384))])
def test_csr_generation(key_type, expect):
    key = certs.generate_key(key_type)
    csr = x509.load_pem_x509_csr(certs.build_csr(key, FQDN, ["alt.corp.example", "10.0.0.5"], organization="Acme",
                                                 country="us"))
    assert csr.is_signature_valid and certs.key_description(csr.public_key()) == expect
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == [FQDN, "alt.corp.example"]
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["10.0.0.5"]
    assert csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "US"


def test_csr_rejects_bad_input():
    with pytest.raises(certs.CertError):
        certs.generate_key("rsa-1024")
    with pytest.raises(certs.CertError, match="two-letter"):
        certs.build_csr(certs.generate_key("ecdsa-p256"), FQDN, [], country="USA")
