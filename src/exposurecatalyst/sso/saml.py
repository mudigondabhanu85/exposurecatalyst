"""Okta SAML 2.0 service provider (python3-saml / OneLogin toolkit) with extra hardening.

* strict mode; signed assertions required; deprecated algorithms (SHA-1) rejected
* SP-initiated only by default: each AuthnRequest ID is stored and must match InResponseTo exactly once,
  within REQUEST_TTL; IdP-initiated responses are refused unless explicitly enabled
* assertion-ID replay cache until NotOnOrAfter
* the URL the toolkit validates Destination/Recipient against is built from EXCAT_PUBLIC_URL, never from
  request headers (no Host-header spoofing behind proxies)
* RelayState is an internal path only (no open redirect)
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from defusedxml import ElementTree as ET  # noqa: N817
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from sqlalchemy import delete
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.models import AppSetting, SamlAssertion, SamlRequest
from exposurecatalyst.security.crypto import get_secret_box

CFG_KEY, KEYS_KEY = "sso.saml", "sso.saml.sp_keys"
REQUEST_TTL = timedelta(minutes=10)
ACS_PATH, METADATA_PATH, LOGIN_PATH = "/api/auth/saml/acs", "/api/saml/metadata", "/api/auth/saml/login"
DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "idp_entity_id": "",
    "idp_sso_url": "",
    "idp_x509_cert": "",
    "sp_entity_id": "",
    "attr_email": "email",
    "attr_first_name": "firstName",
    "attr_last_name": "lastName",
    "attr_groups": "groups",
    "allow_idp_initiated": False,
    "jit_provisioning": True,
    "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
}
NS = {"p": "urn:oasis:names:tc:SAML:2.0:protocol"}


class SamlError(PermissionError):
    pass


def load_config(db: Session) -> dict[str, Any]:
    row = db.get(AppSetting, CFG_KEY)
    return {**DEFAULTS, **(row.value if row and row.value else {})}


def save_config(db: Session, cfg: dict[str, Any], actor: str) -> None:
    row = db.get(AppSetting, CFG_KEY)
    if row is None:
        db.add(AppSetting(key=CFG_KEY, value=cfg, updated_by=actor))
    else:
        row.value, row.updated_by = cfg, actor


def sp_keys(db: Session) -> tuple[str, str]:
    """Self-signed SP certificate + private key (Fernet-encrypted at rest), generated on first use."""
    row = db.get(AppSetting, KEYS_KEY)
    if row and row.value:
        return row.value["cert"], get_secret_box().decrypt(row.value["key_enc"])
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ExposureCatalyst SAML SP")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    value = {"cert": cert_pem, "key_enc": get_secret_box().encrypt(key_pem)}
    if row is None:
        db.add(AppSetting(key=KEYS_KEY, value=value, updated_by="system"))
    else:
        row.value = value
    db.flush()
    return cert_pem, key_pem


def _strip_pem(pem: str) -> str:
    return "".join(line for line in pem.strip().splitlines() if "-----" not in line)


def sp_urls(settings: Settings, cfg: dict[str, Any]) -> dict[str, str]:
    base = settings.public_url.rstrip("/")
    return {
        "entity_id": cfg.get("sp_entity_id") or f"{base}{METADATA_PATH}",
        "acs": f"{base}{ACS_PATH}",
        "metadata": f"{base}{METADATA_PATH}",
        "login": f"{base}{LOGIN_PATH}",
    }


def toolkit_settings(db: Session, settings: Settings, cfg: dict[str, Any], *, for_metadata: bool = False) -> dict:
    cert, key = sp_keys(db)
    urls = sp_urls(settings, cfg)
    sp = {
        "entityId": urls["entity_id"],
        "assertionConsumerService": {"url": urls["acs"], "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
        "NameIDFormat": cfg["name_id_format"],
        "x509cert": _strip_pem(cert),
        "privateKey": _strip_pem(key),
    }
    idp = {
        "entityId": cfg["idp_entity_id"] or "urn:unset",
        "singleSignOnService": {
            "url": cfg["idp_sso_url"] or "https://unset.invalid/sso",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "x509cert": _strip_pem(cfg["idp_x509_cert"] or ""),
    }
    return {
        "strict": True,
        "debug": False,
        "sp": sp,
        "idp": idp,
        "security": {
            "authnRequestsSigned": True,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameId": True,
            "wantAttributeStatement": True,
            "rejectDeprecatedAlgorithm": True,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            "requestedAuthnContext": False,
            "wantXMLValidation": True,
            "allowRepeatAttributeName": True,
        },
    }


def metadata_xml(db: Session, settings: Settings) -> str:
    s = OneLogin_Saml2_Settings(
        toolkit_settings(db, settings, load_config(db), for_metadata=True), sp_validation_only=True
    )
    xml = s.get_sp_metadata()
    errors = s.validate_metadata(xml)
    if errors:
        raise SamlError("invalid SP metadata: " + ", ".join(errors))
    return xml.decode() if isinstance(xml, bytes) else xml


def parse_idp_metadata(xml: str) -> dict[str, str]:
    data = OneLogin_Saml2_IdPMetadataParser.parse(xml)
    idp = data.get("idp", {})
    cert = idp.get("x509cert") or (idp.get("x509certMulti", {}).get("signing") or [""])[0]
    if not idp.get("entityId") or not idp.get("singleSignOnService", {}).get("url") or not cert:
        raise SamlError("metadata must contain an entityID, an SSO URL and a signing certificate")
    return {"idp_entity_id": idp["entityId"], "idp_sso_url": idp["singleSignOnService"]["url"], "idp_x509_cert": cert}


def _request_data(settings: Settings, path: str, get: dict | None = None, post: dict | None = None) -> dict:
    parts = urlsplit(settings.public_url)
    https = parts.scheme == "https"
    return {
        "https": "on" if https else "off",
        "http_host": parts.hostname,
        "server_port": str(parts.port or (443 if https else 80)),
        "script_name": path,
        "get_data": get or {},
        "post_data": post or {},
    }


def safe_relay(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value or "://" in value:
        return "/cves"
    return value[:500]


def login_url(db: Session, settings: Settings, next_path: str | None) -> str:
    cfg = load_config(db)
    if not cfg["enabled"]:
        raise SamlError("SAML single sign-on is not enabled")
    auth = OneLogin_Saml2_Auth(_request_data(settings, LOGIN_PATH), toolkit_settings(db, settings, cfg))
    relay = safe_relay(next_path)
    url = auth.login(return_to=relay)
    db.add(SamlRequest(id=auth.get_last_request_id(), relay_state=relay))
    db.execute(delete(SamlRequest).where(SamlRequest.created_at < utcnow() - timedelta(days=1)))
    db.commit()
    return url


def _in_response_to(saml_response_b64: str) -> str | None:
    try:
        root = ET.fromstring(base64.b64decode(saml_response_b64, validate=False))
    except Exception as exc:  # noqa: BLE001
        raise SamlError("malformed SAMLResponse") from exc
    if root.tag != "{urn:oasis:names:tc:SAML:2.0:protocol}Response":
        raise SamlError("not a SAML Response")
    return root.attrib.get("InResponseTo")


def consume(db: Session, settings: Settings, form: dict[str, str]) -> dict[str, Any]:
    """Validate an ACS POST. Returns {email, first_name, last_name, groups, name_id, relay}."""
    cfg = load_config(db)
    if not cfg["enabled"]:
        raise SamlError("SAML single sign-on is not enabled")
    raw = form.get("SAMLResponse") or ""
    if not raw or len(raw) > 200_000:
        raise SamlError("missing or oversized SAMLResponse")
    irt = _in_response_to(raw)
    req = None
    if irt:
        req = db.get(SamlRequest, irt)
        if req is None or req.used_at is not None or as_utc(req.created_at) < utcnow() - REQUEST_TTL:
            raise SamlError("unknown, expired or already-used AuthnRequest (InResponseTo)")
    elif not cfg["allow_idp_initiated"]:
        raise SamlError("IdP-initiated sign-in is disabled; start from the ExposureCatalyst login page")

    auth = OneLogin_Saml2_Auth(_request_data(settings, ACS_PATH, post=form), toolkit_settings(db, settings, cfg))
    auth.process_response(request_id=irt)
    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        raise SamlError(f"SAML validation failed: {', '.join(errors)} {auth.get_last_error_reason() or ''}".strip())

    assertion_id = auth.get_last_assertion_id()
    if not assertion_id or db.get(SamlAssertion, assertion_id) is not None:
        raise SamlError("assertion replay detected")
    noa = auth.get_last_assertion_not_on_or_after()
    db.add(
        SamlAssertion(
            id=assertion_id, not_on_or_after=datetime.fromtimestamp(noa, UTC) if noa else utcnow() + timedelta(hours=1)
        )
    )
    db.execute(delete(SamlAssertion).where(SamlAssertion.not_on_or_after < utcnow() - timedelta(days=1)))
    if req is not None:
        req.used_at = utcnow()

    attrs = auth.get_attributes()

    def first(name: str) -> str | None:
        v = attrs.get(cfg.get(name) or "")
        return str(v[0]).strip() if v else None

    email = (first("attr_email") or auth.get_nameid() or "").strip().lower()
    if "@" not in email or len(email) > 320:
        raise SamlError("assertion does not carry a valid email")
    return {
        "email": email,
        "name_id": auth.get_nameid(),
        "first_name": first("attr_first_name"),
        "last_name": first("attr_last_name"),
        "groups": list(attrs.get(cfg["attr_groups"], [])),
        "relay": safe_relay(req.relay_state if req else form.get("RelayState")),
    }
