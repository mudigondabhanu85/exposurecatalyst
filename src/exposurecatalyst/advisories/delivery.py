"""MIME construction, mail delivery (SMTP, Microsoft 365 OAuth2, Amazon SES), PDF rendering.

Delivery methods (Settings → SMTP):

* **SMTP + password**: any relay, including Amazon SES's SMTP interface (SMTP credentials) and Microsoft 365
  where SMTP AUTH with a password is still allowed.
* **Microsoft 365 OAuth2**: SMTP AUTH ``XOAUTH2`` with an app-only token from Entra ID (client credentials,
  scope ``https://outlook.office365.com/.default``), the supported unattended method now that Exchange
  Online has retired basic authentication. The app needs ``SMTP.SendAsApp``, an Exchange service principal,
  and *Send As* / FullAccess on the sending mailbox.
* **Amazon SES API**: SESv2 ``SendEmail`` with the raw MIME message, using the default AWS credential chain
  (the ECS task role in the reference deployment), so no keys are stored in the application.
"""

from __future__ import annotations

import io
import re
import smtplib
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

import httpx

from exposurecatalyst.advisories.render import LOGO_CID, logo_bytes, render_html, render_text
from exposurecatalyst.advisories.service import clean_header
from exposurecatalyst.config import Settings
from exposurecatalyst.models import Advisory, Cve
from exposurecatalyst.security.ssrf import METADATA_HOSTS, UnsafeURLError, _ip_is_blocked

XLSX_MIME = ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@dataclass
class SmtpConfig:
    host: str
    port: int
    security: str  # starttls | ssl | none
    username: str | None
    password: str | None
    from_address: str
    from_name: str | None
    reply_to: str | None
    provider: str = "smtp"  # smtp | ses_api
    auth: str = "password"  # password | oauth2_m365 (provider smtp)
    m365_tenant_id: str | None = None
    m365_client_id: str | None = None
    m365_client_secret: str | None = None
    m365_cloud: str = "global"  # global | usgov
    ses_region: str | None = None
    ses_configuration_set: str | None = None


M365_LOGIN = {"global": "https://login.microsoftonline.com", "usgov": "https://login.microsoftonline.us"}
M365_SCOPE = {"global": "https://outlook.office365.com/.default", "usgov": "https://outlook.office365.us/.default"}
M365_SMTP_HOST = {"global": "smtp.office365.com", "usgov": "smtp.office365.us"}
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,99}$")
SES_REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
SES_MAX_RECIPIENTS = 50

# Test hooks
M365_TRANSPORT: httpx.BaseTransport | None = None
_token_cache: dict[tuple[str, str, str], tuple[str, float]] = {}
_token_lock = threading.Lock()


class MailConfigError(ValueError):
    """Configuration problem the admin can fix (shown verbatim)."""


def m365_token(cfg: SmtpConfig, settings: Settings) -> str:
    """App-only access token for SMTP XOAUTH2 (cached until 2 minutes before expiry)."""
    from exposurecatalyst.ingestion.http import SourceClient

    cloud = cfg.m365_cloud if cfg.m365_cloud in M365_LOGIN else "global"
    tenant, client_id = cfg.m365_tenant_id or "", cfg.m365_client_id or ""
    if not TENANT_RE.match(tenant) or not client_id or not cfg.m365_client_secret:
        raise MailConfigError("Microsoft 365 OAuth2 needs a tenant ID, client ID and client secret")
    key = (cloud, tenant, client_id)
    with _token_lock:
        hit = _token_cache.get(key)
        if hit and hit[1] > time.monotonic() + 120:
            return hit[0]
    host = M365_LOGIN[cloud].removeprefix("https://")
    client = SourceClient("m365-oauth", settings, rate=5, per=1.0, allowlist=[host], transport=M365_TRANSPORT,
                          timeout=settings.smtp_timeout_seconds)
    try:
        resp = client.request("POST", f"{M365_LOGIN[cloud]}/{tenant}/oauth2/v2.0/token", data={
            "grant_type": "client_credentials", "client_id": client_id, "client_secret": cfg.m365_client_secret,
            "scope": M365_SCOPE[cloud]}, headers={"Content-Type": "application/x-www-form-urlencoded"})
        body = resp.json()
    finally:
        client.close()
    token = body.get("access_token") if isinstance(body, dict) else None
    if not token:
        raise MailConfigError("Entra ID did not return an access token — check tenant, client ID and secret")
    with _token_lock:
        _token_cache[key] = (token, time.monotonic() + int(body.get("expires_in", 3599)))
    return token


def xoauth2(user: str, token: str) -> Callable[..., str]:
    """smtplib auth object: initial response, then an empty reply to a 334 error challenge (RFC 7628 §3.2.3)."""
    def respond(challenge: bytes | None = None) -> str:
        return "" if challenge else f"user={user}\x01auth=Bearer {token}\x01\x01"
    return respond


def _ses_client(region: str):  # pragma: no cover - patched in tests
    try:
        import boto3
    except ImportError as exc:
        raise MailConfigError('Amazon SES API needs boto3: pip install "exposurecatalyst[aws]"') from exc
    return boto3.client("sesv2", region_name=region)


def send_ses(msg: EmailMessage, recipients: list[str], cfg: SmtpConfig) -> str:
    region = cfg.ses_region or ""
    if not SES_REGION_RE.match(region):
        raise MailConfigError("Amazon SES region is invalid (e.g. us-east-1)")
    client = _ses_client(region)
    del msg["Bcc"]
    raw = msg.as_bytes()
    ids = []
    for i in range(0, len(recipients), SES_MAX_RECIPIENTS):  # SES limit: 50 recipients per message
        batch = recipients[i:i + SES_MAX_RECIPIENTS]
        kw = {"FromEmailAddress": cfg.from_address, "Destination": {"ToAddresses": batch},
              "Content": {"Raw": {"Data": raw}}}
        if cfg.ses_configuration_set:
            kw["ConfigurationSetName"] = cfg.ses_configuration_set
        ids.append(client.send_email(**kw)["MessageId"])
    return ", ".join(f"<{i}@email.amazonses.com>" for i in ids)


def build_message(adv: Advisory, cve: Cve | None, *, from_addr: str, from_name: str | None, reply_to: str | None,
                  xlsx: bytes | None, xlsx_name: str, draft: bool) -> EmailMessage:
    """multipart/mixed( multipart/alternative( text, multipart/related( html, logo[CID] ) ), xlsx ).

    draft=True → .eml for Outlook: X-Unsent: 1 so it opens as an editable, unsent draft.
    """
    msg = EmailMessage()
    msg["Subject"] = clean_header(adv.subject)
    msg["From"] = formataddr((clean_header(from_name or "ExposureCatalyst", 100), from_addr))
    if adv.to_addrs:
        msg["To"] = ", ".join(adv.to_addrs)
    if adv.cc_addrs:
        msg["Cc"] = ", ".join(adv.cc_addrs)
    if draft and adv.bcc_addrs:
        msg["Bcc"] = ", ".join(adv.bcc_addrs)  # kept in drafts; never sent as a header over SMTP
    if reply_to:
        msg["Reply-To"] = reply_to
    domain = from_addr.rsplit("@", 1)[-1]
    msg["Message-ID"] = make_msgid(idstring=adv.advisory_id, domain=domain)
    msg["X-ExposureCatalyst-Advisory-ID"] = adv.advisory_id
    if draft:
        msg["X-Unsent"] = "1"
    else:
        msg["Date"] = formatdate(localtime=False)

    msg.set_content(render_text(adv, cve))
    msg.add_alternative(render_html(adv, cve, logo_src=f"cid:{LOGO_CID}"), subtype="html")
    html_part = msg.get_payload()[1]
    html_part.add_related(logo_bytes(), maintype="image", subtype="png", cid=f"<{LOGO_CID}>",
                          filename="exposurecatalyst.png", disposition="inline")
    if xlsx is not None:
        msg.add_attachment(xlsx, maintype=XLSX_MIME[0], subtype=XLSX_MIME[1], filename=xlsx_name)
    return msg


def validate_smtp_host(host: str, port: int, settings: Settings) -> None:
    """SSRF guard for the admin-configured relay (it is an outbound connection we make)."""
    if port not in settings.smtp_port_list:
        raise UnsafeURLError(f"port {port} not allowed (EXCAT_SMTP_ALLOWED_PORTS)")
    h = host.strip().lower().rstrip(".")
    if not h or h in METADATA_HOSTS:
        raise UnsafeURLError("SMTP host not allowed")
    try:
        infos = socket.getaddrinfo(h, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"cannot resolve SMTP host '{h}'") from exc
    import ipaddress

    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%")[0])
        if str(addr) in METADATA_HOSTS or addr.is_link_local:
            raise UnsafeURLError("SMTP host resolves to a blocked address")
        if _ip_is_blocked(addr) and not settings.smtp_allow_private_hosts:
            raise UnsafeURLError("SMTP host is on a private network; set EXCAT_SMTP_ALLOW_PRIVATE_HOSTS=true "
                                 "if your relay is internal")


def send(msg: EmailMessage, recipients: list[str], cfg: SmtpConfig, settings: Settings) -> str:
    if cfg.provider == "ses_api":
        return send_ses(msg, recipients, cfg)
    if cfg.auth == "oauth2_m365" and cfg.security == "none":
        raise MailConfigError("Microsoft 365 OAuth2 requires STARTTLS or SSL/TLS")
    if cfg.security == "none" and not settings.smtp_allow_plaintext:
        raise ValueError("Plaintext SMTP is disabled (EXCAT_SMTP_ALLOW_PLAINTEXT)")
    validate_smtp_host(cfg.host, cfg.port, settings)
    ctx = ssl.create_default_context()  # certificate + hostname verification
    timeout = settings.smtp_timeout_seconds
    if cfg.security == "ssl":
        client: smtplib.SMTP = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=timeout, context=ctx)
    else:
        client = smtplib.SMTP(cfg.host, cfg.port, timeout=timeout)
    with client:
        client.ehlo()
        if cfg.security == "starttls":
            client.starttls(context=ctx)
            client.ehlo()
        if cfg.auth == "oauth2_m365":
            if not cfg.username:
                raise MailConfigError("Microsoft 365 OAuth2 needs the sending mailbox as the username")
            client.auth("XOAUTH2", xoauth2(cfg.username, m365_token(cfg, settings)))
        elif cfg.username and cfg.password:
            client.login(cfg.username, cfg.password)
        del msg["Bcc"]
        client.send_message(msg, from_addr=cfg.from_address, to_addrs=recipients)
    return str(msg["Message-ID"])


def render_pdf(html: str) -> bytes:
    from xhtml2pdf import pisa  # imported lazily: heavy dependency

    out = io.BytesIO()
    # link_callback blocks every external fetch: only data: URIs (the embedded logo) are resolvable.
    result = pisa.CreatePDF(html, dest=out, encoding="utf-8",
                            link_callback=lambda uri, rel: uri if uri.startswith("data:") else "")
    if result.err:
        raise RuntimeError("PDF rendering failed")
    return out.getvalue()
