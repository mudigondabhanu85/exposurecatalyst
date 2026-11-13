"""MIME construction, SMTP delivery, PDF rendering."""

from __future__ import annotations

import io
import smtplib
import socket
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

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
        if cfg.username and cfg.password:
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
