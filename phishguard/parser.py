"""Leitura de um e-mail (.eml) e extração estruturada: cabeçalhos, corpo, URLs e anexos.

Usa só a biblioteca padrão (módulo email). Nada é executado; o e-mail é apenas lido.
"""
import re
from email import message_from_bytes, message_from_string
from email.policy import default as default_policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.I)
DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".jar", ".msi", ".lnk", ".reg", ".hta", ".cpl",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlm"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img", ".gz"}


class _LinkParser(HTMLParser):
    """Extrai pares (texto visível, href) de links <a>, para detectar texto que mente o destino."""
    def __init__(self):
        super().__init__()
        self.links = []          # (texto, href)
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href", "")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(("".join(self._text).strip(), self._href))
            self._href = None


def _domain(value):
    """Extrai o domínio de um e-mail ou URL."""
    value = (value or "").strip().lower()
    if "@" in value and "://" not in value:
        return value.rsplit("@", 1)[-1].strip(">").strip()
    m = re.search(r"https?://([^/:\s]+)", value)
    if m:
        host = m.group(1)
        return host[4:] if host.startswith("www.") else host
    return value


def parse_email(data):
    """Recebe bytes ou str de um .eml e devolve um dicionário estruturado."""
    if isinstance(data, bytes):
        msg = message_from_bytes(data, policy=default_policy)
    else:
        msg = message_from_string(data, policy=default_policy)

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    received = [str(h) for h in msg.get_all("Received", [])]
    auth_results = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))

    text_body, html_body = _bodies(msg)
    links, attachments = _links_and_attachments(msg, html_body)
    urls = sorted(set(URL_RE.findall(text_body)) | set(URL_RE.findall(html_body)) |
                  {href for _, href in links if href.startswith("http")})

    return {
        "from_name": from_name,
        "from_addr": from_addr.lower(),
        "from_domain": _domain(from_addr),
        "reply_to": reply_to.lower(),
        "reply_to_domain": _domain(reply_to),
        "return_path": return_path.lower(),
        "return_path_domain": _domain(return_path),
        "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "received": received,
        "received_count": len(received),
        "auth_results": auth_results,
        "text_body": text_body,
        "html_body": html_body,
        "urls": urls[:100],
        "links": links[:100],
        "attachments": attachments,
        "has_html": bool(html_body),
    }


def _bodies(msg):
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_filename():
                continue
            ctype = part.get_content_type()
            try:
                payload = part.get_content()
            except Exception:  # noqa: BLE001
                payload = part.get_payload(decode=True)
                payload = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else str(payload)
            if ctype == "text/plain":
                text += payload if isinstance(payload, str) else ""
            elif ctype == "text/html":
                html += payload if isinstance(payload, str) else ""
    else:
        try:
            content = msg.get_content()
        except Exception:  # noqa: BLE001
            content = msg.get_payload()
        if msg.get_content_type() == "text/html":
            html = content if isinstance(content, str) else ""
        else:
            text = content if isinstance(content, str) else ""
    return text, html


def _links_and_attachments(msg, html_body):
    attachments = []
    for part in msg.walk():
        fname = part.get_filename()
        if not fname:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:  # noqa: BLE001
            payload = b""
        ext = ("." + fname.rsplit(".", 1)[-1].lower()) if "." in fname else ""
        attachments.append({
            "filename": fname,
            "content_type": part.get_content_type(),
            "size": len(payload),
            "ext": ext,
            "double_ext": _has_double_ext(fname),
        })
    p = _LinkParser()
    try:
        p.feed(html_body)
    except Exception:  # noqa: BLE001
        pass
    return p.links, attachments


def _has_double_ext(fname):
    parts = fname.lower().split(".")
    if len(parts) >= 3:
        middle = "." + parts[-2]
        if middle in {".pdf", ".doc", ".jpg", ".png", ".txt", ".xls"}:
            return True
    return False


def domain_of(value):
    return _domain(value)
