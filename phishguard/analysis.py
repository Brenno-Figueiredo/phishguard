"""Regras de detecção de phishing. Cada checagem gera 'findings' com peso de risco."""
import re

from .parser import ARCHIVE_EXT, DANGEROUS_EXT, MACRO_EXT, domain_of

FREE_MAIL = {"gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.com.br",
             "live.com", "icloud.com", "proton.me", "gmx.com", "mail.com", "bol.com.br"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
              "cutt.ly", "rb.gy", "shorturl.at", "encurtador.com.br"}
# marcas frequentemente falsificadas (exemplos; a lista real seria maior/configurável)
BRANDS = {
    "banco do brasil": "bb.com.br", "bradesco": "bradesco.com.br", "itau": "itau.com.br",
    "itaú": "itau.com.br", "caixa": "caixa.gov.br", "santander": "santander.com.br",
    "nubank": "nubank.com.br", "mercado livre": "mercadolivre.com.br", "mercado pago": "mercadopago.com.br",
    "netflix": "netflix.com", "microsoft": "microsoft.com", "apple": "apple.com",
    "google": "google.com", "amazon": "amazon.com", "paypal": "paypal.com",
    "receita federal": "gov.br", "serasa": "serasa.com.br", "correios": "correios.com.br",
}
URGENCY = [
    "urgente", "imediato", "suspens", "bloque/?ad", "bloqueio", "expirad", "última chance",
    "ultima chance", "verifique sua conta", "confirme seus dados", "clique aqui", "clique no link",
    "atualize seus dados", "regularize", "pendência", "pendencia", "você ganhou", "voce ganhou",
    "premi", "resgate", "evite o bloqueio", "ação necessária", "acao necessaria", "fatura em atraso",
    "verify your account", "suspended", "click here", "confirm your", "act now", "limited time",
]
SENSITIVE_URL = re.compile(r"(login|signin|secure|account|verify|update|senha|password|conta|banco|pix|cpf)", re.I)
IP_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")


class Finding:
    def __init__(self, check, title, severity, weight, detail="", evidence=""):
        self.check = check
        self.title = title
        self.severity = severity
        self.weight = weight
        self.detail = detail
        self.evidence = evidence

    def to_dict(self):
        return {k: getattr(self, k) for k in
                ("check", "title", "severity", "weight", "detail", "evidence")}


def analyze(email):
    f = []
    _auth(email, f)
    _from_spoofing(email, f)
    _reply_path(email, f)
    _brand_impersonation(email, f)
    _urls(email, f)
    _link_text_mismatch(email, f)
    _attachments(email, f)
    _urgency(email, f)
    return f


def _auth(email, f):
    ar = email["auth_results"].lower()
    if not ar:
        f.append(Finding("auth", "Sem resultados de autenticação", "low", 8,
                         "O e-mail não traz cabeçalho Authentication-Results; não dá para confirmar SPF/DKIM/DMARC.",
                         "Authentication-Results ausente"))
        return
    for proto, label in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
        m = re.search(proto + r"=(\w+)", ar)
        if not m:
            continue
        result = m.group(1)
        if result in ("fail", "softfail", "permerror", "temperror"):
            sev = "high" if proto == "dmarc" else "medium"
            w = 25 if proto == "dmarc" else 15
            f.append(Finding("auth", f"{label} falhou ({result})", sev, w,
                             f"A verificação {label} retornou '{result}', indício de remetente forjado.",
                             f"{proto}={result}"))


def _from_spoofing(email, f):
    name = (email["from_name"] or "").lower()
    dom = email["from_domain"]
    # nome de exibição cita marca, mas domínio é de e-mail gratuito
    for brand, real in BRANDS.items():
        if brand in name and dom in FREE_MAIL:
            f.append(Finding("spoofing", f"Nome de exibição imita '{brand}' mas usa e-mail gratuito",
                             "high", 25,
                             f"O remetente se apresenta como '{email['from_name']}', mas o domínio é {dom} "
                             f"(e-mail gratuito), não o oficial ({real}).",
                             f"From: {email['from_name']} <{email['from_addr']}>"))
            return
    if dom in FREE_MAIL and any(b in name for b in ("suporte", "atendimento", "seguran", "noreply", "no-reply")):
        f.append(Finding("spoofing", "Remetente 'oficial' usando e-mail gratuito", "medium", 12,
                         f"Nome sugere um canal oficial, mas o domínio {dom} é de e-mail gratuito.",
                         f"From: {email['from_name']} <{email['from_addr']}>"))


def _reply_path(email, f):
    frm = email["from_domain"]
    rt = email["reply_to_domain"]
    rp = email["return_path_domain"]
    if rt and frm and rt != frm:
        f.append(Finding("spoofing", "Reply-To difere do remetente", "medium", 14,
                         f"As respostas iriam para {rt}, diferente do domínio do remetente ({frm}). "
                         "Técnica comum para desviar respostas da vítima.",
                         f"From: {frm} | Reply-To: {rt}"))
    if rp and frm and rp != frm and rp not in FREE_MAIL:
        f.append(Finding("spoofing", "Return-Path difere do remetente", "low", 8,
                         f"O caminho de retorno ({rp}) não bate com o domínio do remetente ({frm}).",
                         f"From: {frm} | Return-Path: {rp}"))


def _brand_impersonation(email, f):
    text = f"{email['subject']} {email['text_body']} {email['html_body']}".lower()
    for brand, real in BRANDS.items():
        if brand in text:
            # a marca é citada; algum link aponta para fora do domínio oficial?
            bad = [u for u in email["urls"] if domain_of(u) and not _same_org(domain_of(u), real)]
            legit = [u for u in email["urls"] if _same_org(domain_of(u), real)]
            if bad and not legit:
                f.append(Finding("impersonation", f"Cita '{brand}' mas links não vão ao site oficial",
                                 "high", 20,
                                 f"O e-mail menciona {brand}, mas os links apontam para domínios que não são "
                                 f"{real}.",
                                 f"link suspeito: {bad[0][:80]}"))
            break


def _urls(email, f):
    for url in email["urls"]:
        dom = domain_of(url)
        if IP_URL.match(url):
            f.append(Finding("url", "Link aponta para um endereço IP", "high", 18,
                             "Links legítimos usam nomes de domínio; um IP cru é típico de phishing.",
                             url[:90]))
        if dom in SHORTENERS:
            f.append(Finding("url", f"Encurtador de URL ({dom})", "medium", 12,
                             "Encurtadores escondem o destino real do link.", url[:90]))
        if dom.startswith("xn--") or "xn--" in dom:
            f.append(Finding("url", "Domínio com caracteres internacionais (punycode)", "high", 18,
                             "Domínios punycode (xn--) são usados para imitar marcas com letras parecidas.",
                             dom))
        if SENSITIVE_URL.search(url) and dom not in FREE_MAIL:
            f.append(Finding("url", "Link com palavras sensíveis (login/senha/conta)", "low", 6,
                             "A URL contém termos típicos de páginas de captura de credenciais.",
                             url[:90]))


def _link_text_mismatch(email, f):
    for text, href in email["links"]:
        if not href.startswith("http"):
            continue
        shown = domain_of(text) if ("." in text and " " not in text.strip()) else ""
        # se o texto do link exibe um domínio, mas o href vai para outro
        m = re.search(r"([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)", text.lower())
        shown_dom = m.group(1) if m else shown
        href_dom = domain_of(href)
        if shown_dom and href_dom and not _same_org(shown_dom, href_dom):
            f.append(Finding("url", "Texto do link mente o destino", "high", 22,
                             f"O link exibe '{shown_dom}', mas na verdade leva a '{href_dom}'. "
                             "Enganação clássica de phishing.",
                             f"mostra {shown_dom} → vai para {href_dom}"))
            break


def _attachments(email, f):
    for att in email["attachments"]:
        ext = att["ext"]
        if ext in DANGEROUS_EXT:
            f.append(Finding("attachment", f"Anexo executável perigoso ({ext})", "critical", 30,
                             f"O anexo '{att['filename']}' é um executável, vetor comum de malware.",
                             att["filename"]))
        elif ext in MACRO_EXT:
            f.append(Finding("attachment", f"Documento com macros ({ext})", "high", 20,
                             f"'{att['filename']}' pode conter macros maliciosas.", att["filename"]))
        elif ext in ARCHIVE_EXT:
            f.append(Finding("attachment", f"Anexo compactado ({ext})", "medium", 10,
                             f"Arquivos compactados ('{att['filename']}') podem esconder executáveis.",
                             att["filename"]))
        if att["double_ext"]:
            f.append(Finding("attachment", "Anexo com extensão dupla", "high", 20,
                             f"'{att['filename']}' usa extensão dupla para disfarçar o tipo real.",
                             att["filename"]))


def _urgency(email, f):
    text = f"{email['subject']} {email['text_body']} {email['html_body']}".lower()
    hits = []
    for term in URGENCY:
        if re.search(term, text):
            hits.append(term.replace("/?", ""))
    if len(hits) >= 2:
        f.append(Finding("social", "Linguagem de urgência / isca", "medium", 12,
                         "O texto usa gatilhos de urgência e pressão, típicos de engenharia social.",
                         ", ".join(sorted(set(hits))[:6])))
    elif hits:
        f.append(Finding("social", "Possível isca de engenharia social", "low", 5,
                         "O texto contém ao menos um gatilho de urgência.", hits[0]))


def _same_org(a, b):
    """Compara os dois últimos rótulos do domínio (empresa.com == mail.empresa.com)."""
    if not a or not b:
        return False
    pa, pb = a.split("."), b.split(".")
    return pa[-2:] == pb[-2:]
