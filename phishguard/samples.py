"""Gera e-mails de exemplo (.eml) INOFENSIVOS: casos de phishing e legítimos, para testar."""
import os

PHISHING_BANK = """From: Banco Bradesco Seguranca <seguranca@bradesco-alertas.xyz>
Reply-To: suporte@contas-online.ru
To: cliente@exemplo.com
Subject: URGENTE: Sua conta sera bloqueada em 24 horas - Confirme seus dados
Date: Mon, 20 Oct 2026 09:12:00 -0300
Authentication-Results: mx.exemplo.com; spf=fail smtp.mailfrom=bradesco-alertas.xyz;
 dkim=none; dmarc=fail
Content-Type: text/html; charset=utf-8

<html><body>
<p>Prezado cliente,</p>
<p>Detectamos uma atividade suspeita. Sua conta sera <b>bloqueada</b> em 24 horas.</p>
<p>Para evitar o bloqueio, <b>clique aqui</b> e confirme seus dados imediatamente:</p>
<p><a href="http://191.101.22.14/bradesco/login.php">https://www.bradesco.com.br/login</a></p>
<p>Regularize sua pendencia com urgencia.</p>
</body></html>
"""

PHISHING_ATTACH = """From: "Setor Financeiro" <financeiro@gmail.com>
To: voce@empresa.com
Subject: Nota fiscal pendente - pagamento em atraso
Date: Tue, 21 Oct 2026 14:00:00 -0300
Authentication-Results: mx.empresa.com; spf=softfail; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/plain; charset=utf-8

Segue em anexo a nota fiscal. Abra o arquivo para regularizar o pagamento com urgencia.

--b1
Content-Type: application/octet-stream; name="nota_fiscal.pdf.exe"
Content-Disposition: attachment; filename="nota_fiscal.pdf.exe"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAA==
--b1--
"""

LEGIT = """From: Equipe GitHub <noreply@github.com>
Reply-To: noreply@github.com
To: brenno@exemplo.com
Subject: [GitHub] Um novo login na sua conta
Date: Wed, 21 Oct 2026 10:00:00 -0300
Authentication-Results: mx.exemplo.com; spf=pass smtp.mailfrom=github.com;
 dkim=pass header.d=github.com; dmarc=pass
Content-Type: text/html; charset=utf-8

<html><body>
<p>Ola Brenno,</p>
<p>Detectamos um novo login na sua conta a partir de um novo dispositivo.</p>
<p>Se foi voce, nenhuma acao e necessaria. Caso contrario, revise sua seguranca:</p>
<p><a href="https://github.com/settings/security">https://github.com/settings/security</a></p>
<p>Equipe GitHub</p>
</body></html>
"""

LEGIT_NEWSLETTER = """From: Loja Nerd Drip <contato@nerddrip.com.br>
To: cliente@exemplo.com
Subject: Novidades da semana - novos drops chegaram!
Date: Mon, 20 Oct 2026 08:00:00 -0300
Authentication-Results: mx.exemplo.com; spf=pass; dkim=pass header.d=nerddrip.com.br; dmarc=pass
Content-Type: text/html; charset=utf-8

<html><body>
<p>Confira os novos lancamentos:</p>
<p><a href="https://nerddrip.com.br/novidades">Ver novidades</a></p>
</body></html>
"""

SAMPLES = {
    "phishing_banco.eml": PHISHING_BANK,
    "phishing_anexo.eml": PHISHING_ATTACH,
    "legitimo_github.eml": LEGIT,
    "legitimo_newsletter.eml": LEGIT_NEWSLETTER,
}


def write_samples(directory):
    os.makedirs(directory, exist_ok=True)
    created = []
    for name, content in SAMPLES.items():
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        created.append(path)
    return created
