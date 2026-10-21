"""Pontuação de risco e veredito a partir dos findings."""

SEV_LABEL = {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "info": "Info"}


def score(findings):
    total = min(100, sum(f.weight for f in findings))
    if total >= 70 or any(f.severity == "critical" for f in findings):
        verdict, level = "Phishing muito provável", "critical"
    elif total >= 40:
        verdict, level = "Alta suspeita de phishing", "high"
    elif total >= 18:
        verdict, level = "Alguns sinais suspeitos", "medium"
    elif total > 0:
        verdict, level = "Poucos sinais, provavelmente legítimo", "low"
    else:
        verdict, level = "Nenhum sinal de phishing detectado", "info"
    return {"score": total, "verdict": verdict, "level": level}


def build_result(email, findings):
    s = score(findings)
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings = sorted(findings, key=lambda x: -order.get(x.severity, 0))
    return {
        "score": s["score"],
        "verdict": s["verdict"],
        "level": s["level"],
        "summary": {
            "from": f"{email['from_name']} <{email['from_addr']}>".strip(),
            "from_domain": email["from_domain"],
            "subject": email["subject"],
            "date": email["date"],
            "urls": len(email["urls"]),
            "attachments": len(email["attachments"]),
            "has_html": email["has_html"],
        },
        "findings": [f.to_dict() for f in findings],
        "urls": email["urls"][:30],
        "attachments": email["attachments"],
    }
