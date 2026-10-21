# PhishGuard

**Analisador de e-mails de phishing**, com API REST em Python e interface web. Você envia um e-mail (`.eml`),
e o PhishGuard verifica cabeçalhos, autenticação (SPF/DKIM/DMARC), links e anexos, e devolve um **veredito com
pontuação de risco** e a explicação de cada sinal encontrado.

Phishing é a porta de entrada mais comum de ataques, especialmente no setor financeiro. Esta ferramenta ajuda
a triar e-mails suspeitos de forma rápida e didática.

> Arquitetura full-stack: backend Python (API REST, sem dependências externas) + frontend web responsivo.

## O que ele detecta

| Categoria | Sinais |
|---|---|
| **Autenticação** | SPF, DKIM e DMARC com falha ou ausentes |
| **Falsificação de remetente** | nome de exibição imitando uma marca com e-mail gratuito; Reply-To e Return-Path divergentes |
| **Links** | texto do link que mente o destino, URL para IP cru, encurtadores, domínios punycode (xn--), termos sensíveis |
| **Marcas** | e-mail cita uma marca mas os links não vão ao site oficial |
| **Anexos** | executáveis (.exe, .scr...), documentos com macro (.docm), extensão dupla (`nota.pdf.exe`), compactados |
| **Engenharia social** | linguagem de urgência e pressão ("sua conta será bloqueada", "clique aqui") |

Cada sinal tem um peso; a soma vira uma pontuação de 0 a 100 e um veredito (de "legítimo" a "phishing muito provável").

## Como rodar

Requisito: Python 3.9+. Sem dependências externas.

```bash
# interface web + API REST
python app.py serve

# gerar e-mails de exemplo (phishing e legítimos, inofensivos)
python app.py samples

# analisar pelo terminal
python app.py scan samples/phishing_banco.eml
python app.py scan samples/*.eml
```

O painel abre em `http://127.0.0.1:8600`. Arraste um `.eml`, cole o conteúdo de um e-mail, ou clique num dos
exemplos. A análise roda localmente; nada é enviado para fora.

## API REST

| Método | Rota | Descrição |
|---|---|---|
| `POST` | `/api/analyze` | recebe o e-mail (texto no corpo) e devolve o veredito em JSON |
| `GET` | `/api/samples` | lista os e-mails de exemplo |
| `GET` | `/api/sample/<nome>` | conteúdo de um exemplo |
| `GET` | `/api/health` | status do serviço |

Exemplo de uso da API:
```bash
curl -X POST --data-binary @email.eml http://127.0.0.1:8600/api/analyze
```

Resposta (resumida):
```json
{
  "score": 100,
  "verdict": "Phishing muito provável",
  "level": "critical",
  "findings": [
    {"check": "auth", "title": "DMARC falhou (fail)", "severity": "high", "detail": "..."},
    {"check": "url", "title": "Texto do link mente o destino", "severity": "high", "detail": "..."}
  ]
}
```

## Estrutura

```
app.py                ponto de entrada (web ou terminal)
phishguard/
  parser.py           lê o .eml: cabeçalhos, corpo, URLs, anexos
  analysis.py         regras de detecção de phishing
  score.py            pontuação e veredito
  server.py           API REST + serve o frontend
  samples.py          e-mails de exemplo (inofensivos)
  cli.py              linha de comando
static/index.html     interface web (HTML/CSS/JS, responsiva)
samples/              e-mails de exemplo
tests/                testes automatizados
```

## Como funciona

1. **Parsing** (`parser.py`): o módulo `email` da biblioteca padrão lê o `.eml` e extrai cabeçalhos, corpo
   (texto e HTML), URLs e anexos. Os links HTML são extraídos como pares (texto, href) para comparar o que o
   link *mostra* com o que ele *faz*.
2. **Análise** (`analysis.py`): cada regra inspeciona um aspecto e, se encontra algo suspeito, gera um
   "finding" com peso e severidade.
3. **Pontuação** (`score.py`): a soma dos pesos vira a pontuação de risco e o veredito.
4. **Entrega** (`server.py`): o resultado sai como JSON pela API, e o frontend o mostra de forma visual.

## Segurança e privacidade

- O e-mail é apenas **lido**. Anexos nunca são abertos nem executados.
- A análise roda localmente; o conteúdo do e-mail não sai da sua máquina.
- E-mails reais podem conter dados pessoais: o `.gitignore` impede que arquivos `.eml` (fora os exemplos)
  subam ao GitHub.
- É uma ferramenta de apoio à decisão, não um veredito definitivo.

## Testes

```bash
python -m unittest discover -s tests -v
```

## Possíveis evoluções

- Frontend em Angular (consumindo esta mesma API REST)
- Consulta de reputação de URLs/domínios em serviços de threat intel
- Análise de cabeçalhos `Received` para rastrear a origem
- Suporte a lotes de e-mails e exportação de relatório
