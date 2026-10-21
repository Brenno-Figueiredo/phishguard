#!/usr/bin/env python3
"""PhishGuard - analisador de e-mails de phishing.
Exemplos:
    python app.py serve                 # interface web + API REST
    python app.py scan samples/*.eml    # análise pelo terminal
    python app.py samples               # gera e-mails de exemplo
"""
import sys

from phishguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
