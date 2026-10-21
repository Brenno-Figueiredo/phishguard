"""Linha de comando do PhishGuard."""
import argparse
import json
import sys

from . import __version__
from .analysis import analyze
from .parser import parse_email
from .samples import write_samples
from .score import SEV_LABEL, build_result


def build_parser():
    ap = argparse.ArgumentParser(
        prog="phishguard", description="Analisador de e-mails de phishing (.eml): cabeçalhos, SPF/DKIM/DMARC, "
        "URLs e anexos.")
    sub = ap.add_subparsers(dest="cmd")

    serve = sub.add_parser("serve", help="inicia a interface web + API REST")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8600)
    serve.add_argument("--no-browser", action="store_true")

    scan = sub.add_parser("scan", help="analisa um arquivo .eml pelo terminal")
    scan.add_argument("files", nargs="+")
    scan.add_argument("--json", action="store_true", help="saída em JSON")

    smp = sub.add_parser("samples", help="gera e-mails de exemplo (.eml)")
    smp.add_argument("--dir", default="samples")

    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def cmd_serve(args):
    from .server import serve
    serve(args.host, args.port, not args.no_browser)
    return 0


def cmd_scan(args):
    worst = 0
    for path in args.files:
        with open(path, "rb") as f:
            email = parse_email(f.read())
        result = build_result(email, analyze(email))
        worst = max(worst, result["score"])
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
            continue
        print(f"\n=== {path} ===")
        print(f"De: {result['summary']['from']}")
        print(f"Assunto: {result['summary']['subject']}")
        print(f"\nVEREDITO: {result['verdict']} (score {result['score']}/100)")
        if result["findings"]:
            print("\nSinais encontrados:")
            for fd in result["findings"]:
                print(f"  [{SEV_LABEL.get(fd['severity'], fd['severity'])}] {fd['title']}")
                if fd["detail"]:
                    print(f"      {fd['detail']}")
        print()
    return 1 if worst >= 40 else 0


def cmd_samples(args):
    created = write_samples(args.dir)
    print(f"{len(created)} e-mails de exemplo criados em '{args.dir}/':")
    for p in created:
        print("  " + p.rsplit("/", 1)[-1])
    return 0


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 0
    return {"serve": cmd_serve, "scan": cmd_scan, "samples": cmd_samples}[args.cmd](args)
