"""API REST do PhishGuard + serve o frontend. Só biblioteca padrão."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .analysis import analyze
from .parser import parse_email
from .samples import SAMPLES
from .score import build_result

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
MAX_UPLOAD = 10 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "PhishGuard/" + __version__

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open(os.path.join(STATIC, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            except OSError:
                return self._send(404, b"no frontend")
        if self.path == "/favicon.ico":
            return self._send(204, b"")
        if self.path == "/api/samples":
            return self._json({"samples": list(SAMPLES.keys())})
        if self.path.startswith("/api/sample/"):
            name = self.path.rsplit("/", 1)[-1]
            if name in SAMPLES:
                return self._json({"name": name, "content": SAMPLES[name]})
            return self._json({"error": "amostra não encontrada"}, 404)
        if self.path == "/api/health":
            return self._json({"status": "ok", "version": __version__})
        self._json({"error": "rota não encontrada"}, 404)

    def do_POST(self):
        if self.path != "/api/analyze":
            return self._json({"error": "rota não encontrada"}, 404)
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_UPLOAD:
            return self._json({"error": "arquivo grande demais (máx 10 MB)"}, 413)
        raw = self.rfile.read(n) if n else b""
        if not raw.strip():
            return self._json({"error": "nenhum conteúdo de e-mail recebido"}, 400)
        try:
            email = parse_email(raw)
            result = build_result(email, analyze(email))
            return self._json(result)
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": f"falha ao analisar: {exc}"}, 500)


def serve(host="127.0.0.1", port=8600, open_browser=True):
    server = None
    for p in range(port, port + 10):
        try:
            server = ThreadingHTTPServer((host, p), Handler)
            port = p
            break
        except OSError:
            continue
    if not server:
        raise SystemExit("Nenhuma porta livre.")
    server.daemon_threads = True
    url = f"http://{host}:{port}"
    print(f"\n  PhishGuard v{__version__} rodando em {url}\n  Ctrl+C para encerrar.\n")
    if open_browser:
        import threading
        import webbrowser
        threading.Timer(0.8, webbrowser.open, [url]).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando...")
    finally:
        server.server_close()
