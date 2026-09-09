#!/usr/bin/env python3
"""Local demonstration API with synthetic data. Python 3; no dependencies."""
import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

CARDS = {
    "A100": {"cardId": "A100", "owner": "user-A", "label": "Cartão fictício A"},
    "B200": {"cardId": "B200", "owner": "user-B", "label": "Cartão fictício B"},
}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body):
        data = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def authenticated(self):
        return self.headers.get("Authorization") == "Bearer demo-A"

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/health":
            return self.reply(200, {"lab": "Semantic V2", "data": "synthetic"})
        if not self.authenticated():
            return self.reply(401, {"error": "Use Authorization: Bearer demo-A"})
        if parts.path not in ("/protected/cards", "/vulnerable/cards", "/charon/cards"):
            return self.reply(404, {"error": "route_not_found"})
        identifier = parse_qs(parts.query, keep_blank_values=True).get("cardId", [""])[0]
        if parts.path == "/charon/cards":
            try:
                header = self.headers.get("x-charon-params", "")
                try:
                    payload = json.loads(header)
                except json.JSONDecodeError:
                    payload = json.loads(base64.b64decode(header + "=" * (-len(header) % 4), altchars=b"-_", validate=True))
                identifier = payload["cardId"]
            except (ValueError, TypeError, KeyError):
                return self.reply(400, {"error": "invalid_charon"})
        if not isinstance(identifier, str) or not identifier.isalnum():
            return self.reply(400, {"error": "invalid_card_id"})
        card = CARDS.get(identifier)
        if card is None:
            return self.reply(404, {"error": "not_found"})
        if parts.path != "/vulnerable/cards" and card["owner"] != "user-A":
            return self.reply(403, {"error": "forbidden"})
        return self.reply(200, card)

    def do_POST(self):
        if not self.authenticated():
            return self.reply(401, {"error": "unauthorized"})
        if urlsplit(self.path).path != "/validate":
            return self.reply(404, {"error": "route_not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length < 65536:
                return self.reply(413, {"error": "body_size"})
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                return self.reply(400, {"error": "expected_object"})
            amount, active, name = body.get("amount"), body.get("active"), body.get("name")
            if type(amount) is not int or not 1 <= amount <= 100:
                return self.reply(422, {"error": "amount_must_be_integer_1_to_100"})
            if type(active) is not bool:
                return self.reply(422, {"error": "active_must_be_boolean"})
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
                return self.reply(422, {"error": "name_length_1_to_64"})
            return self.reply(200, {"accepted": body, "persisted": False})
        except (ValueError, UnicodeDecodeError):
            return self.reply(400, {"error": "invalid_json"})

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Laboratório local: http://127.0.0.1:{args.port}", flush=True)
    print("Token fictício: demo-A | IDs: A100 (usuário A), B200 (usuário B). Ctrl+C encerra.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
