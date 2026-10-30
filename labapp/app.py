"""A small, intentionally-vulnerable Flask app for local testing only.

Routes are designed to deterministically trigger BugPilot's existing
detectors (misconfig, xss, idor, cors_misconfig, open_redirect, csrf) so
they can be exercised end-to-end against a real HTTP server without ever
touching a third-party or production target.

DO NOT deploy this app or expose it beyond localhost. It has no
authentication, no input sanitization, and no security headers by design.

Run standalone:

    python -m labapp.app [port]

Or import `app` / `run_in_thread` from tests to boot it on an ephemeral
port for integration testing.
"""

import sys
import threading
from urllib.parse import urlencode
from wsgiref.simple_server import WSGIRequestHandler, make_server

from flask import Flask, request, redirect, abort

app = Flask(__name__)

_ITEMS = {
    1: "Blue Widget (owner: alice)",
    2: "Red Widget (owner: bob)",
    3: "Green Widget (owner: carol)",
}


@app.route("/")
def index():
    links = [
        ("/search?" + urlencode({"q": "hello"}), "Search"),
        ("/item?" + urlencode({"id": "1"}), "Item #1"),
        ("/api", "API"),
        ("/go?" + urlencode({"redirect": "https://example.org"}), "External link"),
        ("/login", "Login"),
    ]
    body = "<h1>BugPilot Lab App</h1><ul>"
    for href, label in links:
        body += f'<li><a href="{href}">{label}</a></li>'
    body += "</ul>"
    return body


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Intentionally vulnerable: reflects input without escaping.
    return f"<html><body><p>Search results for: {q}</p></body></html>"


@app.route("/item")
def item():
    raw_id = request.args.get("id", "")
    if not raw_id.isdigit():
        abort(400)
    item_id = int(raw_id)
    # Intentionally vulnerable: no ownership/authorization check -- any
    # sequential id returns that item's details.
    name = _ITEMS.get(item_id, f"Unknown item #{item_id}")
    return f"<html><body><p>Item {item_id}: {name}</p></body></html>"


@app.route("/api")
def api():
    origin = request.headers.get("Origin", "*")
    resp = app.make_response('{"status": "ok"}')
    resp.headers["Content-Type"] = "application/json"
    # Intentionally vulnerable: reflects any Origin and allows credentials.
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/go")
def go():
    target = request.args.get("redirect", "/")
    # Intentionally vulnerable: redirects to any attacker-supplied URL
    # without validating it against an allowlist.
    return redirect(target, code=302)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return "<html><body><p>Login submitted.</p></body></html>"
    # Intentionally vulnerable: POST form with no anti-CSRF token field.
    return (
        "<html><body>"
        '<form method="post" action="/login">'
        '<input type="text" name="username">'
        '<input type="password" name="password">'
        '<button type="submit">Log in</button>'
        "</form>"
        "</body></html>"
    )


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, fmt, *args):
        pass


def run_in_thread(host="127.0.0.1", port=0):
    """Start the app on a background thread and return (server, thread, base_url)."""
    server = make_server(host, port, app, handler_class=_QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://{host}:{server.server_port}"
    return server, thread, base_url


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    app.run(host="127.0.0.1", port=port)
