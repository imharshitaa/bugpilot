"""Secure backend runner for BugPilot web terminal."""

import asyncio
import json
import os
import shlex
import sys
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from core.utils import load_yaml


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bugpilot_cli.py"
ALLOWED_SUBCOMMANDS = {"scan", "crawl", "recon", "test", "exploit"}
MAX_COMMAND_LENGTH = 4096
SETTINGS = load_yaml(str(ROOT / "config" / "settings.yaml")) or {}
WEB_TERMINAL = SETTINGS.get("web_terminal", {})
RUN_TIMEOUT_SECONDS = int(os.getenv("BUGPILOT_RUN_TIMEOUT", "1800"))
RUNNER_TOKEN = os.getenv("BUGPILOT_RUNNER_TOKEN", WEB_TERMINAL.get("runner_token", "")).strip()
DEMO_MODE = os.getenv(
    "BUGPILOT_DEMO_MODE",
    str(WEB_TERMINAL.get("demo_mode", True)).lower(),
).strip().lower() in {"1", "true", "yes", "on"}
DEMO_ALLOWED_TARGETS = [
    item.strip().rstrip("/")
    for item in (
        os.getenv("BUGPILOT_DEMO_ALLOWED_TARGETS", "")
        or ",".join(WEB_TERMINAL.get("demo_allowed_targets", []))
    ).split(",")
    if item.strip()
]
ORIGINS = [
    item.strip()
    for item in os.getenv("BUGPILOT_ALLOWED_ORIGINS", "*").split(",")
    if item.strip()
]

app = FastAPI(title="BugPilot Runner API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ORIGINS == ["*"] else ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

run_lock = asyncio.Lock()


def _is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _validate_command(raw: str):
    if not raw or len(raw) > MAX_COMMAND_LENGTH:
        raise ValueError("Command is empty or too long.")

    try:
        tokens = shlex.split(raw)
    except Exception as exc:
        raise ValueError(f"Invalid command format: {exc}") from exc

    if len(tokens) < 2:
        raise ValueError("Use: bugpilot <scan|crawl|recon|test|exploit> [target]")
    if tokens[0] != "bugpilot":
        raise ValueError("Only bugpilot commands are allowed.")
    if tokens[1] == "expoit":
        tokens[1] = "exploit"
    if tokens[1] not in ALLOWED_SUBCOMMANDS:
        raise ValueError(f"Subcommand '{tokens[1]}' is not allowed.")

    sub = tokens[1]
    if sub in {"crawl", "recon", "test", "exploit"}:
        if len(tokens) < 3 or not _is_http_url(tokens[2]):
            raise ValueError(f"'{sub}' requires a valid URL target.")
    if sub == "scan":
        if len(tokens) >= 3 and tokens[2].startswith("http"):
            if not _is_http_url(tokens[2]):
                raise ValueError("Invalid URL target for scan.")
        elif len(tokens) >= 3 and tokens[2].startswith("-"):
            # Allow flag-based scan arguments.
            pass
        elif len(tokens) >= 3:
            raise ValueError("scan target must be a URL or valid flags.")

    return tokens


def _extract_target_from_tokens(tokens):
    if len(tokens) < 3:
        return ""
    sub = tokens[1]
    if sub in {"crawl", "recon", "test", "exploit"}:
        return tokens[2].rstrip("/")
    if sub == "scan":
        # `bugpilot scan <url>` shortcut
        if tokens[2].startswith(("http://", "https://")):
            return tokens[2].rstrip("/")
        # `bugpilot scan --headless --targets <url> ...`
        for i, tok in enumerate(tokens):
            if tok == "--targets" and i + 1 < len(tokens):
                return tokens[i + 1].rstrip("/")
    return ""


def _enforce_demo_guard(tokens):
    if not DEMO_MODE:
        return
    target = _extract_target_from_tokens(tokens)
    if not target:
        raise ValueError("Demo mode requires a URL target.")
    if target not in DEMO_ALLOWED_TARGETS:
        raise ValueError(
            "Target blocked in DEMO_MODE. Allowed targets: "
            + ", ".join(DEMO_ALLOWED_TARGETS)
        )


async def _stream_process(websocket: WebSocket, args):
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(CLI),
        *args,
        cwd=str(ROOT),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def forward(stream, stream_name):
        while True:
            line = await stream.readline()
            if not line:
                break
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "line",
                        "stream": stream_name,
                        "line": line.decode("utf-8", errors="replace").rstrip("\n"),
                    }
                )
            )

    await websocket.send_text(json.dumps({"type": "status", "state": "running"}))

    try:
        await asyncio.wait_for(
            asyncio.gather(forward(process.stdout, "stdout"), forward(process.stderr, "stderr")),
            timeout=RUN_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        process.kill()
        await websocket.send_text(
            json.dumps(
                {
                    "type": "status",
                    "state": "timeout",
                    "message": f"Process exceeded {RUN_TIMEOUT_SECONDS}s timeout.",
                }
            )
        )
        return

    code = await process.wait()
    await websocket.send_text(json.dumps({"type": "status", "state": "finished", "exit_code": code}))


@app.get("/health")
async def health():
    return {"ok": True}


@app.websocket("/ws")
async def ws_terminal(websocket: WebSocket):
    await websocket.accept()

    token = websocket.query_params.get("token", "").strip()
    if RUNNER_TOKEN and token != RUNNER_TOKEN:
        await websocket.send_text(json.dumps({"type": "error", "message": "Unauthorized"}))
        await websocket.close()
        return

    await websocket.send_text(
        json.dumps(
            {
                "type": "hello",
                "message": "Connected to BugPilot backend runner.",
                "allowed_commands": sorted(ALLOWED_SUBCOMMANDS),
            }
        )
    )

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"type": "error", "message": "Invalid JSON payload."}))
                continue

            if payload.get("type") != "run":
                await websocket.send_text(json.dumps({"type": "error", "message": "Unsupported message type."}))
                continue

            command = str(payload.get("command", "")).strip()
            try:
                tokens = _validate_command(command)
                _enforce_demo_guard(tokens)
            except ValueError as exc:
                await websocket.send_text(json.dumps({"type": "error", "message": str(exc)}))
                continue

            async with run_lock:
                await websocket.send_text(json.dumps({"type": "status", "state": "queued"}))
                await _stream_process(websocket, tokens[1:])
    except WebSocketDisconnect:
        return
