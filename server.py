#!/usr/bin/env python3
"""
ScamShield AI Backend
─────────────────────
Run:  python3 server.py
Then: open http://localhost:8080 in your browser

No pip installs required — uses Python standard library only.
Your API key is stored in .api_key and never sent to the browser.
"""
import os
import re
import json
import urllib.request
import urllib.error
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

PORT      = 8080
HERE      = Path(__file__).parent
KEY_FILE  = HERE / '.api_key'

SYSTEM_PROMPT = """\
You are an expert fraud and scam detection AI trained on thousands of real-world scam patterns.
Analyze the message provided and return ONLY valid JSON — no markdown, no prose, just raw JSON.

Return exactly this schema:
{
  "risk_level": "safe" | "suspicious" | "likely" | "definite",
  "confidence": <integer 0-100>,
  "scam_type": <string or null>,
  "red_flags": [<string>, ...],
  "explanation": "<2-3 plain-English sentences a non-technical person can understand>",
  "recommended_action": "<one clear, actionable sentence>"
}

risk_level definitions:
  safe       — no meaningful scam signals; message appears legitimate
  suspicious — 1-2 minor warning signs; could be legitimate but warrants caution
  likely     — multiple strong indicators matching known scam patterns
  definite   — textbook scam with clear manipulation tactics; do not engage

If the message is a genuine appointment reminder, shipping notification, or similar
benign communication, say so clearly with risk_level "safe".
"""

# ── API key setup ────────────────────────────────────────────────────────────

def get_api_key() -> str:
    # 1. environment variable
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if key:
        print("✓  API key loaded from environment variable.\n")
        return key
    # 2. saved key file
    if KEY_FILE.exists():
        key = KEY_FILE.read_text().strip()
        if key:
            print("✓  API key loaded from .api_key file.\n")
            return key
    # 3. interactive prompt
    print("\n🔑  First-time setup")
    print("    Get a free API key at: https://console.anthropic.com\n")
    key = input("    Paste your Anthropic API key (sk-ant-...): ").strip()
    if not key:
        print("\n⚠   No key provided. AI analysis will be unavailable.")
        return ""
    KEY_FILE.write_text(key)
    KEY_FILE.chmod(0o600)          # owner-read only
    print("✓   Key saved to .api_key — you won't need to enter it again.\n")
    return key


API_KEY = get_api_key()

# ── Claude call ──────────────────────────────────────────────────────────────

def call_claude(message: str) -> dict:
    if not API_KEY:
        raise RuntimeError("No API key configured. Restart server.py and enter your key.")

    payload = json.dumps({
        "model":      "claude-haiku-4-5",
        "max_tokens": 700,
        "system":     SYSTEM_PROMPT,
        "messages":   [{"role": "user",
                        "content": f"Analyze this message for scam indicators:\n\n{message}"}]
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         API_KEY,
            "anthropic-version": "2023-06-01",
        },
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())

    raw_text = data["content"][0]["text"]
    match = re.search(r'\{[\s\S]*\}', raw_text)
    if not match:
        raise ValueError("AI returned an unexpected format. Please try again.")
    result = json.loads(match.group())

    # normalise fields so the frontend never gets KeyErrors
    result.setdefault("risk_level", "suspicious")
    result.setdefault("confidence", 70)
    result.setdefault("scam_type", None)
    result.setdefault("red_flags", [])
    result.setdefault("explanation", raw_text)
    result.setdefault("recommended_action", "Exercise caution.")

    if result["risk_level"] not in ("safe", "suspicious", "likely", "definite"):
        result["risk_level"] = "suspicious"
    result["confidence"] = max(0, min(100, int(result["confidence"])))

    return result

# ── HTTP handler ─────────────────────────────────────────────────────────────

class Handler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(HERE), **kwargs)

    # ── CORS pre-flight ──
    def do_OPTIONS(self):
        self.send_response(200)
        self._add_cors()
        self.end_headers()

    # ── API endpoint ──
    def do_POST(self):
        if self.path != "/api/analyze":
            self.send_error(404, "Not found")
            return
        try:
            length  = int(self.headers.get("Content-Length", 0))
            body    = json.loads(self.rfile.read(length))
            message = body.get("message", "").strip()
            if not message:
                self._send_json({"error": "No message provided"}, 400)
                return
            result = call_claude(message)
            self._send_json(result)
        except urllib.error.HTTPError as e:
            err = json.loads(e.read()).get("error", {})
            self._send_json({"error": err.get("message", str(e))}, 502)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)

    def _add_cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")

    def _send_json(self, data: dict, code: int = 200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self._add_cors()
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # only print non-200/304 requests to keep the console clean
        if args and str(args[1]) not in ("200", "304", "206"):
            print(f"  [{args[1]}] {args[0]}")


# ── entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = HTTPServer(("", PORT), Handler)
    print(f"🛡️   ScamShield is running!")
    print(f"     Open  →  http://localhost:{PORT}")
    print(f"     Stop  →  Ctrl+C\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n     Server stopped.")
