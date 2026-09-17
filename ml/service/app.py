"""Small, bounded local inference service for the NGFW.

The service has no access to firewall controls. It either loads a registered
scikit-learn/joblib model or returns a conservative heuristic result for lab
development. Requests and secrets are never logged.
"""
from __future__ import annotations

import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

MAX_INPUT = int(os.getenv("NGFW_ML_MAX_INPUT", "65536"))
MODEL_PATH = os.getenv("NGFW_ML_MODEL", "")
_model: Any = None
_model_version = "heuristic-0"


def _load_model() -> None:
    global _model, _model_version
    if not MODEL_PATH:
        return
    path = Path(MODEL_PATH)
    if not path.is_file():
        return
    try:
        import joblib  # type: ignore

        _model = joblib.load(path)
        _model_version = path.stem
    except Exception:
        _model = None


def _heuristic(text: str) -> tuple[str, float, dict[str, float]]:
    # This is a development fallback; production/demo claims must use a
    # trained artifact and the evaluation report that accompanies it.
    patterns = {
        "SQL_INJECTION": [r"\bunion\s+select\b", r"\bor\s+1\s*=\s*1\b", r"sleep\s*\("],
        "XSS": [r"<script\b", r"javascript:", r"onerror\s*="],
        "COMMAND_INJECTION": [r"(?:^|[;&|])\s*(?:cat|curl|wget|bash|sh)\b", r"`[^`]+`"],
    }
    lowered = text.lower()
    for label, rules in patterns.items():
        if any(re.search(rule, lowered) for rule in rules):
            probs = {"BENIGN": 0.02, "SQL_INJECTION": 0.01, "XSS": 0.01, "COMMAND_INJECTION": 0.01, "ANOMALOUS": 0.01}
            probs[label] = 0.94
            return label, 0.94, probs
    return "BENIGN", 0.98, {"BENIGN": 0.98, "SQL_INJECTION": 0.005, "XSS": 0.005, "COMMAND_INJECTION": 0.005, "ANOMALOUS": 0.005}


def classify(text: str) -> dict[str, Any]:
    bounded = text[:MAX_INPUT]
    started = time.perf_counter()
    if _model is None:
        label, confidence, probabilities = _heuristic(bounded)
    else:
        prediction = _model.predict([bounded])[0]
        if hasattr(_model, "predict_proba"):
            values = _model.predict_proba([bounded])[0]
            classes = getattr(_model, "classes_", [])
            probabilities = {str(k): float(v) for k, v in zip(classes, values)}
            confidence = float(max(values))
        else:
            probabilities = {str(prediction): 1.0}
            confidence = 1.0
        label = str(prediction)
    return {"class": label, "confidence": confidence, "probabilities": probabilities, "model_version": _model_version, "processing_time_ms": (time.perf_counter() - started) * 1000}


class Handler(BaseHTTPRequestHandler):
    server_version = "ngfw-ml/1"

    def log_message(self, *_: Any) -> None:
        return

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "ok", "model_version": _model_version})
        elif self.path == "/model":
            self._json(200, {"model_version": _model_version, "loaded": _model is not None})
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/classify":
            self._json(404, {"error": "not_found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > MAX_INPUT + 8192:
                self._json(413, {"error": "input_too_large"})
                return
            body = json.loads(self.rfile.read(size))
            value = str(body.get("text", ""))
            if not value:
                self._json(400, {"error": "text_required"})
                return
            self._json(200, classify(value))
        except Exception:
            self._json(400, {"error": "invalid_request"})


def main() -> None:
    _load_model()
    host = os.getenv("NGFW_ML_HOST", "127.0.0.1")
    port = int(os.getenv("NGFW_ML_PORT", "8090"))
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
