from __future__ import annotations

import argparse
import csv
import hmac
import io
import json
import mimetypes
import os
import threading
import webbrowser
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import urlopen

from .application import CloudDApplication


WEB_ROOT = Path(__file__).resolve().parent.parent
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + 256 * 1024
MAX_ROWS = 10_000


def parse_uploaded_file(filename: str, content: bytes) -> list[dict]:
    extension = Path(filename).suffix.lower()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Upload a UTF-8 CSV or JSON file.") from exc

    if extension == ".csv":
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if not reader.fieldnames:
            raise ValueError("CSV needs a header row.")
        rows = [row for row in reader if any(value not in (None, "") for value in row.values())]
    elif extension in {".jsonl", ".ndjson"}:
        rows = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}.") from exc
            if not isinstance(row, dict):
                raise ValueError(f"Each JSON Lines entry must be an object (line {line_number}).")
            rows.append(row)
    elif extension == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc.msg}.") from exc
        if isinstance(payload, dict) and isinstance(payload.get("records"), list):
            rows = payload["records"]
        elif isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict):
            rows = [payload]
        else:
            raise ValueError("JSON must contain an object, an array of objects, or a records array.")
        if any(not isinstance(row, dict) for row in rows):
            raise ValueError("JSON records must be objects with named fields.")
    else:
        raise ValueError("Supported file types are .csv, .json, .jsonl, and .ndjson.")

    if not rows:
        raise ValueError("The selected file contains no data rows.")
    if len(rows) > MAX_ROWS:
        raise ValueError(f"A single upload is limited to {MAX_ROWS:,} records.")
    return rows


class CloudDHandler(BaseHTTPRequestHandler):
    server_version = "CloudDLocal/1.0"

    @property
    def app(self) -> CloudDApplication:
        return self.server.cloud_d_app  # type: ignore[attr-defined]

    def _authorize_api(self, path: str) -> bool:
        password = os.environ.get("CLOUD_D_ACCESS_PASSWORD", "")
        if not password or path == "/api/health" or not path.startswith("/api/"):
            return True
        authorization = self.headers.get("Authorization", "")
        supplied = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
        if hmac.compare_digest(supplied, password):
            return True
        self._send_json(401, {"error": "Cloud-D access was denied. Check the access password."})
        return False

    def do_GET(self):
        path = urlsplit(self.path).path
        if not self._authorize_api(path):
            return
        if path.startswith("/api/files/") and path.endswith("/download"):
            file_id = path[len("/api/files/"):-len("/download")].strip("/")
            self._download_file(file_id)
            return
        if path == "/api/state":
            self._send_json(200, self.app.get_state())
            return
        if path == "/api/health":
            self._send_json(200, {"ok": True, "mode": "local simulation"})
            return
        if path in {"/", "/index.html"}:
            self._send_file(WEB_ROOT / "index.html", "text/html; charset=utf-8")
            return
        if path == "/cloud-d.js":
            self._send_file(WEB_ROOT / "cloud-d.js", "text/javascript; charset=utf-8")
            return
        self._send_json(404, {"error": "Not found."})

    def _download_file(self, file_id: str):
        stored = self.app.get_file(file_id)
        if stored is None:
            self._send_json(404, {"error": "This file is no longer in the simulated cloud."})
            return
        filename = stored["filename"].replace("\r", "_").replace("\n", "_")
        encoded_name = quote(filename)
        content = stored["content"]
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{encoded_name}")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self._authorize_api(path):
            return
        # A browser page on another site must not be able to drive this local
        # simulation or upload files into it. Non-browser clients may omit Origin.
        origin = self.headers.get("Origin")
        forwarded_host = self.headers.get("X-Forwarded-Host", self.headers.get("Host", "")).split(",", 1)[0].strip()
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "http").split(",", 1)[0].strip()
        allowed_origin = os.environ.get("CLOUD_D_ALLOWED_ORIGIN", "").rstrip("/")
        render_hostname = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "")
        expected_origins = {
            f"http://127.0.0.1:{self.server.server_port}",
            f"http://localhost:{self.server.server_port}",
        }
        if render_hostname:
            expected_origins.add(f"https://{render_hostname}")
        if forwarded_host:
            expected_origins.add(f"{forwarded_proto}://{forwarded_host}")
        if allowed_origin:
            expected_origins.add(allowed_origin)
        if origin and origin.rstrip("/") not in expected_origins:
            self._send_json(403, {"error": "Requests must come from the local Cloud-D page."})
            return
        if path == "/api/upload":
            self._upload()
            return
        body = self._read_body()
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(payload, dict):
                raise ValueError("Request body must be a JSON object.")
            if path == "/api/config":
                self.app.configure(payload)
                self._send_json(200, self.app.get_state())
            elif path == "/api/round":
                self._send_json(200, self.app.simulate_round(payload))
            elif path == "/api/restart":
                self._send_json(200, self.app.begin_new_run(payload))
            elif path == "/api/reset":
                self._send_json(200, self.app.reset())
            else:
                self._send_json(404, {"error": "Not found."})
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:  # Keep stack details in the local terminal, not the browser response.
            print(f"Cloud-D request error: {type(exc).__name__}: {exc}")
            self._send_json(500, {"error": "The local simulation could not complete this request."})

    def _upload(self):
        body = self._read_body()
        if body is None:
            return
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data"):
            self._send_json(400, {"error": "Upload the file using the data upload form."})
            return
        try:
            message = BytesParser(policy=default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii") + body
            )
            values = {}
            items = []
            total_bytes = 0
            total_rows = 0
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition")
                if name == "file":
                    original_name = part.get_filename()
                    if not original_name:
                        continue
                    upload_name = Path(original_name).name[:120]
                    upload_bytes = part.get_payload(decode=True) or b""
                    if len(upload_bytes) > MAX_UPLOAD_BYTES:
                        raise ValueError("Files must be 10 MB or smaller per upload.")
                    total_bytes += len(upload_bytes)
                    if total_bytes > MAX_UPLOAD_BYTES:
                        raise ValueError("Selected files must total 10 MB or less.")
                    if Path(upload_name).suffix.lower() in {".csv", ".json", ".jsonl", ".ndjson"}:
                        rows = parse_uploaded_file(upload_name, upload_bytes)
                        total_rows += len(rows)
                        if total_rows > MAX_ROWS:
                            raise ValueError(f"A single upload is limited to {MAX_ROWS:,} data rows.")
                        items.append({"kind": "rows", "filename": upload_name, "rows": rows, "content": upload_bytes})
                    else:
                        items.append({"kind": "document", "filename": upload_name, "content": upload_bytes})
                elif name:
                    values[name] = (part.get_content() or "").strip()
            if not items:
                raise ValueError("Choose at least one document or data file first.")
            if not values.get("node_id", "").isdigit():
                raise ValueError("Choose the cloud node to receive these records.")
            replace = values.get("mode") == "replace"
            result = self.app.upload_items(int(values["node_id"]), items, replace=replace)
            self._send_json(200, result)
        except (ValueError, TypeError) as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            print(f"Cloud-D upload error: {type(exc).__name__}: {exc}")
            self._send_json(500, {"error": "The local simulation could not import this file."})

    def _read_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "Invalid content length."})
            return None
        if length <= 0:
            self._send_json(400, {"error": "Request body is empty."})
            return None
        if length > MAX_REQUEST_BYTES:
            self._send_json(413, {"error": "Request is too large."})
            return None
        body = self.rfile.read(length)
        if len(body) != length:
            self._send_json(400, {"error": "Request body was incomplete."})
            return None
        return body

    def _send_json(self, status: int, payload: dict):
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'")
        self.end_headers()
        self.wfile.write(encoded)

    def _send_file(self, path: Path, content_type: str):
        try:
            content = path.read_bytes()
        except OSError:
            self._send_json(404, {"error": "Application file not found."})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, fmt: str, *args):
        # Local-only server; avoid echoing headers or uploaded content to logs.
        print(f"Cloud-D: {self.address_string()} {fmt % args}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the local Cloud-D simulation.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically.")
    parser.add_argument("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8765")), help="HTTP port (defaults to PORT or 8765).")
    args = parser.parse_args(argv)
    app = CloudDApplication()
    url = f"http://127.0.0.1:{args.port}/"
    password = os.environ.get("CLOUD_D_ACCESS_PASSWORD", "")
    if args.host not in {"127.0.0.1", "localhost"} and len(password) < 16:
        raise SystemExit("Public binding requires CLOUD_D_ACCESS_PASSWORD to be at least 16 characters.")
    try:
        server = ThreadingHTTPServer((args.host, args.port), CloudDHandler)
    except OSError as exc:
        try:
            with urlopen(f"{url}api/health", timeout=1.5) as response:
                health = json.loads(response.read().decode("utf-8"))
            already_running = response.status == 200 and health.get("mode") == "local simulation"
        except Exception:
            already_running = False
        if already_running:
            print(f"Cloud-D is already running at {url}")
            if not args.no_browser:
                webbrowser.open(url)
            return
        raise SystemExit(
            f"Cloud-D could not use port {args.port} ({exc}). "
            "Close the program using that port, or start Cloud-D with --port 8766."
        ) from exc
    server.cloud_d_app = app  # type: ignore[attr-defined]
    print(f"Cloud-D is running locally at {url}")
    print("Uploaded files remain in memory in this local process; press Ctrl+C to stop and clear them.")
    if not args.no_browser:
        threading.Timer(.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCloud-D stopped. In-memory simulation and uploaded records have been cleared.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
