from __future__ import annotations

import argparse
import csv
import io
import json
import mimetypes
import os
import threading
import webbrowser
from http.cookies import SimpleCookie
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import urlopen

from .application import CloudDApplication
from .storage import DuplicateUploadError


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

    def _session_token(self) -> str | None:
        try:
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookies.get("cloud_d_session")
            return morsel.value if morsel else None
        except (TypeError, ValueError):
            return None

    def _current_user(self) -> dict | None:
        return self.app.resolve_session(self._session_token())

    def _require_user(self) -> dict | None:
        user = self._current_user()
        if user is None:
            self._send_json(401, {"error": "Sign in to continue."})
        return user

    def _session_cookie(self, token: str, max_age: int) -> str:
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
        secure = forwarded_proto == "https" or bool(os.environ.get("RENDER"))
        return f"cloud_d_session={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict" + ("; Secure" if secure else "")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._send_json(200, {"ok": True, "mode": "local simulation"})
            return
        if path == "/api/auth/me":
            self._send_json(200, {"user": self._current_user()})
            return
        if path in {"/", "/index.html"}:
            self._send_file(WEB_ROOT / "index.html", "text/html; charset=utf-8")
            return
        if path == "/cloud-d.js":
            self._send_file(WEB_ROOT / "cloud-d.js", "text/javascript; charset=utf-8")
            return
        if path == "/manifest.json":
            self._send_file(WEB_ROOT / "manifest.json", "application/manifest+json; charset=utf-8")
            return
        if path == "/sw.js":
            self._send_file(WEB_ROOT / "sw.js", "text/javascript; charset=utf-8")
            return
        if path in {"/icon-192.png", "/icon-512.png", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png", "/favicon.ico"}:
            # Generate a clean SVG-based shield icon placeholder for iOS / Android / desktop
            svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192"><rect width="192" height="192" rx="36" fill="#30264a"/><path d="M96 28 L156 56 v44 c0 42 -27 68 -60 80 -33 -12 -60 -38 -60 -80 V56 Z" fill="none" stroke="#c9b4ff" stroke-width="12" stroke-linejoin="round"/><path d="M68 96 L86 114 L128 72" fill="none" stroke="#8d78e8" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"/></svg>'
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(svg)))
            self.send_header("Cache-Control", "max-age=86400")
            self.end_headers()
            self.wfile.write(svg)
            return
        user = self._require_user()
        if user is None:
            return
        if path.startswith("/api/files/") and path.endswith("/download"):
            file_id = path[len("/api/files/"):-len("/download")].strip("/")
            self._download_file(file_id, user)
            return
        if path.startswith("/api/file-groups/") and path.endswith("/versions"):
            logical_id = path[len("/api/file-groups/"):-len("/versions")].strip("/")
            versions = self.app.get_file_versions(logical_id, user)
            if not versions:
                self._send_json(404, {"error": "Version history was not found for this file."})
            else:
                self._send_json(200, {"versions": versions})
            return
        if path == "/api/state":
            self._send_json(200, self.app.get_state(user))
            return
        if path == "/api/folders":
            self._send_json(200, {"folders": self.app.list_folders(user)})
            return
        if path == "/api/nodes":
            # Returns the logical node manifest: simulated nodes, their roles, and current health.
            state = self.app.get_state(user)
            nodes = state.get("nodes", [])
            node_manifest = [
                {"id": 0, "name": "Auth Server", "role": "Authentication & Key Manager",
                 "type": "simulated", "description": "Handles login, session tokens, and staff registration code verification.",
                 "storage_target": None, "health": next((n.get("health") for n in nodes if "Auth" in n.get("name", "")), 100)},
                {"id": 1, "name": "API Gateway", "role": "Traffic Filter & Request Router",
                 "type": "simulated", "description": "Routes requests to the correct database node based on account role.",
                 "storage_target": None, "health": next((n.get("health") for n in nodes if "Gateway" in n.get("name", "")), 100)},
                {"id": 2, "name": "Primary DB", "role": "Staff Vault & Shared Storage",
                 "type": "simulated", "description": "Staff accounts store files here. Encrypted file blobs with AES-256-GCM.",
                 "storage_target": "staff", "health": next((n.get("health") for n in nodes if "Primary" in n.get("name", "")), 100)},
                {"id": 3, "name": "Customer DB", "role": "Customer Private Storage Area",
                 "type": "simulated", "description": "Customer accounts store private files here. Isolated per customer account.",
                 "storage_target": "customer", "health": next((n.get("health") for n in nodes if "Customer" in n.get("name", "")), 100)},
                {"id": 4, "name": "Backup Server", "role": "Air-Gapped Recovery Database",
                 "type": "simulated", "description": "Encrypted recovery copies for all uploaded files. Used for restore operations.",
                 "storage_target": None, "health": next((n.get("health") for n in nodes if "Backup" in n.get("name", "")), 100)},
            ]
            architecture_note = (
                "These five nodes are logically simulated within a single Python service backed by SQLite. "
                "They are NOT independent microservices or database servers. "
                "The simulation models attacker/defender interactions against these logical entities. "
                "Primary DB and Customer DB route real file storage; Auth Server, API Gateway, and Backup Server "
                "are represented in simulation metrics and event logs only."
            )
            self._send_json(200, {"nodes": node_manifest, "architecture": architecture_note,
                                   "implementation": "single-process", "database": "SQLite",
                                   "encryption": "AES-256-GCM file payloads"})
            return
        self._send_json(404, {"error": "Not found."})

    def _download_file(self, file_id: str, user: dict):
        stored = self.app.get_file(file_id, user)
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
        if path in {"/api/auth/login", "/api/auth/signup", "/api/auth/logout"}:
            self._handle_auth(path)
            return
        user = self._require_user()
        if user is None:
            return
        if path == "/api/folders":
            body = self._read_body()
            if body is None:
                return
            try:
                payload = json.loads(body.decode("utf-8"))
                folder = self.app.create_folder(user, payload.get("name", ""))
                self._send_json(201, {"folder": folder, "folders": self.app.list_folders(user)})
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError, ValueError) as exc:
                self._send_json(400, {"error": str(exc) or "Enter a folder name."})
            return
        if path.startswith("/api/files/") and path.endswith("/restore"):
            file_id = path[len("/api/files/"):-len("/restore")].strip("/")
            try:
                result = self.app.restore_backup_file(file_id, user)
                if result is None:
                    self._send_json(404, {"error": "A restorable backup copy was not found."})
                else:
                    self._send_json(200, result)
            except Exception as exc:
                print(f"Cloud-D restore error: {type(exc).__name__}: {exc}")
                self._send_json(500, {"error": "The backup copy could not be restored."})
            return
        if path == "/api/upload":
            self._upload(user)
            return
        if user["role"] != "staff":
            self._send_json(403, {"error": "Security simulation controls are available to staff accounts."})
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
                self._send_json(200, self.app.get_state(user))
            elif path == "/api/node-crypto":
                node_id = payload.get("node_id")
                if isinstance(node_id, bool) or not isinstance(node_id, int) or node_id != 2:
                    raise ValueError("Staff storage operations are restricted to the assigned primary area.")
                action = payload.get("action")
                if action == "verify":
                    result = self.app.verify_node_decryption(node_id)
                elif action == "reencrypt":
                    result = self.app.reencrypt_node(node_id)
                else:
                    raise ValueError("Choose a supported encryption action.")
                self._send_json(200, result)
            elif path == "/api/round":
                self.app.simulate_round(payload)
                self._send_json(200, self.app.get_state(user))
            elif path == "/api/restart":
                self.app.begin_new_run(payload)
                self._send_json(200, self.app.get_state(user))
            elif path == "/api/reset":
                self.app.reset()
                self._send_json(200, self.app.get_state(user))
            else:
                self._send_json(404, {"error": "Not found."})
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:  # Keep stack details in the local terminal, not the browser response.
            print(f"Cloud-D request error: {type(exc).__name__}: {exc}")
            self._send_json(500, {"error": "The local simulation could not complete this request."})

    def _handle_auth(self, path: str):
        if path == "/api/auth/logout":
            self.app.revoke_session(self._session_token())
            self._send_json(200, {"ok": True}, {"Set-Cookie": self._session_cookie("", 0)})
            return
        body = self._read_body()
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(payload, dict):
                raise ValueError("Request body must be a JSON object.")
            if path == "/api/auth/signup":
                result = self.app.register_user(payload)
                self._send_json(201, {"user": result["user"]}, {
                    "Set-Cookie": self._session_cookie(result["session"], 12 * 60 * 60)
                })
                return
            result = self.app.login_user(payload)
            self._send_json(200, {"user": result["user"]}, {
                "Set-Cookie": self._session_cookie(result["session"], 12 * 60 * 60)
            })
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            status = 401 if path == "/api/auth/login" else 400
            self._send_json(status, {"error": str(exc)})
        except Exception as exc:
            print(f"Cloud-D authentication error: {type(exc).__name__}: {exc}")
            self._send_json(500, {"error": "Cloud-D could not complete the account request."})

    def _upload(self, user: dict):
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
            if not values.get("folder_id"):
                raise ValueError("Choose a destination folder.")
            duplicate_mode = values.get("duplicate_mode") or None
            result = self.app.upload_items(
                values["folder_id"], items, user, duplicate_mode=duplicate_mode
            )
            result["state"] = self.app.get_state(user)
            self._send_json(200, result)
        except DuplicateUploadError as exc:
            self._send_json(409, {"error": str(exc), "duplicates": exc.duplicates})
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

    def _send_json(self, status: int, payload: dict, headers: dict[str, str] | None = None):
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
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
    url = f"http://127.0.0.1:{args.port}/"
    staff_registration_code = (
        os.environ.get("CLOUD_D_STAFF_REGISTRATION_CODE")
        or os.environ.get("CLOUD_D_STAFF_INVITE_CODE")
        or os.environ.get("CLOUD_D_ACCESS_PASSWORD", "")
    )
    if args.host not in {"127.0.0.1", "localhost"} and len(staff_registration_code) < 16:
        raise SystemExit(
            "Public binding requires CLOUD_D_STAFF_REGISTRATION_CODE (or a legacy staff code variable) "
            "to be at least 16 characters."
        )
    app = CloudDApplication()
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
            app.close()
            print(f"Cloud-D is already running at {url}")
            if not args.no_browser:
                webbrowser.open(url)
            return
        app.close()
        raise SystemExit(
            f"Cloud-D could not use port {args.port} ({exc}). "
            "Close the program using that port, or start Cloud-D with --port 8766."
        ) from exc
    server.cloud_d_app = app  # type: ignore[attr-defined]
    print(f"Cloud-D is running locally at {url}")
    print("Uploaded files are encrypted in the local SQLite database; press Ctrl+C to stop the simulation.")
    if not args.no_browser:
        threading.Timer(.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCloud-D stopped. Encrypted uploads remain in the Cloud-D data folder.")
    finally:
        server.server_close()
        app.close()


if __name__ == "__main__":
    main()
