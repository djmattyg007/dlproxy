from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import logging
from pathlib import Path
import sqlite3
import sys
from uuid import uuid4

import requests


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()


SCHEMA_VERSION = 1
ROOTDIR = Path(__file__).parent


def dict_row_factory(cursor: sqlite3.Cursor, row: tuple):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


class Connection(sqlite3.Connection):
    def __init__(self, *args, **kwargs):
        kwargs["isolation_level"] = None
        super().__init__(*args, **kwargs)
        self.row_factory = dict_row_factory
        self.execute("PRAGMA journal_mode = wal")
        self.execute("PRAGMA foreign_keys = ON")


db = sqlite3.connect(
    ROOTDIR / "storage" / "storage.db",
    timeout=5,
    factory=Connection,
    check_same_thread=False,
)

user_version = db.execute("PRAGMA user_version").fetchone()["user_version"]
while user_version != SCHEMA_VERSION:
    if user_version:
        logger.info("Upgrading storage database schema v%s", user_version)
        filename = f"upgrade-v{user_version}.sql"
    else:
        logger.info(
            "Creating storage database schema v%s", SCHEMA_VERSION
        )
        filename = "schema.sql"

    with open(ROOTDIR / "schema" / filename) as fh:
        db.executescript(fh.read())

    new_version = db.execute("PRAGMA user_version").fetchone()["user_version"]
    assert new_version != user_version
    user_version = new_version
    logger.info(
        "Successfully upgraded storage database schema to v%s",
        user_version,
    )


class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        self.handle_one_request()
        self.finish()

    @property
    def dest_url(self):
        return self.path[1:]

    def do_HEAD(self):
        dest_url = self.dest_url

        query = "SELECT * FROM files WHERE url = ?"
        cursor = db.execute(query, (dest_url,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", result["content_type"])
            self.send_header("Content-length", result["content_length"])
            self.end_headers()
            return

        try:
            remote_response = requests.head(dest_url, timeout=10)
        except requests.Timeout as exc:
            self.log_error("Remote fetch head timeout", exc)
            self.send_response(HTTPStatus.GATEWAY_TIMEOUT)
            self.end_headers()
            return
        except requests.URLRequired as exc:
            self.log_error("Remote fetch head invalid", exc)
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            return
        except requests.RequestException as exc:
            self.log_error("Remote fetch head error", exc)
            self.send_response(HTTPStatus.BAD_GATEWAY)
            self.end_headers()
            return
        except Exception as exc:
            self.log_error("Remote fetch head error", exc)
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.end_headers()
            return

        if remote_response.status_code != 200:
            self.send_response(remote_response.status_code)
            self.end_headers()
            return

        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    def do_GET(self):
        self.send_response(HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(self.dest_url.encode() + b"\n")
        self.wfile.write(b"lol\n")


with ThreadingHTTPServer(("localhost", 9090), RequestHandler) as httpd:
    host, port = httpd.socket.getsockname()[:2]
    url_host = f"[{host}]" if ":" in host else host
    print(
        f"Serving HTTP on {host} port {port} "
        f"(http://{url_host}:{port}/) ..."
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received, exiting.")

    db.close()
