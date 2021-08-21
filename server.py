from hashlib import sha256
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import logging
import os
from pathlib import Path
import sqlite3
from threading import Lock
import socket
import time
from uuid import uuid4
import weakref

import requests


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()


SCHEMA_VERSION = 1
ROOTDIR = Path(__file__).parent

if os.environ.get("DLPROXY_STORAGE"):
    STORAGEDIR = Path(os.environ.get("DLPROXY_STORAGE"))
else:
    STORAGEDIR = Path(__file__).parent / "storage"

logger.info(f"Using storage path: {STORAGEDIR}")


def hashgen(raw_string: str) -> str:
    hash = sha256()
    hash.update(raw_string.encode())
    return hash.hexdigest()


def check_lock(lock: Lock) -> bool:
    lock_acquired = lock.acquire(blocking=False)
    if lock_acquired:
        try:
            lock.release()
        except RuntimeError:
            pass
    return lock_acquired


def dict_row_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
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
    STORAGEDIR / "storage.db",
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


start_locks = weakref.WeakValueDictionary()


class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    default_request_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        self.log_trace = str(uuid4())
        super().__init__(*args, **kwargs)

    def _log(self, level: int, msg: str, *args):
        logger.log(level, "%s %s [%s] %s" % (
            self.log_trace,
            self.address_string(),
            self.log_date_time_string(),
            msg % args,
        ))

    def log_request(self, code='-', size='-'):
        if isinstance(code, HTTPStatus):
            code = code.value
        self._log(logging.INFO, '"%s" %s', self.requestline, str(code))

    def log_error(self, format, *args):
        self._log(logging.ERROR, format, *args)

    def log_message(self, format, *args):
        self._log(logging.INFO, format, *args)

    def handle(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return

            if not self.parse_request():
                # An error code has been sent, just exit
                return

            mname = "do_" + self.command
            if not hasattr(self, mname):
                self.send_error(
                    HTTPStatus.NOT_IMPLEMENTED,
                    "Unsupported method (%r)" % self.command)
                return

            method = getattr(self, mname)
            method()
        except socket.timeout as e:
            # a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return

    @property
    def dest_url(self):
        return self.path[1:]

    def fetch_db_file(self, file_id: str) -> dict:
        query = "SELECT * FROM files WHERE file_id = ?"
        cursor = db.execute(query, (file_id,))
        result = cursor.fetchone()
        cursor.close()
        return result

    def do_HEAD(self):
        dest_url = self.dest_url
        file_id = hashgen(dest_url)

        db_file = self.fetch_db_file(file_id)

        if db_file:
            self.log_message(f"Found DB file for: {dest_url}")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", db_file["content_type"])
            if db_file["content_length"] != "unknown":
                self.send_header("Content-length", db_file["content_length"])
            self.end_headers()
            return

        self.log_message(f"Fetching HEAD for: {dest_url}")

        headers = {}
        user_agent = self.headers.get("user-agent", "").strip()
        if user_agent:
            headers["User-Agent"] = user_agent

        try:
            remote_response = requests.head(dest_url, timeout=10, headers=headers)
        except requests.Timeout as exc:
            self.log_error(f"Remote fetch head timeout: {exc}")
            self.send_response(HTTPStatus.GATEWAY_TIMEOUT)
            self.end_headers()
            return
        except requests.URLRequired as exc:
            self.log_error(f"Remote fetch head invalid: {exc}")
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            return
        except requests.RequestException as exc:
            self.log_error(f"Remote fetch head error: {exc}")
            self.send_response(HTTPStatus.BAD_GATEWAY)
            self.end_headers()
            return
        except Exception as exc:
            self.log_error(f"Remote fetch head error: {exc}")
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.end_headers()
            return

        self.send_response(remote_response.status_code)
        if remote_response.status_code == HTTPStatus.OK:
            self.send_header("Content-type", remote_response.headers.get("content-type", "application/octet-stream"))
            content_length = remote_response.headers.get("content-length")
            if content_length:
                self.send_header("Content-length", content_length)
        self.end_headers()

    def do_GET(self):
        dest_url = self.dest_url
        file_id = hashgen(dest_url)

        db_file = self.fetch_db_file(file_id)
        lock = start_locks.setdefault(file_id, Lock())

        if db_file:
            # Start returning the response.
            self.log_message(f"Found DB file for: {dest_url}")
            self.send_db_file(db_file, lock)
            return

        lock_acquired = lock.acquire(blocking=False)
        if lock_acquired:
            # Start downloading the file.
            self.log_message(f"Fetching GET for: {dest_url}")

            headers = {}
            user_agent = self.headers.get("user-agent", "").strip()
            if user_agent:
                headers["User-Agent"] = user_agent

            remote_response = None
            remote_response_err = False
            try:
                remote_response = requests.get(dest_url, stream=True, timeout=10, headers=headers)
            except requests.Timeout as exc:
                self.log_error(f"Remote fetch get timeout: {exc}")
                self.send_response(HTTPStatus.GATEWAY_TIMEOUT)
                remote_response_err = True
            except requests.URLRequired as exc:
                self.log_error(f"Remote fetch get invalid: {exc}")
                self.send_response(HTTPStatus.BAD_REQUEST)
                remote_response_err = True
            except requests.RequestException as exc:
                self.log_error(f"Remote fetch get error: {exc}")
                self.send_response(HTTPStatus.BAD_GATEWAY)
                remote_response_err = True
            except BaseException as exc:
                self.log_error(f"Remote fetch get error: {exc}")
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                remote_response_err = True

            if not remote_response:
                if not remote_response_err:
                    self.log_error("Remote fetch logic error")
                    self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                    remote_response_err = True
            elif remote_response.status_code != 200:
                self.send_response(remote_response.status_code)
                remote_response_err = True

            if remote_response_err:
                self.end_headers()
                lock.release()
                return

            disk_file_path = STORAGEDIR / file_id
            try:
                disk_file = disk_file_path.open(mode="xb", buffering=0)
            except BaseException as exc:
                self.log_error(f"Exclusive file creation error: {exc}")
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.end_headers()
                lock.release()
                raise

            reported_content_type = remote_response.headers.get("content-type", "application/octet-stream")
            reported_content_length_raw = remote_response.headers.get("content-length")
            if reported_content_length_raw:
                try:
                    reported_content_length = str(int(reported_content_length_raw))
                except ValueError:
                    self.log_message(f"Invalid reported content length: {reported_content_length_raw}")
                    reported_content_length = "unknown"
            else:
                reported_content_length = "unknown"

            insert_initial_query = (
                "INSERT INTO files (file_id, url, content_type, content_length) "
                "VALUES (?, ?, ?, ?)"
            )
            try:
                with db:
                    db.execute(
                        insert_initial_query,
                        (
                            file_id,
                            dest_url,
                            reported_content_type,
                            reported_content_length,
                        ),
                    )
            except BaseException as exc:
                self.log_error(f"Initial insert query error: {exc}")
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.end_headers()
                disk_file.close()
                lock.release()
                raise

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", reported_content_type)
            if reported_content_length != "unknown":
                self.send_header("Content-length", reported_content_length)
            self.end_headers()

            response_len = 0
            for chunk in remote_response.iter_content(chunk_size=4096):
                response_len += len(chunk)
                disk_file.write(chunk)
                self.wfile.write(chunk)
                time.sleep(0.05)
            # Disconnect the client now, we can keep working without them.
            self.finish()

            try:
                disk_file.close()
            except BaseException as exc:
                self.log_error(f"Closing write file error: {exc}")

            response_len_str = str(response_len)

            initial_update_query = "UPDATE files SET finished = TRUE"
            initial_update_args = ()
            if reported_content_length == "unknown" or reported_content_length != response_len_str:
                initial_update_query += ", content_length = ?"
                initial_update_args += (response_len_str,)
            initial_update_query += " WHERE file_id = ?"
            initial_update_args += (file_id,)
            try:
                with db:
                    db.execute(initial_update_query, initial_update_args)
            except BaseException as exc:
                self.log_error(f"Initial update query error: {exc}")

            lock.release()

            if reported_content_length == "unknown":
                self.log_message(
                    f"No reported content length. Found: {response_len_str}."
                )
            elif reported_content_length != response_len_str:
                self.log_message(
                    f"Mismatched content lengths. Reported: {reported_content_length}. Found: {response_len_str}."
                )
            return
        else:
            # Wait 2 seconds for download to start.
            self.log_message(f"Waiting for DB file to appear for: {dest_url}")
            time.sleep(2)

            # If not started, wait 1 second increments until 10 seconds has passed.
            # If still not started, return error.
            retry_count = 0
            while retry_count < 10:
                db_file = self.fetch_db_file(file_id)
                if db_file:
                    break

                retry_count += 1
                time.sleep(1)

            if not db_file:
                self.log_message("Download start failure")
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.end_headers()
                return

            self.send_db_file(db_file, lock)
            return

    def send_db_file(self, db_file: dict, lock: Lock):
        self.log_message(f"Starting DB file download for: {db_file['url']}")

        file_id = db_file["file_id"]
        disk_file_path = STORAGEDIR / file_id
        if db_file["content_length"] == "unknown":
            expected_content_length = -1
        else:
            expected_content_length = int(db_file["content_length"])

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", db_file["content_type"])
        if expected_content_length > 0:
            self.send_header("Content-length", str(expected_content_length))
        self.end_headers()

        found_content_length = 0
        no_chunk_available_count = 0
        with disk_file_path.open(mode="rb", buffering=0) as disk_file:
            while True:
                chunk = disk_file.read(4096)
                if chunk:
                    no_chunk_available_count = 0
                    found_content_length += len(chunk)
                    self.wfile.write(chunk)
                    continue

                if expected_content_length > 0:
                    if found_content_length >= expected_content_length:
                        break

                    # We know how much we should be waiting for, so it's okay to wait a bit longer.
                    no_chunk_available_count += 1
                    if no_chunk_available_count <= 30:
                        time.sleep(0.1 * min(no_chunk_available_count, 30))
                        continue

                    # If things are looking bad, check the lock.
                    lock_acquired = check_lock(lock)
                    if lock_acquired:
                        self.log_message("Lock freed, but no chunks available.")
                        break
                    elif no_chunk_available_count > 60:
                        self.log_message("Lock not broken, no chunks available, we've waited long enough.")
                        break

                if discovered_writing_finished:
                    break

                no_chunk_available_count += 1
                if no_chunk_available_count <= 20:
                    time.sleep(0.1 * min(no_chunk_available_count, 20))
                    continue

                # If we've been waiting for a while, check if the lock has been released.
                lock_acquired = check_lock(lock)

                if not lock_acquired and no_chunk_available_count <= 40:
                    time.sleep(0.1 * min(no_chunk_available_count, 20))
                    continue

                # Either writing has finished, or we've been waiting quite a while.

                fresh_db_file = self.fetch_db_file(file_id)
                if not fresh_db_file:
                    # Something has gone horribly wrong.
                    self.log_message("Fresh db file not found.")
                    break

                if fresh_db_file["finished"] == True:
                    # Everything's fine. Go around at least once more, but no more than that.
                    discovered_writing_finished = True
                    continue

                self.log_message("Lock freed, but no finish recorded.")

                # Perhaps we can still recover?
                if fresh_db_file["content_length"] == "unknown":
                    # Nope :(
                    break

                expected_content_length = int(fresh_db_file["content_length"])
                # The loop should now hopefully terminate normally.
                no_chunk_available_count = 0


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
