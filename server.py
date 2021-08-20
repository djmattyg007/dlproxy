from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import sqlite3

import requests


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
    Path(__file__).parent / "storage" / "storage.db",
    timeout=5,
    factory=Connection,
)


class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self):
        pass

    def do_GET(self):
        pass

