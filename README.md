# dlproxy - A HTTP Caching Proxy

## Requirements

- Python 3 with SQLite support
- A reasonably up-to-date version of requests (as of August 2021)

## Running the server

Start the server:

```
python3 server.py
```

### Environment variables

- `DLPROXY_STORAGE` - Customise the storage path. Defaults to the `storage` folder in this repository.
- `DLPROXY_HOST` - Customise the network interface to bind to. Defaults to `127.0.0.1`.
- `DLPROXY_PORT` - Customise the port number to bind to. Defaults to `9090`.

## Usage

```
wget -O index.html http://127.0.0.1:9090/https://www.matthewgamble.net/
```

## Notes

It aims to be quite resilient. It should only ever download one copy of a file. If multiple requests
ask for the same file, only one copy should be downloaded. Other requests should read from the cache,
even if the original request has not yet completed.

Details about cached files are stored in an SQLite database in the storage directory. The program has
a hard requirement that no other processes will attempt to write to the SQLite database while it is
running.
