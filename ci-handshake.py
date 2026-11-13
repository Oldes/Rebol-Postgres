"""Exercise startup reads against a local PostgreSQL protocol stub."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time


AUTH_OK = bytes.fromhex("520000000800000000")
READY = bytes.fromhex("5a0000000549")
ERROR_BODY = b"SFATAL\0C28P01\0MAuthentication rejected\0\0"
AUTH_ERROR = b"E" + (len(ERROR_BODY) + 4).to_bytes(4, "big") + ERROR_BODY
CLIENT = """
import %postgres.reb
system/options/log/postgres: 0
pg: make port! as url! get-env "PG_URL"
result: try [open pg]
either "success" = get-env "PG_EXPECT" [
    if error? :result [print result quit/return 1]
    unless all [pg/extra/authenticated? pg/extra/ReadyForQuery] [quit/return 1]
][
    unless error? :result [print "Expected startup failure" quit/return 1]
    unless find mold result get-env "PG_EXPECT" [print result quit/return 1]
]
if open? pg [close pg]
quit/return 0
"""


def receive_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Client closed before sending startup")
        data += chunk
    return data


def check(name, responses, expected):
    failures = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)

        def serve():
            try:
                with listener.accept()[0] as conn:
                    conn.settimeout(5)
                    size = int.from_bytes(receive_exact(conn, 4), "big")
                    receive_exact(conn, size - 4)
                    for delay, payload in responses:
                        time.sleep(delay)
                        conn.sendall(payload)
                    # Keep the connection open until the client finishes or times out.
                    while conn.recv(4096):
                        pass
            except Exception as error:
                failures.append(error)

        server = threading.Thread(target=serve)
        server.start()
        env = dict(os.environ, PG_URL=(
            f"postgres://postgres:password@127.0.0.1:{listener.getsockname()[1]}"
            "/postgres?connect-timeout=1"
        ), PG_EXPECT=expected)
        result = subprocess.run(
            [sys.argv[1] if len(sys.argv) > 1 else "./rebol3", "-qs", "--do", CLIENT],
            cwd=Path(__file__).resolve().parent, env=env,
            capture_output=True, text=True, timeout=5,
        )
        server.join(timeout=6)
        assert not server.is_alive(), f"{name}: server did not finish"
        assert not failures, f"{name}: {failures}"
        assert result.returncode == 0, f"{name}: {result.stdout}{result.stderr}"
        print(f"Startup {name}: OK")


check("combined", [(0, AUTH_OK + READY)], "success")
check("split", [(0, AUTH_OK), (0.2, READY)], "success")
check("auth-error", [(0, AUTH_ERROR)], "PostgreSQL connection failed during handshake")
check("timeout", [(0, AUTH_OK)], "PostgreSQL handshake did not complete")
