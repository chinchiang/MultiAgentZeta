"""Loopback relays: the host's way into a stack on an internal network (〈定義：E1 隔離〉, TK-ENV-008).

A Docker network created with --internal publishes no port, so nothing on the host reaches the stack
through 127.0.0.1. A Relay listens on 127.0.0.1 only and passes each connection to an address given by
`lookup`, asked again for every connection because the container behind it is replaced by a restart.
A connection whose target cannot be found or reached is closed: the caller sees a failed request, never
an answer from somewhere else.
"""
import socket
import threading


class Relay:
    def __init__(self, port, lookup, inner_port):
        """Listen on 127.0.0.1:port. Raises OSError when the port cannot be bound."""
        self.port, self.lookup, self.inner_port = port, lookup, inner_port
        self._open = set()
        self._lock = threading.Lock()
        self._closed = False
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._server.bind(('127.0.0.1', port))
            self._server.listen(64)
        except OSError:
            self._server.close()
            raise
        self._acceptor = threading.Thread(target=self._accept, daemon=True)
        self._acceptor.start()

    def _accept(self):
        while True:
            try:
                client, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._relay, args=(client,), daemon=True).start()

    def _keep(self, sock):
        with self._lock:
            if self._closed:
                sock.close()
                return False
            self._open.add(sock)
            return True

    def _relay(self, client):
        if not self._keep(client):
            return
        upstream = None
        try:
            address = self.lookup()
            if not address:
                return
            upstream = socket.create_connection((address, self.inner_port), timeout=10)
            upstream.settimeout(None)
            if not self._keep(upstream):
                return
            back = threading.Thread(target=_pump, args=(upstream, client), daemon=True)
            back.start()
            _pump(client, upstream)
            back.join()
        except Exception:  # whatever the lookup or the connection raised: this connection fails, the relay stays
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    with self._lock:
                        self._open.discard(sock)
                    sock.close()

    def close(self):
        """Stop listening and drop every open connection; the port is free when this returns."""
        with self._lock:
            self._closed = True
            open_now = list(self._open)
        for sock in [self._server] + open_now:
            try:
                sock.shutdown(socket.SHUT_RDWR)  # wakes a thread blocked in accept() or recv()
            except OSError:
                pass
        self._server.close()
        # The kernel keeps the listening socket, and so the port, until the thread has left accept().
        self._acceptor.join(timeout=5)


def _pump(source, sink):
    try:
        while data := source.recv(65536):
            sink.sendall(data)
    except OSError:
        pass
    finally:
        try:
            sink.shutdown(socket.SHUT_WR)
        except OSError:
            pass
