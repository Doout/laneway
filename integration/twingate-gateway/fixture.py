#!/usr/bin/env python3
"""Private two-ended TUN provider fixture for the worker integration test."""
import fcntl
import http.server
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time


def tunnel(remote, destination):
    tun = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tun, 0x400454ca, struct.pack("16sH", b"fixture0", 0x1001))
    subprocess.run(["ip", "link", "set", "fixture0", "up"], check=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if remote:
        sock.bind(("", 45678))
        subprocess.run(["ip", "address", "add", destination + "/32", "dev", "lo"], check=True)
        subprocess.Popen([sys.executable, __file__, "http", "provider"])
        subprocess.run(["ip", "route", "replace", "10.224.1.1/32", "dev", "fixture0"], check=True)
        peer = None
    else:
        key = json.loads(Path("/etc/twingate/service_key.json").read_text())
        assert key["synthetic"] == "test-only"
        peer = (key["peer"], 45678)
        subprocess.run(["ip", "address", "add", "10.224.1.1/32", "dev", "fixture0"], check=True)
        subprocess.run(["ip", "route", "replace", key["target"] + "/32", "dev", "fixture0"], check=True)
    while True:
        for ready in select.select([tun, sock], [], [])[0]:
            if ready == tun:
                packet = os.read(tun, 65535)
                if peer:
                    sock.sendto(packet, peer)
            else:
                packet, peer = sock.recvfrom(65535)
                os.write(tun, packet)


if sys.argv[1:2] == ["http"]:
    class Response(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(sys.argv[2].encode())

    http.server.ThreadingHTTPServer(("", 8080), Response).serve_forever()
elif sys.argv[1:2] == ["remote"]:
    tunnel(True, sys.argv[2])
else:
    tunnel(False, "")
