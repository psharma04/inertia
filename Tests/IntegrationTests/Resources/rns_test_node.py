#!/usr/bin/env python3
"""
Python Reticulum test node for Swift integration testing.

Starts a Reticulum instance with a TCPServerInterface (added programmatically
to avoid config-file parsing issues with existing shared instances), creates
an LXMF delivery destination, sends an announce, and waits for an incoming
LXMF message.

stdout protocol (one line per event, flushed immediately):
  READY <port> <identity_hash_hex(32)> <lxmf_dest_hash_hex(32)>
  RECEIVED <content_utf8>
  ERROR <reason>

Arguments:
  $1  wait_timeout  (float seconds, default 30.0)

Exit codes:
  0  normal (message received or timeout)
  1  fatal error (Python import failure, RNS start failure)
"""

import sys
import os
import time
import socket
import shutil
import tempfile
import threading


def get_free_port() -> int:
    """Bind to port 0 to let the OS pick a free ephemeral port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    wait_timeout = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0

    try:
        import RNS
        import LXMF
    except ImportError as exc:
        print(f"ERROR Missing Python dependency: {exc}", flush=True)
        sys.exit(1)

    port = get_free_port()
    tmpdir = tempfile.mkdtemp(prefix="rns_swift_integration_")
    try:
        _run(RNS, LXMF, port, tmpdir, wait_timeout)
    except Exception as exc:
        import traceback
        print(f"ERROR {exc}", flush=True)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _run(RNS, LXMF, port: int, tmpdir: str, wait_timeout: float) -> None:
    # ------------------------------------------------------------------ #
    # Start RNS with a minimal config (no interfaces — we add the TCP     #
    # server interface programmatically to avoid conflicts with any        #
    # existing shared RNS instance on the machine).     #
    # ------------------------------------------------------------------ #
    config_path = os.path.join(tmpdir, "config")
    with open(config_path, "w") as f:
        f.write("[reticulum]\n  share_instance = No\n  enable_transport = False\n")

    reticulum = RNS.Reticulum(configdir=tmpdir, loglevel=RNS.LOG_CRITICAL)  # noqa: F841

    # Add the TCP server interface at runtime.
    from RNS.Interfaces.TCPInterface import TCPServerInterface
    iface_cfg = {
        "name": "SwiftIntegrationTest",
        "listen_ip": "127.0.0.1",
        "listen_port": port,
        "interface_enabled": True,
    }
    server_iface = TCPServerInterface(RNS.Transport, iface_cfg)
    server_iface.OUT = True
    # Attributes normally set by Reticulum config loader — required for
    # incoming_connection() to work when the interface is created programmatically.
    server_iface.ifac_size    = 0
    server_iface.ifac_netname = None
    server_iface.ifac_netkey  = None
    server_iface.announce_rate_target  = None
    server_iface.announce_rate_grace   = None
    server_iface.announce_rate_penalty = None
    RNS.Transport.interfaces.append(server_iface)

    # Give the socket a moment to start accepting connections.
    time.sleep(0.3)

    # ------------------------------------------------------------------ #
    # Set up LXMF router and delivery identity.        #
    # ------------------------------------------------------------------ #
    lxmf_dir = os.path.join(tmpdir, "lxmf")
    router = LXMF.LXMRouter(storagepath=lxmf_dir, autopeer=False)

    identity = RNS.Identity()
    local_dest = router.register_delivery_identity(
        identity, display_name="SwiftIntegrationTestNode"
    )
    # Disable ratchets so the announce wire format does not include a 32-byte
    # ratchet key.  The Swift AnnouncePayload parser handles the no-ratchet
    # layout; ratchet support will be added once the protocol layer supports it.
    local_dest.ratchets = None

    received: list = []
    message_ready = threading.Event()

    def on_delivery(message) -> None:
        received.append(message)
        message_ready.set()

    router.register_delivery_callback(on_delivery)

    # Announce periodically so newly-connected peers can receive it.
    # The first announce is sent immediately; subsequent announces every 2 s
    # ensure a Swift client that connects after startup will still receive one.
    def announce_loop() -> None:
        for _ in range(10):
            local_dest.announce()
            time.sleep(2)

    threading.Thread(target=announce_loop, daemon=True).start()

    identity_hash_hex = identity.hash.hex()   # 32 hex chars (16 bytes)
    dest_hash_hex = local_dest.hash.hex()      # 32 hex chars (16 bytes)

    # Signal readiness to the Swift test harness.
    print(f"READY {port} {identity_hash_hex} {dest_hash_hex}", flush=True)

    # ------------------------------------------------------------------ #
    # Block until a message arrives or the deadline expires.              #
    # ------------------------------------------------------------------ #
    if message_ready.wait(timeout=wait_timeout):
        msg = received[0]
        raw = msg.content
        if isinstance(raw, bytes):
            content = raw.decode("utf-8", errors="replace")
        else:
            content = str(raw) if raw is not None else ""
        print(f"RECEIVED {content}", flush=True)


if __name__ == "__main__":
    main()
