#!/usr/bin/env python3
"""
Python Reticulum bidirectional messaging node for Swift integration testing.

Connects to rns.inertia.chat:4242 as a TCPClientInterface, creates an LXMF
delivery destination, announces it, and participates in bidirectional messaging
tests.

stdout protocol (one line per event, flushed immediately):
  READY <identity_hash_hex(32)> <lxmf_dest_hash_hex(32)>
  RECEIVED <content_utf8>
  SENT
  ERROR <reason>

Arguments:
  $1  swift_dest_hash_hex  (32 hex chars = 16 bytes, optional)
        When provided, Python sends a test message to Swift
        after announcing.
  $2  wait_timeout         (float seconds, default 30.0)

Exit codes:
  0  normal (received/sent/timeout)
  1  fatal error (import failure, RNS start failure)
"""

import sys
import os
import time
import shutil
import tempfile
import threading


def main() -> None:
    # Argument parsing: argv[1] is either a hex dest hash or a float timeout.
    # argv[2] (if present) is the float timeout when argv[1] is a hex hash.
    swift_dest_hash_hex = None
    wait_timeout = 30.0
    if len(sys.argv) > 1:
        try:
            wait_timeout = float(sys.argv[1])
        except ValueError:
            swift_dest_hash_hex = sys.argv[1]
            if len(sys.argv) > 2:
                try:
 wait_timeout = float(sys.argv[2])
                except ValueError:
 pass

    try:
        import RNS
        import LXMF
    except ImportError as exc:
        print(f"ERROR Missing Python dependency: {exc}", flush=True)
        sys.exit(1)

    tmpdir = tempfile.mkdtemp(prefix="rns_swift_relay_")
    try:
        _run(RNS, LXMF, swift_dest_hash_hex, tmpdir, wait_timeout)
    except Exception as exc:
        import traceback
        print(f"ERROR {exc}", flush=True)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _run(RNS, LXMF, swift_dest_hash_hex, tmpdir: str, wait_timeout: float) -> None:
    # ------------------------------------------------------------------ #
    # Start RNS with a TCPClientInterface to rns.inertia.chat:4242        #
    # ------------------------------------------------------------------ #
    config_path = os.path.join(tmpdir, "config")
    with open(config_path, "w") as f:
        f.write(
            "[reticulum]\n"
            "  share_instance = No\n"
            "  enable_transport = False\n"
            "\n"
            "[interfaces]\n"
            "\n"
            "  [[RelayInterface]]\n"
            "    type = TCPClientInterface\n"
            "    enabled = yes\n"
            "    target_host = rns.inertia.chat\n"
            "    target_port = 4242\n"
        )

    reticulum = RNS.Reticulum(configdir=tmpdir, loglevel=RNS.LOG_CRITICAL)  # noqa: F841

    # Wait for the TCP connection to come up.
    time.sleep(3.0)

    # ------------------------------------------------------------------ #
    # Set up LXMF router and delivery identity.        #
    # ------------------------------------------------------------------ #
    lxmf_dir = os.path.join(tmpdir, "lxmf")
    router = LXMF.LXMRouter(storagepath=lxmf_dir, autopeer=False)

    identity = RNS.Identity()
    local_dest = router.register_delivery_identity(
        identity, display_name="SwiftRelayTestNode"
    )
    # Disable ratchets for wire-format simplicity.
    local_dest.ratchets = None

    received: list = []
    message_ready = threading.Event()

    def on_delivery(message) -> None:
        received.append(message)
        message_ready.set()

    router.register_delivery_callback(on_delivery)

    # Announce our destination on the relay network.
    local_dest.announce()

    identity_hash_hex = identity.hash.hex()    # 32 hex chars (16 bytes)
    dest_hash_hex     = local_dest.hash.hex()  # 32 hex chars (16 bytes)

    # Signal readiness to the Swift test harness.
    print(f"READY {identity_hash_hex} {dest_hash_hex}", flush=True)

    # ------------------------------------------------------------------ #
    # Optionally send a message to the Swift node.     #
    # ------------------------------------------------------------------ #
    if swift_dest_hash_hex:
        # Wait a moment for path discovery via the relay.
        time.sleep(3.0)

        swift_hash = bytes.fromhex(swift_dest_hash_hex)
        swift_identity = RNS.Identity.recall(swift_hash)
        if swift_identity is None:
            # Request path discovery and wait.
            RNS.Transport.request_path(swift_hash)
            deadline = time.time() + 15.0
            while swift_identity is None and time.time() < deadline:
                time.sleep(0.5)
                swift_identity = RNS.Identity.recall(swift_hash)

        if swift_identity is not None:
            dest = RNS.Destination(
                swift_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "lxmf",
                "delivery",
            )
            msg = LXMF.LXMessage(
                dest,
                local_dest,
                "Hello from Python Reticulum",
                desired_method=LXMF.LXMessage.OPPORTUNISTIC,
            )
            router.handle_outbound(msg)
            # Give the message time to be sent.
            time.sleep(2.0)
            print("SENT", flush=True)
        else:
            print("ERROR Could not discover path to Swift node", flush=True)

    # ------------------------------------------------------------------ #
    # Block until an incoming message arrives or the deadline expires.    #
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
