import Testing
import Foundation
@testable import ReticulumCrypto
@testable import ReticulumPackets
@testable import ReticulumInterfaces
@testable import LXMF

// RNS Integration Tests
//
// End-to-end tests connecting a live Swift Reticulum stack to a real Python
// Reticulum node (rns >= 1.1.3, lxmf >= 0.9.4) via TCPClientInterface.
//
// Failing tests and what they require:
//
//   Suite 1 — Announce Reception
//     ✅ Passes once Python node is reachable and TCPClientInterface connects.
//     ✅ All tests in this suite should pass with the current implementation.
//
//   Suite 2 — LXMF Message Delivery
//     ❌ generatesLocalIdentity    → Identity.generate() not yet implemented
//     ❌ createsSignedMessage       → LXMFMessage.create() not yet implemented
//     ❌ sendsLXMFMessageOpportunistic → depends on both of the above
//     ❌ pythonNodeReceivesMessage  → placeholder for bidirectional messaging
//
// Run with:
//   swift test --filter IntegrationTests
//
// Requires Python 3.
// RNS/LXMF dependencies are auto-bootstrapped by IntegrationTests.

// Suite 1: Announce Reception

/// Verifies that the Swift TCPClientInterface can connect to a Python RNS node
/// and correctly receive + parse the announce packets it broadcasts.
@Suite("RNS Integration — Announce Reception")
struct AnnounceReceptionTests {

    /// The Python node starts, Swift connects, and the interface goes online.
    @Test("TCPClientInterface connects to Python RNS node")
    func connectsToPythonNode() async throws {
        let python = try PythonNodeHelper()
        defer { python.stop() }

        let info = try await python.waitForReady(timeout: 15)

        let iface = TCPClientInterface(
            name: "integration_test",
            host: "127.0.0.1",
            port: info.port
        )
        defer { Task { await iface.stop() } }
        try await iface.start()

        let online = await iface.isOnline
        #expect(online,
                "TCPClientInterface must be online after a successful TCP connection")
    }

    /// After connecting, the Python node immediately broadcasts an announce for
    /// its LXMF delivery destination.  Swift parses it as a valid Packet.
    @Test("Swift receives announce packet from Python RNS node")
    func receivesAnnounce() async throws {
        let python = try PythonNodeHelper()
        defer { python.stop() }

        let info = try await python.waitForReady(timeout: 15)

        let iface = TCPClientInterface(
            name: "integration_test",
            host: "127.0.0.1",
            port: info.port
        )
        defer { Task { await iface.stop() } }

        let collector = PacketCollector()
        await iface.setOnReceive { data in
            if let p = try? Packet.deserialize(from: data) {
                await collector.add(p)
            }
        }
        try await iface.start()

        // Allow up to 10 seconds for the announce to arrive.
        let announce = try await collector.waitForAnnounce(timeout: 10)
        #expect(announce != nil,
                "Expected at least one ANNOUNCE packet from Python node within 10 s")
    }

    /// The announce packet contains a 64-byte identity public key and a valid
    /// Ed25519 signature over (destinationHash + signedData).
    @Test("received announce has valid Ed25519 signature")
    func announceSignatureIsValid() async throws {
        let python = try PythonNodeHelper()
        defer { python.stop() }

        let info = try await python.waitForReady(timeout: 15)

        let iface = TCPClientInterface(
            name: "integration_test",
            host: "127.0.0.1",
            port: info.port
        )
        defer { Task { await iface.stop() } }

        let collector = PacketCollector()
        await iface.setOnReceive { data in
            if let p = try? Packet.deserialize(from: data),
               p.header.packetType == .announce {
                await collector.add(p)
            }
        }
        try await iface.start()

        guard let packet = try await collector.waitForAnnounce(timeout: 10) else {
            Issue.record("No announce received — skipping signature check")
            return
        }

        let payload = try AnnouncePayload.parse(from: packet.payload)
        let valid   = payload.verifySignature(destinationHash: packet.header.destinationHash)
        #expect(valid,
                "Announce from Python node must carry a valid Ed25519 signature")
    }

    /// The Ed25519 public key embedded in the announce derives to the same
    /// identity hash that the Python node reported on the READY line.
    @Test("announce public key derives to the reported identity hash")
    func announcePublicKeyMatchesIdentityHash() async throws {
        let python = try PythonNodeHelper()
        defer { python.stop() }

        let info = try await python.waitForReady(timeout: 15)

        let iface = TCPClientInterface(
            name: "integration_test",
            host: "127.0.0.1",
            port: info.port
        )
        defer { Task { await iface.stop() } }

        let collector = PacketCollector()
        await iface.setOnReceive { data in
            if let p = try? Packet.deserialize(from: data),
               p.header.packetType == .announce {
                await collector.add(p)
            }
        }
        try await iface.start()

        guard let packet = try await collector.waitForAnnounce(timeout: 10) else {
            Issue.record("No announce received — skipping identity hash check")
            return
        }

        let payload      = try AnnouncePayload.parse(from: packet.payload)
        let derivedHash  = Hashing.truncatedHash(
            Data(payload.identityPublicKey), length: 16
        )

        #expect(derivedHash == info.identityHash,
                """
                SHA-256(announce.publicKey)[0:16] must equal identity hash from READY line.
                  derived: \(derivedHash.hexString)
                  expected: \(info.identityHash.hexString)
                """)
    }
}

// Suite 2: LXMF Message Delivery

/// Verifies that the Swift stack can create, sign, and deliver an LXMF message
/// to a live Python Reticulum node using opportunistic (DATA-packet) delivery.
///
/// All tests in this suite initially FAIL because:
///   - `Identity.generate()` is not yet implemented (throws `.keyDerivationFailed`)
///   - `LXMFMessage.create()` is not yet implemented (throws `.notImplemented`)
///
/// They will pass once the LXMF creation pipeline is complete.
@Suite("RNS Integration — LXMF Message Delivery")
struct LXMFDeliveryTests {

    /// Verifies that `Identity.generate()` produces a valid 64-byte public key
    /// and 16-byte hash.  FAILS until `Identity.generate()` is implemented.
    @Test("Swift generates a local identity for LXMF sending")
    func generatesLocalIdentity() throws {
        // FAILS: Identity.generate() throws IdentityError.keyDerivationFailed (stub)
        let identity = try Identity.generate()

        #expect(identity.publicKey.count == 64,
                "Generated identity public key must be 64 bytes (X25519 + Ed25519)")
        #expect(identity.hash.count == 16,
                "Generated identity hash must be 16 bytes (truncated SHA-256)")
        #expect(identity.privateKeySeed != nil,
                "Generated identity must hold a private key seed for signing")
    }

    /// Verifies that a freshly created LXMF message round-trips correctly:
    /// pack → parse → verify signature.  FAILS until both `Identity.generate()`
    /// and `LXMFMessage.create()` are implemented.
    @Test("Swift creates and signs an LXMF message (round-trip)")
    func createsSignedMessage() throws {
        // FAILS: Identity.generate() is not yet implemented
        let senderIdentity = try Identity.generate()
        let recipientHash  = Data(repeating: 0xab, count: 16)

        // FAILS: LXMFMessage.create() is not yet implemented
        let packed = try LXMFMessage.create(
            destinationHash: recipientHash,
            sourceIdentity:  senderIdentity,
            content:         "Hello from Swift Reticulum",
            title:           "",
            timestamp:       1700000000.0
        )

        // Round-trip: parse the bytes we just produced
        let parsed = try LXMFMessage(packed: packed)

        #expect(parsed.content == "Hello from Swift Reticulum")
        #expect(parsed.destinationHash == recipientHash)
        let expectedSourceHash = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: senderIdentity.hash
        )
        #expect(parsed.sourceHash == expectedSourceHash)

        // Verify our own signature
        let pk        = senderIdentity.publicKey
        let offset    = pk.startIndex + 32
        let ed25519PubKey = Data(pk[offset...])
        #expect(
            parsed.verifySignature(ed25519PublicKey: ed25519PubKey),
            "A freshly created LXMF message must carry a valid self-signature"
        )
    }

    /// Placeholder for bidirectional messaging (Python → Swift).
    ///
    /// Disabled until inbound router callbacks are fully wired.
    @Test("Python RNS node sends LXMF message to Swift (placeholder)", .disabled("Pending inbound router wiring"))
    func pythonNodeSendsMessage() async throws {
        // Intentionally disabled.
    }
}

// PacketCollector (actor helper)

/// Thread-safe packet accumulator used in integration tests.
private actor PacketCollector {
    private var packets: [Packet] = []

    func add(_ packet: Packet) {
        packets.append(packet)
    }

    func announces() -> [Packet] {
        packets.filter { $0.header.packetType == .announce }
    }

    /// Poll until at least one ANNOUNCE packet is collected, or timeout.
    func waitForAnnounce(timeout: TimeInterval) async throws -> Packet? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let first = announces().first { return first }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        return announces().first
    }
}
