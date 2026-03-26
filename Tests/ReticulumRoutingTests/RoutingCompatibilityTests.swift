import Testing
import Foundation
@testable import ReticulumRouting
import ReticulumPackets

// Routing Protocol Compatibility Tests
//
// Tests verify the Swift routing layer matches Reticulum routing semantics:
//
//   Path discovery  – receiving an announce populates the routing table
//   Path caching    – better routes replace worse ones; worse routes are ignored
//   Path expiration – stale routes are pruned; fresh routes survive
//   Multi-hop       – announces are forwarded with incremented hop counts;
//  data packets are forwarded to the correct next-hop interface
//
// All routing types (Path, RoutingTable, AnnounceManager, TransportManager,
// NodeInterface) are stubs — tests FAIL until they are implemented.

// Mock infrastructure

/// A deterministic mock interface that records every byte transmitted through it.
private actor MockInterface: NodeInterface {
    let interfaceID: String
    private(set) var sentData: [Data] = []

    init(id: String) { self.interfaceID = id }

    func transmit(_ data: Data) {
        sentData.append(data)
    }

    /// Convenience: parse each transmitted buffer as a Packet.
    var sentPackets: [Packet] {
        sentData.compactMap { try? Packet.deserialize(from: $0) }
    }
}

// Path factory helpers

private func makePath(
    dest:      Data,
    via:       String       = "if0",
    hops:      Int          = 1,
    expiresIn  ttl: TimeInterval = 3_600
) -> Path {
    Path(
        destinationHash:    dest,
        nextHopInterfaceID: via,
        hops:               hops,
        expires:            Date(timeIntervalSinceNow: ttl)
    )
}

private func expiredPath(dest: Data, via: String = "if0", hops: Int = 1) -> Path {
    Path(
        destinationHash:    dest,
        nextHopInterfaceID: via,
        hops:               hops,
        expires:            Date(timeIntervalSinceNow: -1)  // 1 second in the past
    )
}

// Fixture loading

private func loadAnnounceFixture(name: String) throws -> [String: Any] {
    try RoutingFixtureLoader.load(subdir: "announces", name: "\(name).json")
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Suite 1 — Path Data Model
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("Path — Data Model")
struct PathDataModelTests {

    @Test("Path stores destinationHash exactly")
    func storesDestinationHash() {
        let dest = testDestHash(0xAB)
        let path = makePath(dest: dest)
        #expect(path.destinationHash == dest)
    }

    @Test("Path stores nextHopInterfaceID exactly")
    func storesNextHopInterfaceID() {
        let path = makePath(dest: testDestHash(0x01), via: "tcp_upstream")
        #expect(path.nextHopInterfaceID == "tcp_upstream")
    }

    @Test("Path stores hop count exactly")
    func storesHops() {
        let path = makePath(dest: testDestHash(0x02), hops: 5)
        #expect(path.hops == 5)
    }

    @Test("Path.isExpired returns false for a future expiry")
    func isExpiredFalseForFutureDate() {
        let path = makePath(dest: testDestHash(0x03), expiresIn: 3_600)
        #expect(path.isExpired == false)
    }

    @Test("Path.isExpired returns true for a past expiry")
    func isExpiredTrueForPastDate() {
        let path = expiredPath(dest: testDestHash(0x04))
        #expect(path.isExpired == true)
    }

    @Test("Path quality is higher for fewer hops")
    func qualityDecreasesWithHops() {
        let near = makePath(dest: testDestHash(0x05), hops: 1)
        let far  = makePath(dest: testDestHash(0x05), hops: 5)
        #expect(near.quality > far.quality)
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Suite 2 — RoutingTable Insert / Lookup
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("RoutingTable — Insert and Lookup")
struct RoutingTableInsertLookupTests {

    @Test("Empty table returns nil for any destination")
    func emptyTableReturnsNil() async {
        let table = RoutingTable()
        let result = await table.path(for: testDestHash(0x10))
        #expect(result == nil)
    }

    @Test("Inserted path is retrievable by destinationHash")
    func insertedPathIsRetrievable() async {
        let table = RoutingTable()
        let dest  = testDestHash(0x11)
        let path  = makePath(dest: dest)
        await table.insert(path)
        let result = await table.path(for: dest)
        #expect(result != nil)
        #expect(result?.destinationHash == dest)
    }

    @Test("count is zero for an empty table")
    func countStartsAtZero() async {
        let table = RoutingTable()
        let n = await table.count
        #expect(n == 0)
    }

    @Test("count increases after each unique insert")
    func countIncreasesAfterInsert() async {
        let table = RoutingTable()
        await table.insert(makePath(dest: testDestHash(0x12)))
        await table.insert(makePath(dest: testDestHash(0x13)))
        let n = await table.count
        #expect(n == 2)
    }

    @Test("inserting the same destination twice stores only one entry")
    func duplicateDestinationHasOneEntry() async {
        let table = RoutingTable()
        let dest  = testDestHash(0x14)
        await table.insert(makePath(dest: dest, via: "if_a", hops: 3))
        await table.insert(makePath(dest: dest, via: "if_b", hops: 2))
        let n = await table.count
        #expect(n == 1)
    }

    @Test("inserting a better path (fewer hops) replaces the existing entry")
    func betterPathReplacesworse() async {
        let table = RoutingTable()
        let dest  = testDestHash(0x15)
        await table.insert(makePath(dest: dest, via: "slow_if", hops: 5))
        await table.insert(makePath(dest: dest, via: "fast_if", hops: 1))
        let result = await table.path(for: dest)
        #expect(result?.nextHopInterfaceID == "fast_if")
        #expect(result?.hops == 1)
    }

    @Test("inserting a worse path (more hops) does not replace the existing entry")
    func worsePathDoesNotReplacesBetter() async {
        let table = RoutingTable()
        let dest  = testDestHash(0x16)
        await table.insert(makePath(dest: dest, via: "fast_if", hops: 1))
        await table.insert(makePath(dest: dest, via: "slow_if", hops: 7))
        let result = await table.path(for: dest)
        #expect(result?.nextHopInterfaceID == "fast_if")
        #expect(result?.hops == 1)
    }

    @Test("lookup returns nil for a destination that was never inserted")
    func lookupUnknownDestReturnsNil() async {
        let table = RoutingTable()
        await table.insert(makePath(dest: testDestHash(0x17)))
        let result = await table.path(for: testDestHash(0xFF))
        #expect(result == nil)
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Suite 3 — Path Expiration
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("RoutingTable — Path Expiration")
struct RoutingTableExpiryTests {

    @Test("removeExpired removes a path with a past expiry")
    func removesExpiredPath() async {
        let table = RoutingTable()
        let dest  = testDestHash(0x20)
        await table.insert(expiredPath(dest: dest))
        await table.removeExpired()
        let result = await table.path(for: dest)
        #expect(result == nil)
    }

    @Test("removeExpired does not remove a path with a future expiry")
    func keepsFreshPath() async {
        let table = RoutingTable()
        let dest  = testDestHash(0x21)
        await table.insert(makePath(dest: dest, expiresIn: 3_600))
        await table.removeExpired()
        let result = await table.path(for: dest)
        #expect(result != nil)
    }

    @Test("removeExpired only removes the expired paths from a mixed set")
    func onlyExpiredPathsAreRemoved() async {
        let table   = RoutingTable()
        let expired = testDestHash(0x22)
        let fresh   = testDestHash(0x23)
        await table.insert(expiredPath(dest: expired))
        await table.insert(makePath(dest: fresh, expiresIn: 3_600))
        await table.removeExpired()
        let n = await table.count
        #expect(n == 1)
        #expect(await table.path(for: expired) == nil)
        #expect(await table.path(for: fresh) != nil)
    }

    @Test("count drops to zero after all paths expire and removeExpired is called")
    func countDropsToZeroAfterAllExpire() async {
        let table = RoutingTable()
        await table.insert(expiredPath(dest: testDestHash(0x24)))
        await table.insert(expiredPath(dest: testDestHash(0x25)))
        await table.removeExpired()
        let n = await table.count
        #expect(n == 0)
    }

    @Test("path(for:) returns the path while it has not yet expired")
    func pathAvailableBeforeExpiry() async {
        let table = RoutingTable()
        let dest  = testDestHash(0x26)
        // expires in the future — should be found
        await table.insert(makePath(dest: dest, expiresIn: 60))
        let result = await table.path(for: dest)
        #expect(result != nil)
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Suite 4 — AnnounceManager
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("AnnounceManager — Announce Processing")
struct AnnounceManagerTests {

    // Loads the announce_basic fixture and returns the raw packet bytes.
    private func announceBytes() throws -> Data {
        let fixture = try loadAnnounceFixture(name: "announce_basic")
        return try fixture.hexData(at: "expected.raw_hex")
    }

    private func announceDestHash() throws -> Data {
        let fixture = try loadAnnounceFixture(name: "announce_basic")
        return try fixture.hexData(at: "expected.destination_hash_hex")
    }

    @Test("receive() valid Python announce returns true (accepted)")
    func receiveValidAnnounceReturnsTrue() async throws {
        let manager = AnnounceManager()
        let raw     = try announceBytes()
        let accepted = await manager.receive(data: raw, fromInterfaceID: "if0")
        #expect(accepted == true,
                "AnnounceManager should accept a valid Python-generated announce")
    }

    @Test("receive() valid announce → destination becomes known")
    func receiveValidAnnounceDestinationIsKnown() async throws {
        let manager  = AnnounceManager()
        let raw      = try announceBytes()
        let destHash = try announceDestHash()
        _ = await manager.receive(data: raw, fromInterfaceID: "if0")
        let known = await manager.isKnown(destinationHash: destHash)
        #expect(known == true,
                "destination should be known after receiving a valid announce")
    }

    @Test("receive() valid announce → path stored in routing table")
    func receiveValidAnnouncePathStored() async throws {
        let manager  = AnnounceManager()
        let raw      = try announceBytes()
        let destHash = try announceDestHash()
        _ = await manager.receive(data: raw, fromInterfaceID: "if0")
        let path = await manager.path(for: destHash)
        #expect(path != nil, "routing table should contain a path after a valid announce")
    }

    @Test("receive() valid announce → stored path has hops = announce.hops + 1")
    func receiveValidAnnounceStoredHopsIncremented() async throws {
        let manager  = AnnounceManager()
        let raw      = try announceBytes()
        let destHash = try announceDestHash()
        // The fixture's announce_basic has hops = 0 in the header.
        _ = await manager.receive(data: raw, fromInterfaceID: "if0")
        let path = await manager.path(for: destHash)
        #expect(path?.hops == 1,
                "stored path hops should be announce header hops (0) + 1 = 1")
    }

    @Test("receive() valid announce → stored path points to the receiving interface")
    func receiveValidAnnounceStoredPathInterface() async throws {
        let manager  = AnnounceManager()
        let raw      = try announceBytes()
        let destHash = try announceDestHash()
        _ = await manager.receive(data: raw, fromInterfaceID: "if_upstream")
        let path = await manager.path(for: destHash)
        #expect(path?.nextHopInterfaceID == "if_upstream",
                "stored path should point back to the interface the announce arrived on")
    }

    @Test("receive() announce with tampered signature returns false (rejected)")
    func receiveInvalidSignatureReturnsFalse() async throws {
        let manager = AnnounceManager()
        var raw     = try announceBytes()
        // Flip a byte deep inside the Ed25519 signature region of the payload.
        // Signature starts at payload byte 84 → raw byte 19 + 84 = 103.
        raw[103] ^= 0xFF
        let accepted = await manager.receive(data: raw, fromInterfaceID: "if0")
        #expect(accepted == false,
                "AnnounceManager should reject an announce whose signature is invalid")
    }

    @Test("receive() invalid announce → destination remains unknown")
    func receiveInvalidAnnounceDestinationUnknown() async throws {
        let manager  = AnnounceManager()
        var raw      = try announceBytes()
        raw[103]    ^= 0xFF
        let destHash = try announceDestHash()
        _ = await manager.receive(data: raw, fromInterfaceID: "if0")
        let known = await manager.isKnown(destinationHash: destHash)
        #expect(known == false,
                "destination should NOT be known after a rejected (invalid sig) announce")
    }

    @Test("receive() same announce twice → isDuplicate returns true on second arrival")
    func receiveAnnounceTwiceIsDuplicate() async throws {
        let manager = AnnounceManager()
        let raw     = try announceBytes()
        _ = await manager.receive(data: raw, fromInterfaceID: "if0")
        let duplicate = await manager.isDuplicate(data: raw)
        #expect(duplicate == true,
                "the same announce random_hash should be flagged as a duplicate")
    }

    @Test("receive() duplicate announce → accepted == false (already known)")
    func receiveDuplicateAnnounceRejected() async throws {
        let manager = AnnounceManager()
        let raw     = try announceBytes()
        _ = await manager.receive(data: raw, fromInterfaceID: "if0")
        let second  = await manager.receive(data: raw, fromInterfaceID: "if1")
        #expect(second == false,
                "duplicate announce (same random_hash) should not be re-accepted")
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Suite 5 — TransportManager Multi-Hop Forwarding
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("TransportManager — Multi-Hop Forwarding")
struct TransportManagerForwardingTests {

    private func announceBytes() throws -> Data {
        let fixture = try RoutingFixtureLoader.load(subdir: "announces", name: "announce_basic.json")
        return try fixture.hexData(at: "expected.raw_hex")
    }

    // ── Path discovery ───────────────────────────────────────────────────

    @Test("receiving an announce on one interface adds a path to the routing table")
    func receiveAnnounceAddsPath() async throws {
        let transport = TransportManager()
        let ifA       = MockInterface(id: "if_a")
        await transport.register(ifA)

        let raw      = try announceBytes()
        let fixture  = try RoutingFixtureLoader.load(subdir: "announces", name: "announce_basic.json")
        let destHash = try fixture.hexData(at: "expected.destination_hash_hex")

        await transport.receive(data: raw, fromInterfaceID: "if_a")

        let path = await transport.routingTable.path(for: destHash)
        #expect(path != nil,
                "routing table should contain a path after receiving an announce")
    }

    @Test("discovered path's nextHopInterfaceID matches the interface the announce arrived on")
    func discoveredPathPointsToArrivalInterface() async throws {
        let transport = TransportManager()
        let ifA       = MockInterface(id: "if_a")
        await transport.register(ifA)

        let raw      = try announceBytes()
        let fixture  = try RoutingFixtureLoader.load(subdir: "announces", name: "announce_basic.json")
        let destHash = try fixture.hexData(at: "expected.destination_hash_hex")

        await transport.receive(data: raw, fromInterfaceID: "if_a")

        let path = await transport.routingTable.path(for: destHash)
        #expect(path?.nextHopInterfaceID == "if_a",
                "path should point back to the interface where the announce arrived")
    }

    // ── Multi-hop forwarding ─────────────────────────────────────────────

    @Test("announce received on interface A is forwarded to interface B")
    func announceForwardedToOtherInterface() async throws {
        let transport = TransportManager()
        let ifA       = MockInterface(id: "if_a")
        let ifB       = MockInterface(id: "if_b")
        await transport.register(ifA)
        await transport.register(ifB)

        let raw = try announceBytes()
        await transport.receive(data: raw, fromInterfaceID: "if_a")

        let forwarded = await ifB.sentData
        #expect(forwarded.count == 1,
                "interface B should have received exactly one forwarded announce")
    }

    @Test("announce is NOT forwarded back to the interface it arrived on")
    func announceNotForwardedBackToSender() async throws {
        let transport = TransportManager()
        let ifA       = MockInterface(id: "if_a")
        let ifB       = MockInterface(id: "if_b")
        await transport.register(ifA)
        await transport.register(ifB)

        let raw = try announceBytes()
        await transport.receive(data: raw, fromInterfaceID: "if_a")

        let sent = await ifA.sentData
        #expect(sent.isEmpty,
                "interface A should NOT receive the announce it just sent")
    }

    @Test("forwarded announce has hop count incremented by one")
    func forwardedAnnounceHopsIncremented() async throws {
        let transport = TransportManager()
        let ifA       = MockInterface(id: "if_a")
        let ifB       = MockInterface(id: "if_b")
        await transport.register(ifA)
        await transport.register(ifB)

        // announce_basic fixture has hops = 0.
        let raw = try announceBytes()
        await transport.receive(data: raw, fromInterfaceID: "if_a")

        let forwarded = await ifB.sentPackets
        #expect(forwarded.count == 1)
        #expect(forwarded.first?.header.hops == 1,
                "forwarded announce should have hops = original(0) + 1 = 1")
    }

    @Test("forwarded announce preserves the original destination hash")
    func forwardedAnnouncePreservesDestHash() async throws {
        let transport = TransportManager()
        let ifA       = MockInterface(id: "if_a")
        let ifB       = MockInterface(id: "if_b")
        await transport.register(ifA)
        await transport.register(ifB)

        let raw      = try announceBytes()
        let fixture  = try RoutingFixtureLoader.load(subdir: "announces", name: "announce_basic.json")
        let destHash = try fixture.hexData(at: "expected.destination_hash_hex")

        await transport.receive(data: raw, fromInterfaceID: "if_a")

        let forwarded = await ifB.sentPackets
        #expect(forwarded.first?.header.destinationHash == destHash,
                "destination hash must be preserved when forwarding an announce")
    }

    // ── Data packet forwarding ───────────────────────────────────────────

    @Test("DATA packet for a known destination is forwarded to the correct next-hop interface")
    func dataPacketForwardedToNextHop() async throws {
        let transport = TransportManager()
        let ifA       = MockInterface(id: "if_a")
        let ifB       = MockInterface(id: "if_b")
        await transport.register(ifA)
        await transport.register(ifB)

        // Teach the routing table: dest → go via if_b
        let dest = testDestHash(0x30)
        let path = Path(
            destinationHash:    dest,
            nextHopInterfaceID: "if_b",
            hops:               1,
            expires:            Date(timeIntervalSinceNow: 3_600)
        )
        await transport.routingTable.insert(path)

        // Build a DATA packet for that destination
        let header     = PacketHeader(packetType: .data, destinationType: .plain,
                   destinationHash: dest)
        let dataPacket = Packet(header: header, payload: Data("hello".utf8))
        await transport.receive(data: dataPacket.serialize(), fromInterfaceID: "if_a")

        let sent = await ifB.sentData
        #expect(!sent.isEmpty,
                "interface B should have received the DATA packet forwarded to it")
    }

    @Test("DATA packet for an unknown destination is not forwarded anywhere")
    func dataPacketForUnknownDestNotForwarded() async throws {
        let transport = TransportManager()
        let ifA       = MockInterface(id: "if_a")
        let ifB       = MockInterface(id: "if_b")
        await transport.register(ifA)
        await transport.register(ifB)

        // No path in table — routing table is empty
        let dest   = testDestHash(0xFF)
        let header = PacketHeader(packetType: .data, destinationType: .plain,
               destinationHash: dest)
        let pkt    = Packet(header: header, payload: Data("unknown".utf8))
        await transport.receive(data: pkt.serialize(), fromInterfaceID: "if_a")

        let sentA = await ifA.sentData
        let sentB = await ifB.sentData
        #expect(sentA.isEmpty && sentB.isEmpty,
                "no interface should receive a DATA packet for an unknown destination")
    }
}
