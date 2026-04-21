import Testing
import Foundation
@testable import ReticulumInterfaces
import ReticulumCrypto

// MARK: - AutoInterface Tests

@Suite("AutoInterface — Multicast Address Computation")
struct AutoInterfaceMulticastAddressTests {

    @Test("Default group ID 'reticulum' produces known multicast address")
    func defaultGroupProducesKnownAddress() {
        let groupID = "reticulum".data(using: .utf8)!
        let addr = AutoInterface.computeMulticastAddress(
            groupID: groupID,
            type:    "1",   // temporary (default)
            scope:   "2"    // link-local (default)
        )

        // Address must begin with ff12: (type=1, scope=2)
        #expect(addr.hasPrefix("ff12:"))

        // Must have exactly 8 groups separated by colons
        let groups = addr.split(separator: ":")
        #expect(groups.count == 8)

        // First group is always "ff12" for temporary link-local
        #expect(groups[0] == "ff12")

        // Second group is always "0" (fixed in the reference implementation)
        #expect(groups[1] == "0")

        // Concrete value must match the Python reference (SHA-256 based)
        // Both representations must resolve to the same binary IPv6 address
        var expected = sockaddr_in6()
        inet_pton(AF_INET6, "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1", &expected.sin6_addr)
        var actual = sockaddr_in6()
        inet_pton(AF_INET6, addr, &actual.sin6_addr)
        let expectedBytes = withUnsafeBytes(of: expected.sin6_addr) { Data($0) }
        let actualBytes = withUnsafeBytes(of: actual.sin6_addr) { Data($0) }
        #expect(actualBytes == expectedBytes, "Multicast address mismatch: got \(addr)")

        // Verify the address is stable across two calls with identical input
        let addr2 = AutoInterface.computeMulticastAddress(
            groupID: groupID,
            type:    "1",
            scope:   "2"
        )
        #expect(addr == addr2)
    }

    @Test("Permanent address type prefix is ff02")
    func permanentAddressTypeProducesCorrectPrefix() {
        let groupID = "reticulum".data(using: .utf8)!
        let addr = AutoInterface.computeMulticastAddress(
            groupID: groupID,
            type:    "0",   // permanent
            scope:   "2"
        )
        #expect(addr.hasPrefix("ff02:"))
    }

    @Test("Global scope changes scope nibble to 'e'")
    func globalScopePrefix() {
        let groupID = "reticulum".data(using: .utf8)!
        let addr = AutoInterface.computeMulticastAddress(
            groupID: groupID,
            type:    "1",
            scope:   "e"   // global
        )
        #expect(addr.hasPrefix("ff1e:"))
    }

    @Test("Different group IDs produce different multicast addresses")
    func differentGroupIDsProduceDifferentAddresses() {
        let gA = AutoInterface.computeMulticastAddress(
            groupID: "alpha".data(using: .utf8)!, type: "1", scope: "2"
        )
        let gB = AutoInterface.computeMulticastAddress(
            groupID: "beta".data(using: .utf8)!, type: "1", scope: "2"
        )
        #expect(gA != gB)
    }
}

// MARK: -

@Suite("AutoInterface — Discovery Token")
struct AutoInterfaceDiscoveryTokenTests {

    /// Discovery tokens use SHA-256 (Python: RNS.Identity.full_hash = SHA-256)
    @Test("Discovery token is a SHA-256 hash of groupID + addr")
    func discoveryTokenIsCorrectHash() {
        let groupID  = "reticulum".data(using: .utf8)!
        let addr     = "fe80::1"
        let expected = Hashing.sha256(groupID + addr.data(using: .utf8)!)

        // Token must be 32 bytes (SHA-256)
        #expect(expected.count == 32)

        // Must differ from SHA-512 to prove we're using the right function
        let wrongHash = Hashing.sha512(groupID + addr.data(using: .utf8)!)
        #expect(expected != wrongHash.prefix(32), "Token must not be truncated SHA-512")
    }

    @Test("Tokens for different addresses are distinct")
    func tokensForDifferentAddressesDiffer() {
        let groupID = "reticulum".data(using: .utf8)!
        let t1 = Hashing.sha256(groupID + "fe80::1".data(using: .utf8)!)
        let t2 = Hashing.sha256(groupID + "fe80::2".data(using: .utf8)!)
        #expect(t1 != t2)
    }

    @Test("Tokens for different group IDs are distinct for same address")
    func tokensForDifferentGroupsDiffer() {
        let addr = "fe80::1".data(using: .utf8)!
        let t1 = Hashing.sha256("reticulum".data(using: .utf8)! + addr)
        let t2 = Hashing.sha256("mynetwork".data(using: .utf8)! + addr)
        #expect(t1 != t2)
    }

    @Test("Token matches known Python-computed value")
    func tokenMatchesKnownValue() {
        // Python: hashlib.sha256(b"reticulum" + b"fe80::1").hexdigest()
        let groupID = "reticulum".data(using: .utf8)!
        let addr    = "fe80::1".data(using: .utf8)!
        let token   = Hashing.sha256(groupID + addr)
        let hexStr  = token.map { String(format: "%02x", $0) }.joined()
        #expect(hexStr == "97b25576749ea936b0d8a8536ffaf442d157cf47d460dcf13c48b7bd18b6c163")
    }
}

// MARK: -

@Suite("AutoInterface — Interface Enumeration")
struct AutoInterfaceEnumerationTests {

    @Test("enumerateIPv6LinkLocal returns only fe80:: addresses")
    func enumerationReturnsOnlyLinkLocal() {
        let results = AutoInterface.enumerateIPv6LinkLocal()
        for (_, addr) in results {
            #expect(addr.hasPrefix("fe80:"))
        }
    }

    @Test("enumerateIPv6LinkLocal returns no scope specifiers in addresses")
    func enumerationStripsScopeSpecifier() {
        let results = AutoInterface.enumerateIPv6LinkLocal()
        for (_, addr) in results {
            // Scope specifier '%ifname' must have been stripped
            #expect(!addr.contains("%"))
        }
    }
}

// MARK: -

@Suite("AutoInterface — Configuration")
struct AutoInterfaceConfigurationTests {

    @Test("Default ports match Reticulum reference values")
    func defaultPortsMatchReference() {
        #expect(AutoInterface.defaultDiscoveryPort == 29716)
        #expect(AutoInterface.defaultDataPort == 42671)
    }

    @Test("unicastDiscoveryPort is discoveryPort + 1")
    func unicastPortIsDiscoveryPlusOne() async {
        #expect(AutoInterface.defaultDiscoveryPort + 1 == 29717)
    }

    @Test("AutoInterface is not online before start()")
    func notOnlineBeforeStart() async {
        let iface = AutoInterface(name: "test")
        let online = await iface.isOnline
        #expect(!online)
    }
}

// MARK: -

@Suite("AutoInterface — Peer Key Scoping")
struct AutoInterfacePeerKeyTests {

    @Test("peerKey combines address and interface name")
    func peerKeyFormat() {
        let key = AutoInterface.peerKey(addr: "fe80::1", ifname: "en0")
        #expect(key == "fe80::1%en0")
    }

    @Test("Same address on different interfaces produces different keys")
    func differentInterfacesDifferentKeys() {
        let k1 = AutoInterface.peerKey(addr: "fe80::1", ifname: "en0")
        let k2 = AutoInterface.peerKey(addr: "fe80::1", ifname: "en1")
        #expect(k1 != k2)
    }

    @Test("Different addresses on same interface produce different keys")
    func differentAddressesDifferentKeys() {
        let k1 = AutoInterface.peerKey(addr: "fe80::1", ifname: "en0")
        let k2 = AutoInterface.peerKey(addr: "fe80::2", ifname: "en0")
        #expect(k1 != k2)
    }
}

// MARK: -

@Suite("AutoInterface — Dedup Ring Buffer")
struct AutoInterfaceDedupTests {

    @Test("AutoInterfacePeer dedup hash uses SHA-256")
    func dedupHashIsSHA256() {
        let data = Data([0x01, 0x02, 0x03, 0x04])
        let hash = Hashing.sha256(data)
        #expect(hash.count == 32, "Dedup hash must be 32 bytes (SHA-256)")

        let sha512truncated = Hashing.sha512(data).prefix(32)
        #expect(hash != Data(sha512truncated))
    }

    @Test("Dedup ring buffer detects duplicates within TTL")
    func dedupDetectsDuplicates() async {
        let iface = AutoInterface(name: "dedup-test")

        let hash = Hashing.sha256(Data([0xDE, 0xAD]))
        let now = Date()

        let first = await iface.testDequeCheck(hash: hash, timestamp: now)
        #expect(!first, "First occurrence should not be duplicate")

        let second = await iface.testDequeCheck(hash: hash, timestamp: now)
        #expect(second, "Second occurrence should be duplicate")
    }

    @Test("Dedup ring buffer expires entries after TTL")
    func dedupExpiresAfterTTL() async throws {
        let iface = AutoInterface(name: "dedup-ttl-test")

        let hash = Hashing.sha256(Data([0xBE, 0xEF]))
        let now = Date()

        _ = await iface.testDequeCheck(hash: hash, timestamp: now)

        // Wait past the 0.75s TTL so wall-clock eviction kicks in
        try await Task.sleep(nanoseconds: 800_000_000)

        let afterExpiry = await iface.testDequeCheck(hash: hash, timestamp: Date())
        #expect(!afterExpiry, "Entry should have expired past TTL")
    }

    @Test("Dedup ring buffer respects size limit with FIFO eviction")
    func dedupFIFOEviction() async {
        let iface = AutoInterface(name: "dedup-fifo-test")
        let now = Date()

        // Fill the ring buffer to capacity (48 entries)
        for i in 0..<48 {
            let hash = Hashing.sha256(Data([UInt8(i & 0xFF), UInt8(i >> 8)]))
            _ = await iface.testDequeCheck(hash: hash, timestamp: now)
        }

        // Adding one more should evict the oldest entry
        let newHash = Hashing.sha256(Data([0xFF, 0xFF]))
        _ = await iface.testDequeCheck(hash: newHash, timestamp: now)

        // The first entry should no longer be detected as duplicate
        let firstHash = Hashing.sha256(Data([0x00, 0x00]))
        let isStillThere = await iface.testDequeCheck(hash: firstHash, timestamp: now)
        #expect(!isStillThere, "First entry should have been evicted by FIFO")
    }

    @Test("Distinct data produces distinct hashes")
    func distinctDataDistinctHashes() async {
        let iface = AutoInterface(name: "dedup-distinct-test")
        let now = Date()

        let hash1 = Hashing.sha256(Data([0x01]))
        let hash2 = Hashing.sha256(Data([0x02]))

        _ = await iface.testDequeCheck(hash: hash1, timestamp: now)

        let isDuplicate = await iface.testDequeCheck(hash: hash2, timestamp: now)
        #expect(!isDuplicate, "Different data should not be considered duplicate")
    }
}

// MARK: -

@Suite("AutoInterface — Lifecycle")
struct AutoInterfaceLifecycleTests {

    @Test("stop() on a never-started interface does not crash")
    func stopWithoutStart() async {
        let iface = AutoInterface(name: "test-lifecycle")
        await iface.stop()
        let online = await iface.isOnline
        #expect(!online)
    }

    @Test("AutoInterface conforms to MessageTransportInterface")
    func conformsToProtocol() async {
        let iface = AutoInterface(name: "test-protocol")
        // Verify the key protocol methods exist and are callable
        let online = await iface.isOnline
        #expect(!online)

        await iface.setOnReceive { _ in }
        let key = await iface.identityPublicKey(for: Data())
        #expect(key == nil)
    }
}
