import Testing
@testable import ReticulumPackets

// ReticulumPackets Module Tests
//
// Binary protocol tests must verify exact byte-level equality
// with values produced by the Python RNS reference implementation.

@Suite("ReticulumPackets")
struct ReticulumPacketsTests {
    // Tests will be added here as features are implemented.
    // First features to test:
    //   - PacketHeader serialization / deserialization round-trip
    //   - Known-good header bytes from Python reference
    //   - PacketType raw values match protocol constants
    //   - Full Packet round-trip (serialize then parse)
}
