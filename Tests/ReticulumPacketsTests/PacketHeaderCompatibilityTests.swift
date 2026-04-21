import Testing
import Foundation
@testable import ReticulumPackets


// Helpers

private func loadPacketFixture(name: String) throws -> [String: Any] {
    try FixtureLoader.load(subdir: "packets", name: "\(name).json")
}

private func loadAnnounceFixture(name: String) throws -> [String: Any] {
    try FixtureLoader.load(subdir: "announces", name: "\(name).json")
}

// Flags Byte Encoding

@Suite("PacketHeader — Flags Byte Encoding")
struct PacketHeaderFlagsByteTests {

    // MARK: DATA / PLAIN

    @Test("DATA+PLAIN: flags byte is 0x08 (destType=PLAIN<<2 | pktType=DATA)")
    func dataPlainFlagsByte() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let expected = try fixture.uint8(at: "expected.header_byte_hex")

        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: try fixture.hexData(at: "inputs.destination_hash_hex"),
            hops:            0
        )
        #expect(header.flagsByte == expected,
                "flags byte mismatch — expected \(String(format: "0x%02x", expected)), got \(String(format: "0x%02x", header.flagsByte))")
    }

    @Test("DATA+PLAIN: packetType field decodes back to .data")
    func dataPlainPacketTypeField() throws {
        let fixture = try loadPacketFixture(name: "data_packet_plain")
        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: try fixture.hexData(at: "inputs.destination_hash_hex"),
            hops:            0
        )
        #expect(header.packetType == .data)
    }

    @Test("DATA+PLAIN: destinationType field decodes back to .plain")
    func dataPlainDestinationTypeField() throws {
        let fixture = try loadPacketFixture(name: "data_packet_plain")
        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: try fixture.hexData(at: "inputs.destination_hash_hex"),
            hops:            0
        )
        #expect(header.destinationType == .plain)
    }

    @Test("DATA+PLAIN: headerType is .header1 by default")
    func dataPlainHeaderType() throws {
        let fixture = try loadPacketFixture(name: "data_packet_plain")
        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: try fixture.hexData(at: "inputs.destination_hash_hex"),
            hops:            0
        )
        #expect(header.headerType == .header1)
    }

    @Test("DATA+PLAIN: propagationType is .broadcast by default")
    func dataPlainPropagationType() throws {
        let fixture = try loadPacketFixture(name: "data_packet_plain")
        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: try fixture.hexData(at: "inputs.destination_hash_hex"),
            hops:            0
        )
        #expect(header.propagationType == .broadcast)
    }

    // MARK: ANNOUNCE / SINGLE

    @Test("ANNOUNCE+SINGLE: flags byte is 0x01 (destType=SINGLE<<2 | pktType=ANNOUNCE)")
    func announceSingleFlagsByte() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let expected = try fixture.uint8(at: "expected.header_byte_hex")

        let header = PacketHeader(
            packetType:      .announce,
            destinationType: .single,
            destinationHash: try fixture.hexData(at: "expected.destination_hash_hex"),
            hops:            0
        )
        #expect(header.flagsByte == expected,
                "flags byte mismatch — expected \(String(format: "0x%02x", expected)), got \(String(format: "0x%02x", header.flagsByte))")
    }

    @Test("ANNOUNCE+SINGLE: packetType field decodes back to .announce")
    func announceSinglePacketTypeField() throws {
        let fixture = try loadAnnounceFixture(name: "announce_basic")
        let header = PacketHeader(
            packetType:      .announce,
            destinationType: .single,
            destinationHash: try fixture.hexData(at: "expected.destination_hash_hex"),
            hops:            0
        )
        #expect(header.packetType == .announce)
    }

    @Test("ANNOUNCE+SINGLE: destinationType field decodes back to .single")
    func announceSingleDestinationTypeField() throws {
        let fixture = try loadAnnounceFixture(name: "announce_basic")
        let header = PacketHeader(
            packetType:      .announce,
            destinationType: .single,
            destinationHash: try fixture.hexData(at: "expected.destination_hash_hex"),
            hops:            0
        )
        #expect(header.destinationType == .single)
    }

    // MARK: Flag-bit isolation

    @Test("flags byte bit layout: DATA=0b00 occupies bits [1:0]")
    func dataPacketTypeOccupiesLowBits() {
        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: Data(repeating: 0, count: 16),
            hops:            0
        )
        #expect(header.flagsByte & 0x03 == PacketType.data.rawValue)
    }

    @Test("flags byte bit layout: ANNOUNCE=0b01 occupies bits [1:0]")
    func announcePacketTypeOccupiesLowBits() {
        let header = PacketHeader(
            packetType:      .announce,
            destinationType: .single,
            destinationHash: Data(repeating: 0, count: 16),
            hops:            0
        )
        #expect(header.flagsByte & 0x03 == PacketType.announce.rawValue)
    }

    @Test("flags byte bit layout: PLAIN=0b10 occupies bits [3:2]")
    func plainDestTypeOccupiesBits3to2() {
        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: Data(repeating: 0, count: 16),
            hops:            0
        )
        #expect((header.flagsByte >> 2) & 0x03 == PacketHeader.DestinationType.plain.rawValue)
    }

    @Test("flags byte bit layout: SINGLE=0b00 occupies bits [3:2]")
    func singleDestTypeOccupiesBits3to2() {
        let header = PacketHeader(
            packetType:      .announce,
            destinationType: .single,
            destinationHash: Data(repeating: 0, count: 16),
            hops:            0
        )
        #expect((header.flagsByte >> 2) & 0x03 == PacketHeader.DestinationType.single.rawValue)
    }
}

// Serialisation

@Suite("PacketHeader — Serialisation")
struct PacketHeaderSerializationTests {

    // MARK: DATA / PLAIN

    @Test("DATA+PLAIN: serialize() first byte equals Python header_byte_hex (0x08)")
    func dataPlainSerializedHeaderByte() throws {
        let fixture      = try loadPacketFixture(name: "data_packet_plain")
        let destHash     = try fixture.hexData(at: "inputs.destination_hash_hex")
        let expectedByte = try fixture.uint8(at: "expected.header_byte_hex")

        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: destHash,
            hops:            0
        )
        let bytes = header.serialize()
        #expect(bytes.first == expectedByte,
                "first byte mismatch — expected \(String(format: "0x%02x", expectedByte)), got \(bytes.first.map { String(format: "0x%02x", $0) } ?? "nil")")
    }

    @Test("DATA+PLAIN: serialize() second byte equals Python hops_byte_hex (0x00)")
    func dataPlainSerializedHopsByte() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let destHash = try fixture.hexData(at: "inputs.destination_hash_hex")
        let expected = try fixture.uint8(at: "expected.hops_byte_hex")

        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: destHash,
            hops:            expected
        )
        let bytes = header.serialize()
        #expect(bytes.count >= 2)
        #expect(bytes[1] == expected)
    }

    @Test("DATA+PLAIN: serialize() bytes 2–17 equal destination hash")
    func dataPlainSerializedDestinationHash() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let destHash = try fixture.hexData(at: "inputs.destination_hash_hex")
        let expected = try fixture.hexData(at: "expected.destination_hash_hex")

        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: destHash,
            hops:            0
        )
        let bytes = header.serialize()
        #expect(bytes.count >= 18)
        #expect(Data(bytes[2..<18]) == expected,
                "destination hash mismatch in serialised header")
    }

    @Test("DATA+PLAIN: serialize() byte 18 equals context byte (0x00)")
    func dataPlainSerializedContextByte() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let destHash = try fixture.hexData(at: "inputs.destination_hash_hex")
        let expected = try fixture.uint8(at: "expected.context_byte_hex")

        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: destHash,
            hops:            0,
            context:         expected
        )
        let bytes = header.serialize()
        #expect(bytes.count >= 19)
        #expect(bytes[18] == expected)
    }

    @Test("DATA+PLAIN: serialize() produces exactly 19 bytes for HEADER_1")
    func dataPlainSerializedLength() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let destHash = try fixture.hexData(at: "inputs.destination_hash_hex")

        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: destHash,
            hops:            0
        )
        #expect(header.serialize().count == 19)
    }

    @Test("DATA+PLAIN: full serialize() bytes match Python raw_hex prefix (first 19 bytes)")
    func dataPlainSerializedBytesMatchRawPrefix() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let destHash = try fixture.hexData(at: "inputs.destination_hash_hex")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = rawBytes.prefix(19)

        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: destHash,
            hops:            0,
            context:         rawBytes[18]
        )
        #expect(Data(header.serialize()) == Data(expected),
                "serialised header prefix mismatch — expected \(Data(expected).hexString), got \(Data(header.serialize()).hexString)")
    }

    // MARK: ANNOUNCE / SINGLE

    @Test("ANNOUNCE+SINGLE: serialize() first byte equals Python header_byte_hex (0x01)")
    func announceSingleSerializedHeaderByte() throws {
        let fixture      = try loadAnnounceFixture(name: "announce_basic")
        let destHash     = try fixture.hexData(at: "expected.destination_hash_hex")
        let expectedByte = try fixture.uint8(at: "expected.header_byte_hex")

        let header = PacketHeader(
            packetType:      .announce,
            destinationType: .single,
            destinationHash: destHash,
            hops:            0
        )
        let bytes = header.serialize()
        #expect(bytes.first == expectedByte,
                "ANNOUNCE header byte mismatch — expected \(String(format: "0x%02x", expectedByte)), got \(bytes.first.map { String(format: "0x%02x", $0) } ?? "nil")")
    }

    @Test("ANNOUNCE+SINGLE: full serialize() bytes match Python raw_hex prefix (first 19 bytes)")
    func announceSingleSerializedBytesMatchRawPrefix() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let destHash = try fixture.hexData(at: "expected.destination_hash_hex")
        let expected = rawBytes.prefix(19)

        let header = PacketHeader(
            packetType:      .announce,
            destinationType: .single,
            destinationHash: destHash,
            hops:            rawBytes[1],
            context:         rawBytes[18]
        )
        #expect(Data(header.serialize()) == Data(expected),
                "serialised ANNOUNCE header prefix mismatch — expected \(Data(expected).hexString), got \(Data(header.serialize()).hexString)")
    }

    @Test("ANNOUNCE+SINGLE: destination hash in serialize() matches Python reference")
    func announceSingleSerializedDestHash() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let destHash = try fixture.hexData(at: "expected.destination_hash_hex")

        let header = PacketHeader(
            packetType:      .announce,
            destinationType: .single,
            destinationHash: destHash,
            hops:            0
        )
        let bytes = header.serialize()
        #expect(Data(bytes[2..<18]) == destHash)
    }
}

// Deserialisation

@Suite("PacketHeader — Deserialisation")
struct PacketHeaderDeserializationTests {

    // MARK: DATA / PLAIN

    @Test("DATA+PLAIN: deserialize() from raw_hex prefix → packetType == .data")
    func dataPlainDeserializedPacketType() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.packetType == .data)
    }

    @Test("DATA+PLAIN: deserialize() from raw_hex prefix → destinationType == .plain")
    func dataPlainDeserializedDestinationType() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.destinationType == .plain)
    }

    @Test("DATA+PLAIN: deserialize() from raw_hex prefix → headerType == .header1")
    func dataPlainDeserializedHeaderType() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.headerType == .header1)
    }

    @Test("DATA+PLAIN: deserialize() from raw_hex prefix → propagationType == .broadcast")
    func dataPlainDeserializedPropagationType() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.propagationType == .broadcast)
    }

    @Test("DATA+PLAIN: deserialize() from raw_hex → hops == 0")
    func dataPlainDeserializedHops() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = try fixture.uint8(at: "expected.hops_byte_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.hops == expected)
    }

    @Test("DATA+PLAIN: deserialize() from raw_hex → destinationHash matches Python reference")
    func dataPlainDeserializedDestinationHash() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = try fixture.hexData(at: "expected.destination_hash_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.destinationHash == expected,
                "destinationHash mismatch — expected \(expected.hexString), got \(header.destinationHash.hexString)")
    }

    @Test("DATA+PLAIN: deserialize() from raw_hex → context byte == 0x00")
    func dataPlainDeserializedContextByte() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = try fixture.uint8(at: "expected.context_byte_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.context == expected)
    }

    @Test("DATA+PLAIN: deserialize() flags byte reconstructs to expected value")
    func dataPlainDeserializedFlagsByte() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = try fixture.uint8(at: "expected.header_byte_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.flagsByte == expected,
                "flagsByte mismatch after deserialize — expected \(String(format: "0x%02x", expected)), got \(String(format: "0x%02x", header.flagsByte))")
    }

    // MARK: ANNOUNCE / SINGLE

    @Test("ANNOUNCE+SINGLE: deserialize() → packetType == .announce")
    func announceSingleDeserializedPacketType() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.packetType == .announce)
    }

    @Test("ANNOUNCE+SINGLE: deserialize() → destinationType == .single")
    func announceSingleDeserializedDestinationType() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.destinationType == .single)
    }

    @Test("ANNOUNCE+SINGLE: deserialize() → destinationHash matches Python reference")
    func announceSingleDeserializedDestinationHash() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = try fixture.hexData(at: "expected.destination_hash_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.destinationHash == expected,
                "ANNOUNCE destinationHash mismatch — expected \(expected.hexString), got \(header.destinationHash.hexString)")
    }

    @Test("ANNOUNCE+SINGLE: deserialize() flags byte reconstructs to 0x01")
    func announceSingleDeserializedFlagsByte() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = try fixture.uint8(at: "expected.header_byte_hex")

        let header = try PacketHeader.deserialize(from: rawBytes)
        #expect(header.flagsByte == expected,
                "ANNOUNCE flagsByte mismatch after deserialize — expected \(String(format: "0x%02x", expected)), got \(String(format: "0x%02x", header.flagsByte))")
    }

    // MARK: Error handling

    @Test("deserialize() throws on input shorter than 19 bytes")
    func deserializeTooShortThrows() {
        let short = Data(repeating: 0x00, count: 18)
        #expect(throws: (any Error).self) {
            try PacketHeader.deserialize(from: short)
        }
    }
}

// Round-trip

@Suite("PacketHeader — Round-trip")
struct PacketHeaderRoundTripTests {

    @Test("DATA+PLAIN: serialize(deserialize(rawPrefix)) == rawPrefix (19 bytes)")
    func dataPlainRoundTrip() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = Data(rawBytes.prefix(19))

        let parsed     = try PacketHeader.deserialize(from: rawBytes)
        let serialized = Data(parsed.serialize())

        #expect(serialized == expected,
                "round-trip mismatch — expected \(expected.hexString), got \(serialized.hexString)")
    }

    @Test("ANNOUNCE+SINGLE: serialize(deserialize(rawPrefix)) == rawPrefix (19 bytes)")
    func announceSingleRoundTrip() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = Data(rawBytes.prefix(19))

        let parsed     = try PacketHeader.deserialize(from: rawBytes)
        let serialized = Data(parsed.serialize())

        #expect(serialized == expected,
                "ANNOUNCE round-trip mismatch — expected \(expected.hexString), got \(serialized.hexString)")
    }

    @Test("constructing then serialising produces the same bytes as Python raw_hex prefix")
    func constructAndSerializeMatchesPython() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")

        // Build header from scratch using fixture inputs
        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: try fixture.hexData(at: "inputs.destination_hash_hex"),
            hops:            0,
            context:         0
        )
        let expected = Data(rawBytes.prefix(19))
        #expect(Data(header.serialize()) == expected)
    }

    @Test("hops field survives a serialize / deserialize round-trip")
    func hopsRoundTrip() throws {
        let fixture = try loadPacketFixture(name: "data_packet_plain")
        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: try fixture.hexData(at: "inputs.destination_hash_hex"),
            hops:            7
        )
        let parsed = try PacketHeader.deserialize(from: header.serialize() + Data(count: 12))
        #expect(parsed.hops == 7)
    }

    @Test("all PacketType values round-trip through the flags byte without loss")
    func allPacketTypesRoundTrip() throws {
        let fixture = try loadPacketFixture(name: "data_packet_plain")
        let dummyHash = try fixture.hexData(at: "inputs.destination_hash_hex")

        for pt in [PacketType.data, .announce, .linkRequest, .proof] {
            let header = PacketHeader(
                packetType:      pt,
                destinationType: .plain,
                destinationHash: dummyHash,
                hops:            0
            )
            let bytes  = header.serialize() + Data(count: 12)
            let parsed = try PacketHeader.deserialize(from: bytes)
            #expect(parsed.packetType == pt,
 "packetType \(pt) did not survive round-trip")
        }
    }
}
