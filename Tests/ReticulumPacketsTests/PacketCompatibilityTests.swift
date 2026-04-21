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

// DATA / PLAIN — Deserialisation

@Suite("Packet — DATA/PLAIN Deserialisation")
struct PacketDataPlainDeserialiseTests {

    @Test("DATA+PLAIN: deserialize() returns a Packet without throwing")
    func dataPlainDeserialiseSucceeds() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        _ = try Packet.deserialize(from: rawBytes)
    }

    @Test("DATA+PLAIN: deserialize() → header.packetType == .data")
    func dataPlainDeserialisePacketType() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.packetType == .data)
    }

    @Test("DATA+PLAIN: deserialize() → header.destinationType == .plain")
    func dataPlainDeserialiseDestinationType() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.destinationType == .plain)
    }

    @Test("DATA+PLAIN: deserialize() → header.destinationHash matches Python reference")
    func dataPlainDeserialiseDestinationHash() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = try fixture.hexData(at: "expected.destination_hash_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.destinationHash == expected,
                "destinationHash mismatch — expected \(expected.hexString), got \(packet.header.destinationHash.hexString)")
    }

    @Test("DATA+PLAIN: deserialize() → header.hops == 0")
    func dataPlainDeserialiseHops() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.hops == 0)
    }

    @Test("DATA+PLAIN: deserialize() → header.context == 0x00")
    func dataPlainDeserialiseContext() throws {
        let fixture   = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let expected  = try fixture.uint8(at: "expected.context_byte_hex")
        let packet    = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.context == expected)
    }

    @Test("DATA+PLAIN: deserialize() → payload bytes match Python reference")
    func dataPlainDeserialisePayloadBytes() throws {
        let fixture   = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let expected  = try fixture.hexData(at: "expected.payload_hex")
        let packet    = try Packet.deserialize(from: rawBytes)
        #expect(packet.payload == expected,
                "payload mismatch — expected \(expected.hexString), got \(packet.payload.hexString)")
    }

    @Test("DATA+PLAIN: deserialize() → payload decodes to UTF-8 string 'test payload'")
    func dataPlainDeserialisePayloadUTF8() throws {
        let fixture   = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let expected  = try fixture.string(at: "inputs.payload_utf8")
        let packet    = try Packet.deserialize(from: rawBytes)
        let decoded   = String(bytes: packet.payload, encoding: .utf8)
        #expect(decoded == expected,
                "payload UTF-8 mismatch — expected \"\(expected)\", got \"\(decoded ?? "<nil>")\"")
    }

    @Test("DATA+PLAIN: deserialize() → payload is exactly 12 bytes")
    func dataPlainDeserialisePayloadLength() throws {
        let fixture   = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let expected  = try fixture.hexData(at: "expected.payload_hex")
        let packet    = try Packet.deserialize(from: rawBytes)
        #expect(packet.payload.count == expected.count,
                "payload length mismatch — expected \(expected.count), got \(packet.payload.count)")
    }

    @Test("DATA+PLAIN: deserialize() → header.flagsByte matches Python header_byte_hex")
    func dataPlainDeserialiseFlagsByte() throws {
        let fixture   = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let expected  = try fixture.uint8(at: "expected.header_byte_hex")
        let packet    = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.flagsByte == expected,
                "flagsByte mismatch — expected \(String(format: "0x%02x", expected)), got \(String(format: "0x%02x", packet.header.flagsByte))")
    }
}

// DATA / PLAIN — Serialisation

@Suite("Packet — DATA/PLAIN Serialisation")
struct PacketDataPlainSerialiseTests {

    @Test("DATA+PLAIN: serialize() produces byte-identical output to Python raw_hex")
    func dataPlainSerialiseMatchesPython() throws {
        let fixture   = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let packet    = try Packet.deserialize(from: rawBytes)
        let result    = packet.serialize()
        #expect(result == rawBytes,
                "serialized bytes mismatch — expected \(rawBytes.hexString), got \(result.hexString)")
    }

    @Test("DATA+PLAIN: serialize() first 19 bytes match header.serialize()")
    func dataPlainSerialiseHeaderPrefix() throws {
        let fixture   = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let packet    = try Packet.deserialize(from: rawBytes)
        let result    = packet.serialize()
        let expected  = packet.header.serialize()
        #expect(Data(result.prefix(19)) == expected,
                "header prefix mismatch — expected \(expected.hexString), got \(Data(result.prefix(19)).hexString)")
    }

    @Test("DATA+PLAIN: serialize() bytes after header equal payload")
    func dataPlainSerialisePayloadSuffix() throws {
        let fixture   = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let expected  = try fixture.hexData(at: "expected.payload_hex")
        let packet    = try Packet.deserialize(from: rawBytes)
        let result    = Data(packet.serialize().dropFirst(19))
        #expect(result == expected,
                "payload suffix mismatch — expected \(expected.hexString), got \(result.hexString)")
    }

    @Test("DATA+PLAIN: constructing Packet from fixture inputs then serializing matches Python raw_hex")
    func dataPlainConstructAndSerialise() throws {
        let fixture     = try loadPacketFixture(name: "data_packet_plain")
        let destHash    = try fixture.hexData(at: "inputs.destination_hash_hex")
        let payload     = try fixture.hexData(at: "inputs.payload_hex")
        let rawExpected = try fixture.hexData(at: "expected.raw_hex")

        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: destHash,
            hops:            0,
            context:         0
        )
        let packet = Packet(header: header, payload: payload)
        let result = packet.serialize()
        #expect(result == rawExpected,
                "constructed packet bytes mismatch — expected \(rawExpected.hexString), got \(result.hexString)")
    }
}

// ANNOUNCE / SINGLE — Deserialisation

@Suite("Packet — ANNOUNCE/SINGLE Deserialisation")
struct PacketAnnounceSingleDeserialiseTests {

    @Test("ANNOUNCE+SINGLE: deserialize() returns a Packet without throwing")
    func announceSingleDeserialiseSucceeds() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        _ = try Packet.deserialize(from: rawBytes)
    }

    @Test("ANNOUNCE+SINGLE: deserialize() → header.packetType == .announce")
    func announceSingleDeserialisePacketType() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.packetType == .announce)
    }

    @Test("ANNOUNCE+SINGLE: deserialize() → header.destinationType == .single")
    func announceSingleDeserialiseDestinationType() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.destinationType == .single)
    }

    @Test("ANNOUNCE+SINGLE: deserialize() → header.destinationHash matches Python reference")
    func announceSingleDeserialiseDestinationHash() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = try fixture.hexData(at: "expected.destination_hash_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.destinationHash == expected,
                "destinationHash mismatch — expected \(expected.hexString), got \(packet.header.destinationHash.hexString)")
    }

    @Test("ANNOUNCE+SINGLE: deserialize() → header.hops == 0")
    func announceSingleDeserialiseHops() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.hops == 0)
    }

    @Test("ANNOUNCE+SINGLE: deserialize() → payload == raw_hex bytes after the 19-byte header")
    func announceSingleDeserialisePayloadMatchesRawSuffix() throws {
        let fixture   = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let expected  = Data(rawBytes.dropFirst(PacketHeader.serializedLength))
        let packet    = try Packet.deserialize(from: rawBytes)
        #expect(packet.payload == expected,
                "payload mismatch — expected \(expected.hexString), got \(packet.payload.hexString)")
    }

    @Test("ANNOUNCE+SINGLE: deserialize() → payload starts with the 64-byte identity public key")
    func announceSingleDeserialisePayloadStartsWithPubKey() throws {
        let fixture   = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes  = try fixture.hexData(at: "expected.raw_hex")
        let pubKey    = try fixture.hexData(at: "inputs.identity_public_key_hex")
        let packet    = try Packet.deserialize(from: rawBytes)
        let prefix    = Data(packet.payload.prefix(64))
        #expect(prefix == pubKey,
                "payload public key prefix mismatch — expected \(pubKey.hexString), got \(prefix.hexString)")
    }

    @Test("ANNOUNCE+SINGLE: deserialize() → header.flagsByte matches Python header_byte_hex (0x01)")
    func announceSingleDeserialiseFlagsByte() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let expected = try fixture.uint8(at: "expected.header_byte_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        #expect(packet.header.flagsByte == expected,
                "flagsByte mismatch — expected \(String(format: "0x%02x", expected)), got \(String(format: "0x%02x", packet.header.flagsByte))")
    }
}

// ANNOUNCE / SINGLE — Serialisation

@Suite("Packet — ANNOUNCE/SINGLE Serialisation")
struct PacketAnnounceSingleSerialiseTests {

    @Test("ANNOUNCE+SINGLE: serialize() produces byte-identical output to Python raw_hex")
    func announceSingleSerialiseMatchesPython() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        let result   = packet.serialize()
        #expect(result == rawBytes,
                "serialized bytes mismatch — expected \(rawBytes.hexString), got \(result.hexString)")
    }

    @Test("ANNOUNCE+SINGLE: serialize() first 19 bytes match header.serialize()")
    func announceSingleSerialiseHeaderPrefix() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        let result   = packet.serialize()
        let expected = packet.header.serialize()
        #expect(Data(result.prefix(19)) == expected,
                "header prefix mismatch — expected \(expected.hexString), got \(Data(result.prefix(19)).hexString)")
    }

    @Test("ANNOUNCE+SINGLE: serialize() bytes after header match raw payload")
    func announceSingleSerialisePayloadSuffix() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let packet   = try Packet.deserialize(from: rawBytes)
        let result   = Data(packet.serialize().dropFirst(19))
        let expected = Data(rawBytes.dropFirst(19))
        #expect(result == expected,
                "payload suffix mismatch — expected \(expected.hexString), got \(result.hexString)")
    }
}

// Round-trip

@Suite("Packet — Round-trip")
struct PacketRoundTripTests {

    @Test("DATA+PLAIN: serialize(deserialize(raw)) == raw")
    func dataPlainRoundTrip() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let parsed   = try Packet.deserialize(from: rawBytes)
        let result   = parsed.serialize()
        #expect(result == rawBytes,
                "DATA+PLAIN round-trip mismatch — expected \(rawBytes.hexString), got \(result.hexString)")
    }

    @Test("ANNOUNCE+SINGLE: serialize(deserialize(raw)) == raw")
    func announceSingleRoundTrip() throws {
        let fixture  = try loadAnnounceFixture(name: "announce_basic")
        let rawBytes = try fixture.hexData(at: "expected.raw_hex")
        let parsed   = try Packet.deserialize(from: rawBytes)
        let result   = parsed.serialize()
        #expect(result == rawBytes,
                "ANNOUNCE+SINGLE round-trip mismatch — expected \(rawBytes.hexString), got \(result.hexString)")
    }

    @Test("hops field survives a Packet round-trip")
    func hopsRoundTrip() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let destHash = try fixture.hexData(at: "inputs.destination_hash_hex")
        let payload  = try fixture.hexData(at: "inputs.payload_hex")

        let header = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: destHash,
            hops:            42
        )
        let packet  = Packet(header: header, payload: payload)
        let parsed  = try Packet.deserialize(from: packet.serialize())
        #expect(parsed.header.hops == 42)
    }

    @Test("all PacketType values survive a Packet round-trip")
    func allPacketTypesRoundTrip() throws {
        let fixture   = try loadPacketFixture(name: "data_packet_plain")
        let dummyHash = try fixture.hexData(at: "inputs.destination_hash_hex")
        let payload   = Data([0xDE, 0xAD])

        for pt in [PacketType.data, .announce, .linkRequest, .proof] {
            let header = PacketHeader(
                packetType:      pt,
                destinationType: .plain,
                destinationHash: dummyHash,
                hops:            0
            )
            let packet = Packet(header: header, payload: payload)
            let parsed = try Packet.deserialize(from: packet.serialize())
            #expect(parsed.header.packetType == pt,
 "packetType \(pt) did not survive Packet round-trip")
        }
    }
}

// Error Handling

@Suite("Packet — Error Handling")
struct PacketErrorTests {

    @Test("deserialize() throws when data is shorter than 19 bytes")
    func deserializeThrowsOnTooShort() throws {
        let shortData = Data(count: 10)
        #expect(throws: (any Error).self) {
            try Packet.deserialize(from: shortData)
        }
    }

    @Test("deserialize() throws when data is exactly 0 bytes")
    func deserializeThrowsOnEmpty() throws {
        #expect(throws: (any Error).self) {
            try Packet.deserialize(from: Data())
        }
    }

    @Test("deserialize() succeeds when data is exactly 19 bytes (header-only, empty payload)")
    func deserializeSucceedsWithHeaderOnly() throws {
        let fixture  = try loadPacketFixture(name: "data_packet_plain")
        let destHash = try fixture.hexData(at: "inputs.destination_hash_hex")
        let header   = PacketHeader(
            packetType:      .data,
            destinationType: .plain,
            destinationHash: destHash
        )
        let headerOnly = header.serialize()
        let packet = try Packet.deserialize(from: headerOnly)
        #expect(packet.payload.isEmpty)
    }
}
