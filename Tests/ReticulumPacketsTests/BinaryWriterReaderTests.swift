import Testing
import Foundation
@testable import ReticulumPackets

// BinaryWriter Tests

@Suite("BinaryWriter")
struct BinaryWriterTests {

    // MARK: UInt8

    @Test("writeUInt8 appends a single byte with the correct value")
    func writeUInt8() {
        var writer = BinaryWriter()
        writer.writeUInt8(0xAB)
        #expect(writer.data == Data([0xAB]))
    }

    @Test("writeUInt8 zero appends 0x00")
    func writeUInt8Zero() {
        var writer = BinaryWriter()
        writer.writeUInt8(0x00)
        #expect(writer.data == Data([0x00]))
    }

    @Test("writeUInt8 max value appends 0xFF")
    func writeUInt8Max() {
        var writer = BinaryWriter()
        writer.writeUInt8(0xFF)
        #expect(writer.data == Data([0xFF]))
    }

    // MARK: UInt16

    @Test("writeUInt16 encodes in big-endian byte order")
    func writeUInt16BigEndian() {
        var writer = BinaryWriter()
        writer.writeUInt16(0x1234)
        // Big-endian: high byte first
        #expect(writer.data == Data([0x12, 0x34]))
    }

    @Test("writeUInt16 zero encodes as two zero bytes")
    func writeUInt16Zero() {
        var writer = BinaryWriter()
        writer.writeUInt16(0x0000)
        #expect(writer.data == Data([0x00, 0x00]))
    }

    @Test("writeUInt16 max value encodes as 0xFF 0xFF")
    func writeUInt16Max() {
        var writer = BinaryWriter()
        writer.writeUInt16(0xFFFF)
        #expect(writer.data == Data([0xFF, 0xFF]))
    }

    // MARK: UInt32

    @Test("writeUInt32 encodes in big-endian byte order")
    func writeUInt32BigEndian() {
        var writer = BinaryWriter()
        writer.writeUInt32(0x12345678)
        #expect(writer.data == Data([0x12, 0x34, 0x56, 0x78]))
    }

    @Test("writeUInt32 zero encodes as four zero bytes")
    func writeUInt32Zero() {
        var writer = BinaryWriter()
        writer.writeUInt32(0x00000000)
        #expect(writer.data == Data([0x00, 0x00, 0x00, 0x00]))
    }

    @Test("writeUInt32 max value encodes as four 0xFF bytes")
    func writeUInt32Max() {
        var writer = BinaryWriter()
        writer.writeUInt32(0xFFFFFFFF)
        #expect(writer.data == Data([0xFF, 0xFF, 0xFF, 0xFF]))
    }

    // MARK: Byte arrays

    @Test("writeBytes appends raw bytes verbatim")
    func writeBytes() {
        var writer = BinaryWriter()
        let payload = Data([0x01, 0x02, 0x03, 0x04])
        writer.writeBytes(payload)
        #expect(writer.data == payload)
    }

    @Test("writeBytes with empty Data appends nothing")
    func writeBytesEmpty() {
        var writer = BinaryWriter()
        writer.writeBytes(Data())
        #expect(writer.data.isEmpty)
    }

    @Test("writeBytes preserves every byte value 0x00–0xFF")
    func writeBytesFullRange() {
        var writer = BinaryWriter()
        let allBytes = Data(0x00...0xFF)
        writer.writeBytes(allBytes)
        #expect(writer.data == allBytes)
    }

    // MARK: Deterministic ordering

    @Test("sequential writes produce deterministic concatenated output")
    func deterministicOrdering() {
        var writer = BinaryWriter()
        writer.writeUInt8(0xAA)
        writer.writeUInt16(0xBBCC)
        writer.writeUInt32(0xDDEEFF00)
        writer.writeBytes(Data([0x11, 0x22]))
        // Expected: AA | BB CC | DD EE FF 00 | 11 22
        let expected = Data([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22])
        #expect(writer.data == expected)
    }

    @Test("two writers with identical operations produce identical bytes")
    func deterministicRepeatability() {
        var w1 = BinaryWriter()
        w1.writeUInt8(0x01)
        w1.writeUInt16(0x0203)
        w1.writeUInt32(0x04050607)

        var w2 = BinaryWriter()
        w2.writeUInt8(0x01)
        w2.writeUInt16(0x0203)
        w2.writeUInt32(0x04050607)

        #expect(w1.data == w2.data)
    }
}

// BinaryReader Tests

@Suite("BinaryReader")
struct BinaryReaderTests {

    // MARK: UInt8

    @Test("readUInt8 returns the first byte and advances cursor")
    func readUInt8() throws {
        var reader = BinaryReader(data: Data([0xAB, 0xCD]))
        let value = try reader.readUInt8()
        #expect(value == 0xAB)
        // cursor should have advanced; next read returns second byte
        let next = try reader.readUInt8()
        #expect(next == 0xCD)
    }

    @Test("readUInt8 on a single-byte buffer returns that byte")
    func readUInt8SingleByte() throws {
        var reader = BinaryReader(data: Data([0xFF]))
        let value = try reader.readUInt8()
        #expect(value == 0xFF)
    }

    // MARK: UInt16

    @Test("readUInt16 decodes two bytes as big-endian")
    func readUInt16BigEndian() throws {
        var reader = BinaryReader(data: Data([0x12, 0x34]))
        let value = try reader.readUInt16()
        #expect(value == 0x1234)
    }

    @Test("readUInt16 advances cursor by 2 bytes")
    func readUInt16AdvancesCursor() throws {
        var reader = BinaryReader(data: Data([0x00, 0x01, 0xFF]))
        _ = try reader.readUInt16()
        let trailing = try reader.readUInt8()
        #expect(trailing == 0xFF)
    }

    // MARK: UInt32

    @Test("readUInt32 decodes four bytes as big-endian")
    func readUInt32BigEndian() throws {
        var reader = BinaryReader(data: Data([0x12, 0x34, 0x56, 0x78]))
        let value = try reader.readUInt32()
        #expect(value == 0x12345678)
    }

    @Test("readUInt32 advances cursor by 4 bytes")
    func readUInt32AdvancesCursor() throws {
        var reader = BinaryReader(data: Data([0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF]))
        _ = try reader.readUInt32()
        let hi = try reader.readUInt8()
        let lo = try reader.readUInt8()
        #expect(hi == 0xBE)
        #expect(lo == 0xEF)
    }

    // MARK: Byte arrays

    @Test("readBytes returns the requested number of bytes verbatim")
    func readBytes() throws {
        let source = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        var reader = BinaryReader(data: source)
        let slice = try reader.readBytes(3)
        #expect(slice == Data([0x01, 0x02, 0x03]))
    }

    @Test("readBytes advances cursor by the requested count")
    func readBytesAdvancesCursor() throws {
        var reader = BinaryReader(data: Data([0xAA, 0xBB, 0xCC, 0xDD]))
        _ = try reader.readBytes(2)
        let remaining = try reader.readBytes(2)
        #expect(remaining == Data([0xCC, 0xDD]))
    }

    @Test("readBytes with count zero returns empty Data without advancing")
    func readBytesZeroCount() throws {
        var reader = BinaryReader(data: Data([0x01]))
        let empty = try reader.readBytes(0)
        #expect(empty.isEmpty)
        // cursor should still be at start — next read still yields 0x01
        let still = try reader.readUInt8()
        #expect(still == 0x01)
    }

    // MARK: Round-trip (BinaryWriter → BinaryReader)

    @Test("round-trip: written bytes are read back with identical values")
    func roundTripAllTypes() throws {
        var writer = BinaryWriter()
        writer.writeUInt8(0xDE)
        writer.writeUInt16(0xADBE)
        writer.writeUInt32(0xEF012345)
        writer.writeBytes(Data([0x11, 0x22, 0x33]))

        var reader = BinaryReader(data: writer.data)
        #expect(try reader.readUInt8()  == 0xDE)
        #expect(try reader.readUInt16() == 0xADBE)
        #expect(try reader.readUInt32() == 0xEF012345)
        #expect(try reader.readBytes(3) == Data([0x11, 0x22, 0x33]))
    }

    // MARK: Out-of-bounds reads

    @Test("readUInt8 on empty buffer throws BinaryReaderError.outOfBounds")
    func readUInt8OutOfBounds() {
        var reader = BinaryReader(data: Data())
        #expect(throws: BinaryReaderError.outOfBounds) {
            try reader.readUInt8()
        }
    }

    @Test("readUInt16 with only one byte remaining throws outOfBounds")
    func readUInt16OutOfBounds() {
        var reader = BinaryReader(data: Data([0x01]))
        #expect(throws: BinaryReaderError.outOfBounds) {
            try reader.readUInt16()
        }
    }

    @Test("readUInt32 with only three bytes remaining throws outOfBounds")
    func readUInt32OutOfBounds() {
        var reader = BinaryReader(data: Data([0x01, 0x02, 0x03]))
        #expect(throws: BinaryReaderError.outOfBounds) {
            try reader.readUInt32()
        }
    }

    @Test("readBytes requesting more than available throws outOfBounds")
    func readBytesOutOfBounds() {
        var reader = BinaryReader(data: Data([0x01, 0x02]))
        #expect(throws: BinaryReaderError.outOfBounds) {
            try reader.readBytes(3)
        }
    }

    @Test("readUInt8 after exhausting buffer throws outOfBounds")
    func readUInt8AfterExhaustion() throws {
        var reader = BinaryReader(data: Data([0xAA]))
        _ = try reader.readUInt8()
        #expect(throws: BinaryReaderError.outOfBounds) {
            try reader.readUInt8()
        }
    }
}
