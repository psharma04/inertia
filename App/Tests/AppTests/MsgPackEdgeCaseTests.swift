import Testing
import Foundation
@testable import Inertia

@Suite("MsgPack edge cases")
struct MsgPackEdgeCaseTests {

    // MARK: - Empty / nil data

    @Test("Decoding empty data returns nil")
    func decodesEmptyDataReturnsNil() {
        #expect(MsgPack.decodeDisplayName(Data()) == nil)
        #expect(MsgPack.decodeAny(Data()) == nil)
        #expect(MsgPack.decodePropagationNodeStampCost(Data()) == nil)
        #expect(MsgPack.decodePropagationNodeEnabled(Data()) == nil)
        #expect(MsgPack.decodePropagationGetLinkRequest(Data()) == nil)
        #expect(MsgPack.decodePropagationGetLinkResponse(Data()) == nil)
    }

    @Test("Decoding single nil byte returns nil for display name")
    func decodesNilByteReturnsNil() {
        #expect(MsgPack.decodeDisplayName(Data([0xC0])) == nil)
    }

    // MARK: - encode/decodeAny round trips

    @Test("Round-trips nil")
    func roundTripNil() throws {
        let encoded = try MsgPack.encode(NSNull())
        #expect(Array(encoded) == [0xC0])
        #expect(MsgPack.decodeAny(encoded) == nil)
    }

    @Test("Round-trips booleans")
    func roundTripBooleans() throws {
        let trueEncoded = try MsgPack.encode(true)
        let falseEncoded = try MsgPack.encode(false)
        #expect(MsgPack.decodeAny(trueEncoded) as? Bool == true)
        #expect(MsgPack.decodeAny(falseEncoded) as? Bool == false)
    }

    @Test("Round-trips positive fixint")
    func roundTripPositiveFixint() throws {
        let encoded = try MsgPack.encode(42)
        #expect(MsgPack.decodeAny(encoded) as? Int == 42)
    }

    @Test("Round-trips negative fixint")
    func roundTripNegativeFixint() throws {
        let encoded = try MsgPack.encode(-5)
        #expect(MsgPack.decodeAny(encoded) as? Int == -5)
    }

    @Test("Round-trips uint16 value")
    func roundTripUint16() throws {
        let encoded = try MsgPack.encode(300)
        #expect(MsgPack.decodeAny(encoded) as? Int == 300)
    }

    @Test("Round-trips uint32 value")
    func roundTripUint32() throws {
        let encoded = try MsgPack.encode(70_000)
        #expect(MsgPack.decodeAny(encoded) as? Int == 70_000)
    }

    @Test("Round-trips float64")
    func roundTripFloat64() throws {
        let encoded = try MsgPack.encode(3.14159)
        let decoded = MsgPack.decodeAny(encoded) as? Double
        #expect(decoded != nil)
        #expect(abs(decoded! - 3.14159) < 0.00001)
    }

    @Test("Round-trips binary data")
    func roundTripBinary() throws {
        let data = Data(repeating: 0xAB, count: 64)
        let encoded = try MsgPack.encode(data)
        let decoded = MsgPack.decodeAny(encoded) as? Data
        #expect(decoded == data)
    }

    @Test("Round-trips empty binary data")
    func roundTripEmptyBinary() throws {
        let data = Data()
        let encoded = try MsgPack.encode(data)
        let decoded = MsgPack.decodeAny(encoded) as? Data
        #expect(decoded == data)
    }

    @Test("Round-trips string")
    func roundTripString() throws {
        let encoded = try MsgPack.encode("Hello, World!")
        let decoded = MsgPack.decodeAny(encoded) as? String
        #expect(decoded == "Hello, World!")
    }

    @Test("Round-trips empty string")
    func roundTripEmptyString() throws {
        let encoded = try MsgPack.encode("")
        let decoded = MsgPack.decodeAny(encoded) as? String
        #expect(decoded == "")
    }

    @Test("Round-trips Unicode strings")
    func roundTripUnicode() throws {
        let text = "Ünïcödé 🦊 日本語"
        let encoded = try MsgPack.encode(text)
        let decoded = MsgPack.decodeAny(encoded) as? String
        #expect(decoded == text)
    }

    @Test("Round-trips array of mixed values")
    func roundTripArray() throws {
        let array: [Any] = [1, "two", true, NSNull()]
        let encoded = try MsgPack.encode(array)
        let decoded = MsgPack.decodeAny(encoded) as? [Any?]
        #expect(decoded != nil)
        #expect(decoded?.count == 4)
        #expect(decoded?[0] as? Int == 1)
        #expect(decoded?[1] as? String == "two")
        #expect(decoded?[2] as? Bool == true)
        #expect(decoded?[3] == nil || decoded?[3] is NSNull)
    }

    @Test("Round-trips empty array")
    func roundTripEmptyArray() throws {
        let array: [Any] = []
        let encoded = try MsgPack.encode(array)
        let decoded = MsgPack.decodeAny(encoded) as? [Any?]
        #expect(decoded != nil)
        #expect(decoded?.count == 0)
    }

    // MARK: - Large data

    @Test("Encodes and decodes str8 (32-255 byte string)")
    func roundTripStr8() throws {
        let longName = String(repeating: "A", count: 200)
        let encoded = try MsgPack.encode(longName)
        let decoded = MsgPack.decodeAny(encoded) as? String
        #expect(decoded == longName)
    }

    @Test("Encodes and decodes bin16 (256-65535 byte binary)")
    func roundTripBin16() throws {
        let data = Data(repeating: 0x42, count: 512)
        let encoded = try MsgPack.encode(data)
        let decoded = MsgPack.decodeAny(encoded) as? Data
        #expect(decoded == data)
    }

    // MARK: - Display name edge cases

    @Test("Decodes display name from str16 format")
    func decodesStr16DisplayName() {
        // fixarray(1), str16 marker, length 0x0005, "Hello"
        let bytes: [UInt8] = [0x91, 0xDA, 0x00, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F]
        let name = MsgPack.decodeDisplayName(Data(bytes))
        #expect(name == "Hello")
    }

    @Test("Returns nil for map without display name key")
    func returnsNilForMapMissingDisplayNameKey() {
        // fixmap(1), key=0x05, fixstr(3)="Bob"
        let bytes: [UInt8] = [0x81, 0x05, 0xA3, 0x42, 0x6F, 0x62]
        let name = MsgPack.decodeDisplayName(Data(bytes))
        #expect(name == nil)
    }

    // MARK: - Delivery announce

    @Test("encodeDeliveryAnnounce with nil stamp cost has nil element")
    func encodeDeliveryAnnounceNilStamp() {
        let encoded = MsgPack.encodeDeliveryAnnounce(displayName: "Test", stampCost: nil)
        let decoded = MsgPack.decodeAny(encoded) as? [Any?]
        #expect(decoded?.count == 2)
        #expect(decoded?[1] == nil || decoded?[1] is NSNull)
    }

    @Test("encodeDeliveryAnnounce with stamp cost round-trips")
    func encodeDeliveryAnnounceWithStamp() {
        let encoded = MsgPack.encodeDeliveryAnnounce(displayName: "Alice", stampCost: 8)
        let result = MsgPack.decodeDisplayNameAndStampCost(encoded)
        #expect(result.displayName == "Alice")
        #expect(result.stampCost == 8)
    }

    // MARK: - Propagation get request edge cases

    @Test("propagation /get with nil wants/haves/limit round-trips")
    func propagationGetNils() {
        let encoded = MsgPack.encodePropagationGetLinkRequest(
            timestamp: 1_000_000.0,
            wants: nil,
            haves: nil,
            limitKilobytes: nil
        )
        let decoded = MsgPack.decodePropagationGetLinkRequest(encoded)
        #expect(decoded != nil)
        #expect(decoded?.wants == nil)
        #expect(decoded?.haves == nil)
        #expect(decoded?.limitKilobytes == nil)
    }

    @Test("propagation /get with empty arrays round-trips")
    func propagationGetEmptyArrays() {
        let encoded = MsgPack.encodePropagationGetLinkRequest(
            timestamp: 1_000_000.0,
            wants: [],
            haves: [],
            limitKilobytes: 0
        )
        let decoded = MsgPack.decodePropagationGetLinkRequest(encoded)
        #expect(decoded != nil)
        #expect(decoded?.wants?.count == 0)
        #expect(decoded?.haves?.count == 0)
    }

    // MARK: - Ticket field edge cases

    @Test("decodeTicketField returns nil for truncated data")
    func ticketFieldTruncated() {
        #expect(MsgPack.decodeTicketField(Data([0x92])) == nil)
    }

    @Test("decodeTicketField returns nil for empty data")
    func ticketFieldEmpty() {
        #expect(MsgPack.decodeTicketField(Data()) == nil)
    }

    // MARK: - Propagation node decode edge cases

    @Test("decodePropagationNodeEnabled returns nil for non-array")
    func propagationNodeEnabledNonArray() {
        // fixmap(1) instead of fixarray
        #expect(MsgPack.decodePropagationNodeEnabled(Data([0x81, 0x01, 0xC3])) == nil)
    }

    @Test("decodePropagationNodeEnabled returns nil for too-short array")
    func propagationNodeEnabledShortArray() {
        // fixarray(2), nil, 30
        #expect(MsgPack.decodePropagationNodeEnabled(Data([0x92, 0xC0, 0x1E])) == nil)
    }

    @Test("decodePropagationNodeStampCost returns nil for no stamp info element")
    func propagationNodeStampCostMissing() {
        // fixarray(5), nil, 30, true, 0, 0 — no 6th element with stamp cost
        let bytes: [UInt8] = [0x95, 0xC0, 0x1E, 0xC3, 0x00, 0x00]
        #expect(MsgPack.decodePropagationNodeStampCost(Data(bytes)) == nil)
    }
}
