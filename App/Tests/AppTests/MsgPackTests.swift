import Testing
import Foundation
@testable import Inertia

@Suite("MsgPack announce decoding")
struct MsgPackTests {

    @Test("Decodes display name from map format")
    func decodesMapDisplayName() {
        let encoded = MsgPack.encode([MsgPack.Field.displayName.rawValue: "Alice"])
        let name = MsgPack.decodeDisplayName(encoded)
        #expect(name == "Alice")
    }

    @Test("Decodes display name from list format with fixstr")
    func decodesListDisplayName() {
        // msgpack: ["Bob", nil]
        // fixarray(2)=0x92, fixstr(3)=0xA3, 'B''o''b', nil=0xC0
        let bytes: [UInt8] = [0x92, 0xA3, 0x42, 0x6F, 0x62, 0xC0]
        let name = MsgPack.decodeDisplayName(Data(bytes))
        #expect(name == "Bob")
    }

    @Test("Decodes display name from map bin value")
    func decodesMapBinDisplayName() {
        // msgpack: {1: b"Eve"}
        // fixmap(1)=0x81, key=0x01, bin8=0xC4, len=0x03, bytes...
        let bytes: [UInt8] = [0x81, 0x01, 0xC4, 0x03, 0x45, 0x76, 0x65]
        let name = MsgPack.decodeDisplayName(Data(bytes))
        #expect(name == "Eve")
    }

    @Test("Decodes display name from list format with bin value")
    func decodesListBinDisplayName() {
        // msgpack: [b"Zoe"]
        // fixarray(1)=0x91, bin8=0xC4, len=0x03, bytes...
        let bytes: [UInt8] = [0x91, 0xC4, 0x03, 0x5A, 0x6F, 0x65]
        let name = MsgPack.decodeDisplayName(Data(bytes))
        #expect(name == "Zoe")
    }

    @Test("Encodes display name list in LXMF 0.5 format")
    func encodesDisplayNameList() {
        let encoded = MsgPack.encodeDisplayNameList("Alice")
        // fixarray(1), bin8(5), "Alice"
        let expected: [UInt8] = [0x91, 0xC4, 0x05, 0x41, 0x6C, 0x69, 0x63, 0x65]
        #expect(Array(encoded) == expected)
    }

    @Test("Decodes propagation node stamp cost from propagation app_data")
    func decodesPropagationNodeStampCost() {
        // [nil, 30, true, 0, 0, [42, nil, nil]]
        let bytes: [UInt8] = [
            0x96, 0xC0, 0x1E, 0xC3, 0x00, 0x00,
            0x93, 0x2A, 0xC0, 0xC0
        ]
        let cost = MsgPack.decodePropagationNodeStampCost(Data(bytes))
        #expect(cost == 42)
    }

    @Test("Decodes propagation node enabled flag from propagation app_data")
    func decodesPropagationNodeEnabled() {
        // [nil, 30, true, 0, 0, [42, nil, nil]]
        let enabledBytes: [UInt8] = [
            0x96, 0xC0, 0x1E, 0xC3, 0x00, 0x00,
            0x93, 0x2A, 0xC0, 0xC0
        ]
        #expect(MsgPack.decodePropagationNodeEnabled(Data(enabledBytes)) == true)

        // [nil, 30, false, 0, 0, [42, nil, nil]]
        let disabledBytes: [UInt8] = [
            0x96, 0xC0, 0x1E, 0xC2, 0x00, 0x00,
            0x93, 0x2A, 0xC0, 0xC0
        ]
        #expect(MsgPack.decodePropagationNodeEnabled(Data(disabledBytes)) == false)
    }

    @Test("Decodes outbound ticket field payload")
    func decodesTicketFieldPayload() {
        let expires = 1_700_000_123.0
        let ticket = Data(repeating: 0xAB, count: 16)
        let encoded = MsgPack.encodeTicketField(expires: expires, ticket: ticket)
        let decoded = MsgPack.decodeTicketField(encoded)
        #expect(decoded != nil)
        #expect(decoded?.expires == expires)
        #expect(decoded?.ticket == ticket)
    }

    @Test("Encodes and decodes propagation /get link request")
    func propagationGetRequestRoundTrip() {
        let timestamp = 1_700_000_000.0
        let wants = [
            Data(repeating: 0xAA, count: 32),
            Data(repeating: 0xBB, count: 32),
        ]
        let haves = [
            Data(repeating: 0x11, count: 32),
        ]

        let encoded = MsgPack.encodePropagationGetLinkRequest(
            timestamp: timestamp,
            wants: wants,
            haves: haves,
            limitKilobytes: 1000
        )
        let decoded = MsgPack.decodePropagationGetLinkRequest(encoded)

        #expect(decoded != nil)
        #expect(decoded?.timestamp == timestamp)
        #expect(decoded?.wants == wants)
        #expect(decoded?.haves == haves)
        #expect(decoded?.limitKilobytes == 1000)
    }

    @Test("Rejects propagation /get request with wrong path hash")
    func rejectsPropagationGetRequestWithWrongPathHash() {
        let encoded = MsgPack.encodePropagationGetLinkRequest(
            timestamp: 1_700_000_000.0,
            wants: nil,
            haves: nil,
            limitKilobytes: nil
        )
        var tampered = Array(encoded)
        // fixarray(3), float64 marker+8 bytes, then bin8 marker+len before path hash.
        let pathStart = 1 + 9 + 2
        tampered[pathStart] ^= 0x01
        #expect(MsgPack.decodePropagationGetLinkRequest(Data(tampered)) == nil)
    }

    @Test("Decodes propagation /get response transient-id list")
    func decodesPropagationGetTransientListResponse() {
        let requestID = Array(repeating: UInt8(0x55), count: 16)
        let transient1 = Array(repeating: UInt8(0xAA), count: 32)
        let transient2 = Array(repeating: UInt8(0xBB), count: 32)

        let payload = Data(
            [0x92] + msgpackBin(requestID) +
                [0x92] + msgpackBin(transient1) + msgpackBin(transient2)
        )
        guard let decoded = MsgPack.decodePropagationGetLinkResponse(payload) else {
            Issue.record("Failed decoding propagation transient-id response")
            return
        }

        #expect(decoded.requestID == Data(requestID))
        switch decoded.response {
        case .transientIDs(let ids):
            #expect(ids == [Data(transient1), Data(transient2)])
        default:
            Issue.record("Expected .transientIDs response")
        }
    }

    @Test("Decodes propagation /get response messages payload list")
    func decodesPropagationGetMessagesResponse() {
        let requestID = Array(repeating: UInt8(0x21), count: 16)
        let message1 = Array(repeating: UInt8(0x61), count: 40)
        let message2 = Array(repeating: UInt8(0x62), count: 48)

        let payload = Data(
            [0x92] + msgpackBin(requestID) +
                [0x92] + msgpackBin(message1) + msgpackBin(message2)
        )
        guard let decoded = MsgPack.decodePropagationGetLinkResponse(payload) else {
            Issue.record("Failed decoding propagation messages response")
            return
        }

        switch decoded.response {
        case .messages(let blobs):
            #expect(blobs == [Data(message1), Data(message2)])
        default:
            Issue.record("Expected .messages response")
        }
    }

    @Test("Decodes propagation /get response error code")
    func decodesPropagationGetErrorResponse() {
        let requestID = Array(repeating: UInt8(0x44), count: 16)
        let payload = Data([0x92] + msgpackBin(requestID) + [0x05])
        guard let decoded = MsgPack.decodePropagationGetLinkResponse(payload) else {
            Issue.record("Failed decoding propagation error response")
            return
        }
        switch decoded.response {
        case .error(let code):
            #expect(code == 5)
        default:
            Issue.record("Expected .error response")
        }
    }

    private func msgpackBin(_ bytes: [UInt8]) -> [UInt8] {
        [0xC4, UInt8(bytes.count)] + bytes
    }
}
