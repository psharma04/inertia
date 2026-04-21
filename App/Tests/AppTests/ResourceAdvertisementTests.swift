import Testing
import Foundation
@testable import Inertia

@Suite("Resource Advertisement Parsing")
struct ResourceAdvertisementTests {

    /// Minimal valid advertisement with 11 keys.
    private static let validAdvBytes: [UInt8] = [
        0x8B, // fixmap with 11 entries
        0xA1, 0x74, 0xCD, 0x04, 0x00, // "t": 1024
        0xA1, 0x64, 0xCD, 0x02, 0x00, // "d": 512
        0xA1, 0x6E, 0x03,             // "n": 3
        0xA1, 0x68, 0xC4, 0x20,       // "h": bin8(32)
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xA1, 0x72, 0xC4, 0x04,       // "r": bin8(4)
        0xBB, 0xBB, 0xBB, 0xBB,
        0xA1, 0x6F, 0xC4, 0x20,       // "o": bin8(32)
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xA1, 0x69, 0x01,             // "i": 1
        0xA1, 0x6C, 0x01,             // "l": 1
        0xA1, 0x71, 0xC0,             // "q": nil
        0xA1, 0x66, 0x03,             // "f": 3
        0xA1, 0x6D, 0xC4, 0x0C,       // "m": bin8(12)
        0x11, 0x11, 0x11, 0x11,
        0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33,
    ]

    @Test("Parses valid advertisement")
    func parseValid() throws {
        let data = Data(Self.validAdvBytes)
        let adv = MsgPack.decodeResourceAdvertisement(data)
        #expect(adv != nil)

        guard let adv else { return }
        #expect(adv.transferSize == 1024)
        #expect(adv.dataSize == 512)
        #expect(adv.numParts == 3)
        #expect(adv.resourceHash == Data(repeating: 0xAA, count: 32))
        #expect(adv.randomHash == Data(repeating: 0xBB, count: 4))
        #expect(adv.originalHash == Data(repeating: 0xCC, count: 32))
        #expect(adv.segmentIndex == 1)
        #expect(adv.totalSegments == 1)
        #expect(adv.requestID == nil)
        #expect(adv.flags == 0x03)
        #expect(adv.isEncrypted == true)
        #expect(adv.isCompressed == true)
        #expect(adv.isSplit == false)
    }

    @Test("Parses hashmap into 4-byte chunks")
    func parseHashmap() throws {
        let data = Data(Self.validAdvBytes)
        guard let adv = MsgPack.decodeResourceAdvertisement(data) else {
            Issue.record("Failed to parse advertisement")
            return
        }
        #expect(adv.hashmapRaw.count == 12)
        // The hashmap should contain 3 entries of 4 bytes each.
        let hashes = stride(from: 0, to: adv.hashmapRaw.count, by: 4).map {
            Data(adv.hashmapRaw[$0..<$0+4])
        }
        #expect(hashes.count == 3)
        #expect(hashes[0] == Data(repeating: 0x11, count: 4))
        #expect(hashes[1] == Data(repeating: 0x22, count: 4))
        #expect(hashes[2] == Data(repeating: 0x33, count: 4))
    }

    @Test("Returns nil for too-small data")
    func parseTooSmall() {
        let adv = MsgPack.decodeResourceAdvertisement(Data([0x80]))
        #expect(adv == nil)
    }

    @Test("Returns nil for empty data")
    func parseEmpty() {
        let adv = MsgPack.decodeResourceAdvertisement(Data())
        #expect(adv == nil)
    }

    @Test("Flag bits are correctly decoded")
    func flagBits() throws {
        // Test encrypted only (0x01)
        var bytes = Self.validAdvBytes
        // "f" value is at the byte right after 0xA1 0x66 → find index
        let fIdx = bytes.firstIndex(of: 0x66)! + 1
        bytes[fIdx] = 0x01  // encrypted only
        var adv = MsgPack.decodeResourceAdvertisement(Data(bytes))
        #expect(adv?.isEncrypted == true)
        #expect(adv?.isCompressed == false)

        bytes[fIdx] = 0x12  // is_response + compressed
        adv = MsgPack.decodeResourceAdvertisement(Data(bytes))
        #expect(adv?.isResponse == true)
        #expect(adv?.isCompressed == true)
        #expect(adv?.isEncrypted == false)
    }
}
