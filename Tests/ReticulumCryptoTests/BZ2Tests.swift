import Testing
import Foundation
@testable import ReticulumCrypto

@Suite("BZ2 Decompression Tests")
struct BZ2Tests {

    @Test("Decompresses valid bz2 data")
    func decompressValid() throws {
        // "Hello, World!\n" compressed with bz2.compress()
        let compressed = Data([
            0x42, 0x5A, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26,
            0x53, 0x59, 0x99, 0xAC, 0x22, 0x56, 0x00, 0x00,
            0x02, 0x57, 0x80, 0x00, 0x10, 0x60, 0x04, 0x00,
            0x40, 0x00, 0x80, 0x06, 0x04, 0x90, 0x00, 0x20,
            0x00, 0x22, 0x06, 0x81, 0x90, 0x80, 0x69, 0xA6,
            0x89, 0x18, 0x6A, 0xCE, 0xA4, 0x19, 0x6F, 0x8B,
            0xB9, 0x22, 0x9C, 0x28, 0x48, 0x4C, 0xD6, 0x11,
            0x2B, 0x00
        ])
        let decompressed = try BZ2.decompress(compressed)
        let text = String(data: decompressed, encoding: .utf8)
        #expect(text == "Hello, World!\n")
    }

    @Test("Throws on invalid bz2 data")
    func decompressInvalid() {
        let garbage = Data([0x00, 0x01, 0x02, 0x03, 0x04])
        #expect(throws: BZ2.BZ2Error.self) {
            _ = try BZ2.decompress(garbage)
        }
    }

    @Test("Handles empty compressed data gracefully")
    func decompressEmpty() {
        #expect(throws: BZ2.BZ2Error.self) {
            _ = try BZ2.decompress(Data())
        }
    }
}
