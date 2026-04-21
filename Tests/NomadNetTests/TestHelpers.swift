import Foundation
import CryptoKit

// Data helpers

extension Data {
    init?(hexString: String) {
        let clean = hexString.replacingOccurrences(of: " ", with: "")
        guard clean.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(clean.count / 2)
        var index = clean.startIndex
        while index < clean.endIndex {
            let next = clean.index(index, offsetBy: 2)
            guard let byte = UInt8(clean[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// Minimal msgpack helpers (for MockNomadNode)

func msgpackPageResponse(requestID: Data, content: Data) -> Data {
    var out = Data()
    out.append(0x92)  // fixarray(2)
    // request_id: always 16 bytes → bin8(16)
    out.append(0xc4)
    out.append(UInt8(requestID.count))
    out.append(contentsOf: requestID)
    // content: bin8 (≤255 bytes) or bin16 (256–65535 bytes)
    if content.count <= 255 {
        out.append(0xc4)
        out.append(UInt8(content.count))
    } else {
        out.append(0xc5)
        out.append(UInt8(content.count >> 8))
        out.append(UInt8(content.count & 0xff))
    }
    out.append(contentsOf: content)
    return out
}

func extractPathHash(from payload: Data) -> Data? {
    guard payload.count >= 28 else { return nil }
    guard payload[payload.startIndex + 0]  == 0x93,  // fixarray(3)
          payload[payload.startIndex + 1]  == 0xcb,  // float64
          payload[payload.startIndex + 10] == 0xc4,  // bin8
          payload[payload.startIndex + 11] == 0x10   // length = 16
    else { return nil }
    let start = payload.startIndex + 12
    return Data(payload[start ..< start + 16])
}

/// Compute SHA-256(data)[0:16] — the truncated hash used throughout RNS and NomadNet.
func truncatedHash(_ data: Data) -> Data {
    Data(SHA256.hash(data: data).prefix(16))
}
