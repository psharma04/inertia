import Foundation
import ReticulumCrypto

public actor NomadClient {

    private let link: any NomadLinkProtocol

    public init(link: any NomadLinkProtocol) {
        self.link = link
    }

    public func requestPage(path: String, timestamp: Double) async throws -> NomadPage {
        let payload = NomadClient.buildRequestPayload(path: path, timestamp: timestamp, formData: nil)
        let response = try await link.request(payload: payload)
        let (requestID, content) = try NomadClient.parsePageResponse(response)
        return NomadPage(path: path, requestID: requestID, content: content)
    }

    /// Request a page using the current time as the timestamp.
    public func requestPage(path: String) async throws -> NomadPage {
        try await requestPage(path: path, timestamp: Date().timeIntervalSince1970)
    }

    public func downloadFile(path: String) async throws -> Data {
        let payload = NomadClient.buildRequestPayload(path: path, timestamp: Date().timeIntervalSince1970, formData: nil)
        let response = try await link.request(payload: payload)
        let (_, content) = try NomadClient.parsePageResponse(response)
        return content
    }

    public static func pathHash(for path: String) -> Data {
        Hashing.truncatedHash(Data(path.utf8), length: 16)
    }

    public static func buildRequestPayload(
        path: String,
        timestamp: Double,
        formData: [String: String]?
    ) -> Data {
        var out = Data()

        // fixarray(3)
        out.append(0x93)

        // float64 timestamp (msgpack 0xcb + 8 bytes big-endian IEEE 754)
        out.append(0xcb)
        let bits = timestamp.bitPattern.bigEndian
        withUnsafeBytes(of: bits) { out.append(contentsOf: $0) }

        // bin8(16) path hash
        let hash = pathHash(for: path)
        out.append(0xc4)
        out.append(UInt8(hash.count))
        out.append(contentsOf: hash)

        // form data: nil (0xc0) or msgpack map
        if let formData = formData, !formData.isEmpty {
            // fixmap or map16 for form fields
            if formData.count <= 15 {
                out.append(0x80 | UInt8(formData.count))
            } else {
                out.append(0xde)
                out.append(UInt8(formData.count >> 8))
                out.append(UInt8(formData.count & 0xff))
            }
            for (key, value) in formData {
                let keyBytes = Data(key.utf8)
                appendMsgpackStr(&out, keyBytes)
                let valBytes = Data(value.utf8)
                appendMsgpackStr(&out, valBytes)
            }
        } else {
            out.append(0xc0)  // nil
        }

        return out
    }

    private static func appendMsgpackStr(_ out: inout Data, _ bytes: Data) {
        if bytes.count <= 31 {
            out.append(0xa0 | UInt8(bytes.count))
        } else if bytes.count <= 255 {
            out.append(0xd9)
            out.append(UInt8(bytes.count))
        } else {
            out.append(0xda)
            out.append(UInt8(bytes.count >> 8))
            out.append(UInt8(bytes.count & 0xff))
        }
        out.append(contentsOf: bytes)
    }

    public static func parsePageRequest(_ data: Data) throws -> (timestamp: Double, pathHash: Data, formData: [String: String]?) {
        guard !data.isEmpty else { throw NomadError.invalidMsgpack }

        var cursor = data.startIndex

        func readByte() throws -> UInt8 {
            guard cursor < data.endIndex else { throw NomadError.invalidMsgpack }
            let b = data[cursor]
            cursor = data.index(after: cursor)
            return b
        }

        func readBytes(_ n: Int) throws -> Data {
            let end = cursor + n
            guard end <= data.endIndex else { throw NomadError.invalidMsgpack }
            let slice = Data(data[cursor ..< end])
            cursor = end
            return slice
        }

        // Must be fixarray(3)
        let header = try readByte()
        guard header == 0x93 else { throw NomadError.invalidMsgpack }

        // Parse timestamp: float64 (0xcb + 8 bytes big-endian)
        let tsTag = try readByte()
        guard tsTag == 0xcb else { throw NomadError.invalidMsgpack }
        let tsBytes = try readBytes(8)
        let tsBits = tsBytes.withUnsafeBytes { $0.load(as: UInt64.self).bigEndian }
        let timestamp = Double(bitPattern: tsBits)

        // Parse path hash: bin8(16)
        let phTag = try readByte()
        let pathHash: Data
        switch phTag {
        case 0xc4:
            let len = Int(try readByte())
            pathHash = try readBytes(len)
        case 0xc5:
            let hi = Int(try readByte())
            let lo = Int(try readByte())
            pathHash = try readBytes((hi << 8) | lo)
        default:
            throw NomadError.invalidMsgpack
        }

        // Parse form data: nil (0xc0) or map
        let fdTag = try readByte()
        if fdTag == 0xc0 {
            return (timestamp, pathHash, nil)
        }

        // fixmap or map16
        let mapCount: Int
        if fdTag >= 0x80 && fdTag <= 0x8f {
            mapCount = Int(fdTag & 0x0f)
        } else if fdTag == 0xde {
            let hi = Int(try readByte())
            let lo = Int(try readByte())
            mapCount = (hi << 8) | lo
        } else {
            throw NomadError.invalidMsgpack
        }

        var formData = [String: String]()
        for _ in 0..<mapCount {
            let key = try readMsgpackStr(from: data, cursor: &cursor)
            let value = try readMsgpackStr(from: data, cursor: &cursor)
            formData[key] = value
        }

        return (timestamp, pathHash, formData)
    }

    private static func readMsgpackStr(from data: Data, cursor: inout Data.Index) throws -> String {
        guard cursor < data.endIndex else { throw NomadError.invalidMsgpack }
        let tag = data[cursor]
        cursor = data.index(after: cursor)

        let len: Int
        if tag >= 0xa0 && tag <= 0xbf {
            len = Int(tag & 0x1f)
        } else if tag == 0xd9 {
            guard cursor < data.endIndex else { throw NomadError.invalidMsgpack }
            len = Int(data[cursor])
            cursor = data.index(after: cursor)
        } else if tag == 0xda {
            guard cursor + 2 <= data.endIndex else { throw NomadError.invalidMsgpack }
            len = Int(data[cursor]) << 8 | Int(data[data.index(after: cursor)])
            cursor = data.index(cursor, offsetBy: 2)
        } else {
            throw NomadError.invalidMsgpack
        }

        let end = cursor + len
        guard end <= data.endIndex else { throw NomadError.invalidMsgpack }
        let str = String(data: Data(data[cursor..<end]), encoding: .utf8) ?? ""
        cursor = end
        return str
    }

    public static func buildPageResponse(requestID: Data, content: Data) -> Data {
        var out = Data()

        // fixarray(2)
        out.append(0x92)

        // request ID as bin
        appendMsgpackBin(&out, requestID)

        // content as bin
        appendMsgpackBin(&out, content)

        return out
    }

    private static func appendMsgpackBin(_ out: inout Data, _ bytes: Data) {
        if bytes.count <= 255 {
            out.append(0xc4)
            out.append(UInt8(bytes.count))
        } else if bytes.count <= 65535 {
            out.append(0xc5)
            out.append(UInt8(bytes.count >> 8))
            out.append(UInt8(bytes.count & 0xff))
        } else {
            out.append(0xc6)
            out.append(UInt8((bytes.count >> 24) & 0xff))
            out.append(UInt8((bytes.count >> 16) & 0xff))
            out.append(UInt8((bytes.count >> 8) & 0xff))
            out.append(UInt8(bytes.count & 0xff))
        }
        out.append(contentsOf: bytes)
    }

    public static func parsePageResponse(_ data: Data) throws -> (requestID: Data, content: Data) {
        guard !data.isEmpty else { throw NomadError.invalidMsgpack }

        var cursor = data.startIndex

        func readByte() throws -> UInt8 {
            guard cursor < data.endIndex else { throw NomadError.invalidMsgpack }
            let b = data[cursor]
            cursor = data.index(after: cursor)
            return b
        }

        func readBytes(_ n: Int) throws -> Data {
            let end = cursor + n
            guard end <= data.endIndex else { throw NomadError.invalidMsgpack }
            let slice = Data(data[cursor ..< end])
            cursor = end
            return slice
        }

        // Must be fixarray(2)
        let header = try readByte()
        guard header == 0x92 else { throw NomadError.invalidMsgpack }

        // Parse first element (request_id): bin8/bin16/bin32
        let requestID: Data
        let tag1 = try readByte()
        switch tag1 {
        case 0xc4:  // bin8
            let len = Int(try readByte())
            requestID = try readBytes(len)
        case 0xc5:  // bin16
            let hi = Int(try readByte())
            let lo = Int(try readByte())
            requestID = try readBytes((hi << 8) | lo)
        case 0xc6:  // bin32
            let b0 = Int(try readByte())
            let b1 = Int(try readByte())
            let b2 = Int(try readByte())
            let b3 = Int(try readByte())
            requestID = try readBytes((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
        default:
            throw NomadError.invalidMsgpack
        }

        // Parse second element (content): bin8/bin16/bin32
        let content: Data
        let tag2 = try readByte()
        switch tag2 {
        case 0xc4:  // bin8
            let len = Int(try readByte())
            content = try readBytes(len)
        case 0xc5:  // bin16
            let hi = Int(try readByte())
            let lo = Int(try readByte())
            content = try readBytes((hi << 8) | lo)
        case 0xc6:  // bin32
            let b0 = Int(try readByte())
            let b1 = Int(try readByte())
            let b2 = Int(try readByte())
            let b3 = Int(try readByte())
            content = try readBytes((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
        default:
            throw NomadError.invalidMsgpack
        }

        return (requestID, content)
    }
}
