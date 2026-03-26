import Foundation
import ReticulumCrypto

// NomadClient

/// Client for requesting pages and files from a Nomad Network node.
///
/// Protocol summary (over an established Reticulum link):
///
///   Request (msgpack 3-element array):
///     [0] timestamp  float64     — time.time() at send
///     [1] path_hash  bytes(16)   — SHA-256(path.utf8)[0:16]
///     [2] form_data  map | nil   — form field dict or nil
///
///   Response (msgpack 2-element array):
///     [0] request_id  bytes(16)  — echo of server-assigned request ID
///     [1] content     bytes      — raw Micron markup (UTF-8)
///
/// Key path hashes (SHA-256(path.utf8)[0:16]):
///   "/page/index.mu"    → fb40abf359b3f25fa0086107c5eee516
///   "/page/about.mu"    → 88136a8b75cd27b5b7171bffdd657280
///   "/file/example.txt" → 95958aa7e6b88c228e73771a281f5764
public actor NomadClient {

    private let link: any NomadLinkProtocol

    // Initialiser

    public init(link: any NomadLinkProtocol) {
        self.link = link
    }

    // Page requests

    /// Request a page from the node using a deterministic timestamp.
    ///
    /// - Parameters:
    ///   - path: Page path, e.g. "/page/index.mu"
    ///   - timestamp: Unix timestamp to embed in the request (for testing).
    /// - Throws: NomadError on failure.
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

    // File download

    /// Download a file from the node.
    ///
    /// - Parameter path: File path, e.g. "/file/example.txt"
    /// - Throws: NomadError on failure.
    public func downloadFile(path: String) async throws -> Data {
        let payload = NomadClient.buildRequestPayload(path: path, timestamp: Date().timeIntervalSince1970, formData: nil)
        let response = try await link.request(payload: payload)
        let (_, content) = try NomadClient.parsePageResponse(response)
        return content
    }

    // Wire format utilities

    /// Compute the 16-byte path hash used in NomadNet requests.
    ///
    /// path_hash = SHA-256(path.utf8)[0:16]
    ///
    /// Test vectors:
    ///   pathHash("/page/index.mu")    == fb40abf359b3f25fa0086107c5eee516
    ///   pathHash("/page/about.mu")    == 88136a8b75cd27b5b7171bffdd657280
    ///   pathHash("/file/example.txt") == 95958aa7e6b88c228e73771a281f5764
    public static func pathHash(for path: String) -> Data {
        Hashing.truncatedHash(Data(path.utf8), length: 16)
    }

    /// Build the msgpack-encoded request payload.
    ///
    /// Output: msgpack fixarray(3) + float64 + bin8(16) + nil
    ///   [timestamp_f64, path_hash_bytes16, form_data_map | nil]
    ///
    /// For "/page/index.mu" at t=1700000000.0 with no form data (29 bytes):
    ///   93cb41d954fc40000000c410fb40abf359b3f25fa0086107c5eee516c0
    ///
    /// - Parameters:
    ///   - path: Page/file path.
    ///   - timestamp: Unix timestamp.
    ///   - formData: Optional form field dict (nil for plain GET).
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

    /// Parse a msgpack-encoded response payload into (requestID, content).
    ///
    /// Expected format: fixarray(2) + bin8(16, requestID) + bin8(N, content)
    ///
    /// - Parameter data: Raw msgpack response bytes from the link.
    /// - Returns: Tuple of (16-byte request ID, raw content bytes).
    /// - Throws: NomadError.invalidMsgpack on malformed input.
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
