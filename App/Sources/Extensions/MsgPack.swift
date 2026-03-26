import Foundation
import ReticulumCrypto

/// Minimal msgpack encoder/decoder for the LXMF announce app_data format.
///
/// LXMF encodes announce metadata as `umsgpack.packb({field_id: value, ...})`.
/// We only need to handle a fixmap of int keys → string values.
///
/// Relevant msgpack type prefixes:
/// - `0x80…0x8F`  fixmap  (up to 15 entries)
/// - `0x00…0x7F`  positive fixint
/// - `0xA0…0xBF`  fixstr  (0–31 bytes)
/// - `0xD9`        str8    (8-bit length prefix, up to 255 bytes)
enum MsgPack {

    /// LXMF announce app_data field IDs.
    enum Field: Int {
        case displayName = 0x01
        case stampCost   = 0x0A
    }

    // Encode

    /// Encodes delivery announce app_data as:
    /// `msgpack([display_name_bytes, stamp_cost])`.
    ///
    /// `stamp_cost` is encoded as `nil` when absent/disabled.
    static func encodeDeliveryAnnounce(displayName: String, stampCost: Int?) -> Data {
        var out = Data([0x92]) // fixarray(2)
        out.append(encodeBinary(Data(displayName.utf8)))
        if let stampCost, stampCost > 0, stampCost < 255 {
            out.append(encodeInteger(stampCost))
        } else {
            out.append(0xC0) // nil
        }
        return out
    }

    /// Encodes announce app_data in Python LXMF 0.5.0+ style:
    /// `msgpack([display_name_bytes])`.
    ///
    /// This is the format used by Sideband/Reticulum clients for outbound
    /// `lxmf.delivery` announces.
    static func encodeDisplayNameList(_ displayName: String) -> Data {
        var out = Data([0x91]) // fixarray(1), legacy compatibility
        out.append(encodeBinary(Data(displayName.utf8)))
        return out
    }

    /// Encodes `fields` as a msgpack fixmap `{Int: String}`.
    ///
    /// Only handles maps with ≤ 15 entries and string values ≤ 255 UTF-8 bytes.
    static func encode(_ fields: [Int: String]) -> Data {
        var out = Data()
        let count = min(fields.count, 15)
        out.append(UInt8(0x80 | count))         // fixmap

        for (key, value) in fields.prefix(count) {
            // Positive fixint key (0x00–0x7F).
            out.append(UInt8(clamping: key))

            let utf8 = Array(value.utf8)
            if utf8.count <= 31 {
                out.append(UInt8(0xA0 | utf8.count)) // fixstr
            } else {
                out.append(0xD9)   // str8
                out.append(UInt8(min(utf8.count, 255)))
            }
            out.append(contentsOf: utf8.prefix(255))
        }
        return out
    }

    // Decode

    /// Decodes a msgpack fixmap `{Int: String}` from `data`.
    ///
    /// Returns `nil` if the bytes do not start with a fixmap marker.
    /// Unknown field IDs and non-string values are silently skipped.
    static func decode(_ data: Data) -> [Int: String]? {
        guard !data.isEmpty else { return nil }
        let bytes = Array(data)
        var i = 0

        // Must start with fixmap.
        guard bytes[i] & 0xF0 == 0x80 else { return nil }
        let count = Int(bytes[i] & 0x0F)
        i += 1

        var result: [Int: String] = [:]

        for _ in 0..<count {
            guard i < bytes.count else { break }

            // Key: positive fixint only.
            guard bytes[i] & 0x80 == 0 else { break }
            let key = Int(bytes[i])
            i += 1
            guard i < bytes.count else { break }

            // Value: str/bin/nil or other scalar types.
            let (str, advance) = readStringOrBytesOrNil(bytes, at: i)
            i += advance
            if let str { result[key] = str }
        }

        return result.isEmpty ? nil : result
    }

    /// Extracts a peer display name from LXMF announce app_data.
    ///
    /// Supports both formats used by LXMF clients:
    /// - map:  `{0x01: <display_name>, ...}`
    /// - list: `[display_name, stamp_cost]`
    static func decodeDisplayName(_ data: Data) -> String? {
        if let map = decode(data), let name = map[Field.displayName.rawValue], !name.isEmpty {
            return name
        }
        return decodeDisplayNameAndStampCost(data).displayName
    }

    /// Extracts `(display_name, stamp_cost)` from LXMF announce app_data.
    ///
    /// Supports both formats:
    /// - map:  `{0x01: <display_name>, 0x0A: <stamp_cost_as_string>, ...}`
    /// - list: `[display_name, stamp_cost]`
    static func decodeDisplayNameAndStampCost(_ data: Data) -> (displayName: String?, stampCost: Int?) {
        if let map = decode(data) {
            let name = map[Field.displayName.rawValue].flatMap { $0.isEmpty ? nil : $0 }
            let parsedCost = map[Field.stampCost.rawValue]
                .flatMap(Int.init)
                .flatMap { ($0 > 0 && $0 < 255) ? $0 : nil }
            return (name, parsedCost)
        }

        if let list = decodeDisplayNameStampCostList(data) {
            return list
        }

        return (nil, nil)
    }

    /// Extracts only stamp cost from announce app_data.
    static func decodeStampCost(_ data: Data) -> Int? {
        decodeDisplayNameAndStampCost(data).stampCost
    }

    /// Extracts propagation-node target stamp cost from `lxmf.propagation` app_data.
    static func decodePropagationNodeStampCost(_ data: Data) -> Int? {
        var reader = Reader(data)
        guard let count = try? reader.readArrayHeader(), count >= 6 else { return nil }

        // Skip fields 0..4.
        for _ in 0..<5 {
            guard (try? reader.skipValue()) != nil else { return nil }
        }

        // Field 5: [cost, flexibility, peering_cost]
        guard let stampArrayCount = try? reader.readArrayHeader(), stampArrayCount >= 1 else { return nil }
        let decodedCost: Int?
        do {
            decodedCost = try reader.readIntOrNil()
        } catch {
            return nil
        }
        guard let rawCost = decodedCost else { return nil }
        guard rawCost > 0 && rawCost < 255 else { return nil }
        return rawCost
    }

    /// Extracts propagation-node enabled state (`node_state`) from app_data.
    static func decodePropagationNodeEnabled(_ data: Data) -> Bool? {
        var reader = Reader(data)
        guard let count = try? reader.readArrayHeader(), count >= 3 else { return nil }

        // Skip fields 0..1, then parse field 2 (node_state).
        for _ in 0..<2 {
            guard (try? reader.skipValue()) != nil else { return nil }
        }

        guard let enabled = try? reader.readBoolOrNil() else { return nil }
        return enabled
    }

    /// Decodes ticket field payload `[expires_unix, ticket_bytes]`.
    static func encodeTicketField(expires: Double, ticket: Data) -> Data {
        var out = Data([0x92]) // [expires, ticket]
        out.append(0xCB)
        let bits = expires.bitPattern.bigEndian
        withUnsafeBytes(of: bits) { out.append(contentsOf: $0) }
        out.append(encodeBinary(ticket))
        return out
    }

    /// Decodes ticket field payload `[expires_unix, ticket_bytes]`.
    static func decodeTicketField(_ data: Data) -> (expires: Double, ticket: Data)? {
        var reader = Reader(data)
        guard let count = try? reader.readArrayHeader(), count >= 2 else { return nil }
        guard let expires = try? reader.readDouble() else { return nil }
        guard let ticket = try? reader.readBytesOrString(), ticket.count == 16 else { return nil }
        return (expires, ticket)
    }

    enum PropagationGetResponse: Equatable {
        case error(Int)
        case transientIDs([Data])
        case messages([Data])
    }

    struct PropagationGetRequest: Equatable {
        let timestamp: Double
        let wants: [Data]?
        let haves: [Data]?
        let limitKilobytes: Double?
    }

    /// Encodes a Reticulum LINK request payload for LXMF propagation `"/get"`.
    ///
    /// Wire format:
    /// `msgpack([timestamp, truncated_hash("/get"), [wants, haves, limit_kb?]])`
    static func encodePropagationGetLinkRequest(
        timestamp: Double = Date().timeIntervalSince1970,
        wants: [Data]?,
        haves: [Data]?,
        limitKilobytes: Double? = nil
    ) -> Data {
        var out = Data()
        out.append(contentsOf: encodeArrayHeader(3))
        out.append(contentsOf: encodeDouble(timestamp))
        out.append(encodeBinary(propagationGetPathHash()))

        let nestedCount = limitKilobytes == nil ? 2 : 3
        out.append(contentsOf: encodeArrayHeader(nestedCount))
        out.append(contentsOf: encodeOptionalDataArray(wants))
        out.append(contentsOf: encodeOptionalDataArray(haves))
        if let limitKilobytes {
            out.append(contentsOf: encodeDouble(limitKilobytes))
        }

        return out
    }

    /// Decodes a LINK request payload for LXMF propagation `"/get"`.
    static func decodePropagationGetLinkRequest(_ data: Data) -> PropagationGetRequest? {
        var reader = Reader(data)
        guard let outerCount = try? reader.readArrayHeader(), outerCount == 3 else { return nil }
        guard let timestamp = try? reader.readDouble() else { return nil }
        guard let pathHash = try? reader.readBytesOrString(), pathHash == propagationGetPathHash() else {
            return nil
        }

        guard let nestedCount = try? reader.readArrayHeader(), nestedCount >= 2 else { return nil }
        guard let wants = try? readOptionalDataArray(reader: &reader) else { return nil }
        guard let haves = try? readOptionalDataArray(reader: &reader) else { return nil }

        var limitKilobytes: Double? = nil
        if nestedCount >= 3 {
            guard let parsed = try? readDoubleOrIntOrNil(reader: &reader) else { return nil }
            limitKilobytes = parsed
        }

        if nestedCount > 3 {
            for _ in 0..<(nestedCount - 3) {
                guard (try? reader.skipValue()) != nil else { return nil }
            }
        }

        guard reader.isAtEnd else { return nil }
        return PropagationGetRequest(
            timestamp: timestamp,
            wants: wants,
            haves: haves,
            limitKilobytes: limitKilobytes
        )
    }

    /// Decodes a Reticulum LINK response envelope:
    /// `msgpack([request_id, response_data])`
    ///
    /// Used for propagation `"/get"` responses.
    static func decodePropagationGetLinkResponse(_ data: Data) -> (requestID: Data, response: PropagationGetResponse)? {
        var reader = Reader(data)
        guard let outerCount = try? reader.readArrayHeader(), outerCount == 2 else { return nil }
        guard let requestID = try? reader.readBytesOrString(), requestID.count == 16 else { return nil }
        guard let response = try? decodePropagationGetResponseValue(reader: &reader) else { return nil }
        guard reader.isAtEnd else { return nil }
        return (requestID, response)
    }

    // Private

    private static func encodeBinary(_ data: Data) -> Data {
        let len = data.count
        var out = Data()
        if len <= 0xFF {
            out.append(0xC4)
            out.append(UInt8(len))
        } else if len <= 0xFFFF {
            out.append(0xC5)
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        } else {
            out.append(0xC6)
            out.append(UInt8((len >> 24) & 0xFF))
            out.append(UInt8((len >> 16) & 0xFF))
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        }
        out.append(data)
        return out
    }

    private static func encodeArrayHeader(_ count: Int) -> Data {
        precondition(count >= 0)
        if count <= 0x0F {
            return Data([0x90 | UInt8(count)])
        } else if count <= 0xFFFF {
            return Data([
                0xDC,
                UInt8((count >> 8) & 0xFF),
                UInt8(count & 0xFF),
            ])
        } else {
            return Data([
                0xDD,
                UInt8((count >> 24) & 0xFF),
                UInt8((count >> 16) & 0xFF),
                UInt8((count >> 8) & 0xFF),
                UInt8(count & 0xFF),
            ])
        }
    }

    private static func encodeDouble(_ value: Double) -> Data {
        var out = Data([0xCB])
        let bits = value.bitPattern.bigEndian
        withUnsafeBytes(of: bits) { out.append(contentsOf: $0) }
        return out
    }

    private static func encodeOptionalDataArray(_ values: [Data]?) -> Data {
        guard let values else { return Data([0xC0]) }
        var out = Data()
        out.append(contentsOf: encodeArrayHeader(values.count))
        for value in values {
            out.append(encodeBinary(value))
        }
        return out
    }

    private static func readOptionalDataArray(reader: inout Reader) throws -> [Data]? {
        let tag = try reader.readByte()
        if tag == 0xC0 {
            return nil
        }

        reader.unreadByte()
        let count = try reader.readArrayHeader()
        var values: [Data] = []
        values.reserveCapacity(count)
        for _ in 0..<count {
            values.append(try reader.readBytesOrString())
        }
        return values
    }

    private static func readDoubleOrIntOrNil(reader: inout Reader) throws -> Double? {
        let tag = try reader.readByte()
        reader.unreadByte()

        if tag == 0xCB {
            return try reader.readDouble()
        }

        if isIntegerTag(tag) || tag == 0xC0 {
            guard let value = try reader.readIntOrNil() else { return nil }
            return Double(value)
        }

        throw MsgPackReaderError.malformed
    }

    private static func decodePropagationGetResponseValue(reader: inout Reader) throws -> PropagationGetResponse {
        let tag = try reader.readByte()
        reader.unreadByte()

        if isIntegerTag(tag) {
            guard let value = try reader.readIntOrNil() else { throw MsgPackReaderError.malformed }
            return .error(value)
        }

        if tag == 0xC0 {
            _ = try reader.readIntOrNil()
            return .transientIDs([])
        }

        if isArrayTag(tag) {
            let count = try reader.readArrayHeader()
            var entries: [Data] = []
            entries.reserveCapacity(count)
            for _ in 0..<count {
                entries.append(try reader.readBytesOrString())
            }

            // Propagation transient IDs are SHA-256 digests (32 bytes).
            let transientLike = entries.isEmpty || entries.allSatisfy { $0.count == 32 }
            return transientLike ? .transientIDs(entries) : .messages(entries)
        }

        throw MsgPackReaderError.malformed
    }

    private static func isIntegerTag(_ tag: UInt8) -> Bool {
        switch tag {
        case 0x00...0x7F, 0xE0...0xFF, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2:
            return true
        default:
            return false
        }
    }

    private static func isArrayTag(_ tag: UInt8) -> Bool {
        (0x90...0x9F).contains(tag) || tag == 0xDC || tag == 0xDD
    }

    private static func propagationGetPathHash() -> Data {
        Hashing.truncatedHash(Data("/get".utf8), length: 16)
    }

    private static func encodeInteger(_ value: Int) -> Data {
        if value >= 0 {
            if value <= 0x7F {
                return Data([UInt8(value)])
            } else if value <= 0xFF {
                return Data([0xCC, UInt8(value)])
            } else if value <= 0xFFFF {
                return Data([
 0xCD,
 UInt8((value >> 8) & 0xFF),
 UInt8(value & 0xFF),
                ])
            } else {
                return Data([
 0xCE,
 UInt8((value >> 24) & 0xFF),
 UInt8((value >> 16) & 0xFF),
 UInt8((value >> 8) & 0xFF),
 UInt8(value & 0xFF),
                ])
            }
        }

        let signed = Int32(value)
        if signed >= -32 {
            return Data([UInt8(bitPattern: Int8(signed))])
        } else if signed >= Int32(Int8.min) {
            return Data([0xD0, UInt8(bitPattern: Int8(signed))])
        } else if signed >= Int32(Int16.min) {
            return Data([
                0xD1,
                UInt8((Int(signed) >> 8) & 0xFF),
                UInt8(Int(signed) & 0xFF),
            ])
        } else {
            return Data([
                0xD2,
                UInt8((Int(signed) >> 24) & 0xFF),
                UInt8((Int(signed) >> 16) & 0xFF),
                UInt8((Int(signed) >> 8) & 0xFF),
                UInt8(Int(signed) & 0xFF),
            ])
        }
    }

    private static func readStringOrBytesOrNil(_ bytes: [UInt8], at i: Int) -> (String?, Int) {
        guard i < bytes.count else { return (nil, 0) }
        let tag = bytes[i]

        if tag & 0xE0 == 0xA0 {
            // fixstr: length in low 5 bits.
            let len = Int(tag & 0x1F)
            let start = i + 1
            guard start + len <= bytes.count else { return (nil, 1 + len) }
            let str = String(bytes: bytes[start..<(start + len)], encoding: .utf8)
            return (str, 1 + len)

        } else if tag == 0xD9 {
            // str8: 1-byte length follows.
            guard i + 1 < bytes.count else { return (nil, 1) }
            let len = Int(bytes[i + 1])
            let start = i + 2
            guard start + len <= bytes.count else { return (nil, 2 + len) }
            let str = String(bytes: bytes[start..<(start + len)], encoding: .utf8)
            return (str, 2 + len)

        } else if tag == 0xC4 {
            // bin8
            guard i + 1 < bytes.count else { return (nil, 1) }
            let len = Int(bytes[i + 1])
            let start = i + 2
            guard start + len <= bytes.count else { return (nil, 2 + len) }
            let str = String(bytes: bytes[start..<(start + len)], encoding: .utf8)
            return (str, 2 + len)

        } else if tag == 0xC5 {
            // bin16
            guard i + 2 < bytes.count else { return (nil, 1) }
            let len = (Int(bytes[i + 1]) << 8) | Int(bytes[i + 2])
            let start = i + 3
            guard start + len <= bytes.count else { return (nil, 3 + len) }
            let str = String(bytes: bytes[start..<(start + len)], encoding: .utf8)
            return (str, 3 + len)

        } else if tag == 0xC6 {
            // bin32
            guard i + 4 < bytes.count else { return (nil, 1) }
            let len = (Int(bytes[i + 1]) << 24)
 | (Int(bytes[i + 2]) << 16)
 | (Int(bytes[i + 3]) << 8)
 |  Int(bytes[i + 4])
            let start = i + 5
            guard start + len <= bytes.count else { return (nil, 5 + len) }
            let str = String(bytes: bytes[start..<(start + len)], encoding: .utf8)
            return (str, 5 + len)

        } else if tag == 0xC0 || tag == 0xC2 || tag == 0xC3 {
            // nil/false/true
            return (nil, 1)
        } else if tag <= 0x7F || tag >= 0xE0 {
            // positive/negative fixint
            return (nil, 1)
        } else if tag == 0xCC || tag == 0xD0 {
            return (nil, 2)
        } else if tag == 0xCD || tag == 0xD1 {
            return (nil, 3)
        } else if tag == 0xCE || tag == 0xD2 || tag == 0xCA {
            return (nil, 5)
        } else if tag == 0xCF || tag == 0xD3 || tag == 0xCB {
            return (nil, 9)
        } else {
            // Unsupported value type — skip 1 byte and give up on this entry.
            return (nil, 1)
        }
    }

    private static func readIntOrNil(_ bytes: [UInt8], at i: Int) -> (Int?, Int) {
        guard i < bytes.count else { return (nil, 0) }
        let tag = bytes[i]
        switch tag {
        case 0xC0:
            return (nil, 1)
        case 0x00...0x7F:
            return (Int(tag), 1)
        case 0xE0...0xFF:
            return (Int(Int8(bitPattern: tag)), 1)
        case 0xCC:
            guard i + 1 < bytes.count else { return (nil, 1) }
            return (Int(bytes[i + 1]), 2)
        case 0xCD:
            guard i + 2 < bytes.count else { return (nil, 1) }
            let value = (Int(bytes[i + 1]) << 8) | Int(bytes[i + 2])
            return (value, 3)
        case 0xCE:
            guard i + 4 < bytes.count else { return (nil, 1) }
            let value = (Int(bytes[i + 1]) << 24)
 | (Int(bytes[i + 2]) << 16)
 | (Int(bytes[i + 3]) << 8)
 |  Int(bytes[i + 4])
            return (value, 5)
        default:
            return (nil, 1)
        }
    }

    private static func decodeDisplayNameStampCostList(_ data: Data) -> (displayName: String?, stampCost: Int?)? {
        let bytes = Array(data)
        guard !bytes.isEmpty else { return nil }

        var i = 0
        let count: Int
        let tag = bytes[i]
        if tag & 0xF0 == 0x90 {
            count = Int(tag & 0x0F)
            i += 1
        } else if tag == 0xDC {
            guard i + 2 < bytes.count else { return nil }
            count = (Int(bytes[i + 1]) << 8) | Int(bytes[i + 2])
            i += 3
        } else if tag == 0xDD {
            guard i + 4 < bytes.count else { return nil }
            count = (Int(bytes[i + 1]) << 24)
                  | (Int(bytes[i + 2]) << 16)
                  | (Int(bytes[i + 3]) << 8)
                  |  Int(bytes[i + 4])
            i += 5
        } else {
            return nil
        }

        guard count >= 1 else { return nil }
        let (rawName, nameAdvance) = readStringOrBytesOrNil(bytes, at: i)
        i += nameAdvance

        var stampCost: Int? = nil
        if count >= 2 {
            let (rawCost, _) = readIntOrNil(bytes, at: i)
            if let rawCost, rawCost > 0, rawCost < 255 {
                stampCost = rawCost
            }
        }

        let displayName = rawName.flatMap { $0.isEmpty ? nil : $0 }
        return (displayName, stampCost)
    }
}

private struct Reader {
    private let bytes: [UInt8]
    private var index: Int = 0

    init(_ data: Data) {
        self.bytes = Array(data)
    }

    var isAtEnd: Bool { index == bytes.count }

    mutating func readByte() throws -> UInt8 {
        guard index < bytes.count else { throw MsgPackReaderError.malformed }
        defer { index += 1 }
        return bytes[index]
    }

    mutating func unreadByte() {
        if index > 0 {
            index -= 1
        }
    }

    mutating func readN(_ count: Int) throws -> [UInt8] {
        guard count >= 0, index + count <= bytes.count else { throw MsgPackReaderError.malformed }
        defer { index += count }
        return Array(bytes[index..<(index + count)])
    }

    mutating func readUInt16() throws -> UInt16 {
        let b = try readN(2)
        return (UInt16(b[0]) << 8) | UInt16(b[1])
    }

    mutating func readUInt32() throws -> UInt32 {
        let b = try readN(4)
        return (UInt32(b[0]) << 24)
             | (UInt32(b[1]) << 16)
             | (UInt32(b[2]) << 8)
             | UInt32(b[3])
    }

    mutating func readUInt64() throws -> UInt64 {
        let b = try readN(8)
        var out: UInt64 = 0
        for byte in b {
            out = (out << 8) | UInt64(byte)
        }
        return out
    }

    mutating func readArrayHeader() throws -> Int {
        let tag = try readByte()
        switch tag {
        case 0x90...0x9F:
            return Int(tag & 0x0F)
        case 0xDC:
            return Int(try readUInt16())
        case 0xDD:
            return Int(try readUInt32())
        default:
            throw MsgPackReaderError.malformed
        }
    }

    mutating func readDouble() throws -> Double {
        let tag = try readByte()
        guard tag == 0xCB else { throw MsgPackReaderError.malformed }
        let bits = try readUInt64()
        return Double(bitPattern: bits)
    }

    mutating func readBytesOrString() throws -> Data {
        let tag = try readByte()
        switch tag {
        case 0xC4:
            return Data(try readN(Int(try readByte())))
        case 0xC5:
            return Data(try readN(Int(try readUInt16())))
        case 0xC6:
            return Data(try readN(Int(try readUInt32())))
        case 0xA0...0xBF:
            return Data(try readN(Int(tag & 0x1F)))
        case 0xD9:
            return Data(try readN(Int(try readByte())))
        case 0xDA:
            return Data(try readN(Int(try readUInt16())))
        case 0xDB:
            return Data(try readN(Int(try readUInt32())))
        default:
            throw MsgPackReaderError.malformed
        }
    }

    mutating func readIntOrNil() throws -> Int? {
        let tag = try readByte()
        switch tag {
        case 0xC0:
            return nil
        case 0x00...0x7F:
            return Int(tag)
        case 0xE0...0xFF:
            return Int(Int8(bitPattern: tag))
        case 0xCC:
            return Int(try readByte())
        case 0xCD:
            return Int(try readUInt16())
        case 0xCE:
            return Int(try readUInt32())
        case 0xCF:
            return Int(try readUInt64())
        case 0xD0:
            return Int(Int8(bitPattern: try readByte()))
        case 0xD1:
            return Int(Int16(bitPattern: try readUInt16()))
        case 0xD2:
            return Int(Int32(bitPattern: try readUInt32()))
        default:
            throw MsgPackReaderError.malformed
        }
    }

    mutating func readBoolOrNil() throws -> Bool? {
        let tag = try readByte()
        switch tag {
        case 0xC0:
            return nil
        case 0xC2:
            return false
        case 0xC3:
            return true
        case 0x00...0x7F:
            return tag != 0
        case 0xE0...0xFF:
            return Int8(bitPattern: tag) != 0
        case 0xCC:
            return try readByte() != 0
        case 0xCD:
            return try readUInt16() != 0
        case 0xCE:
            return try readUInt32() != 0
        case 0xCF:
            return try readUInt64() != 0
        case 0xD0:
            return Int8(bitPattern: try readByte()) != 0
        case 0xD1:
            return Int16(bitPattern: try readUInt16()) != 0
        case 0xD2:
            return Int32(bitPattern: try readUInt32()) != 0
        default:
            throw MsgPackReaderError.malformed
        }
    }

    mutating func skipValue() throws {
        let tag = try readByte()
        switch tag {
        case 0x00...0x7F, 0xE0...0xFF, 0xC0, 0xC2, 0xC3:
            return
        case 0xCC, 0xD0:
            _ = try readN(1)
        case 0xCD, 0xD1:
            _ = try readN(2)
        case 0xCE, 0xD2, 0xCA:
            _ = try readN(4)
        case 0xCF, 0xD3, 0xCB:
            _ = try readN(8)
        case 0xA0...0xBF:
            _ = try readN(Int(tag & 0x1F))
        case 0xD9:
            _ = try readN(Int(try readByte()))
        case 0xDA:
            _ = try readN(Int(try readUInt16()))
        case 0xDB:
            _ = try readN(Int(try readUInt32()))
        case 0xC4:
            _ = try readN(Int(try readByte()))
        case 0xC5:
            _ = try readN(Int(try readUInt16()))
        case 0xC6:
            _ = try readN(Int(try readUInt32()))
        case 0x90...0x9F:
            for _ in 0..<Int(tag & 0x0F) {
                try skipValue()
            }
        case 0xDC:
            for _ in 0..<Int(try readUInt16()) {
                try skipValue()
            }
        case 0xDD:
            for _ in 0..<Int(try readUInt32()) {
                try skipValue()
            }
        case 0x80...0x8F:
            for _ in 0..<Int(tag & 0x0F) {
                try skipValue()
                try skipValue()
            }
        case 0xDE:
            for _ in 0..<Int(try readUInt16()) {
                try skipValue()
                try skipValue()
            }
        case 0xDF:
            for _ in 0..<Int(try readUInt32()) {
                try skipValue()
                try skipValue()
            }
        default:
            throw MsgPackReaderError.malformed
        }
    }
}

private enum MsgPackReaderError: Error {
    case malformed
}
