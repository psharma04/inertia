import Foundation
import ReticulumCrypto

public enum LXMFField: Int, Sendable {
    case embeddedLXMs     = 0x01
    case telemetry        = 0x02
    case telemetryStream  = 0x03
    case iconAppearance   = 0x04
    case fileAttachments  = 0x05
    case image            = 0x06
    case audio            = 0x07
    case thread           = 0x08
    case commands         = 0x09
    case results          = 0x0A
    case group            = 0x0B
    case ticket           = 0x0C
    case event            = 0x0D
    case rnrRefs          = 0x0E
    case renderer         = 0x0F
    case customType       = 0xFB
    case customData       = 0xFC
    case customMeta       = 0xFD
    case nonSpecific      = 0xFE
    case debug            = 0xFF
}

public enum LXMFRenderer: Int, Sendable {
    case plain   = 0x00
    case micron  = 0x01
    case markdown = 0x02
    case bbcode  = 0x03
}

public enum LXMFError: Error, Sendable {
    case invalidLength(Int)
    case invalidMsgpack
    case invalidEncoding
    case missingField(String)
    case invalidStampLength(Int)
    case invalidTicketLength(Int)
    case stampGenerationFailed
}

public struct LXMFMessage: Sendable {
    public static let ticketStampValue = 0x100

    public let destinationHash: Data
    public let sourceHash: Data
    public let signature: Data
    public let msgpackPayload: Data

    /// Canonical payload used for hash/signature calculations.
    public let canonicalMsgpackPayload: Data

    public let timestamp: Double
    public let title: String
    public let content: String

    /// LXMF extension fields (integer keys → raw msgpack-encoded value bytes).
    public let fields: [Int: Data]

    /// Optional 32-byte message stamp.
    public let stamp: Data?

    public init(packed: Data) throws {
        let minLength = 16 + 16 + 64
        guard packed.count >= minLength else {
            throw LXMFError.invalidLength(packed.count)
        }

        let base = packed.startIndex
        let destHash = Data(packed[base ..< base + 16])
        let srcHash = Data(packed[base + 16 ..< base + 32])
        let sig = Data(packed[base + 32 ..< base + 96])
        let rawPayload = Data(packed[(base + 96)...])

        var reader = MsgpackReader(rawPayload)
        let elementCount = try reader.readArrayHeader()
        guard elementCount >= 4 else {
            throw LXMFError.missingField("payload array must have at least 4 elements, got \(elementCount)")
        }

        let ts = try reader.readFloat64()
        let titleD = try reader.readBytesOrString()
        let contentD = try reader.readBytesOrString()
        let flds = try reader.readIntKeyedDict()

        var parsedStamp: Data? = nil
        if elementCount >= 5 {
            let stampValue = try reader.readBytesOrString()
            if !stampValue.isEmpty {
                let validLengths = [LXMFStamper.stampSize, Destination.hashLength]
                guard validLengths.contains(stampValue.count) else {
 throw LXMFError.invalidStampLength(stampValue.count)
                }
                parsedStamp = stampValue
            }
        }

        if elementCount > 5 {
            for _ in 0..<(elementCount - 5) {
                try reader.skipValue()
            }
        }

        let canonicalPayload = Self.encodeCanonicalPayload(
            timestamp: ts,
            titleBytes: titleD,
            contentBytes: contentD,
            fields: flds
        )

        self.destinationHash = destHash
        self.sourceHash = srcHash
        self.signature = sig
        self.msgpackPayload = rawPayload
        self.canonicalMsgpackPayload = canonicalPayload
        self.timestamp = ts
        self.title = String(data: titleD, encoding: .utf8) ?? ""
        self.content = String(data: contentD, encoding: .utf8) ?? ""
        self.fields = flds
        self.stamp = parsedStamp
    }

    /// Re-serialise this message with the original payload bytes.
    public func pack() throws -> Data {
        var result = Data(capacity: destinationHash.count + sourceHash.count +
                 signature.count + msgpackPayload.count)
        result.append(destinationHash)
        result.append(sourceHash)
        result.append(signature)
        result.append(msgpackPayload)
        return result
    }

    public var hash: Data {
        Self.computeMessageHash(
            destinationHash: destinationHash,
            sourceHash: sourceHash,
            canonicalPayload: canonicalMsgpackPayload
        )
    }

    public func verifySignature(ed25519PublicKey: Data) -> Bool {
        var signedPart = Data(capacity: destinationHash.count + sourceHash.count +
  canonicalMsgpackPayload.count + 32)
        signedPart.append(destinationHash)
        signedPart.append(sourceHash)
        signedPart.append(canonicalMsgpackPayload)
        signedPart.append(hash)
        return Signature.verify(signedPart, signature: signature, publicKeyBytes: ed25519PublicKey)
    }

    public func validateStamp(targetCost: Int, tickets: [Data]? = nil) -> (valid: Bool, value: Int?) {
        guard targetCost > 0 && targetCost < 255 else { return (false, nil) }
        guard let stamp else { return (false, nil) }

        if let tickets {
            for ticket in tickets where ticket.count == Destination.hashLength {
                let derived = Hashing.truncatedHash(ticket + hash, length: Destination.hashLength)
                if stamp == derived {
 return (true, Self.ticketStampValue)
                }
            }
        }

        guard stamp.count == LXMFStamper.stampSize else { return (false, nil) }
        let workblock = LXMFStamper.stampWorkblock(material: hash)
        guard LXMFStamper.stampValid(stamp: stamp, targetCost: targetCost, workblock: workblock) else {
            return (false, nil)
        }
        return (true, LXMFStamper.stampValue(workblock: workblock, stamp: stamp))
    }

    public static func create(
        destinationHash: Data,
        sourceIdentity: Identity,
        content: String,
        title: String = "",
        timestamp: Double = 0,
        fields: [Int: Data] = [:],
        stampCost: Int? = nil,
        stamp: Data? = nil,
        outboundTicket: Data? = nil
    ) throws -> Data {
        if let stamp {
            let validLengths = [LXMFStamper.stampSize, Destination.hashLength]
            if !validLengths.contains(stamp.count) {
                throw LXMFError.invalidStampLength(stamp.count)
            }
        }
        if let outboundTicket, outboundTicket.count != Destination.hashLength {
            throw LXMFError.invalidTicketLength(outboundTicket.count)
        }

        let sourceHash = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: sourceIdentity.hash
        )

        let titleBytes = Data(title.utf8)
        let contentBytes = Data(content.utf8)

        let canonicalPayload = encodeCanonicalPayload(
            timestamp: timestamp,
            titleBytes: titleBytes,
            contentBytes: contentBytes,
            fields: fields
        )

        let messageHash = computeMessageHash(
            destinationHash: destinationHash,
            sourceHash: sourceHash,
            canonicalPayload: canonicalPayload
        )

        var signedPart = Data(capacity: 16 + 16 + canonicalPayload.count + 32)
        signedPart.append(destinationHash)
        signedPart.append(sourceHash)
        signedPart.append(canonicalPayload)
        signedPart.append(messageHash)
        let signature = try sourceIdentity.sign(signedPart)

        let resolvedStamp: Data?
        if let stamp {
            resolvedStamp = stamp
        } else if let outboundTicket {
            resolvedStamp = Hashing.truncatedHash(
                outboundTicket + messageHash,
                length: Destination.hashLength
            )
        } else if let stampCost {
            guard stampCost > 0 && stampCost < 255 else {
                throw LXMFError.invalidEncoding
            }
            guard let generated = LXMFStamper.generateStamp(
                messageID: messageHash,
                stampCost: stampCost
            ) else {
                throw LXMFError.stampGenerationFailed
            }
            resolvedStamp = generated.stamp
        } else {
            resolvedStamp = nil
        }

        let payloadForWire: Data
        if let resolvedStamp {
            payloadForWire = appendStampToPayload(
                canonicalPayload: canonicalPayload,
                stamp: resolvedStamp
            )
        } else {
            payloadForWire = canonicalPayload
        }

        var packed = Data(capacity: 16 + 16 + 64 + payloadForWire.count)
        packed.append(destinationHash)
        packed.append(sourceHash)
        packed.append(signature)
        packed.append(payloadForWire)
        return packed
    }

    /// Pack a message for paper (QR/URI) delivery.
    /// Returns the raw bytes: destinationHash(16) + encrypt(rest of packed message).
    /// The caller encrypts with the recipient's X25519 public key via ReticulumToken.
    public static func packPaper(
        destinationHash: Data,
        sourceIdentity: Identity,
        recipientX25519PublicKey: Data,
        recipientIdentityHash: Data,
        content: String,
        title: String = "",
        timestamp: Double = 0,
        fields: [Int: Data] = [:]
    ) throws -> Data {
        let packed = try create(
            destinationHash: destinationHash,
            sourceIdentity: sourceIdentity,
            content: content,
            title: title,
            timestamp: timestamp,
            fields: fields
        )
        let payload = Data(packed[Destination.hashLength...])
        let encrypted = try ReticulumToken.encrypt(
            payload,
            recipientX25519PublicKey: recipientX25519PublicKey,
            identityHash: recipientIdentityHash
        )
        return Data(packed[..<Destination.hashLength]) + encrypted
    }

    /// Generate a paper message URI (`lxm://…`).
    public static func paperURI(paperPacked: Data) -> String {
        let encoded = paperPacked.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "lxm://\(encoded)"
    }

    static func encodeCanonicalPayload(
        timestamp: Double,
        titleBytes: Data,
        contentBytes: Data,
        fields: [Int: Data]
    ) -> Data {
        var payload = Data()
        payload.append(contentsOf: msgpackArrayHeader(4))
        payload.append(contentsOf: msgpackFloat64(timestamp))
        payload.append(contentsOf: msgpackBin(titleBytes))
        payload.append(contentsOf: msgpackBin(contentBytes))
        payload.append(contentsOf: msgpackIntKeyedMap(fields))
        return payload
    }

    static func computeMessageHash(
        destinationHash: Data,
        sourceHash: Data,
        canonicalPayload: Data
    ) -> Data {
        var hashInput = Data(capacity: destinationHash.count + sourceHash.count + canonicalPayload.count)
        hashInput.append(destinationHash)
        hashInput.append(sourceHash)
        hashInput.append(canonicalPayload)
        return Hashing.sha256(hashInput)
    }

    static func appendStampToPayload(canonicalPayload: Data, stamp: Data) -> Data {
        if canonicalPayload.isEmpty { return canonicalPayload }

        var payload = canonicalPayload
        let first = payload[payload.startIndex]

        if first >= 0x90 && first <= 0x9F {
            let count = Int(first & 0x0F)
            if count == 0x0F {
                // Convert fixarray(15) -> array16(16)
                payload.removeFirst()
                var out = Data([0xDC, 0x00, 0x10])
                out.append(payload)
                out.append(contentsOf: msgpackBin(stamp))
                return out
            }
            payload[payload.startIndex] = UInt8(0x90 | UInt8(count + 1))
            payload.append(contentsOf: msgpackBin(stamp))
            return payload
        }

        if first == 0xDC, payload.count >= 3 {
            let cHi = Int(payload[payload.startIndex + 1])
            let cLo = Int(payload[payload.startIndex + 2])
            let count = (cHi << 8) | cLo
            let incremented = count + 1
            payload[payload.startIndex + 1] = UInt8((incremented >> 8) & 0xFF)
            payload[payload.startIndex + 2] = UInt8(incremented & 0xFF)
            payload.append(contentsOf: msgpackBin(stamp))
            return payload
        }

        if first == 0xDD, payload.count >= 5 {
            let b1 = Int(payload[payload.startIndex + 1])
            let b2 = Int(payload[payload.startIndex + 2])
            let b3 = Int(payload[payload.startIndex + 3])
            let b4 = Int(payload[payload.startIndex + 4])
            let count = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
            let incremented = count + 1
            payload[payload.startIndex + 1] = UInt8((incremented >> 24) & 0xFF)
            payload[payload.startIndex + 2] = UInt8((incremented >> 16) & 0xFF)
            payload[payload.startIndex + 3] = UInt8((incremented >> 8) & 0xFF)
            payload[payload.startIndex + 4] = UInt8(incremented & 0xFF)
            payload.append(contentsOf: msgpackBin(stamp))
            return payload
        }

        // Fallback: keep payload unchanged if malformed.
        return canonicalPayload
    }

    // Minimal msgpack encoding helpers

    private static func msgpackArrayHeader(_ count: Int) -> [UInt8] {
        if count <= 0x0F {
            return [0x90 | UInt8(count)]
        } else if count <= 0xFFFF {
            return [0xDC, UInt8((count >> 8) & 0xFF), UInt8(count & 0xFF)]
        } else {
            return [
                0xDD,
                UInt8((count >> 24) & 0xFF),
                UInt8((count >> 16) & 0xFF),
                UInt8((count >> 8) & 0xFF),
                UInt8(count & 0xFF),
            ]
        }
    }

    private static func msgpackFloat64(_ value: Double) -> [UInt8] {
        let bits = value.bitPattern
        return [
            0xCB,
            UInt8((bits >> 56) & 0xFF),
            UInt8((bits >> 48) & 0xFF),
            UInt8((bits >> 40) & 0xFF),
            UInt8((bits >> 32) & 0xFF),
            UInt8((bits >> 24) & 0xFF),
            UInt8((bits >> 16) & 0xFF),
            UInt8((bits >> 8) & 0xFF),
            UInt8(bits & 0xFF),
        ]
    }

    private static func msgpackBin(_ data: Data) -> [UInt8] {
        let len = data.count
        var result: [UInt8]
        if len <= 0xFF {
            result = [0xC4, UInt8(len)]
        } else if len <= 0xFFFF {
            result = [0xC5, UInt8((len >> 8) & 0xFF), UInt8(len & 0xFF)]
        } else {
            result = [
                0xC6,
                UInt8((len >> 24) & 0xFF),
                UInt8((len >> 16) & 0xFF),
                UInt8((len >> 8) & 0xFF),
                UInt8(len & 0xFF),
            ]
        }
        result.append(contentsOf: data)
        return result
    }

    private static func msgpackInt(_ value: Int) -> [UInt8] {
        if value >= 0 {
            if value <= 0x7F { return [UInt8(value)] }
            if value <= 0xFF { return [0xCC, UInt8(value)] }
            if value <= 0xFFFF {
                return [0xCD, UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
            }
            return [
                0xCE,
                UInt8((value >> 24) & 0xFF),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8(value & 0xFF),
            ]
        } else {
            if value >= -32 { return [UInt8(bitPattern: Int8(value))] }
            if value >= Int(Int8.min) { return [0xD0, UInt8(bitPattern: Int8(value))] }
            if value >= Int(Int16.min) {
                let v = Int16(value)
                return [
 0xD1,
 UInt8((Int(v) >> 8) & 0xFF),
 UInt8(Int(v) & 0xFF),
                ]
            }
            let v = Int32(value)
            return [
                0xD2,
                UInt8((Int(v) >> 24) & 0xFF),
                UInt8((Int(v) >> 16) & 0xFF),
                UInt8((Int(v) >> 8) & 0xFF),
                UInt8(Int(v) & 0xFF),
            ]
        }
    }

    private static func msgpackIntKeyedMap(_ values: [Int: Data]) -> [UInt8] {
        let sorted = values.sorted { lhs, rhs in lhs.key < rhs.key }
        let count = sorted.count

        var out: [UInt8] = []
        if count <= 0x0F {
            out.append(0x80 | UInt8(count))
        } else if count <= 0xFFFF {
            out.append(0xDE)
            out.append(UInt8((count >> 8) & 0xFF))
            out.append(UInt8(count & 0xFF))
        } else {
            out.append(0xDF)
            out.append(UInt8((count >> 24) & 0xFF))
            out.append(UInt8((count >> 16) & 0xFF))
            out.append(UInt8((count >> 8) & 0xFF))
            out.append(UInt8(count & 0xFF))
        }

        for (key, rawValue) in sorted {
            out.append(contentsOf: msgpackInt(key))
            out.append(contentsOf: rawValue)
        }
        return out
    }
}

/// Cursor-based msgpack decoder covering the subset of types used in LXMF payloads.
private struct MsgpackReader {
    private let data: Data
    private var cursor: Int

    init(_ data: Data) {
        self.data = data
        self.cursor = data.startIndex
    }

    mutating func readByte() throws -> UInt8 {
        guard cursor < data.endIndex else { throw LXMFError.invalidMsgpack }
        defer { cursor += 1 }
        return data[cursor]
    }

    mutating func readN(_ n: Int) throws -> Data {
        guard n >= 0, cursor + n <= data.endIndex else { throw LXMFError.invalidMsgpack }
        defer { cursor += n }
        return Data(data[cursor ..< cursor + n])
    }

    mutating func readUInt16() throws -> UInt16 {
        let b = try readN(2)
        return (UInt16(b[b.startIndex]) << 8) | UInt16(b[b.startIndex + 1])
    }

    mutating func readUInt32() throws -> UInt32 {
        let b = try readN(4)
        return (UInt32(b[b.startIndex]) << 24)
             | (UInt32(b[b.startIndex + 1]) << 16)
             | (UInt32(b[b.startIndex + 2]) << 8)
             | UInt32(b[b.startIndex + 3])
    }

    mutating func readUInt64() throws -> UInt64 {
        let b = try readN(8)
        var v: UInt64 = 0
        for i in 0..<8 { v = (v << 8) | UInt64(b[b.startIndex + i]) }
        return v
    }

    mutating func readFloat64() throws -> Double {
        let tag = try readByte()
        guard tag == 0xCB else { throw LXMFError.invalidMsgpack }
        return Double(bitPattern: try readUInt64())
    }

    mutating func readArrayHeader() throws -> Int {
        let tag = try readByte()
        switch tag {
        case 0x90...0x9F: return Int(tag & 0x0F)
        case 0xDC: return Int(try readUInt16())
        case 0xDD: return Int(try readUInt32())
        default: throw LXMFError.invalidMsgpack
        }
    }

    mutating func readMapHeader() throws -> Int {
        let tag = try readByte()
        switch tag {
        case 0x80...0x8F: return Int(tag & 0x0F)
        case 0xDE: return Int(try readUInt16())
        case 0xDF: return Int(try readUInt32())
        default: throw LXMFError.invalidMsgpack
        }
    }

    mutating func readBytesOrString() throws -> Data {
        let tag = try readByte()
        switch tag {
        case 0xC4: return try readN(Int(try readByte()))
        case 0xC5: return try readN(Int(try readUInt16()))
        case 0xC6: return try readN(Int(try readUInt32()))
        case 0xA0...0xBF: return try readN(Int(tag & 0x1F))
        case 0xD9: return try readN(Int(try readByte()))
        case 0xDA: return try readN(Int(try readUInt16()))
        case 0xDB: return try readN(Int(try readUInt32()))
        default: throw LXMFError.invalidMsgpack
        }
    }

    mutating func readIntKey() throws -> Int {
        let tag = try readByte()
        switch tag {
        case 0x00...0x7F: return Int(tag)
        case 0xE0...0xFF: return Int(Int8(bitPattern: tag))
        case 0xCC: return Int(try readByte())
        case 0xCD: return Int(try readUInt16())
        case 0xCE: return Int(try readUInt32())
        case 0xCF: return Int(bitPattern: UInt(try readUInt64()))
        case 0xD0: return Int(Int8(bitPattern: try readByte()))
        case 0xD1: return Int(Int16(bitPattern: try readUInt16()))
        case 0xD2: return Int(Int32(bitPattern: try readUInt32()))
        case 0xD3: return Int(Int64(bitPattern: try readUInt64()))
        default: throw LXMFError.invalidMsgpack
        }
    }

    mutating func readIntKeyedDict() throws -> [Int: Data] {
        let count = try readMapHeader()
        var result: [Int: Data] = [:]
        result.reserveCapacity(count)
        for _ in 0..<count {
            let key = try readIntKey()
            let value = try readRawValue()
            result[key] = value
        }
        return result
    }

    mutating func readRawValue() throws -> Data {
        let start = cursor
        try skipValue()
        return Data(data[start..<cursor])
    }

    mutating func skipValue() throws {
        let tag = try readByte()
        switch tag {
        case 0xC0, 0xC2, 0xC3, 0x00...0x7F, 0xE0...0xFF:
            break
        case 0xCC, 0xD0:
            _ = try readN(1)
        case 0xCD, 0xD1:
            _ = try readN(2)
        case 0xCA, 0xCE, 0xD2:
            _ = try readN(4)
        case 0xCB, 0xCF, 0xD3:
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
            for _ in 0..<Int(tag & 0x0F) { try skipValue() }
        case 0xDC:
            for _ in 0..<Int(try readUInt16()) { try skipValue() }
        case 0xDD:
            for _ in 0..<Int(try readUInt32()) { try skipValue() }
        case 0x80...0x8F:
            for _ in 0..<Int(tag & 0x0F) { try skipValue(); try skipValue() }
        case 0xDE:
            for _ in 0..<Int(try readUInt16()) { try skipValue(); try skipValue() }
        case 0xDF:
            for _ in 0..<Int(try readUInt32()) { try skipValue(); try skipValue() }
        default:
            throw LXMFError.invalidMsgpack
        }
    }
}
