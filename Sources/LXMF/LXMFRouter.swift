import Foundation
import CryptoKit
import ReticulumCrypto
import os.log

/// Routes LXMF messages using opportunistic, direct, or propagated delivery.
public actor LXMFRouter {

    public enum RouterError: Error, Sendable {
        case invalidDestinationHashLength(Int)
        case invalidIdentityPublicKeyLength(Int)
        case invalidRatchetPublicKeyLength(Int)
        case invalidTicketLength(Int)
        case invalidStampCost(Int)
        case invalidLinkProofLength(Int)
        case invalidLinkProofSignature
        case invalidLinkProofSignalling
        case missingDirectRequest
        case missingDirectLink
        case invalidMsgpack
    }

    public enum DeliveryMethod: UInt8, Sendable {
        case opportunistic = 0x01
        case direct        = 0x02
        case propagated    = 0x03
    }

    public struct OpportunisticOutbound: Sendable {
        public let packedMessage: Data
        public let encryptedPayload: Data
    }

    public struct DirectLinkRequest: Sendable {
        public let destinationHash: Data
        public let linkID: Data
        public let requesterX25519PublicKey: Data
        public let requesterEd25519PublicKey: Data
        public let signalling: Data

        public var payload: Data {
            requesterX25519PublicKey + requesterEd25519PublicKey + signalling
        }
    }

    public struct DirectLinkState: Sendable {
        public let destinationHash: Data
        public let linkID: Data
        public let derivedKey: Data

        public init(destinationHash: Data, linkID: Data, derivedKey: Data) {
            self.destinationHash = destinationHash
            self.linkID = linkID
            self.derivedKey = derivedKey
        }
    }

    public struct PropagatedOutbound: Sendable {
        public let packedMessage: Data
        public let lxmData: Data
        public let transientID: Data
        public let propagationContainer: Data
        public let encryptedContainer: Data
    }

    private struct PendingDirectRequest {
        let destinationHash: Data
        let requesterX25519PrivateKey: Data
        let signalling: Data
    }

    private var pendingDirectRequests: [Data: PendingDirectRequest] = [:] // linkID -> request
    private var directLinksByDestination: [Data: DirectLinkState] = [:]    // destinationHash -> active link

    public init() {}

    // OPPORTUNISTIC

    public func createOpportunisticOutbound(
        destinationHash: Data,
        sourceIdentity: Identity,
        recipientIdentityPublicKey: Data,
        recipientRatchetPublicKey: Data? = nil,
        messageStampCost: Int? = nil,
        outboundTicket: Data? = nil,
        fields: [Int: Data] = [:],
        content: String,
        title: String = "",
        timestamp: Double = Date().timeIntervalSince1970
    ) throws -> OpportunisticOutbound {
        try Self.validateDestinationHash(destinationHash)
        try Self.validateIdentityPublicKey(recipientIdentityPublicKey)
        if let recipientRatchetPublicKey,
           recipientRatchetPublicKey.count != 32 {
            throw RouterError.invalidRatchetPublicKeyLength(recipientRatchetPublicKey.count)
        }
        if let outboundTicket, outboundTicket.count != Destination.hashLength {
            throw RouterError.invalidTicketLength(outboundTicket.count)
        }

        let packed = try LXMFMessage.create(
            destinationHash: destinationHash,
            sourceIdentity: sourceIdentity,
            content: content,
            title: title,
            timestamp: timestamp,
            fields: fields,
            stampCost: messageStampCost,
            outboundTicket: outboundTicket
        )

        let encryptedPayload = try Self.encryptForSingleDestination(
            plaintext: Data(packed.dropFirst(16)),
            recipientIdentityPublicKey: recipientIdentityPublicKey,
            ratchetX25519PublicKey: recipientRatchetPublicKey
        )

        return OpportunisticOutbound(
            packedMessage: packed,
            encryptedPayload: encryptedPayload
        )
    }

    // DIRECT

    public func createDirectLinkRequest(
        destinationHash: Data,
        mtu: Int = 500,
        mode: UInt8 = 0x01
    ) throws -> DirectLinkRequest {
        try Self.validateDestinationHash(destinationHash)

        let requesterX25519 = Curve25519.KeyAgreement.PrivateKey()
        let requesterEd25519 = Curve25519.Signing.PrivateKey()

        let requesterX25519Pub = requesterX25519.publicKey.rawRepresentation
        let requesterEd25519Pub = requesterEd25519.publicKey.rawRepresentation
        let signalling = Self.linkSignallingBytes(mtu: mtu, mode: mode)
        let linkID = Self.computeLinkID(
            destinationHash: destinationHash,
            context: 0x00,
            requesterX25519PublicKey: requesterX25519Pub,
            requesterEd25519PublicKey: requesterEd25519Pub
        )

        pendingDirectRequests[linkID] = PendingDirectRequest(
            destinationHash: destinationHash,
            requesterX25519PrivateKey: requesterX25519.rawRepresentation,
            signalling: signalling
        )

        return DirectLinkRequest(
            destinationHash: destinationHash,
            linkID: linkID,
            requesterX25519PublicKey: requesterX25519Pub,
            requesterEd25519PublicKey: requesterEd25519Pub,
            signalling: signalling
        )
    }

    public func completeDirectLink(
        linkID: Data,
        proofPayload: Data,
        recipientIdentityPublicKey: Data
    ) throws -> DirectLinkState {
        let lxmfLog = OSLog(subsystem: "chat.inertia.app", category: "lxmfrouter")
        os_log("CDL step 1: ENTER link=%{public}@", log: lxmfLog, type: .default, linkID.prefix(4).map { String(format: "%02x", $0) }.joined())
        try Self.validateIdentityPublicKey(recipientIdentityPublicKey)
        os_log("CDL step 2: identity ok", log: lxmfLog, type: .default)

        guard proofPayload.count == 99 else {
            os_log("CDL FAIL: proof len=%d", log: lxmfLog, type: .default, proofPayload.count)
            throw RouterError.invalidLinkProofLength(proofPayload.count)
        }
        os_log("CDL step 3: proof len ok", log: lxmfLog, type: .default)

        guard let pending = pendingDirectRequests.removeValue(forKey: linkID) else {
            os_log("CDL FAIL: no pending for link", log: lxmfLog, type: .default)
            throw RouterError.missingDirectRequest
        }
        os_log("CDL step 4: pending found", log: lxmfLog, type: .default)

        let signature = Data(proofPayload.prefix(64))
        let responderX25519Pub = Data(proofPayload[64..<96])
        let proofSignalling = Data(proofPayload[96..<99])
        // Python only checks that mode matches, not full signalling equality.
        // Transport nodes may clamp MTU, so the signalling bytes can differ.
        let proofMode = proofSignalling[proofSignalling.startIndex]
        let pendingMode = pending.signalling[pending.signalling.startIndex]
        guard proofMode == pendingMode else {
            os_log("CDL FAIL: mode mismatch proof=%d pending=%d", log: lxmfLog, type: .default, proofMode, pendingMode)
            throw RouterError.invalidLinkProofSignalling
        }
        os_log("CDL step 5: mode ok", log: lxmfLog, type: .default)

        let recipientEd25519Pub = Data(recipientIdentityPublicKey[32..<64])
        // Use the PROOF's signalling in signed data (not ours), matching Python's validate_proof
        var signedData = Data()
        signedData.append(linkID)
        signedData.append(responderX25519Pub)
        signedData.append(recipientEd25519Pub)
        signedData.append(proofSignalling)
        os_log("CDL step 6: signed data built", log: lxmfLog, type: .default)

        guard Signature.verify(
            signedData,
            signature: signature,
            publicKeyBytes: recipientEd25519Pub
        ) else {
            os_log("CDL FAIL: sig verify failed", log: lxmfLog, type: .default)
            throw RouterError.invalidLinkProofSignature
        }
        os_log("CDL step 7: sig ok", log: lxmfLog, type: .default)

        let derivedKey = try Self.deriveDirectKey(
            requesterX25519PrivateKey: pending.requesterX25519PrivateKey,
            responderX25519PublicKey: responderX25519Pub,
            linkID: linkID
        )
        os_log("CDL step 8: key derived", log: lxmfLog, type: .default)

        let linkState = DirectLinkState(
            destinationHash: pending.destinationHash,
            linkID: linkID,
            derivedKey: derivedKey
        )
        directLinksByDestination[pending.destinationHash] = linkState
        os_log("CDL step 9: DONE", log: lxmfLog, type: .default)
        return linkState
    }

    public func directLink(for destinationHash: Data) -> DirectLinkState? {
        directLinksByDestination[destinationHash]
    }

    public func removeDirectLink(for destinationHash: Data) {
        directLinksByDestination.removeValue(forKey: destinationHash)
    }

    public func removeDirectLinkByLinkID(_ linkID: Data) {
        directLinksByDestination = directLinksByDestination.filter { $0.value.linkID != linkID }
    }

    public func encryptDirectPayload(
        destinationHash: Data,
        lxmfPackedMessage: Data
    ) throws -> Data {
        guard let linkState = directLinksByDestination[destinationHash] else {
            throw RouterError.missingDirectLink
        }
        return try ReticulumToken.encryptLinkData(lxmfPackedMessage, key: linkState.derivedKey)
    }

    // PROPAGATED

    public func createPropagatedOutbound(
        destinationHash: Data,
        sourceIdentity: Identity,
        recipientIdentityPublicKey: Data,
        recipientRatchetPublicKey: Data? = nil,
        propagationNodeIdentityPublicKey: Data,
        propagationNodeRatchetPublicKey: Data? = nil,
        messageStampCost: Int? = nil,
        propagationStampCost: Int? = nil,
        outboundTicket: Data? = nil,
        fields: [Int: Data] = [:],
        content: String,
        title: String = "",
        messageTimestamp: Double = Date().timeIntervalSince1970,
        propagationTimestamp: Double = Date().timeIntervalSince1970
    ) throws -> PropagatedOutbound {
        try Self.validateDestinationHash(destinationHash)
        try Self.validateIdentityPublicKey(recipientIdentityPublicKey)
        try Self.validateIdentityPublicKey(propagationNodeIdentityPublicKey)
        if let recipientRatchetPublicKey,
           recipientRatchetPublicKey.count != 32 {
            throw RouterError.invalidRatchetPublicKeyLength(recipientRatchetPublicKey.count)
        }
        if let propagationNodeRatchetPublicKey,
           propagationNodeRatchetPublicKey.count != 32 {
            throw RouterError.invalidRatchetPublicKeyLength(propagationNodeRatchetPublicKey.count)
        }
        if let outboundTicket, outboundTicket.count != Destination.hashLength {
            throw RouterError.invalidTicketLength(outboundTicket.count)
        }

        let packed = try LXMFMessage.create(
            destinationHash: destinationHash,
            sourceIdentity: sourceIdentity,
            content: content,
            title: title,
            timestamp: messageTimestamp,
            fields: fields,
            stampCost: messageStampCost,
            outboundTicket: outboundTicket
        )

        // Python LXMF propagation packs destinationHash + encrypted(src+sig+payload).
        let innerEncrypted = try Self.encryptForSingleDestination(
            plaintext: Data(packed.dropFirst(16)),
            recipientIdentityPublicKey: recipientIdentityPublicKey,
            ratchetX25519PublicKey: recipientRatchetPublicKey
        )

        var lxmData = Data()
        lxmData.append(destinationHash)
        lxmData.append(innerEncrypted)

        let transientID = Hashing.sha256(lxmData)
        if let propagationStampCost {
            guard propagationStampCost > 0 && propagationStampCost < 255 else {
                throw RouterError.invalidStampCost(propagationStampCost)
            }
            guard let generated = LXMFStamper.generateStamp(
                messageID: transientID,
                stampCost: propagationStampCost,
                expandRounds: LXMFStamper.propagationWorkblockExpandRounds
            ) else {
                throw LXMFError.stampGenerationFailed
            }
            lxmData.append(generated.stamp)
        }

        let propagationContainer = Self.encodePropagationContainer(
            timestamp: propagationTimestamp,
            lxmDatas: [lxmData]
        )

        let encryptedContainer = try Self.encryptForSingleDestination(
            plaintext: propagationContainer,
            recipientIdentityPublicKey: propagationNodeIdentityPublicKey,
            ratchetX25519PublicKey: propagationNodeRatchetPublicKey
        )

        return PropagatedOutbound(
            packedMessage: packed,
            lxmData: lxmData,
            transientID: transientID,
            propagationContainer: propagationContainer,
            encryptedContainer: encryptedContainer
        )
    }

    // Propagation msgpack

    /// Encodes propagation container as msgpack: `[timestamp, [lxm_data, ...]]`
    public static func encodePropagationContainer(timestamp: Double, lxmDatas: [Data]) -> Data {
        var out = Data()
        out.append(contentsOf: msgpackArrayHeader(2))
        out.append(contentsOf: msgpackFloat64(timestamp))
        out.append(contentsOf: msgpackArrayHeader(lxmDatas.count))
        for lxmData in lxmDatas {
            out.append(contentsOf: msgpackBin(lxmData))
        }
        return out
    }

    public static func decodePropagationContainer(_ packed: Data) throws -> (timestamp: Double, lxmDatas: [Data]) {
        var reader = PropagationMsgpackReader(packed)
        let outerCount = try reader.readArrayHeader()
        guard outerCount == 2 else { throw RouterError.invalidMsgpack }

        let timestamp = try reader.readFloat64()
        let lxmCount = try reader.readArrayHeader()
        var lxmDatas: [Data] = []
        lxmDatas.reserveCapacity(lxmCount)
        for _ in 0..<lxmCount {
            lxmDatas.append(try reader.readBytesOrString())
        }

        guard reader.isAtEnd else { throw RouterError.invalidMsgpack }
        return (timestamp, lxmDatas)
    }

    // Private helpers

    private static func validateDestinationHash(_ hash: Data) throws {
        guard hash.count == Destination.hashLength else {
            throw RouterError.invalidDestinationHashLength(hash.count)
        }
    }

    private static func validateIdentityPublicKey(_ key: Data) throws {
        guard key.count == Identity.publicKeyLength else {
            throw RouterError.invalidIdentityPublicKeyLength(key.count)
        }
    }

    private static func encryptForSingleDestination(
        plaintext: Data,
        recipientIdentityPublicKey: Data,
        ratchetX25519PublicKey: Data? = nil
    ) throws -> Data {
        let recipientX25519Pub = ratchetX25519PublicKey ?? Data(recipientIdentityPublicKey.prefix(32))
        let recipientIdentityHash = Hashing.truncatedHash(
            recipientIdentityPublicKey,
            length: Identity.hashLength
        )
        return try ReticulumToken.encrypt(
            plaintext,
            recipientX25519PublicKey: recipientX25519Pub,
            identityHash: recipientIdentityHash
        )
    }

    /// Reticulum link signalling bytes: 3-byte big-endian signalling value.
    private static func linkSignallingBytes(mtu: Int, mode: UInt8) -> Data {
        let signallingValue = (mtu & 0x1FFFFF) + (((Int(mode) << 5) & 0xE0) << 16)
        let be = withUnsafeBytes(of: UInt32(signallingValue).bigEndian) { Data($0) }
        return Data(be.dropFirst(1))
    }

    private static func computeLinkID(
        destinationHash: Data,
        context: UInt8,
        requesterX25519PublicKey: Data,
        requesterEd25519PublicKey: Data
    ) -> Data {
        var hashable = Data([0x02]) // (destinationType=SINGLE << 2) | packetType=LINKREQUEST
        hashable.append(destinationHash)
        hashable.append(context)
        hashable.append(requesterX25519PublicKey)
        hashable.append(requesterEd25519PublicKey)
        // Single SHA256 truncated to 16 bytes — matches Python's Identity.truncated_hash()
        return Hashing.truncatedHash(hashable, length: 16)
    }

    private static func deriveDirectKey(
        requesterX25519PrivateKey: Data,
        responderX25519PublicKey: Data,
        linkID: Data
    ) throws -> Data {
        let ourPrivate = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: requesterX25519PrivateKey)
        let responderPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: responderX25519PublicKey)
        let sharedSecret = try ourPrivate.sharedSecretFromKeyAgreement(with: responderPublic)
        let derived = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: linkID,
            sharedInfo: Data(),
            outputByteCount: 64
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    private static func msgpackArrayHeader(_ count: Int) -> [UInt8] {
        if count <= 0x0f {
            return [0x90 | UInt8(count)]
        } else if count <= 0xffff {
            return [0xdc, UInt8((count >> 8) & 0xff), UInt8(count & 0xff)]
        } else {
            return [
                0xdd,
                UInt8((count >> 24) & 0xff),
                UInt8((count >> 16) & 0xff),
                UInt8((count >>  8) & 0xff),
                UInt8(count & 0xff),
            ]
        }
    }

    private static func msgpackFloat64(_ value: Double) -> [UInt8] {
        let bits = value.bitPattern
        return [
            0xcb,
            UInt8((bits >> 56) & 0xff),
            UInt8((bits >> 48) & 0xff),
            UInt8((bits >> 40) & 0xff),
            UInt8((bits >> 32) & 0xff),
            UInt8((bits >> 24) & 0xff),
            UInt8((bits >> 16) & 0xff),
            UInt8((bits >>  8) & 0xff),
            UInt8(bits & 0xff),
        ]
    }

    private static func msgpackBin(_ data: Data) -> [UInt8] {
        let len = data.count
        var out: [UInt8]
        if len <= 0xff {
            out = [0xc4, UInt8(len)]
        } else if len <= 0xffff {
            out = [0xc5, UInt8((len >> 8) & 0xff), UInt8(len & 0xff)]
        } else {
            out = [
                0xc6,
                UInt8((len >> 24) & 0xff),
                UInt8((len >> 16) & 0xff),
                UInt8((len >>  8) & 0xff),
                UInt8(len & 0xff),
            ]
        }
        out.append(contentsOf: data)
        return out
    }
}

private struct PropagationMsgpackReader {
    private let data: Data
    private var cursor: Int

    init(_ data: Data) {
        self.data = data
        self.cursor = data.startIndex
    }

    var isAtEnd: Bool {
        cursor == data.endIndex
    }

    mutating func readByte() throws -> UInt8 {
        guard cursor < data.endIndex else { throw LXMFRouter.RouterError.invalidMsgpack }
        defer { cursor += 1 }
        return data[cursor]
    }

    mutating func readN(_ count: Int) throws -> Data {
        guard count >= 0, cursor + count <= data.endIndex else {
            throw LXMFRouter.RouterError.invalidMsgpack
        }
        defer { cursor += count }
        return Data(data[cursor..<cursor + count])
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
        for i in 0..<8 {
            v = (v << 8) | UInt64(b[b.startIndex + i])
        }
        return v
    }

    mutating func readArrayHeader() throws -> Int {
        let tag = try readByte()
        switch tag {
        case 0x90...0x9f: return Int(tag & 0x0f)
        case 0xdc: return Int(try readUInt16())
        case 0xdd: return Int(try readUInt32())
        default: throw LXMFRouter.RouterError.invalidMsgpack
        }
    }

    mutating func readFloat64() throws -> Double {
        let tag = try readByte()
        guard tag == 0xcb else { throw LXMFRouter.RouterError.invalidMsgpack }
        return Double(bitPattern: try readUInt64())
    }

    mutating func readBytesOrString() throws -> Data {
        let tag = try readByte()
        switch tag {
        case 0xc4: return try readN(Int(try readByte()))
        case 0xc5: return try readN(Int(try readUInt16()))
        case 0xc6: return try readN(Int(try readUInt32()))
        case 0xa0...0xbf: return try readN(Int(tag & 0x1f))
        case 0xd9: return try readN(Int(try readByte()))
        case 0xda: return try readN(Int(try readUInt16()))
        case 0xdb: return try readN(Int(try readUInt32()))
        default: throw LXMFRouter.RouterError.invalidMsgpack
        }
    }
}
