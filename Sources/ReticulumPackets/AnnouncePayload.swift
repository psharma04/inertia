import Foundation
import ReticulumCrypto

public struct AnnouncePayload: Sendable {

    public static let publicKeyLength = 64
    public static let nameHashLength = 10
    public static let randomHashLength = 10
    public static let signatureLength = 64
    public static let minimumLength = publicKeyLength + nameHashLength + randomHashLength + signatureLength

    /// Full 64-byte Reticulum public key: `[X25519 pub (32) | Ed25519 pub (32)]`.
    public var identityPublicKey: Data
    public var nameHash: Data
    public var randomHash: Data
    public var ratchetKey: Data?
    public var signature: Data
    public var appData: Data

    public init(
        identityPublicKey: Data,
        nameHash: Data,
        randomHash: Data,
        signature: Data,
        appData: Data = Data(),
        ratchetKey: Data? = nil
    ) {
        self.identityPublicKey = identityPublicKey
        self.nameHash = nameHash
        self.randomHash = randomHash
        self.signature = signature
        self.appData = appData
        self.ratchetKey = ratchetKey
    }

    public static func parse(from data: Data, hasRatchet: Bool = false) throws -> AnnouncePayload {
        let ratchetLength  = hasRatchet ? 32 : 0
        let requiredLength = minimumLength + ratchetLength
        guard data.count >= requiredLength else {
            throw AnnouncePayloadError.tooShort(data.count)
        }

        let base = data.startIndex

        let identityPublicKey = Data(data[base ..< base + publicKeyLength])
        let nameHash = Data(data[base + publicKeyLength ..< base + publicKeyLength + nameHashLength])
        let randomHashStart = publicKeyLength + nameHashLength
        let randomHash = Data(data[base + randomHashStart ..< base + randomHashStart + randomHashLength])

        var offset = randomHashStart + randomHashLength
        var ratchetKey: Data? = nil
        if hasRatchet {
            ratchetKey = Data(data[base + offset ..< base + offset + 32])
            offset    += 32
        }

        let signature = Data(data[base + offset ..< base + offset + signatureLength])
        offset += signatureLength

        let appData = (base + offset) < data.endIndex
 ? Data(data[(base + offset)...])
 : Data()
        return AnnouncePayload(
            identityPublicKey: identityPublicKey,
            nameHash: nameHash,
            randomHash: randomHash,
            signature: signature,
            appData: appData,
            ratchetKey: ratchetKey
        )
    }

    public func signedData(destinationHash: Data) -> Data {
        var data = destinationHash
        data.append(identityPublicKey)
        data.append(nameHash)
        data.append(randomHash)
        if let rk = ratchetKey { data.append(rk) }
        if !appData.isEmpty {
            data.append(appData)
        }
        return data
    }

    public func verifySignature(destinationHash: Data) -> Bool {
        guard identityPublicKey.count == Self.publicKeyLength else { return false }
        let ed25519Pub = Data(identityPublicKey.suffix(32))
        let message = signedData(destinationHash: destinationHash)
        return Signature.verify(message, signature: signature, publicKeyBytes: ed25519Pub)
    }
}

public enum AnnouncePayloadError: Error, Equatable {
    case tooShort(Int)
}
