import Foundation
import CryptoKit
import Sodium

public enum IdentityError: Error, Equatable {
    case invalidPrivateKeyLength(Int)
    case invalidPublicKeyLength(Int)
    case privateKeyNotAvailable
    case keyDerivationFailed
    case decryptionKeyNotAvailable
}

public struct Identity: Sendable {

    public static let publicKeyLength = 64
    public static let privateKeyLength = 64
    public static let hashLength = 16

    /// Full 64-byte Reticulum wire-format public key: `[X25519 pub (32) | Ed25519 pub (32)]`.
    public let publicKey: Data

    /// `nil` when the identity was constructed from a public key only.
    public let privateKeyData: Data?
    public let privateKeySeed: Data?

    public var hash: Data {
        Hashing.truncatedHash(publicKey, length: Self.hashLength)
    }

    /// Full 32-byte SHA-256 of the public key.
    public var fullHash: Data {
        Hashing.sha256(publicKey)
    }

    public init(privateKey: Data) throws {
        guard privateKey.count == Self.privateKeyLength else {
            throw IdentityError.invalidPrivateKeyLength(privateKey.count)
        }

        let x25519PrvBytes = Data(privateKey[privateKey.startIndex ..< privateKey.startIndex + 32])
        let seed = Data(privateKey[privateKey.startIndex + 32 ..< privateKey.startIndex + 64])

        let x25519PrivKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519PrvBytes)
        let x25519Pub = x25519PrivKey.publicKey.rawRepresentation

        // Derive Ed25519 public key via libsodium (Swift-Sodium).
        // This matches `nacl.signing.SigningKey(seed)` used by Python Reticulum / PyNaCl.
        let sodium = Sodium()
        guard let kp = sodium.sign.keyPair(seed: Bytes(seed)) else {
            throw IdentityError.keyDerivationFailed
        }

        self.privateKeySeed = seed
        self.privateKeyData = privateKey
        self.publicKey = x25519Pub + Data(kp.publicKey)   // 32 + 32 = 64 bytes
    }

    public init(publicKey: Data) throws {
        guard publicKey.count == Self.publicKeyLength else {
            throw IdentityError.invalidPublicKeyLength(publicKey.count)
        }
        self.publicKey = publicKey
        self.privateKeySeed = nil
        self.privateKeyData = nil
    }

    public static func generate() throws -> Identity {
        let x25519Prv = Curve25519.KeyAgreement.PrivateKey()
        let ed25519Seed = SymmetricKey(size: .bits256)

        let privateKeyBytes = x25519Prv.rawRepresentation +
           ed25519Seed.withUnsafeBytes { Data($0) }
        return try Identity(privateKey: privateKeyBytes)
    }

    public func sign(_ message: Data) throws -> Data {
        guard let seed = privateKeySeed else {
            throw IdentityError.privateKeyNotAvailable
        }
        return try Signature.sign(message, seed: seed)
    }

    public func verify(_ message: Data, signature: Data) -> Bool {
        let ed25519Pub = publicKey[publicKey.startIndex + 32 ..< publicKey.startIndex + 64]
        return Signature.verify(message, signature: signature, publicKeyBytes: Data(ed25519Pub))
    }

    public func encrypt(_ data: Data) throws -> Data {
        let recipientX25519PublicKey = Data(publicKey.prefix(32))
        return try ReticulumToken.encrypt(
            data,
            recipientX25519PublicKey: recipientX25519PublicKey,
            identityHash: hash
        )
    }

    public func decrypt(_ data: Data) throws -> Data {
        guard let privateKeyData else {
            throw IdentityError.decryptionKeyNotAvailable
        }
        let recipientX25519PrivateKey = Data(privateKeyData.prefix(32))
        return try ReticulumToken.decrypt(
            data,
            recipientX25519PrivateKey: recipientX25519PrivateKey,
            identityHash: hash
        )
    }
}
