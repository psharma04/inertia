import Foundation
import CryptoKit
import Sodium

// Errors

/// Errors thrown when constructing or using a Reticulum `Identity`.
public enum IdentityError: Error, Equatable {
    /// The supplied private key was not exactly 64 bytes.
    case invalidPrivateKeyLength(Int)
    /// The supplied public key was not exactly 64 bytes.
    case invalidPublicKeyLength(Int)
    /// A signing operation was attempted without a private key.
    case privateKeyNotAvailable
    /// libsodium failed to derive a keypair from the supplied seed.
    case keyDerivationFailed
    /// Decryption was attempted on a public-only identity.
    case decryptionKeyNotAvailable
}

// Identity

/// A Reticulum identity holding an X25519 key-exchange pair and an Ed25519
/// signing pair.
///
/// ## Wire layout (all multi-byte values big-endian)
///
/// **Private key** (64 bytes):
/// ```
/// [0 : 32]  X25519 private key
/// [32: 64]  Ed25519 private key seed
/// ```
///
/// **Public key** (64 bytes):
/// ```
/// [0 : 32]  X25519 public key
/// [32: 64]  Ed25519 public key
/// ```
///
/// **Identity hash** (16 bytes):
/// ```
/// SHA-256(publicKey)[0:16]
/// ```
///
/// This layout is byte-compatible with `RNS.Identity` in the Python
/// reference implementation.
public struct Identity: Sendable {

    // Constants

    /// Length of the concatenated public key in bytes.
    public static let publicKeyLength  = 64
    /// Length of the concatenated private key in bytes.
    public static let privateKeyLength = 64
    /// Length of the identity hash in bytes.
    public static let hashLength       = 16

    // Stored properties

    /// Full 64-byte Reticulum wire-format public key: `[X25519 pub (32) | Ed25519 pub (32)]`.
    public let publicKey: Data

    /// Full 64-byte private key `[X25519 prv (32) | Ed25519 seed (32)]`.
    /// `nil` when the identity was constructed from a public key only.
    public let privateKeyData: Data?

    /// 32-byte Ed25519 private key seed (libsodium `sign.keyPair(seed:)` input).
    /// `nil` when the identity was constructed from a public key only.
    public let privateKeySeed: Data?

    // Derived properties

    /// 16-byte identity hash: `SHA-256(publicKey)[0:16]`.
    ///
    /// `publicKey` is the full 64-byte Reticulum composite key, matching
    /// `RNS.Identity` in the Python reference implementation.
    public var hash: Data {
        Hashing.truncatedHash(publicKey, length: Self.hashLength)
    }

    /// Full 32-byte SHA-256 of the public key.
    public var fullHash: Data {
        Hashing.sha256(publicKey)
    }

    // Initialisers

    /// Creates an identity from a 64-byte Reticulum private key.
    ///
    /// Layout: `[X25519 prv (32) | Ed25519 seed (32)]`
    ///
    /// - The X25519 public key is derived via CryptoKit (raw format is
    ///   identical to libsodium's `crypto_box` key format).
    /// - The Ed25519 public key is derived via libsodium (`sign.keyPair(seed:)`),
    ///   guaranteeing byte-identical output to PyNaCl / Python Reticulum.
    ///
    /// - Parameter privateKey: 64-byte key: `[X25519 prv (32) | Ed25519 seed (32)]`
    /// - Throws: `IdentityError.invalidPrivateKeyLength` if `privateKey.count ≠ 64`
    /// - Throws: `IdentityError.keyDerivationFailed` if libsodium rejects the seed.
    public init(privateKey: Data) throws {
        guard privateKey.count == Self.privateKeyLength else {
            throw IdentityError.invalidPrivateKeyLength(privateKey.count)
        }

        let x25519PrvBytes = Data(privateKey[privateKey.startIndex ..< privateKey.startIndex + 32])
        let seed           = Data(privateKey[privateKey.startIndex + 32 ..< privateKey.startIndex + 64])

        // Derive X25519 public key.
        // CryptoKit's Curve25519.KeyAgreement uses the same raw key format as
        // libsodium's crypto_box, so output is wire-compatible.
        let x25519PrivKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519PrvBytes)
        let x25519Pub     = x25519PrivKey.publicKey.rawRepresentation

        // Derive Ed25519 public key via libsodium (Swift-Sodium).
        // This matches `nacl.signing.SigningKey(seed)` used by Python Reticulum / PyNaCl.
        let sodium = Sodium()
        guard let kp = sodium.sign.keyPair(seed: Bytes(seed)) else {
            throw IdentityError.keyDerivationFailed
        }

        self.privateKeySeed = seed
        self.privateKeyData = privateKey
        self.publicKey      = x25519Pub + Data(kp.publicKey)   // 32 + 32 = 64 bytes
    }

    /// Creates a verification-only identity from a 64-byte Reticulum public key.
    ///
    /// - Parameter publicKey: 64-byte key: `[X25519 pub (32) | Ed25519 pub (32)]`
    /// - Throws: `IdentityError.invalidPublicKeyLength` if `publicKey.count ≠ 64`
    public init(publicKey: Data) throws {
        guard publicKey.count == Self.publicKeyLength else {
            throw IdentityError.invalidPublicKeyLength(publicKey.count)
        }
        self.publicKey      = publicKey
        self.privateKeySeed = nil
        self.privateKeyData = nil
    }

    // Generation

    /// Generate a fresh random Identity.
    ///
    /// Produces a new 64-byte private key from cryptographically secure random
    /// bytes (32 bytes X25519 + 32 bytes Ed25519 seed) and derives the
    /// corresponding public key pair.
    public static func generate() throws -> Identity {
        // Generate 32 cryptographically random bytes for each key component.
        // CryptoKit's key initialiser uses SecRandomCopyBytes internally, which
        // is the correct source of randomness on Apple platforms.
        let x25519Prv = Curve25519.KeyAgreement.PrivateKey()
        let ed25519Seed = SymmetricKey(size: .bits256)

        let privateKeyBytes = x25519Prv.rawRepresentation +
           ed25519Seed.withUnsafeBytes { Data($0) }
        return try Identity(privateKey: privateKeyBytes)
    }

    // Signing

    /// Signs `message` with this identity's Ed25519 private key seed.
    ///
    /// Delegates to `Signature.sign(_:seed:)` which uses libsodium for
    /// deterministic RFC 8032 signing, byte-identical to Python Reticulum.
    ///
    /// - Returns: 64-byte Ed25519 signature.
    /// - Throws: `IdentityError.privateKeyNotAvailable` if constructed from
    ///   a public key only.
    public func sign(_ message: Data) throws -> Data {
        guard let seed = privateKeySeed else {
            throw IdentityError.privateKeyNotAvailable
        }
        return try Signature.sign(message, seed: seed)
    }

    // Verification

    /// Verifies an Ed25519 `signature` over `message` using this identity's
    /// Ed25519 public key (bytes 32–63 of `publicKey`).
    ///
    /// - Returns: `true` if the signature is valid; `false` otherwise.
    public func verify(_ message: Data, signature: Data) -> Bool {
        let ed25519Pub = publicKey[publicKey.startIndex + 32 ..< publicKey.startIndex + 64]
        return Signature.verify(message, signature: signature, publicKeyBytes: Data(ed25519Pub))
    }

    // Reticulum token encryption/decryption

    /// Encrypt data for this identity using the Reticulum token format.
    ///
    /// Equivalent to the working implementation in `inertia-original`:
    /// - X25519 ECDH with recipient public key
    /// - HKDF-SHA256 with `identity.hash` as salt
    /// - AES-256-CBC + HMAC-SHA256 token, prefixed with ephemeral public key
    public func encrypt(_ data: Data) throws -> Data {
        let recipientX25519PublicKey = Data(publicKey.prefix(32))
        return try ReticulumToken.encrypt(
            data,
            recipientX25519PublicKey: recipientX25519PublicKey,
            identityHash: hash
        )
    }

    /// Decrypt data addressed to this identity in Reticulum token format.
    ///
    /// Requires a private key and mirrors `inertia-original` decryption flow.
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
