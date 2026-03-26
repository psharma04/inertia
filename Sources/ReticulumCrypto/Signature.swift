import Foundation
import Sodium

/// Ed25519 signature utilities for Reticulum packet and announce signing.
///
/// Uses libsodium via Swift-Sodium for deterministic RFC 8032 Ed25519,
/// matching Python's `cryptography` library `Ed25519PrivateKey.sign(message)`.
///
/// Apple CryptoKit's `Curve25519.Signing` is intentionally avoided here because
/// its Ed25519 implementation is non-deterministic (randomised nonce), which
/// produces signatures that differ from the Python reference on every call.
public enum Signature {

    public enum SignatureError: Error {
        case invalidSeedLength(Int)
        case signingFailed
    }

    /// Signs `message` with `seed` (32-byte Ed25519 private key seed).
    ///
    /// Returns the 64-byte detached Ed25519 signature.
    /// Signing is deterministic: the same `seed` and `message` always produce
    /// the same output (RFC 8032 §5.1.6).
    ///
    /// - Throws: `SignatureError.invalidSeedLength` if `seed` is not 32 bytes.
    /// - Throws: `SignatureError.signingFailed` if libsodium fails (should not occur).
    public static func sign(_ message: Data, seed: Data) throws -> Data {
        guard seed.count == 32 else {
            throw SignatureError.invalidSeedLength(seed.count)
        }
        let sodium = Sodium()
        guard let kp = sodium.sign.keyPair(seed: Bytes(seed)),
              let sig = sodium.sign.signature(message: Bytes(message), secretKey: kp.secretKey)
        else {
            throw SignatureError.signingFailed
        }
        return Data(sig)
    }

    /// Verifies a detached `signature` over `message` using a 32-byte Ed25519 `publicKeyBytes`.
    ///
    /// Returns `false` rather than throwing on invalid or malformed input.
    public static func verify(
        _ message: Data,
        signature: Data,
        publicKeyBytes: Data
    ) -> Bool {
        let sodium = Sodium()
        return sodium.sign.verify(
            message: Bytes(message),
            publicKey: Bytes(publicKeyBytes),
            signature: Bytes(signature)
        )
    }
}

