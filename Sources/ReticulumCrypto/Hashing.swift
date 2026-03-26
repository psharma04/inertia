import Foundation
import CryptoKit

/// SHA-256 hashing utilities used throughout the Reticulum stack.
public enum Hashing {

    /// Returns the full 32-byte SHA-256 digest of `data`.
    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// Returns the full 64-byte SHA-512 digest of `data`.
    public static func sha512(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    /// Returns the first `length` bytes of the SHA-256 digest of `data`.
    ///
    /// Used for Reticulum identity hashes (length = 16) and destination
    /// hashes (length = 16).
    public static func truncatedHash(_ data: Data, length: Int) -> Data {
        Data(sha256(data).prefix(length))
    }
}
