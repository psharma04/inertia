import Foundation

// Destination

/// A Reticulum destination identified by a truncated SHA-256 hash.
///
/// ## Hash algorithm (matches Python `RNS.Destination` exactly)
///
/// **Stage 1 — name hash** (10 bytes, identity-independent):
/// ```
/// name_hash = SHA-256("<app_name>.<aspect>…".utf8)[0:10]
/// ```
///
/// **Stage 2 — destination hash** (16 bytes):
/// ```
/// // SINGLE — tied to a specific identity
/// destination_hash = SHA-256(name_hash || identity.hash)[0:16]
///
/// // PLAIN — no identity
/// destination_hash = SHA-256(name_hash)[0:16]
/// ```
///
/// This two-stage construction is why the name hash and the destination hash
/// for PLAIN destinations are NOT simply different-length truncations of the
/// same SHA-256 digest: the destination hash is a *second* SHA-256 over the
/// already-truncated name hash bytes.
public struct Destination: Sendable {

    // Constants

    /// Byte length of the destination hash used in Reticulum packet headers.
    public static let hashLength     = 16   // 128 bits

    /// Byte length of the name hash (app name + aspects only, no identity).
    public static let nameHashLength = 10   // 80 bits

    // Stored properties

    /// 16-byte destination hash for packet-header addressing.
    public let hash: Data

    /// Human-readable full destination name.
    ///
    /// - SINGLE: `"<app>.<aspect>….<identity_hash_hex>"`
    /// - PLAIN:  `"<app>.<aspect>…"`
    public let name: String

    /// 10-byte name hash derived from app name and aspects only.
    ///
    /// This value is identity-independent: two SINGLE destinations with the
    /// same `appName` and `aspects` but different identities share the same
    /// `nameHash`.
    public let nameHash: Data

    // Initialisers

    /// Creates a Destination from an explicit identity hash (SINGLE) or
    /// without one (PLAIN).
    ///
    /// - Parameters:
    ///   - appName:      Application name (e.g. `"inertia"`).
    ///   - aspects:      One or more path components (e.g. `["test"]`).
    ///   - identityHash: 16-byte identity hash for SINGLE; `nil` for PLAIN.
    public init(appName: String, aspects: [String], identityHash: Data?) {
        self.nameHash = Self.nameHash(appName: appName, aspects: aspects)
        self.name     = Self.fullName(appName: appName, aspects: aspects, identityHash: identityHash)
        self.hash     = Self.hash(appName: appName, aspects: aspects, identityHash: identityHash)
    }

    /// Creates a SINGLE Destination from an `Identity` struct.
    ///
    /// Uses `identity.hash` (the 16-byte truncated SHA-256 of the identity's
    /// composite public key) as the identity component of the destination hash.
    public init(appName: String, aspects: [String], identity: Identity) {
        self.init(appName: appName, aspects: aspects, identityHash: identity.hash)
    }

    // Static helpers

    /// Returns the 16-byte destination hash.
    ///
    /// Matches `RNS.Destination.hash_from_name_and_identity` in the Python
    /// reference implementation.
    ///
    /// - Parameters:
    ///   - appName:      Application name.
    ///   - aspects:      One or more path components.
    ///   - identityHash: 16-byte identity hash, or `nil` for PLAIN.
    public static func hash(appName: String, aspects: [String], identityHash: Data?) -> Data {
        let nh = nameHash(appName: appName, aspects: aspects)
        let material: Data = identityHash.map { nh + $0 } ?? nh
        return Hashing.truncatedHash(material, length: hashLength)
    }

    /// Returns the full destination name string.
    ///
    /// - SINGLE: `"<app>.<aspect>….<identity_hash_hex>"`
    /// - PLAIN:  `"<app>.<aspect>…"`
    ///
    /// The identity hash is encoded as a lowercase hex string, matching
    /// `RNS.hexrep(identity.hash, delimit=False)` in the Python reference.
    public static func fullName(appName: String, aspects: [String], identityHash: Data?) -> String {
        var parts = [appName] + aspects
        if let ih = identityHash {
            parts.append(ih.map { String(format: "%02x", $0) }.joined())
        }
        return parts.joined(separator: ".")
    }

    /// Returns the 10-byte name hash derived from app name and aspects only.
    ///
    /// The name hash is computed as `SHA-256("<app>.<aspects>".utf8)[0:10]`
    /// and is independent of the identity.
    public static func nameHash(appName: String, aspects: [String]) -> Data {
        let baseName = ([appName] + aspects).joined(separator: ".")
        return Hashing.truncatedHash(Data(baseName.utf8), length: nameHashLength)
    }
}
