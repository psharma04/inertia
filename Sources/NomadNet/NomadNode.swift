import Foundation
import ReticulumCrypto

// NomadNode

/// Represents a Nomad Network node discovered via Reticulum announce.
///
/// Announce wire format:
///   destination: SINGLE IN, "nomadnetwork", "node"
///   app_data:    raw UTF-8 bytes of the node display name (no length prefix)
///
/// Destination hash derivation:
///   name_hash   = SHA-256("nomadnetwork.node")[0:16]
///   name_hash10 = name_hash[0:10]
///   dest_hash   = SHA-256(name_hash10 + identity_hash)[0:16]
///
/// Test vector:
///   identity_hash = aca31af0441d81dbec71e82da0b4b5f5
///   dest_hash     = 8e484af42dd1c865a87fb2d16a5d8e63
public struct NomadNode: Sendable {

    /// 16-byte destination hash of the nomadnetwork.node destination.
    public let destinationHash: Data

    /// Display name of the node, decoded from the announce app_data (raw UTF-8).
    public let name: String

    // Initialiser

    /// Construct a NomadNode from a received announce.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash from the announce source.
    ///   - appData: Raw UTF-8 bytes of the node name from announce app_data.
    public init(destinationHash: Data, appData: Data) throws {
        self.destinationHash = destinationHash
        self.name = String(data: appData, encoding: .utf8) ?? ""
    }

    // Destination hash derivation

    /// Compute the nomadnetwork.node destination hash for a given identity hash.
    ///
    /// Algorithm (matching Python RNS destination hashing):
    ///   name_hash   = SHA-256("nomadnetwork.node")[0:16]
    ///   name_hash10 = name_hash[0:10]
    ///   dest_hash   = SHA-256(name_hash10 + identity_hash)[0:16]
    ///
    /// - Parameter identityHash: 16-byte RNS identity hash.
    /// - Returns: 16-byte destination hash.
    public static func destinationHash(for identityHash: Data) -> Data {
        let nameHash10 = announceNameHash()
        return Hashing.truncatedHash(nameHash10 + identityHash, length: 16)
    }

    /// 10-byte announce name-hash for the `nomadnetwork.node` destination.
    ///
    /// Equivalent to:
    ///   SHA-256("nomadnetwork.node")[0:10]
    public static func announceNameHash() -> Data {
        Data(Hashing.sha256(Data("nomadnetwork.node".utf8)).prefix(10))
    }
}
