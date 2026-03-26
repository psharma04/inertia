import Foundation
import ReticulumCrypto

/// Helpers for LXMF address derivation and recipient-hash resolution.
public enum LXMFAddressing {
    public static let deliveryAppName = "lxmf"
    public static let deliveryAspects = ["delivery"]
    public static let propagationAspects = ["propagation"]

    /// Returns the 10-byte name hash for `lxmf.delivery`.
    public static func deliveryNameHash() -> Data {
        Destination.nameHash(appName: deliveryAppName, aspects: deliveryAspects)
    }

    /// Returns the 16-byte `lxmf.delivery` destination hash for a 16-byte identity hash.
    public static func deliveryDestinationHash(identityHash: Data) -> Data {
        Destination.hash(appName: deliveryAppName, aspects: deliveryAspects, identityHash: identityHash)
    }

    /// Returns the 10-byte name hash for `lxmf.propagation`.
    public static func propagationNameHash() -> Data {
        Destination.nameHash(appName: deliveryAppName, aspects: propagationAspects)
    }

    /// Returns the 16-byte `lxmf.propagation` destination hash for a 16-byte identity hash.
    public static func propagationDestinationHash(identityHash: Data) -> Data {
        Destination.hash(appName: deliveryAppName, aspects: propagationAspects, identityHash: identityHash)
    }

    /// Resolves a user-provided hash to an LXMF destination hash when possible.
    ///
    /// - If `inputHash` is already a known LXMF destination hash, it is returned unchanged.
    /// - If `inputHash` matches a known peer identity hash, it is converted to
    ///   `hash("lxmf.delivery", identityHash)`.
    /// - Otherwise, `inputHash` is returned unchanged.
    public static func resolveRecipientHash(
        _ inputHash: Data,
        knownDestinationHashes: Set<Data>,
        knownIdentityHashes: Set<Data>
    ) -> Data {
        guard inputHash.count == Destination.hashLength else { return inputHash }
        if knownDestinationHashes.contains(inputHash) { return inputHash }
        if knownIdentityHashes.contains(inputHash) {
            return deliveryDestinationHash(identityHash: inputHash)
        }
        return inputHash
    }
}
