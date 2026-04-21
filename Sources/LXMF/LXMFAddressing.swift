import Foundation
import ReticulumCrypto

/// Helpers for LXMF address derivation and recipient-hash resolution.
public enum LXMFAddressing {
    public static let deliveryAppName = "lxmf"
    public static let deliveryAspects = ["delivery"]
    public static let propagationAspects = ["propagation"]

    public static func deliveryNameHash() -> Data {
        Destination.nameHash(appName: deliveryAppName, aspects: deliveryAspects)
    }

    public static func deliveryDestinationHash(identityHash: Data) -> Data {
        Destination.hash(appName: deliveryAppName, aspects: deliveryAspects, identityHash: identityHash)
    }

    public static func propagationNameHash() -> Data {
        Destination.nameHash(appName: deliveryAppName, aspects: propagationAspects)
    }

    public static func propagationDestinationHash(identityHash: Data) -> Data {
        Destination.hash(appName: deliveryAppName, aspects: propagationAspects, identityHash: identityHash)
    }

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
