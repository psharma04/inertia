import Testing
import Foundation
@testable import LXMF
@testable import ReticulumCrypto

@Suite("LXMF Addressing")
struct LXMFAddressingTests {

    @Test("Known destination hash is preserved")
    func keepsKnownDestinationHash() {
        let identityHash = Data(repeating: 0x11, count: 16)
        let destination = LXMFAddressing.deliveryDestinationHash(identityHash: identityHash)

        let resolved = LXMFAddressing.resolveRecipientHash(
            destination,
            knownDestinationHashes: [destination],
            knownIdentityHashes: []
        )

        #expect(resolved == destination)
    }

    @Test("Known identity hash resolves to lxmf.delivery destination")
    func resolvesKnownIdentityHash() {
        let identityHash = Data(repeating: 0x22, count: 16)
        let expectedDestination = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: identityHash
        )

        let resolved = LXMFAddressing.resolveRecipientHash(
            identityHash,
            knownDestinationHashes: [],
            knownIdentityHashes: [identityHash]
        )

        #expect(resolved == expectedDestination)
    }

    @Test("Unknown 16-byte hash remains unchanged")
    func preservesUnknownHash() {
        let unknownHash = Data(repeating: 0x33, count: 16)

        let resolved = LXMFAddressing.resolveRecipientHash(
            unknownHash,
            knownDestinationHashes: [],
            knownIdentityHashes: []
        )

        #expect(resolved == unknownHash)
    }

    @Test("Non-16-byte input remains unchanged")
    func preservesNonStandardLength() {
        let invalidLength = Data(repeating: 0x44, count: 15)

        let resolved = LXMFAddressing.resolveRecipientHash(
            invalidLength,
            knownDestinationHashes: [],
            knownIdentityHashes: []
        )

        #expect(resolved == invalidLength)
    }
}
