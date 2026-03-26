import Testing
import Foundation
@testable import ReticulumCrypto

@Suite("Identity — Generation Security")
struct IdentityGenerationSecurityTests {

    @Test("Generated identities produce unique private and public keys")
    func generatedIdentitiesAreUnique() throws {
        var seenPrivateKeys = Set<Data>()
        var seenPublicKeys = Set<Data>()
        var seenHashes = Set<Data>()

        for _ in 0..<128 {
            let identity = try Identity.generate()
            let privateKey = try #require(identity.privateKeyData)

            #expect(privateKey.count == Identity.privateKeyLength)
            #expect(identity.publicKey.count == Identity.publicKeyLength)
            #expect(identity.hash.count == Identity.hashLength)

            #expect(seenPrivateKeys.insert(privateKey).inserted)
            #expect(seenPublicKeys.insert(identity.publicKey).inserted)
            #expect(seenHashes.insert(identity.hash).inserted)
        }
    }

    @Test("Regenerated install identity differs from previous identity")
    func regeneratedIdentityChangesKeyMaterial() throws {
        let first = try Identity.generate()
        let second = try Identity.generate()

        let firstPrivate = try #require(first.privateKeyData)
        let secondPrivate = try #require(second.privateKeyData)

        #expect(firstPrivate != secondPrivate)
        #expect(first.publicKey != second.publicKey)
        #expect(first.hash != second.hash)
    }
}
