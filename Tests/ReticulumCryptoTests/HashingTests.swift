import Testing
import Foundation
@testable import ReticulumCrypto

@Suite("Hashing")
struct HashingTests {
    @Test("SHA-256 and SHA-512 outputs match known vectors")
    func knownVectors() {
        let input = Data("abc".utf8)
        let expectedSHA256 = Data(
            hexString: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )!
        let expectedSHA512 = Data(
            hexString: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )!

        #expect(Hashing.sha256(input) == expectedSHA256)
        #expect(Hashing.sha512(input) == expectedSHA512)
    }
}
