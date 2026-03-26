import Testing
@testable import NomadNet

@Suite("NomadAddress")
struct NomadAddressTests {
    private let sampleHash = "1e12dc236a05c930bd2c9190a2940ce7"

    @Test("parses canonical hash:/page path")
    func parsesCanonicalHashColonPath() {
        let address = NomadAddress(raw: "\(sampleHash):/page/index.mu")
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/index.mu")
        #expect(address.canonical == "\(sampleHash):/page/index.mu")
    }

    @Test("parses bare hash with default page path")
    func parsesBareHash() {
        let address = NomadAddress(raw: sampleHash)
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/index.mu")
    }

    @Test("parses nn:// hash path")
    func parsesNNScheme() {
        let address = NomadAddress(raw: "nn://\(sampleHash)/page/about.mu")
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/about.mu")
    }

    @Test("resolves local :/page link with default destination")
    func resolvesLocalColonSlashLink() {
        let address = NomadAddress(
            raw: ":/page/index.mu",
            defaultDestinationHashHex: sampleHash
        )
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/index.mu")
    }

    @Test("resolves relative page path with default destination")
    func resolvesRelativePagePath() {
        let address = NomadAddress(
            raw: "page/next.mu",
            defaultDestinationHashHex: sampleHash
        )
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/next.mu")
    }

    @Test("rejects invalid destination hash")
    func rejectsInvalidHash() {
        let address = NomadAddress(raw: "zzzz:/page/index.mu")
        #expect(address.destinationHashHex == nil)
    }
}
