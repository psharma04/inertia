import Testing
import Foundation
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

    @Test("parses nomadnet:// scheme URI")
    func parsesNomadnetScheme() {
        let address = NomadAddress(raw: "nomadnet://\(sampleHash):/page/about.mu")
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/about.mu")
    }

    @Test("parses nomadnet:// scheme with slash-separated path")
    func parsesNomadnetSchemeSlash() {
        let address = NomadAddress(raw: "nomadnet://\(sampleHash)/page/index.mu")
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/index.mu")
    }

    @Test("parses nomadnet:// scheme with bare hash")
    func parsesNomadnetSchemeBareHash() {
        let address = NomadAddress(raw: "nomadnet://\(sampleHash)")
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/index.mu")
    }

    @Test("resolves bare /page path with default destination")
    func resolvesAbsolutePagePath() {
        let address = NomadAddress(
            raw: "/page/other.mu",
            defaultDestinationHashHex: sampleHash
        )
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/other.mu")
    }

    @Test("resolves file/ relative path with default destination")
    func resolvesRelativeFilePath() {
        let address = NomadAddress(
            raw: "file/data.txt",
            defaultDestinationHashHex: sampleHash
        )
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/file/data.txt")
    }

    @Test("does not resolve http URL as NomadAddress")
    func doesNotResolveHTTP() {
        let address = NomadAddress(raw: "https://example.com")
        #expect(address.destinationHashHex == nil)
    }

    @Test("does not resolve lxmf URL as NomadAddress")
    func doesNotResolveLXMF() {
        let address = NomadAddress(raw: "lxmf://somebase64data")
        #expect(address.destinationHashHex == nil)
    }

    // MARK: - Link URL Resolution (matches NomadBrowserView styledAttributedString logic)

    @Test("resolves different hash link to nomadnet URL")
    func resolvesDifferentHashLink() {
        let otherHash = "47850a3b99243cfb1147e8856bab2691"
        let address = NomadAddress(
            raw: "\(otherHash):/page/index.mu",
            defaultDestinationHashHex: sampleHash
        )
        #expect(address.destinationHashHex == otherHash)
        #expect(address.path == "/page/index.mu")
        // Verify nomadnet:// URL construction works
        let url = URL(string: "nomadnet://\(address.destinationHashHex!)\(address.path)")
        #expect(url != nil)
        #expect(url?.scheme == "nomadnet")
        #expect(url?.host == otherHash)
        #expect(url?.path == "/page/index.mu" || url?.path() == "/page/index.mu")
    }

    @Test("resolves bare path link under current node")
    func resolvesBarePathLinkUnderCurrentNode() {
        let address = NomadAddress(
            raw: "/page/about.mu",
            defaultDestinationHashHex: sampleHash
        )
        #expect(address.destinationHashHex == sampleHash)
        #expect(address.path == "/page/about.mu")
        let url = URL(string: "nomadnet://\(sampleHash)\(address.path)")
        #expect(url?.scheme == "nomadnet")
    }

    @Test("does not construct NomadAddress for path-only link without default hash")
    func pathOnlyWithoutDefaultHash() {
        let address = NomadAddress(raw: "/page/about.mu")
        #expect(address.destinationHashHex == nil)
    }
}
