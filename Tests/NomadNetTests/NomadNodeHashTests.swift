import Testing
import Foundation
@testable import NomadNet

@Suite("NomadNode Hashes")
struct NomadNodeHashTests {
    @Test("announceNameHash is SHA-256('nomadnetwork.node')[0:10]")
    func announceNameHashMatchesReference() {
        let expected = Data(hexString: "213e6311bcec54ab4fde")!
        let got = NomadNode.announceNameHash()
        #expect(got == expected)
        #expect(got.count == 10)
    }
}
