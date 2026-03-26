import Testing
import Foundation
@testable import NomadNet

private actor ClaimsNomadLink: NomadLinkProtocol {
    let response: Data
    private(set) var payloads: [Data] = []

    init(response: Data) {
        self.response = response
    }

    func request(payload: Data) async throws -> Data {
        payloads.append(payload)
        return response
    }
}

@Suite("Reticulum Claims — Request/Response")
struct NomadClaimsTests {

    @Test("Nomad request/response API is structured and deterministic")
    func requestResponseRoundTrip() async throws {
        let requestID = Data(repeating: 0x44, count: 16)
        let content = Data("Hello Nomad".utf8)
        let response = Data([0x92, 0xc4, 0x10]) + requestID + Data([0xc4, UInt8(content.count)]) + content

        let link = ClaimsNomadLink(response: response)
        let client = NomadClient(link: link)
        let page = try await client.requestPage(path: "/page/index.mu", timestamp: 1_700_000_000.0)

        #expect(page.requestID == requestID)
        #expect(page.content == content)

        let sent = await link.payloads
        #expect(sent.count == 1)
        #expect(sent[0].count == 29)
        #expect(sent[0][sent[0].startIndex] == 0x93) // request is msgpack array of 3
    }

    @Test("Path hashing is deterministic and 16 bytes")
    func pathHashDeterministic() {
        let first = NomadClient.pathHash(for: "/page/index.mu")
        let second = NomadClient.pathHash(for: "/page/index.mu")

        #expect(first.count == 16)
        #expect(first == second)
    }
}
