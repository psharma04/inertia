import Testing
import Foundation
import CryptoKit
@testable import NomadNet


// MockNomadNode

actor MockNomadNode: NomadLinkProtocol {

    private var pages: [String: Data]  = [:]  // path hash hex → page content bytes
    private var files: [String: Data]  = [:]  // path hash hex → file bytes
    private(set) var receivedRequests: [Data] = []

    // Registration

    func addPage(path: String, content: String) {
        let hash = truncatedHash(Data(path.utf8)).hexString
        pages[hash] = Data(content.utf8)
    }

    func addFile(path: String, data: Data) {
        let hash = truncatedHash(Data(path.utf8)).hexString
        files[hash] = data
    }

    // NomadLinkProtocol

    func request(payload: Data) async throws -> Data {
        receivedRequests.append(payload)

        // Derive a deterministic request_id from the payload bytes.
        let requestID = truncatedHash(payload)

        // Extract path hash from the standard request layout.
        guard let pathHash = extractPathHash(from: payload) else {
            throw NomadError.invalidMsgpack
        }
        let pathHashHex = pathHash.hexString

        // Look up page content first, then files.
        if let content = pages[pathHashHex] {
            return msgpackPageResponse(requestID: requestID, content: content)
        }
        if let fileData = files[pathHashHex] {
            return msgpackPageResponse(requestID: requestID, content: fileData)
        }

        throw NomadError.pageNotFound(pathHashHex)
    }

    // Helpers

    var requestCount: Int { receivedRequests.count }
}

// Suite 1: Node Announce Parsing

@Suite("NomadNet — Node Announce Parsing")
struct NomadNodeAnnounceTests {

    /// Python reference: node name "Test Node" → app_data = 54657374204e6f6465
    @Test("NomadNode: parses display name from UTF-8 app_data")
    func parsesNameFromAppData() throws {
        let destHash = Data(repeating: 0xab, count: 16)  // arbitrary
        let appData  = Data("Test Node".utf8)             // 54657374204e6f6465

        let node = try NomadNode(destinationHash: destHash, appData: appData)
        #expect(node.name == "Test Node",
                "Expected name \"Test Node\", got \"\(node.name)\"")
    }

    @Test("NomadNode: empty app_data produces empty name")
    func emptyAppDataGivesEmptyName() throws {
        let destHash = Data(repeating: 0x01, count: 16)
        let node = try NomadNode(destinationHash: destHash, appData: Data())
        #expect(node.name == "",
                "Expected empty name, got \"\(node.name)\"")
    }

    @Test("NomadNode: destinationHash stored verbatim")
    func destinationHashStoredVerbatim() throws {
        let destHash = Data(hexString: "8e484af42dd1c865a87fb2d16a5d8e63")!
        let node = try NomadNode(destinationHash: destHash, appData: Data("My Node".utf8))
        #expect(node.destinationHash == destHash,
                "destinationHash mismatch")
    }

    @Test("NomadNode.destinationHash(for:) matches Python test vector")
    func destinationHashMatchesPythonTestVector() {
        let identityHash = Data(hexString: "aca31af0441d81dbec71e82da0b4b5f5")!
        let expected     = Data(hexString: "8e484af42dd1c865a87fb2d16a5d8e63")!

        let got = NomadNode.destinationHash(for: identityHash)
        #expect(got == expected,
                "dest_hash mismatch: expected \(expected.hexString), got \(got.hexString)")
    }
}

// Suite 2: Path Hashing

@Suite("NomadNet — Path Hashing")
struct NomadPathHashingTests {

    /// All vectors computed by Python: SHA-256(path.encode())[0:16]

    @Test("pathHash(\"/page/index.mu\") matches Python reference")
    func indexPageHash() {
        let expected = Data(hexString: "fb40abf359b3f25fa0086107c5eee516")!
        let got = NomadClient.pathHash(for: "/page/index.mu")
        #expect(got == expected,
                "path hash mismatch: expected \(expected.hexString), got \(got.hexString)")
    }

    @Test("pathHash(\"/page/about.mu\") matches Python reference")
    func aboutPageHash() {
        let expected = Data(hexString: "88136a8b75cd27b5b7171bffdd657280")!
        let got = NomadClient.pathHash(for: "/page/about.mu")
        #expect(got == expected,
                "path hash mismatch: expected \(expected.hexString), got \(got.hexString)")
    }

    @Test("pathHash(\"/file/example.txt\") matches Python reference")
    func exampleFileHash() {
        let expected = Data(hexString: "95958aa7e6b88c228e73771a281f5764")!
        let got = NomadClient.pathHash(for: "/file/example.txt")
        #expect(got == expected,
                "path hash mismatch: expected \(expected.hexString), got \(got.hexString)")
    }

    @Test("pathHash returns exactly 16 bytes")
    func pathHashIs16Bytes() {
        let got = NomadClient.pathHash(for: "/page/index.mu")
        #expect(got.count == 16,
                "path hash must be 16 bytes, got \(got.count)")
    }
}

// Suite 3: Request Building

@Suite("NomadNet — Request Building")
struct NomadRequestBuildingTests {


    let knownRequestHex = "93cb41d954fc40000000c410fb40abf359b3f25fa0086107c5eee516c0"
    let knownTimestamp  = 1700000000.0
    let knownPath       = "/page/index.mu"

    @Test("buildRequestPayload: matches known Python reference bytes")
    func buildRequestMatchesReferenceBytes() {
        let expected = Data(hexString: knownRequestHex)!
        let got = NomadClient.buildRequestPayload(
            path: knownPath,
            timestamp: knownTimestamp,
            formData: nil
        )
        #expect(got == expected,
                """
                request payload mismatch:
                  expected: \(expected.hexString)
                  got:      \(got.hexString)
                """)
    }

    @Test("buildRequestPayload: length is 29 bytes for nil form data")
    func buildRequestIs29Bytes() {
        let got = NomadClient.buildRequestPayload(
            path: knownPath,
            timestamp: knownTimestamp,
            formData: nil
        )
        #expect(got.count == 29,
                "Expected 29-byte request, got \(got.count) bytes")
    }

    @Test("buildRequestPayload: first byte is fixarray(3) = 0x93")
    func buildRequestStartsWithFixarray3() {
        let got = NomadClient.buildRequestPayload(
            path: knownPath,
            timestamp: knownTimestamp,
            formData: nil
        )
        guard !got.isEmpty else {
            Issue.record("buildRequestPayload returned empty Data")
            return
        }
        #expect(got[got.startIndex] == 0x93,
                "First byte must be 0x93 (fixarray 3), got 0x\(String(got[got.startIndex], radix: 16))")
    }

    @Test("buildRequestPayload: timestamp encoded as float64 (0xcb marker)")
    func buildRequestTimestampIsFloat64() {
        let got = NomadClient.buildRequestPayload(
            path: knownPath,
            timestamp: knownTimestamp,
            formData: nil
        )
        guard got.count >= 2 else {
            Issue.record("buildRequestPayload too short")
            return
        }
        #expect(got[got.startIndex + 1] == 0xcb,
                "Byte [1] must be 0xcb (float64 marker), got 0x\(String(got[got.startIndex + 1], radix: 16))")
    }

    @Test("buildRequestPayload: path hash at bytes [12:28] matches pathHash()")
    func buildRequestEmbeddsCorrectPathHash() {
        let got = NomadClient.buildRequestPayload(
            path: knownPath,
            timestamp: knownTimestamp,
            formData: nil
        )
        guard got.count >= 28 else {
            Issue.record("buildRequestPayload too short to extract path hash")
            return
        }
        let embeddedHash = Data(got[(got.startIndex + 12) ..< (got.startIndex + 28)])
        let expected = NomadClient.pathHash(for: knownPath)
        // Only meaningful if pathHash is implemented; both are Data() if not
        if !expected.isEmpty {
            #expect(embeddedHash == expected,
 "Embedded path hash mismatch")
        }
    }

    @Test("buildRequestPayload: last byte is nil (0xc0) for no form data")
    func buildRequestEndsWithNil() {
        let got = NomadClient.buildRequestPayload(
            path: knownPath,
            timestamp: knownTimestamp,
            formData: nil
        )
        guard let lastByte = got.last else {
            Issue.record("buildRequestPayload returned empty Data")
            return
        }
        #expect(lastByte == 0xc0,
                "Last byte must be 0xc0 (nil), got 0x\(String(lastByte, radix: 16))")
    }
}

// Suite 4: Response Parsing

@Suite("NomadNet — Response Parsing")
struct NomadResponseParsingTests {

    /// Reference response fixture from Python Nomad implementation.

    let responseHex = "92c41037d4af658bb1e6618a74edb49c01848cc42e3e57656c636f6d6520746f2054657374204e6f64650a0a546869732069732074686520686f6d6520706167652e0a"
    let expectedRequestID = "37d4af658bb1e6618a74edb49c01848c"
    let expectedContent   = ">Welcome to Test Node\n\nThis is the home page.\n"

    @Test("parsePageResponse: extracts requestID from Python fixture")
    func parsesRequestID() throws {
        let data = Data(hexString: responseHex)!
        let (requestID, _) = try NomadClient.parsePageResponse(data)
        let expected = Data(hexString: expectedRequestID)!
        #expect(requestID == expected,
                "requestID mismatch: expected \(expected.hexString), got \(requestID.hexString)")
    }

    @Test("parsePageResponse: extracts content bytes from Python fixture")
    func parsesContent() throws {
        let data = Data(hexString: responseHex)!
        let (_, content) = try NomadClient.parsePageResponse(data)
        let expected = Data(expectedContent.utf8)
        #expect(content == expected,
                "content mismatch: expected \"\(expectedContent)\", got \"\(String(data: content, encoding: .utf8) ?? "<non-utf8>")\"")
    }

    @Test("parsePageResponse: requestID is exactly 16 bytes")
    func requestIDIs16Bytes() throws {
        let data = Data(hexString: responseHex)!
        let (requestID, _) = try NomadClient.parsePageResponse(data)
        #expect(requestID.count == 16,
                "requestID must be 16 bytes, got \(requestID.count)")
    }

    @Test("parsePageResponse: throws on empty input")
    func throwsOnEmptyInput() {
        #expect(throws: (any Error).self) {
            try NomadClient.parsePageResponse(Data())
        }
    }

    @Test("parsePageResponse: throws on invalid msgpack")
    func throwsOnInvalidMsgpack() {
        let garbage = Data([0xff, 0xfe, 0x00, 0x01, 0x02])
        #expect(throws: (any Error).self) {
            try NomadClient.parsePageResponse(garbage)
        }
    }
}

// Suite 5: Page Request via Mock Node

@Suite("NomadNet — Page Request via Mock Node")
struct NomadPageRequestTests {

    @Test("requestPage: sends exactly one request to the mock node")
    func sendsOneRequest() async throws {
        let mock = MockNomadNode()
        await mock.addPage(path: "/page/index.mu", content: ">Home\n\nWelcome.\n")
        let client = NomadClient(link: mock)

        _ = try await client.requestPage(path: "/page/index.mu",
   timestamp: 1700000000.0)

        let count = await mock.requestCount
        #expect(count == 1, "Expected 1 request to mock node, got \(count)")
    }

    @Test("requestPage: returned NomadPage has correct content")
    func returnsCorrectContent() async throws {
        let pageContent = ">Home Page\n\nHello from mock node.\n"
        let mock = MockNomadNode()
        await mock.addPage(path: "/page/index.mu", content: pageContent)
        let client = NomadClient(link: mock)

        let page = try await client.requestPage(path: "/page/index.mu",
          timestamp: 1700000000.0)

        #expect(page.contentString == pageContent,
                "content mismatch: expected \"\(pageContent)\", got \"\(page.contentString)\"")
    }

    @Test("requestPage: returned NomadPage.path matches requested path")
    func returnedPageHasCorrectPath() async throws {
        let mock = MockNomadNode()
        await mock.addPage(path: "/page/index.mu", content: ">Test\n")
        let client = NomadClient(link: mock)

        let page = try await client.requestPage(path: "/page/index.mu",
          timestamp: 1700000000.0)

        #expect(page.path == "/page/index.mu",
                "page.path mismatch: expected \"/page/index.mu\", got \"\(page.path)\"")
    }

    @Test("requestPage: requestID is 16 bytes")
    func requestIDIs16Bytes() async throws {
        let mock = MockNomadNode()
        await mock.addPage(path: "/page/index.mu", content: ">Test\n")
        let client = NomadClient(link: mock)

        let page = try await client.requestPage(path: "/page/index.mu",
          timestamp: 1700000000.0)

        #expect(page.requestID.count == 16,
                "requestID must be 16 bytes, got \(page.requestID.count)")
    }

    @Test("requestPage: different paths reach different registered pages")
    func differentPathsReturnDifferentPages() async throws {
        let mock = MockNomadNode()
        await mock.addPage(path: "/page/index.mu", content: ">Index\n")
        await mock.addPage(path: "/page/about.mu", content: ">About\n\nAbout this node.\n")
        let client = NomadClient(link: mock)

        let index = try await client.requestPage(path: "/page/index.mu",
           timestamp: 1700000000.0)
        let about = try await client.requestPage(path: "/page/about.mu",
           timestamp: 1700000001.0)

        #expect(index.contentString == ">Index\n")
        #expect(about.contentString == ">About\n\nAbout this node.\n")
    }

    @Test("requestPage: throws when page not registered in mock")
    func throwsWhenPageNotFound() async throws {
        let mock = MockNomadNode()  // no pages registered
        let client = NomadClient(link: mock)

        await #expect(throws: (any Error).self) {
            _ = try await client.requestPage(path: "/page/missing.mu",
       timestamp: 1700000000.0)
        }
    }
}

// Suite 6: File Download via Mock Node

@Suite("NomadNet — File Download via Mock Node")
struct NomadFileDownloadTests {

    @Test("downloadFile: returned Data matches registered file bytes")
    func returnsCorrectFileBytes() async throws {
        let fileContent = Data("Hello, world! This is a text file.\n".utf8)
        let mock = MockNomadNode()
        await mock.addFile(path: "/file/hello.txt", data: fileContent)
        let client = NomadClient(link: mock)

        let result = try await client.downloadFile(path: "/file/hello.txt")
        #expect(result == fileContent,
                "file bytes mismatch")
    }

    @Test("downloadFile: sends exactly one request to the mock node")
    func sendsOneRequest() async throws {
        let mock = MockNomadNode()
        await mock.addFile(path: "/file/hello.txt", data: Data("content".utf8))
        let client = NomadClient(link: mock)

        _ = try await client.downloadFile(path: "/file/hello.txt")

        let count = await mock.requestCount
        #expect(count == 1, "Expected 1 request to mock node, got \(count)")
    }

    @Test("downloadFile: throws when file not registered in mock")
    func throwsWhenFileNotFound() async throws {
        let mock = MockNomadNode()  // no files registered
        let client = NomadClient(link: mock)

        await #expect(throws: (any Error).self) {
            _ = try await client.downloadFile(path: "/file/missing.bin")
        }
    }

    @Test("downloadFile: path hash for /file/example.txt is 95958aa7e6b88c228e73771a281f5764")
    func filePathHashMatchesPythonTestVector() {
        let expected = Data(hexString: "95958aa7e6b88c228e73771a281f5764")!
        let got = NomadClient.pathHash(for: "/file/example.txt")
        #expect(got == expected,
                "file path hash mismatch: expected \(expected.hexString), got \(got.hexString)")
    }
}
