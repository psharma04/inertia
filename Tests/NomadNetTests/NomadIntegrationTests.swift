import Testing
import Foundation
@testable import NomadNet


// MARK: - Suite 1: Full Round-Trip (Client → Server → Client)

@Suite("NomadNet — Full Round-Trip")
struct NomadRoundTripIntegrationTests {

    /// Create a temp directory with pages and files, wire up a NomadNodeServer,
    /// feed client requests through it, and verify the parsed responses.
    @Test("round-trip: client request → server → parsed response")
    func fullRoundTrip() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nomad_integration_\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let server = NomadNodeServer(storageDir: tmpDir, nodeName: "Integration Test Node")
        try await server.ensureDirectories()

        let pageContent = """
        >Welcome to Integration Test
        
        This is a test page served by the Swift NomadNodeServer.
        
        `!Bold text`! and `*italic text`* here.
        """
        try await server.registerPage(path: "/page/index.mu", content: Data(pageContent.utf8))

        // Build a client request
        let requestPayload = NomadClient.buildRequestPayload(
            path: "/page/index.mu",
            timestamp: Date().timeIntervalSince1970,
            formData: nil
        )

        // Feed through server
        let responsePayload = try await server.handleRequest(requestPayload)

        // Parse the response
        let (requestID, content) = try NomadClient.parsePageResponse(responsePayload)
        #expect(requestID.count == 16, "requestID must be 16 bytes")
        #expect(content == Data(pageContent.utf8), "content must match original page")

        // Verify statistics
        let pageCount = await server.servedPageRequests
        #expect(pageCount == 1)
    }

    @Test("round-trip: file request returns raw bytes")
    func fileRoundTrip() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nomad_integration_\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let server = NomadNodeServer(storageDir: tmpDir, nodeName: "File Test Node")
        try await server.ensureDirectories()

        let fileBytes = Data([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])  // PNG header
        try await server.registerFile(path: "/file/test.png", content: fileBytes)

        let requestPayload = NomadClient.buildRequestPayload(
            path: "/file/test.png",
            timestamp: Date().timeIntervalSince1970,
            formData: nil
        )
        let responsePayload = try await server.handleRequest(requestPayload)
        let (_, content) = try NomadClient.parsePageResponse(responsePayload)
        #expect(content == fileBytes, "file bytes must match")

        let fileCount = await server.servedFileRequests
        #expect(fileCount == 1)
    }

    @Test("round-trip: form data is parsed correctly on server side")
    func formDataRoundTrip() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nomad_integration_\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let server = NomadNodeServer(storageDir: tmpDir, nodeName: "Form Test Node")
        try await server.ensureDirectories()

        let pageContent = ">Form Page\nThis page has form fields."
        try await server.registerPage(path: "/page/form.mu", content: Data(pageContent.utf8))

        // Build request with form data
        let formData = ["field_username": "testuser", "field_message": "hello"]
        let requestPayload = NomadClient.buildRequestPayload(
            path: "/page/form.mu",
            timestamp: Date().timeIntervalSince1970,
            formData: formData
        )

        // Verify the request can be parsed back
        let (_, pathHash, parsedForm) = try NomadClient.parsePageRequest(requestPayload)
        #expect(pathHash == NomadClient.pathHash(for: "/page/form.mu"))
        #expect(parsedForm?["field_username"] == "testuser")
        #expect(parsedForm?["field_message"] == "hello")

        // Feed through server — should still serve the page
        let responsePayload = try await server.handleRequest(requestPayload)
        let (_, content) = try NomadClient.parsePageResponse(responsePayload)
        #expect(content == Data(pageContent.utf8))
    }

    @Test("round-trip: unknown path returns error page")
    func unknownPathReturnsError() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nomad_integration_\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let server = NomadNodeServer(storageDir: tmpDir, nodeName: "Error Test Node")
        try await server.ensureDirectories()

        let requestPayload = NomadClient.buildRequestPayload(
            path: "/page/nonexistent.mu",
            timestamp: Date().timeIntervalSince1970,
            formData: nil
        )
        let responsePayload = try await server.handleRequest(requestPayload)
        let (_, content) = try NomadClient.parsePageResponse(responsePayload)
        let contentStr = String(data: content, encoding: .utf8) ?? ""
        #expect(contentStr.contains("Not Found"), "error page should mention not found")
    }

    @Test("round-trip: access denied for restricted page")
    func accessDeniedRoundTrip() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nomad_integration_\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let server = NomadNodeServer(storageDir: tmpDir, nodeName: "ACL Test Node")
        try await server.ensureDirectories()

        // Create restricted page
        let pageContent = ">Secret Page\nThis is restricted."
        try await server.registerPage(path: "/page/secret.mu", content: Data(pageContent.utf8))

        // Create .allowed file allowing only one identity
        let allowedContent = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1\n"
        let allowedURL = tmpDir.appendingPathComponent("pages/secret.mu.allowed")
        try allowedContent.write(to: allowedURL, atomically: true, encoding: .utf8)

        let requestPayload = NomadClient.buildRequestPayload(
            path: "/page/secret.mu",
            timestamp: Date().timeIntervalSince1970,
            formData: nil
        )

        // Request with unauthorized identity
        let responsePayload = try await server.handleRequest(
            requestPayload,
            remoteIdentityHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        let (_, content) = try NomadClient.parsePageResponse(responsePayload)
        let contentStr = String(data: content, encoding: .utf8) ?? ""
        #expect(contentStr.contains("Access Denied"), "should return access denied page")

        // Request with authorized identity
        let responsePayload2 = try await server.handleRequest(
            requestPayload,
            remoteIdentityHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
        )
        let (_, content2) = try NomadClient.parsePageResponse(responsePayload2)
        #expect(content2 == Data(pageContent.utf8), "authorized request should get the page")
    }
}

// MARK: - Suite 2: Live Test Page Parsing

@Suite("NomadNet — Live Test Page Parsing")
struct NomadLivePageParsingTests {

    static let testPageContent = """
    -
    <
    `c`!Inertia`!
    An Reticulum client for iOS and MacOS
    <
    -

    `l`

    App coming soon.

    Contact `F3d3@pepsi:inyourair.space`f on Matrix for progress updates, or message in `F3d3#reticulum:matrix.org`f.

    Via LXMF, contact `F3d33662d822203188617b2e44f2908b0bb3`f.

    > RNS Services

    >> TCP Server Interface

    Try `F07f`_rns.inertia.chat:4242`_`f as a TCP Client Interface.

    >> Propagation Node

    Try `_4c59456b269469fb44bc62c125e8db36`_ as a propagation node.

    The propagation node has a message size limit of 256 kilobytes.
    """

    @Test("live page: Micron parser produces correct block count")
    func livePageBlockCount() {
        let doc = MicronParser.parse(Self.testPageContent)
        // Should have headings, dividers, text lines
        #expect(doc.blocks.count > 15, "Expected many blocks from the test page, got \(doc.blocks.count)")
    }

    @Test("live page: detects dividers")
    func livePageDividers() {
        let doc = MicronParser.parse(Self.testPageContent)
        let dividers = doc.blocks.filter {
            if case .divider = $0 { return true }
            return false
        }
        #expect(dividers.count >= 2, "Expected at least 2 dividers")
    }

    @Test("live page: detects headings")
    func livePageHeadings() {
        let doc = MicronParser.parse(Self.testPageContent)
        let headings = doc.blocks.compactMap { block -> (Int, String)? in
            if case let .heading(level, line) = block {
                return (level, line.plainText)
            }
            return nil
        }
        #expect(headings.count >= 3, "Expected at least 3 headings")

        let h1 = headings.first { $0.0 == 1 }
        #expect(h1?.1.contains("RNS Services") == true, "Should have 'RNS Services' heading")

        let h2s = headings.filter { $0.0 == 2 }
        #expect(h2s.count >= 2, "Expected at least 2 level-2 headings")
    }

    @Test("live page: detects bold formatting in 'Inertia' title")
    func livePageBoldTitle() {
        let doc = MicronParser.parse(Self.testPageContent)

        // Find a line that contains "Inertia" with bold formatting
        let inertiaBlock = doc.blocks.first { block in
            if case let .line(line) = block {
                return line.inlines.contains { inline in
                    if case let .text(text, style: style) = inline {
                        return text.contains("Inertia") && style.bold
                    }
                    return false
                }
            }
            return false
        }
        #expect(inertiaBlock != nil, "Should find bold 'Inertia' text")
    }

    @Test("live page: detects center alignment")
    func livePageCenterAlignment() {
        let doc = MicronParser.parse(Self.testPageContent)
        let centerLines = doc.blocks.filter { block in
            if case let .line(line) = block {
                return line.alignment == .center
            }
            return false
        }
        #expect(!centerLines.isEmpty, "Expected at least one center-aligned line")
    }

    @Test("live page: detects left alignment")
    func livePageLeftAlignment() {
        let doc = MicronParser.parse(Self.testPageContent)
        let leftLines = doc.blocks.filter { block in
            if case let .line(line) = block {
                return line.alignment == .left
            }
            return false
        }
        #expect(!leftLines.isEmpty, "Expected at least one left-aligned line")
    }

    @Test("live page: detects colored text")
    func livePageColoredText() {
        let doc = MicronParser.parse(Self.testPageContent)
        let coloredLines = doc.blocks.filter { block in
            if case let .line(line) = block {
                return line.inlines.contains { inline in
                    inline.style.foreground != nil
                }
            }
            return false
        }
        #expect(coloredLines.count >= 3, "Expected multiple lines with colored text")
    }

    @Test("live page: detects underlined text")
    func livePageUnderlinedText() {
        let doc = MicronParser.parse(Self.testPageContent)
        let underlinedInlines = doc.blocks.flatMap { block -> [MicronInline] in
            switch block {
            case let .line(line): return line.inlines
            case let .heading(_, line): return line.inlines
            case .divider: return []
            }
        }.filter { $0.style.underline }
        #expect(!underlinedInlines.isEmpty, "Expected underlined text in page")
    }

    @Test("live page: section depth resets with '<'")
    func livePageSectionDepthReset() {
        let doc = MicronParser.parse(Self.testPageContent)
        // After a `<` line, subsequent lines should have sectionDepth = 0
        var foundResetLine = false
        for block in doc.blocks {
            if case let .line(line) = block, line.sectionDepth == 0, !line.plainText.isEmpty {
                foundResetLine = true
                break
            }
        }
        #expect(foundResetLine, "Should have lines at section depth 0 after reset")
    }

    @Test("live page: full plaintext extraction")
    func livePagePlainText() {
        let doc = MicronParser.parse(Self.testPageContent)
        let plain = doc.plainText
        #expect(plain.contains("Inertia"), "Plain text should contain 'Inertia'")
        #expect(plain.contains("Reticulum"), "Plain text should contain 'Reticulum'")
        #expect(plain.contains("rns.inertia.chat"), "Plain text should contain server address")
        #expect(plain.contains("propagation node"), "Plain text should contain 'propagation node'")
    }
}

// MARK: - Suite 3: Address Parsing Integration

@Suite("NomadNet — Address Parsing Integration")
struct NomadAddressIntegrationTests {

    /// The target destination from the user's task.
    static let targetDestHash = "1e12dc236a05c930bd2c9190a2940ce7"

    @Test("address: parses canonical format hash:/path")
    func canonicalFormat() {
        let addr = NomadAddress(raw: "\(Self.targetDestHash):/page/index.mu")
        #expect(addr.destinationHashHex == Self.targetDestHash)
        #expect(addr.path == "/page/index.mu")
    }

    @Test("address: parses bare hash (defaults to index.mu)")
    func bareHash() {
        let addr = NomadAddress(raw: Self.targetDestHash)
        #expect(addr.destinationHashHex == Self.targetDestHash)
        #expect(addr.path == "/page/index.mu")
    }

    @Test("address: parses nn:// scheme")
    func nnScheme() {
        let addr = NomadAddress(raw: "nn://\(Self.targetDestHash)/page/about.mu")
        #expect(addr.destinationHashHex == Self.targetDestHash)
        #expect(addr.path == "/page/about.mu")
    }

    @Test("address: parses nomadnet:// scheme")
    func nomadnetScheme() {
        let addr = NomadAddress(raw: "nomadnet://\(Self.targetDestHash)/page/about.mu")
        #expect(addr.destinationHashHex == Self.targetDestHash)
        #expect(addr.path == "/page/about.mu")
    }

    @Test("address: local link with default destination")
    func localLink() {
        let addr = NomadAddress(raw: ":/page/about.mu", defaultDestinationHashHex: Self.targetDestHash)
        #expect(addr.destinationHashHex == Self.targetDestHash)
        #expect(addr.path == "/page/about.mu")
    }

    @Test("address: path hash for target index.mu matches known value")
    func targetIndexPathHash() {
        let hash = NomadClient.pathHash(for: "/page/index.mu")
        let expected = Data(hexString: "fb40abf359b3f25fa0086107c5eee516")!
        #expect(hash == expected)
    }
}

// MARK: - Suite 4: Node Server Lifecycle

@Suite("NomadNet — Node Server Lifecycle")
struct NomadServerLifecycleTests {

    @Test("server: periodic refresh picks up new files")
    func periodicRefresh() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nomad_lifecycle_\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let server = NomadNodeServer(storageDir: tmpDir, nodeName: "Refresh Node")
        try await server.ensureDirectories()

        // Register initial page
        try await server.registerPage(path: "/page/index.mu", content: Data(">Home\n".utf8))

        var pages = await server.listPages()
        #expect(pages.contains("/page/index.mu"))

        // Manually add a file to the filesystem (simulating external change)
        let newPage = tmpDir.appendingPathComponent("pages/new.mu")
        try ">New Page\n".write(to: newPage, atomically: true, encoding: .utf8)

        // Before refresh, new page is not indexed
        pages = await server.listPages()
        #expect(!pages.contains("/page/new.mu"), "New page shouldn't be indexed yet")

        // Set very short refresh interval and trigger refresh
        await server.setPageRefreshInterval(0)
        await server.refreshIfNeeded()

        pages = await server.listPages()
        #expect(pages.contains("/page/new.mu"), "New page should be indexed after refresh")
    }

    @Test("server: recordConnect increments counter")
    func recordConnect() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nomad_lifecycle_\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let server = NomadNodeServer(storageDir: tmpDir, nodeName: "Connect Node")
        try await server.ensureDirectories()

        await server.recordConnect()
        await server.recordConnect()
        await server.recordConnect()

        let stats = await server.statistics
        #expect(stats["node_connects"] == 3)
    }

    @Test("server: statistics tracks all request types")
    func statisticsTracking() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nomad_lifecycle_\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let server = NomadNodeServer(storageDir: tmpDir, nodeName: "Stats Node")
        try await server.ensureDirectories()

        try await server.registerPage(path: "/page/index.mu", content: Data(">Home\n".utf8))
        try await server.registerFile(path: "/file/data.bin", content: Data([0x01, 0x02]))

        // Make requests
        let pageReq = NomadClient.buildRequestPayload(path: "/page/index.mu", timestamp: 1.0, formData: nil)
        _ = try await server.handleRequest(pageReq)
        _ = try await server.handleRequest(pageReq)

        let fileReq = NomadClient.buildRequestPayload(path: "/file/data.bin", timestamp: 1.0, formData: nil)
        _ = try await server.handleRequest(fileReq)

        await server.recordConnect()

        let stats = await server.statistics
        #expect(stats["served_page_requests"] == 2)
        #expect(stats["served_file_requests"] == 1)
        #expect(stats["node_connects"] == 1)
    }
}

// MARK: - Suite 5: Node Announce Wire Format

@Suite("NomadNet — Node Announce Wire Format")
struct NomadAnnounceWireFormatTests {

    @Test("buildAnnounceData: encodes node name as UTF-8")
    func announceDataEncoding() {
        let data = NomadNode.buildAnnounceData(nodeName: "My Swift Node")
        #expect(data == Data("My Swift Node".utf8))
    }

    @Test("parseAnnounceName: decodes UTF-8 bytes")
    func announceNameDecoding() {
        let data = Data("Nomad Test Node".utf8)
        let name = NomadNode.parseAnnounceName(from: data)
        #expect(name == "Nomad Test Node")
    }

    @Test("parseAnnounceName: handles empty data")
    func emptyAnnounceData() {
        let name = NomadNode.parseAnnounceName(from: Data())
        #expect(name == "")
    }

    @Test("buildAnnounceData round-trips through parseAnnounceName")
    func announceRoundTrip() {
        let names = ["Test Node", "🌐 Unicode Node", "", "A", String(repeating: "x", count: 200)]
        for name in names {
            let data = NomadNode.buildAnnounceData(nodeName: name)
            let parsed = NomadNode.parseAnnounceName(from: data)
            #expect(parsed == name, "Round-trip failed for \"\(name)\"")
        }
    }

    @Test("announceNameHash: is 10 bytes")
    func announceNameHashLength() {
        let hash = NomadNode.announceNameHash()
        #expect(hash.count == 10, "announceNameHash must be 10 bytes, got \(hash.count)")
    }

    @Test("announceNameHash: deterministic")
    func announceNameHashDeterministic() {
        let hash1 = NomadNode.announceNameHash()
        let hash2 = NomadNode.announceNameHash()
        #expect(hash1 == hash2, "announceNameHash should be deterministic")
    }
}

// MARK: - Suite 6: Cache Directive Integration

@Suite("NomadNet — Cache Directive Integration")
struct NomadCacheDirectiveIntegrationTests {

    @Test("page with #!c=60 has cacheTTL of 60 seconds")
    func cacheTTLFromMetadata() {
        let source = "#!c=60\n>Cached Page\nThis page has a 60-second cache."
        let page = NomadPage(path: "/page/cached.mu", requestID: Data(repeating: 0, count: 16), content: Data(source.utf8))
        #expect(page.cacheTTL == 60)
    }

    @Test("page with #!c=0 has cacheTTL of 0 (no caching)")
    func noCaching() {
        let source = "#!c=0\n>Dynamic Page\nThis page should not be cached."
        let page = NomadPage(path: "/page/dynamic.mu", requestID: Data(repeating: 0, count: 16), content: Data(source.utf8))
        #expect(page.cacheTTL == 0)
    }

    @Test("page without #!c has nil cacheTTL (use default)")
    func defaultCaching() {
        let source = ">Normal Page\nThis page uses default caching."
        let page = NomadPage(path: "/page/normal.mu", requestID: Data(repeating: 0, count: 16), content: Data(source.utf8))
        #expect(page.cacheTTL == nil)
    }

    @Test("page metadata is preserved through full parse")
    func metadataPreservedThroughParse() {
        let source = "#!c=300\n#!title=Test Page\n>Hello\nWorld"
        let doc = MicronParser.parse(source)
        #expect(doc.metadata["c"] == "300")
        #expect(doc.metadata["title"] == "Test Page")
        #expect(doc.cacheTTL == 300)
    }
}

// MARK: - Suite 7: Protocol Msgpack Edge Cases

@Suite("NomadNet — Protocol Edge Cases")
struct NomadProtocolEdgeCaseTests {

    @Test("buildRequestPayload with form data encodes valid msgpack")
    func formDataEncoding() throws {
        let payload = NomadClient.buildRequestPayload(
            path: "/page/form.mu",
            timestamp: 1700000000.0,
            formData: ["field_name": "Alice", "field_msg": "Hello"]
        )
        // Should be parseable
        let (ts, hash, form) = try NomadClient.parsePageRequest(payload)
        #expect(ts == 1700000000.0)
        #expect(hash == NomadClient.pathHash(for: "/page/form.mu"))
        #expect(form?["field_name"] == "Alice")
        #expect(form?["field_msg"] == "Hello")
    }

    @Test("buildRequestPayload with empty form data treats as nil")
    func emptyFormDataIsNil() throws {
        let payload = NomadClient.buildRequestPayload(
            path: "/page/index.mu",
            timestamp: 1700000000.0,
            formData: [:]
        )
        let (_, _, form) = try NomadClient.parsePageRequest(payload)
        #expect(form == nil, "Empty form data should be encoded as nil")
    }

    @Test("buildPageResponse → parsePageResponse round-trip")
    func responseRoundTrip() throws {
        let requestID = Data(repeating: 0xab, count: 16)
        let content = Data(">Test Page\nContent here.\n".utf8)

        let response = NomadClient.buildPageResponse(requestID: requestID, content: content)
        let (parsedID, parsedContent) = try NomadClient.parsePageResponse(response)

        #expect(parsedID == requestID)
        #expect(parsedContent == content)
    }

    @Test("buildPageResponse handles large content (bin16)")
    func largeContent() throws {
        let requestID = Data(repeating: 0x01, count: 16)
        let content = Data(repeating: 0x42, count: 300)

        let response = NomadClient.buildPageResponse(requestID: requestID, content: content)
        let (parsedID, parsedContent) = try NomadClient.parsePageResponse(response)

        #expect(parsedID == requestID)
        #expect(parsedContent == content)
    }

    @Test("buildPageResponse handles very large content (bin32)")
    func veryLargeContent() throws {
        let requestID = Data(repeating: 0x02, count: 16)
        let content = Data(repeating: 0x43, count: 70_000)

        let response = NomadClient.buildPageResponse(requestID: requestID, content: content)
        let (parsedID, parsedContent) = try NomadClient.parsePageResponse(response)

        #expect(parsedID == requestID)
        #expect(parsedContent == content)
    }
}


