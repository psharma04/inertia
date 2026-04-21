import Testing
import Foundation
@testable import NomadNet

@Suite("NomadNodeServer")
struct NomadNodeServerTests {

    /// Create a temporary storage directory with the required structure.
    private func makeTempStorage() throws -> URL {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("NomadNodeServerTests-\(UUID().uuidString)")
        let pagesDir = tmp.appendingPathComponent("pages", isDirectory: true)
        let filesDir = tmp.appendingPathComponent("files", isDirectory: true)
        try FileManager.default.createDirectory(at: pagesDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: filesDir, withIntermediateDirectories: true)
        return tmp
    }

    private func cleanup(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: - Page Serving

    @Test("serves a registered page")
    func servesRegisteredPage() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir, nodeName: "TestNode")
        let pageContent = Data(">Hello\nWelcome to my node!".utf8)
        try await server.registerPage(path: "/page/index.mu", content: pageContent)

        let request = NomadClient.buildRequestPayload(
            path: "/page/index.mu",
            timestamp: 1700000000.0,
            formData: nil
        )
        let response = try await server.handleRequest(request)

        let (requestID, content) = try NomadClient.parsePageResponse(response)
        #expect(requestID.count == 16)
        #expect(content == pageContent)
    }

    @Test("returns not-found page for missing path")
    func missingPageReturnsNotFound() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir)
        let request = NomadClient.buildRequestPayload(
            path: "/page/nonexistent.mu",
            timestamp: 1700000000.0,
            formData: nil
        )
        let response = try await server.handleRequest(request)

        let (_, content) = try NomadClient.parsePageResponse(response)
        let text = String(data: content, encoding: .utf8) ?? ""
        #expect(text.contains("Not Found"))
    }

    // MARK: - File Serving

    @Test("serves a registered file")
    func servesRegisteredFile() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir)
        let fileContent = Data("Hello, binary world!".utf8)
        try await server.registerFile(path: "/file/readme.txt", content: fileContent)

        let request = NomadClient.buildRequestPayload(
            path: "/file/readme.txt",
            timestamp: 1700000000.0,
            formData: nil
        )
        let response = try await server.handleRequest(request)

        let (_, content) = try NomadClient.parsePageResponse(response)
        #expect(content == fileContent)
    }

    // MARK: - Access Control

    @Test("allows access when no .allowed file exists")
    func openAccessWithoutAllowedFile() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir)
        let result = await server.isPathAllowed("/page/index.mu", identityHash: "abc123")
        #expect(result == true)
    }

    @Test("allows access for listed identity")
    func allowedIdentityGrantsAccess() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir)
        let pageContent = Data(">Secret Page\nTop secret content.".utf8)
        try await server.registerPage(path: "/page/secret.mu", content: pageContent)

        // Create .allowed file
        let allowedFile = dir.appendingPathComponent("pages/secret.mu.allowed")
        try "abc123def456\n# comment line\nfedcba654321".write(to: allowedFile, atomically: true, encoding: .utf8)

        let allowed = await server.isPathAllowed("/page/secret.mu", identityHash: "abc123def456")
        #expect(allowed == true)

        let denied = await server.isPathAllowed("/page/secret.mu", identityHash: "unknown000000")
        #expect(denied == false)
    }

    @Test("access check is case-insensitive")
    func allowedCaseInsensitive() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir)
        try await server.registerPage(path: "/page/test.mu", content: Data("test".utf8))

        let allowedFile = dir.appendingPathComponent("pages/test.mu.allowed")
        try "ABC123DEF456".write(to: allowedFile, atomically: true, encoding: .utf8)

        let result = await server.isPathAllowed("/page/test.mu", identityHash: "abc123def456")
        #expect(result == true)
    }

    @Test("access denied returns error page")
    func accessDeniedResponse() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir)
        let pageContent = Data(">Secret".utf8)
        try await server.registerPage(path: "/page/locked.mu", content: pageContent)

        let allowedFile = dir.appendingPathComponent("pages/locked.mu.allowed")
        try "authorized_hash_only".write(to: allowedFile, atomically: true, encoding: .utf8)

        let request = NomadClient.buildRequestPayload(
            path: "/page/locked.mu",
            timestamp: 1700000000.0,
            formData: nil
        )
        let response = try await server.handleRequest(request, remoteIdentityHash: "unauthorized_hash")

        let (_, content) = try NomadClient.parsePageResponse(response)
        let text = String(data: content, encoding: .utf8) ?? ""
        #expect(text.contains("Access Denied"))
    }

    // MARK: - Indexing

    @Test("indexes pages from filesystem")
    func indexesPages() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let pagesDir = dir.appendingPathComponent("pages")
        try Data(">Page 1".utf8).write(to: pagesDir.appendingPathComponent("one.mu"))
        try Data(">Page 2".utf8).write(to: pagesDir.appendingPathComponent("two.mu"))

        let server = NomadNodeServer(storageDir: dir)
        let pages = await server.listPages()
        #expect(pages.count == 2)
        #expect(pages.contains("/page/one.mu"))
        #expect(pages.contains("/page/two.mu"))
    }

    @Test("indexes files from filesystem")
    func indexesFiles() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let filesDir = dir.appendingPathComponent("files")
        try Data("data".utf8).write(to: filesDir.appendingPathComponent("doc.txt"))

        let server = NomadNodeServer(storageDir: dir)
        let files = await server.listFiles()
        #expect(files.count == 1)
        #expect(files.contains("/file/doc.txt"))
    }

    @Test("skips .allowed files when indexing")
    func indexSkipsAllowedFiles() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let pagesDir = dir.appendingPathComponent("pages")
        try Data(">Page".utf8).write(to: pagesDir.appendingPathComponent("main.mu"))
        try Data("hash1\nhash2".utf8).write(to: pagesDir.appendingPathComponent("main.mu.allowed"))

        let server = NomadNodeServer(storageDir: dir)
        let pages = await server.listPages()
        #expect(pages.count == 1)
        #expect(pages.contains("/page/main.mu"))
    }

    @Test("reindex refreshes the path index")
    func reindexRefreshes() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir)
        var pages = await server.listPages()
        #expect(pages.isEmpty)

        let pagesDir = dir.appendingPathComponent("pages")
        try Data(">New".utf8).write(to: pagesDir.appendingPathComponent("new.mu"))
        await server.reindex()

        pages = await server.listPages()
        #expect(pages.count == 1)
    }

    // MARK: - Statistics

    @Test("tracks served request counts")
    func tracksStatistics() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir)
        try await server.registerPage(path: "/page/stats.mu", content: Data(">Stats".utf8))
        try await server.registerFile(path: "/file/data.bin", content: Data([0x01, 0x02]))

        let pageReq = NomadClient.buildRequestPayload(path: "/page/stats.mu", timestamp: 1.0, formData: nil)
        _ = try await server.handleRequest(pageReq)
        _ = try await server.handleRequest(pageReq)

        let fileReq = NomadClient.buildRequestPayload(path: "/file/data.bin", timestamp: 1.0, formData: nil)
        _ = try await server.handleRequest(fileReq)

        #expect(await server.servedPageRequests == 2)
        #expect(await server.servedFileRequests == 1)
    }

    // MARK: - Round-trip

    @Test("full client-server round-trip")
    func clientServerRoundTrip() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir, nodeName: "RoundTrip")
        let markup = ">Hello World\nThis is a test page with `!bold text`!."
        try await server.registerPage(path: "/page/index.mu", content: Data(markup.utf8))

        // Client builds request
        let request = NomadClient.buildRequestPayload(
            path: "/page/index.mu",
            timestamp: Date().timeIntervalSince1970,
            formData: nil
        )

        // Server handles request
        let responseBytes = try await server.handleRequest(request)

        // Client parses response
        let (requestID, content) = try NomadClient.parsePageResponse(responseBytes)
        let page = NomadPage(path: "/page/index.mu", requestID: requestID, content: content)

        #expect(page.contentString == markup)
        #expect(page.micronDocument.blocks.count > 0)
    }

    @Test("subdirectory pages are indexed and served")
    func subdirectoryPages() async throws {
        let dir = try makeTempStorage()
        defer { cleanup(dir) }

        let server = NomadNodeServer(storageDir: dir)
        let subDir = dir.appendingPathComponent("pages/docs")
        try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)
        try Data(">Docs\nDocumentation page.".utf8).write(to: subDir.appendingPathComponent("readme.mu"))

        await server.reindex()

        let request = NomadClient.buildRequestPayload(
            path: "/page/docs/readme.mu",
            timestamp: 1.0,
            formData: nil
        )
        let response = try await server.handleRequest(request)
        let (_, content) = try NomadClient.parsePageResponse(response)
        #expect(String(data: content, encoding: .utf8)?.contains("Documentation") == true)
    }
}
