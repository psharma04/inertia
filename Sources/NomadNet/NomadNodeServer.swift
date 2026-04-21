import Foundation
import ReticulumCrypto

public actor NomadNodeServer {

    public let storageDir: URL
    public let nodeName: String

    private var pathIndex: [Data: String] = [:]
    private var indexed = false

    public private(set) var servedPageRequests: Int = 0
    public private(set) var servedFileRequests: Int = 0
    public private(set) var nodeConnects: Int = 0

    public var pageRefreshInterval: TimeInterval = 180
    public var fileRefreshInterval: TimeInterval = 180

    public func setPageRefreshInterval(_ interval: TimeInterval) {
        pageRefreshInterval = interval
    }

    public func setFileRefreshInterval(_ interval: TimeInterval) {
        fileRefreshInterval = interval
    }

    /// Timestamp of last refresh
    private var lastPageRefresh: Date?
    private var lastFileRefresh: Date?

    public init(storageDir: URL, nodeName: String = "") {
        self.storageDir = storageDir
        self.nodeName = nodeName
    }

    // MARK: - Request Handling

    public func handleRequest(_ payload: Data, remoteIdentityHash: String? = nil) throws -> Data {
        let (_, pathHash, formData) = try NomadClient.parsePageRequest(payload)

        ensureIndexed()

        guard let resolvedPath = pathIndex[pathHash] else {
            return buildErrorResponse(notFoundPage)
        }

        // Check per-file access control
        if let identityHash = remoteIdentityHash,
           !isPathAllowed(resolvedPath, identityHash: identityHash) {
            return buildErrorResponse(accessDeniedPage)
        }

        if resolvedPath.hasPrefix("/page/") {
            servedPageRequests += 1
            return try servePage(resolvedPath, formData: formData, remoteIdentityHash: remoteIdentityHash)
        } else if resolvedPath.hasPrefix("/file/") {
            servedFileRequests += 1
            return try serveFile(resolvedPath)
        } else {
            return buildErrorResponse(notFoundPage)
        }
    }

    private func servePage(_ path: String, formData: [String: String]?, remoteIdentityHash: String?) throws -> Data {
        let relativePath = String(path.dropFirst("/page/".count))
        let fileURL = pagesDir.appendingPathComponent(relativePath)

        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return buildErrorResponse(notFoundPage)
        }

        let content: Data

        #if !os(iOS) && !os(watchOS) && !os(tvOS)
        if FileManager.default.isExecutableFile(atPath: fileURL.path),
           !fileURL.pathExtension.lowercased().hasSuffix("mu") {
            content = try executeDynamicPage(fileURL, formData: formData, remoteIdentityHash: remoteIdentityHash)
        } else {
            content = try Data(contentsOf: fileURL)
        }
        #else
        content = try Data(contentsOf: fileURL)
        #endif

        let requestID = generateRequestID()
        return NomadClient.buildPageResponse(requestID: requestID, content: content)
    }

    private func serveFile(_ path: String) throws -> Data {
        let relativePath = String(path.dropFirst("/file/".count))
        let fileURL = filesDir.appendingPathComponent(relativePath)

        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return buildErrorResponse(notFoundPage)
        }

        let content = try Data(contentsOf: fileURL)
        let requestID = generateRequestID()
        return NomadClient.buildPageResponse(requestID: requestID, content: content)
    }

    #if !os(iOS) && !os(watchOS) && !os(tvOS)
    private func executeDynamicPage(_ fileURL: URL, formData: [String: String]?, remoteIdentityHash: String?) throws -> Data {
        let process = Process()
        process.executableURL = fileURL
        process.currentDirectoryURL = pagesDir

        var env: [String: String] = [:]
        if let path = ProcessInfo.processInfo.environment["PATH"] {
            env["PATH"] = path
        }
        if let identityHash = remoteIdentityHash {
            env["remote_identity"] = identityHash
        }
        if let formData = formData {
            for (key, value) in formData where key.hasPrefix("field_") || key.hasPrefix("var_") {
                env[key] = value
            }
        }
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        try process.run()
        process.waitUntilExit()

        return pipe.fileHandleForReading.readDataToEndOfFile()
    }
    #endif

    // MARK: - Access Control

    public func isPathAllowed(_ path: String, identityHash: String) -> Bool {
        let fileURL: URL
        if path.hasPrefix("/page/") {
            let relativePath = String(path.dropFirst("/page/".count))
            fileURL = pagesDir.appendingPathComponent(relativePath)
        } else if path.hasPrefix("/file/") {
            let relativePath = String(path.dropFirst("/file/".count))
            fileURL = filesDir.appendingPathComponent(relativePath)
        } else {
            return true
        }

        let allowedURL = fileURL.appendingPathExtension("allowed")

        guard FileManager.default.fileExists(atPath: allowedURL.path) else {
            return true  // No .allowed file = open access
        }

        let allowedContent: String

        #if !os(iOS) && !os(watchOS) && !os(tvOS)
        // Executable .allowed files run as scripts and output allowed hashes
        if FileManager.default.isExecutableFile(atPath: allowedURL.path) {
            let process = Process()
            process.executableURL = allowedURL
            process.currentDirectoryURL = allowedURL.deletingLastPathComponent()
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                process.waitUntilExit()
                let output = pipe.fileHandleForReading.readDataToEndOfFile()
                allowedContent = String(data: output, encoding: .utf8) ?? ""
            } catch {
                return true
            }
        } else {
            guard let content = try? String(contentsOf: allowedURL, encoding: .utf8) else {
                return true
            }
            allowedContent = content
        }
        #else
        guard let content = try? String(contentsOf: allowedURL, encoding: .utf8) else {
            return true
        }
        allowedContent = content
        #endif

        let allowedHashes = Set(
            allowedContent
                .components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        )

        return allowedHashes.contains(identityHash.lowercased())
    }

    /// Register a page at the given path with content.
    public func registerPage(path: String, content: Data) throws {
        guard path.hasPrefix("/page/") else {
            throw NomadError.invalidResponse
        }
        let relativePath = String(path.dropFirst("/page/".count))
        let fileURL = pagesDir.appendingPathComponent(relativePath)

        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try content.write(to: fileURL)

        let hash = NomadClient.pathHash(for: path)
        pathIndex[hash] = path
    }

    /// Register a file to be served at the given path.
    public func registerFile(path: String, content: Data) throws {
        guard path.hasPrefix("/file/") else {
            throw NomadError.invalidResponse
        }
        let relativePath = String(path.dropFirst("/file/".count))
        let fileURL = filesDir.appendingPathComponent(relativePath)

        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try content.write(to: fileURL)

        let hash = NomadClient.pathHash(for: path)
        pathIndex[hash] = path
    }

    /// List all available pages.
    public func listPages() -> [String] {
        ensureIndexed()
        return pathIndex.values.filter { $0.hasPrefix("/page/") }.sorted()
    }

    /// List all available files.
    public func listFiles() -> [String] {
        ensureIndexed()
        return pathIndex.values.filter { $0.hasPrefix("/file/") }.sorted()
    }

    private func ensureIndexed() {
        guard !indexed else { return }
        indexDirectory(pagesDir, prefix: "/page/")
        indexDirectory(filesDir, prefix: "/file/")
        indexed = true
    }

    public func reindex() {
        pathIndex.removeAll()
        indexed = false
        ensureIndexed()
    }

    public func refreshIfNeeded() {
        let now = Date()
        if lastPageRefresh.map({ now.timeIntervalSince($0) >= pageRefreshInterval }) ?? true {
            pathIndex = pathIndex.filter { !$0.value.hasPrefix("/page/") }
            indexDirectory(pagesDir, prefix: "/page/")
            lastPageRefresh = now
        }
        if lastFileRefresh.map({ now.timeIntervalSince($0) >= fileRefreshInterval }) ?? true {
            pathIndex = pathIndex.filter { !$0.value.hasPrefix("/file/") }
            indexDirectory(filesDir, prefix: "/file/")
            lastFileRefresh = now
        }
        indexed = true
    }

    /// Record an incoming node connection (for statistics tracking).
    public func recordConnect() {
        nodeConnects += 1
    }

    /// All tracked statistics as a dictionary (for persistence).
    public var statistics: [String: Int] {
        [
            "served_page_requests": servedPageRequests,
            "served_file_requests": servedFileRequests,
            "node_connects": nodeConnects
        ]
    }

    private func indexDirectory(_ dir: URL, prefix: String) {
        let resolvedDir = dir.standardizedFileURL
        guard let enumerator = FileManager.default.enumerator(
            at: resolvedDir,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        let basePath = resolvedDir.path
        while let fileURL = enumerator.nextObject() as? URL {
            guard let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey]),
                  values.isRegularFile == true else { continue }

            // Skip .allowed files — they are access control, not content
            guard fileURL.pathExtension != "allowed" else { continue }

            let filePath = fileURL.standardizedFileURL.path
            guard filePath.hasPrefix(basePath) else { continue }
            var relativePath = String(filePath.dropFirst(basePath.count))
            if relativePath.hasPrefix("/") {
                relativePath = String(relativePath.dropFirst())
            }
            let fullPath = prefix + relativePath

            let hash = NomadClient.pathHash(for: fullPath)
            pathIndex[hash] = fullPath
        }
    }

    private var pagesDir: URL {
        storageDir.appendingPathComponent("pages", isDirectory: true)
    }

    private var filesDir: URL {
        storageDir.appendingPathComponent("files", isDirectory: true)
    }

    /// Ensure storage directories exist.
    public func ensureDirectories() throws {
        try FileManager.default.createDirectory(at: pagesDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: filesDir, withIntermediateDirectories: true)
    }

    private func generateRequestID() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { bytes[i] = UInt8.random(in: 0...255) }
        return Data(bytes)
    }

    private func buildErrorResponse(_ pageContent: String) -> Data {
        let requestID = generateRequestID()
        return NomadClient.buildPageResponse(requestID: requestID, content: Data(pageContent.utf8))
    }

    public static let defaultIndexPage = """
    #!c=0
    >Welcome
    This NomadNet node is online, but no home page has been configured.

    To set up a home page, place an `index.mu` file in the pages directory.
    """

    private let notFoundPage = """
    #!c=0
    >Page Not Found
    The requested page could not be found on this node.
    """

    private let accessDeniedPage = """
    #!c=0
    >Access Denied
    You do not have permission to access this resource.
    """
}
