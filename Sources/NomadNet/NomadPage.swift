import Foundation

// NomadPage

public struct NomadPage: Sendable {

    /// The path that was requested (e.g. "/page/index.mu").
    public let path: String

    /// 16-byte request identifier echoed from the server response.
    public let requestID: Data

    /// Raw Micron markup bytes (UTF-8 encoded).
    public let content: Data

    /// Parsed Micron document for UI rendering.
    public var micronDocument: MicronDocument {
        MicronParser.parse(contentString)
    }

    /// The page content decoded as a UTF-8 string.
    public var contentString: String {
        String(data: content, encoding: .utf8) ?? ""
    }

    /// Cache TTL from page metadata `#!c=N`, or nil for default.
    public var cacheTTL: TimeInterval? {
        micronDocument.cacheTTL
    }

    /// Initialise directly (used by NomadClient when parsing responses).
    public init(path: String, requestID: Data, content: Data) {
        self.path      = path
        self.requestID = requestID
        self.content   = content
    }
}
