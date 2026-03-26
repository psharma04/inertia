import Foundation

/// Canonical Nomad address parser/normaliser.
///
/// Supports:
/// - `<hash>`
/// - `<hash>/<path>`
/// - `<hash>:/<path>`
/// - `nn://<hash>/<path>`
/// - local path links like `:/page/index.mu` (requires default destination hash)
public struct NomadAddress: Hashable, Sendable {
    public let raw: String
    public let destinationHashHex: String?
    public let path: String

    /// Canonical rendering when destination hash is valid.
    public var canonical: String? {
        guard let destinationHashHex else { return nil }
        return "\(destinationHashHex):\(path)"
    }

    public init(raw: String, defaultDestinationHashHex: String? = nil) {
        self.raw = raw
        let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let defaultPath = "/page/index.mu"

        guard !cleaned.isEmpty else {
            self.destinationHashHex = nil
            self.path = defaultPath
            return
        }

        var working = cleaned
        if working.lowercased().hasPrefix("nn://") {
            working = String(working.dropFirst(5))
        }

        let normalisedDefaultHash = Self.normaliseHash(defaultDestinationHashHex)

        // Local-node link forms used inside Micron documents.
        if working.hasPrefix(":/") {
            self.destinationHashHex = normalisedDefaultHash
            self.path = Self.normalisePath(String(working.dropFirst()))
            return
        }

        if working.hasPrefix("/") {
            self.destinationHashHex = normalisedDefaultHash
            self.path = Self.normalisePath(working)
            return
        }

        if working.hasPrefix("page/") || working.hasPrefix("file/") {
            self.destinationHashHex = normalisedDefaultHash
            self.path = Self.normalisePath(working)
            return
        }

        // Canonical Nomad format: <hash>:/path
        if let colonSlash = working.range(of: ":/") {
            let hash = Self.normaliseHash(String(working[..<colonSlash.lowerBound]))
            let pathPart = String(working[colonSlash.lowerBound...]).dropFirst()
            if let hash {
                self.destinationHashHex = hash
                self.path = Self.normalisePath(String(pathPart))
                return
            }
        }

        // Legacy/common input: <hash> or <hash>/<path>
        let parts = working.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let hashPart = Self.normaliseHash(parts.first.map(String.init) ?? working)
        if let hashPart {
            self.destinationHashHex = hashPart
            if parts.count > 1 {
                self.path = Self.normalisePath("/" + parts[1])
            } else {
                self.path = defaultPath
            }
            return
        }

        self.destinationHashHex = nil
        self.path = defaultPath
    }

    private static func normalisePath(_ path: String) -> String {
        guard !path.isEmpty else { return "/page/index.mu" }
        if path.hasPrefix("/") { return path }
        return "/" + path
    }

    private static func normaliseHash(_ hash: String?) -> String? {
        guard let hash = hash?.lowercased() else { return nil }
        guard hash.count == 32 else { return nil }
        guard hash.allSatisfy({ $0.isHexDigit }) else { return nil }
        return hash
    }
}
