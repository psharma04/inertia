import Foundation
import NomadNet

public actor NomadStore {

    struct CachedPage: Codable, Sendable {
        let path: String
        let requestID: Data
        let content: Data
        let cachedAt: Date
        let destinationHashHex: String
        let customTTL: TimeInterval?
    }

    /// A bookmarked node with optional custom display name.
    public struct NodeFavorite: Codable, Sendable, Identifiable, Equatable {
        public var id: String { destinationHashHex }
        public let destinationHashHex: String
        public var customName: String
        public let addedAt: Date

        public init(destinationHashHex: String, customName: String = "", addedAt: Date = Date()) {
            self.destinationHashHex = destinationHashHex
            self.customName = customName
            self.addedAt = addedAt
        }
    }

    /// A discovered NomadNet node from network announces.
    public struct DiscoveredNode: Codable, Sendable, Identifiable, Equatable {
        public var id: String { destinationHashHex }
        public let destinationHashHex: String
        public var name: String
        public let firstSeen: Date
        public var lastSeen: Date

        public init(destinationHashHex: String, name: String = "",
                    firstSeen: Date = Date(), lastSeen: Date = Date()) {
            self.destinationHashHex = destinationHashHex
            self.name = name
            self.firstSeen = firstSeen
            self.lastSeen = lastSeen
        }
    }

    public static let cacheTTL: TimeInterval = 12 * 60 * 60

    private let pageCacheDir: URL
    private let favoritesFile: URL
    private let nodeDirectoryFile: URL

    private var favorites: [NodeFavorite] = []
    private var discoveredNodes: [String: DiscoveredNode] = [:]

    public static let defaultFavorites: [NodeFavorite] = [
        NodeFavorite(
            destinationHashHex: "1e12dc236a05c930bd2c9190a2940ce7",
            customName: "Inertia"
        ),
    ]

    public init() {
        // swiftlint:disable force_unwrapping
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        pageCacheDir = caches.appendingPathComponent("NomadPageCache", isDirectory: true)

        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        // swiftlint:enable force_unwrapping
        favoritesFile = docs.appendingPathComponent("nomad_favorites.json")
        nodeDirectoryFile = docs.appendingPathComponent("nomad_nodes.json")

        try? FileManager.default.createDirectory(at: pageCacheDir, withIntermediateDirectories: true)
        favorites = Self.loadFavorites(from: favoritesFile)
        discoveredNodes = Self.loadNodes(from: nodeDirectoryFile)

        // Seed default favorites on first launch (when no favorites file exists yet)
        if favorites.isEmpty {
            favorites = Self.defaultFavorites
            if let data = try? JSONEncoder().encode(favorites) {
                try? data.write(to: favoritesFile, options: .atomic)
            }
        }
    }

    /// Testable initializer with custom storage paths. Does NOT seed defaults.
    public init(pageCacheDir: URL, favoritesFile: URL, nodeDirectoryFile: URL) {
        self.pageCacheDir = pageCacheDir
        self.favoritesFile = favoritesFile
        self.nodeDirectoryFile = nodeDirectoryFile
        try? FileManager.default.createDirectory(at: pageCacheDir, withIntermediateDirectories: true)
        favorites = Self.loadFavorites(from: favoritesFile)
        discoveredNodes = Self.loadNodes(from: nodeDirectoryFile)
    }

    // MARK: - Page Cache

    private static func cacheKey(destinationHashHex: String, path: String) -> String {
        let input = Data("\(destinationHashHex):\(path)".utf8)
        return sha256Hex(input)
    }

    /// Save a fetched page to the cache.
    public func save(page: NomadPage, destinationHashHex: String) {
        let key = Self.cacheKey(destinationHashHex: destinationHashHex, path: page.path)
        let entry = CachedPage(
            path: page.path,
            requestID: page.requestID,
            content: page.content,
            cachedAt: Date(),
            destinationHashHex: destinationHashHex,
            customTTL: page.cacheTTL
        )
        let file = pageCacheDir.appendingPathComponent("\(key).json")
        if let data = try? JSONEncoder().encode(entry) {
            try? data.write(to: file, options: .atomic)
        }
    }

    /// Fetch a cached page if it exists and hasn't expired.
    public func fetchPage(destinationHashHex: String, path: String) -> NomadPage? {
        let key = Self.cacheKey(destinationHashHex: destinationHashHex, path: path)
        let file = pageCacheDir.appendingPathComponent("\(key).json")
        guard let data = try? Data(contentsOf: file),
              let entry = try? JSONDecoder().decode(CachedPage.self, from: data) else {
            return nil
        }
        // Check TTL — use per-page TTL if set, otherwise default
        let ttl = entry.customTTL ?? Self.cacheTTL
        guard Date().timeIntervalSince(entry.cachedAt) < ttl else {
            try? FileManager.default.removeItem(at: file)
            return nil
        }
        return NomadPage(path: entry.path, requestID: entry.requestID, content: entry.content)
    }

    /// Remove all expired cache entries.
    public func evictExpired() {
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: pageCacheDir, includingPropertiesForKeys: nil
        ) else { return }

        let decoder = JSONDecoder()
        let now = Date()
        for file in files where file.pathExtension == "json" {
            guard let data = try? Data(contentsOf: file),
                  let entry = try? decoder.decode(CachedPage.self, from: data) else {
                continue
            }
            if now.timeIntervalSince(entry.cachedAt) >= (entry.customTTL ?? Self.cacheTTL) {
                try? FileManager.default.removeItem(at: file)
            }
        }
    }

    /// Clear all cached pages.
    public func clearCache() {
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: pageCacheDir, includingPropertiesForKeys: nil
        ) else { return }
        for file in files {
            try? FileManager.default.removeItem(at: file)
        }
    }

    // MARK: - Favorites

    public func allFavorites() -> [NodeFavorite] {
        favorites
    }

    public func isFavorite(destinationHashHex: String) -> Bool {
        favorites.contains { $0.destinationHashHex == destinationHashHex }
    }

    public func addFavorite(_ fav: NodeFavorite) {
        if let idx = favorites.firstIndex(where: { $0.destinationHashHex == fav.destinationHashHex }) {
            favorites[idx] = fav
        } else {
            favorites.append(fav)
        }
        persistFavorites()
    }

    public func removeFavorite(destinationHashHex: String) {
        favorites.removeAll { $0.destinationHashHex == destinationHashHex }
        persistFavorites()
    }

    public func renameFavorite(destinationHashHex: String, newName: String) {
        guard let idx = favorites.firstIndex(where: { $0.destinationHashHex == destinationHashHex }) else { return }
        favorites[idx].customName = newName
        persistFavorites()
    }

    // MARK: - Node Directory

    public func allNodes() -> [DiscoveredNode] {
        Array(discoveredNodes.values).sorted { $0.lastSeen > $1.lastSeen }
    }

    public func recordNode(destinationHashHex: String, name: String) {
        let hex = destinationHashHex.lowercased()
        if var existing = discoveredNodes[hex] {
            existing.name = name
            existing.lastSeen = Date()
            discoveredNodes[hex] = existing
        } else {
            discoveredNodes[hex] = DiscoveredNode(
                destinationHashHex: hex,
                name: name
            )
        }
        persistNodes()
    }

    public func removeNode(destinationHashHex: String) {
        discoveredNodes.removeValue(forKey: destinationHashHex.lowercased())
        persistNodes()
    }

    public func node(for destinationHashHex: String) -> DiscoveredNode? {
        discoveredNodes[destinationHashHex.lowercased()]
    }

    public func evictStaleNodes(olderThan interval: TimeInterval) {
        let cutoff = Date().addingTimeInterval(-interval)
        let stale = discoveredNodes.filter { $0.value.lastSeen < cutoff }
        for key in stale.keys {
            discoveredNodes.removeValue(forKey: key)
        }
        if !stale.isEmpty { persistNodes() }
    }

    private func persistFavorites() {
        if let data = try? JSONEncoder().encode(favorites) {
            try? data.write(to: favoritesFile, options: .atomic)
        }
    }

    private func persistNodes() {
        let nodes = Array(discoveredNodes.values)
        if let data = try? JSONEncoder().encode(nodes) {
            try? data.write(to: nodeDirectoryFile, options: .atomic)
        }
    }

    private static func loadFavorites(from url: URL) -> [NodeFavorite] {
        guard let data = try? Data(contentsOf: url),
              let favs = try? JSONDecoder().decode([NodeFavorite].self, from: data) else {
            return []
        }
        return favs
    }

    private static func loadNodes(from url: URL) -> [String: DiscoveredNode] {
        guard let data = try? Data(contentsOf: url),
              let nodes = try? JSONDecoder().decode([DiscoveredNode].self, from: data) else {
            return [:]
        }
        var dict: [String: DiscoveredNode] = [:]
        for node in nodes {
            dict[node.destinationHashHex] = node
        }
        return dict
    }

    private static func sha256Hex(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { buf in
            _ = CC_SHA256(buf.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}

import CommonCrypto
