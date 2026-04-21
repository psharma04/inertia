import Foundation
import NomadNet
import Persistence

public actor NomadService {

    private let store: NomadStore

    public typealias PageFetcher = @Sendable (Data, String, [String: String]?) async throws -> NomadPage
    public typealias FileFetcher = @Sendable (Data, String) async throws -> Data

    private var pageFetcher: PageFetcher?
    private var fileFetcher: FileFetcher?

    public init(store: NomadStore) {
        self.store = store
    }

    public func configure(pageFetcher: @escaping PageFetcher, fileFetcher: @escaping FileFetcher) {
        self.pageFetcher = pageFetcher
        self.fileFetcher = fileFetcher
    }

    public func fetchPage(
        destinationHash: Data,
        path: String,
        formData: [String: String]? = nil,
        bypassCache: Bool = false
    ) async throws -> NomadPage {
        let hex = destinationHash.map { String(format: "%02x", $0) }.joined()

        // Form submissions always bypass cache
        let shouldCache = formData == nil && !bypassCache

        if shouldCache {
            if let cached = await store.fetchPage(destinationHashHex: hex, path: path) {
                return cached
            }
        }

        guard let fetcher = pageFetcher else {
            throw NomadError.notImplemented
        }

        let page = try await fetcher(destinationHash, path, formData)

        if shouldCache {
            await store.save(page: page, destinationHashHex: hex)
        }

        return page
    }

    public func downloadFile(destinationHash: Data, path: String) async throws -> Data {
        guard let fetcher = fileFetcher else {
            throw NomadError.notImplemented
        }
        return try await fetcher(destinationHash, path)
    }

    public func clearCache() async {
        await store.clearCache()
    }

    public func evictExpired() async {
        await store.evictExpired()
    }

    public func allFavorites() async -> [NomadStore.NodeFavorite] {
        await store.allFavorites()
    }

    public func isFavorite(destinationHashHex: String) async -> Bool {
        await store.isFavorite(destinationHashHex: destinationHashHex)
    }

    public func addFavorite(_ fav: NomadStore.NodeFavorite) async {
        await store.addFavorite(fav)
    }

    public func removeFavorite(destinationHashHex: String) async {
        await store.removeFavorite(destinationHashHex: destinationHashHex)
    }

    public func renameFavorite(destinationHashHex: String, newName: String) async {
        await store.renameFavorite(destinationHashHex: destinationHashHex, newName: newName)
    }

    public func allNodes() async -> [NomadStore.DiscoveredNode] {
        await store.allNodes()
    }

    public func recordNode(destinationHashHex: String, name: String) async {
        await store.recordNode(destinationHashHex: destinationHashHex, name: name)
    }

    public func removeNode(destinationHashHex: String) async {
        await store.removeNode(destinationHashHex: destinationHashHex)
    }

    public func node(for destinationHashHex: String) async -> NomadStore.DiscoveredNode? {
        await store.node(for: destinationHashHex)
    }
}
