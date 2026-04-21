import Testing
import Foundation
@testable import Persistence
@testable import NomadNet

@Suite("NomadStore — Default Bookmarks")
struct NomadStoreDefaultBookmarksTests {

    @Test("Default favorites include the Inertia node")
    func defaultFavoritesIncludeInertia() {
        let defaults = NomadStore.defaultFavorites
        let inertia = defaults.first { $0.destinationHashHex == "1e12dc236a05c930bd2c9190a2940ce7" }
        #expect(inertia != nil, "Inertia node should be in default favorites")
        #expect(inertia?.customName == "Inertia")
    }

    @Test("Fresh NomadStore seeds default favorites when file is empty")
    func freshStoreHasDefaultFavorites() async {
        let store = NomadStore()
        let favorites = await store.allFavorites()
        #expect(!favorites.isEmpty, "Fresh store should have seeded default favorites")
        let hasInertia = favorites.contains { $0.destinationHashHex == "1e12dc236a05c930bd2c9190a2940ce7" }
        #expect(hasInertia)
    }
}

// MARK: - Helpers

private func makeTempDir() -> URL {
    let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("NomadStoreTests-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    return tmp
}

private func cleanUp(_ url: URL) {
    try? FileManager.default.removeItem(at: url)
}

private func makeStore(dir: URL) -> NomadStore {
    NomadStore(
        pageCacheDir: dir.appendingPathComponent("pages", isDirectory: true),
        favoritesFile: dir.appendingPathComponent("favorites.json"),
        nodeDirectoryFile: dir.appendingPathComponent("nodes.json")
    )
}

@Suite("NomadStore — Favorites CRUD")
struct NomadStoreFavoritesTests {

    @Test("Add and retrieve a favorite")
    func addAndRetrieve() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        let fav = NomadStore.NodeFavorite(destinationHashHex: "aabbccdd", customName: "Test Node")
        await store.addFavorite(fav)

        let all = await store.allFavorites()
        #expect(all.count == 1)
        #expect(all.first?.destinationHashHex == "aabbccdd")
        #expect(all.first?.customName == "Test Node")
    }

    @Test("isFavorite returns correct results")
    func isFavoriteCheck() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        let fav = NomadStore.NodeFavorite(destinationHashHex: "aabbccdd")
        await store.addFavorite(fav)

        let yes = await store.isFavorite(destinationHashHex: "aabbccdd")
        let no = await store.isFavorite(destinationHashHex: "11223344")
        #expect(yes == true)
        #expect(no == false)
    }

    @Test("Remove favorite")
    func removeFavorite() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        await store.addFavorite(NomadStore.NodeFavorite(destinationHashHex: "aabb"))
        await store.addFavorite(NomadStore.NodeFavorite(destinationHashHex: "ccdd"))
        await store.removeFavorite(destinationHashHex: "aabb")

        let all = await store.allFavorites()
        #expect(all.count == 1)
        #expect(all.first?.destinationHashHex == "ccdd")
    }

    @Test("Rename favorite")
    func renameFavorite() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        await store.addFavorite(NomadStore.NodeFavorite(destinationHashHex: "aabb", customName: "Old"))
        await store.renameFavorite(destinationHashHex: "aabb", newName: "New")

        let all = await store.allFavorites()
        #expect(all.first?.customName == "New")
    }

    @Test("Add duplicate favorite updates instead of duplicating")
    func addDuplicateUpdates() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        await store.addFavorite(NomadStore.NodeFavorite(destinationHashHex: "aabb", customName: "V1"))
        await store.addFavorite(NomadStore.NodeFavorite(destinationHashHex: "aabb", customName: "V2"))

        let all = await store.allFavorites()
        #expect(all.count == 1)
        #expect(all.first?.customName == "V2")
    }

    @Test("Favorites persist across store instances")
    func favoritesPersistAcrossInstances() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }

        let store1 = makeStore(dir: dir)
        await store1.addFavorite(NomadStore.NodeFavorite(destinationHashHex: "beef", customName: "Persistent"))

        let store2 = makeStore(dir: dir)
        let all = await store2.allFavorites()
        #expect(all.count == 1)
        #expect(all.first?.customName == "Persistent")
    }
}

@Suite("NomadStore — Page Cache")
struct NomadStorePageCacheTests {

    @Test("Save and fetch a cached page")
    func saveAndFetch() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        let page = NomadPage(
            path: "/page/index.mu",
            requestID: Data(repeating: 0xAB, count: 16),
            content: Data("Hello World".utf8)
        )
        await store.save(page: page, destinationHashHex: "deadbeef")

        let fetched = await store.fetchPage(destinationHashHex: "deadbeef", path: "/page/index.mu")
        #expect(fetched != nil)
        #expect(fetched?.contentString == "Hello World")
    }

    @Test("Cache miss for unknown page returns nil")
    func cacheMiss() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        let result = await store.fetchPage(destinationHashHex: "aabb", path: "/nonexistent")
        #expect(result == nil)
    }

    @Test("clearCache removes all cached pages")
    func clearCache() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        let page = NomadPage(path: "/a", requestID: Data(count: 16), content: Data("A".utf8))
        await store.save(page: page, destinationHashHex: "aa")

        await store.clearCache()
        let result = await store.fetchPage(destinationHashHex: "aa", path: "/a")
        #expect(result == nil)
    }

    @Test("Corrupted JSON file is treated as cache miss")
    func corruptedJSON() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        // Save a valid page first, then corrupt the file
        let page = NomadPage(path: "/b", requestID: Data(count: 16), content: Data("B".utf8))
        await store.save(page: page, destinationHashHex: "bb")

        // Corrupt every json file in the cache dir
        let cacheDir = dir.appendingPathComponent("pages", isDirectory: true)
        if let files = try? FileManager.default.contentsOfDirectory(at: cacheDir, includingPropertiesForKeys: nil) {
            for file in files where file.pathExtension == "json" {
                try? Data("NOT JSON".utf8).write(to: file)
            }
        }

        let result = await store.fetchPage(destinationHashHex: "bb", path: "/b")
        #expect(result == nil, "Corrupted JSON should return nil, not crash")
    }
}

@Suite("NomadStore — Node Directory")
struct NomadStoreNodeDirectoryTests {

    @Test("Record and retrieve a discovered node")
    func recordAndRetrieve() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        await store.recordNode(destinationHashHex: "AABB", name: "Test Node")
        let node = await store.node(for: "aabb")
        #expect(node != nil)
        #expect(node?.name == "Test Node")
    }

    @Test("Recording same node updates name and lastSeen")
    func recordUpdates() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        await store.recordNode(destinationHashHex: "aabb", name: "V1")
        await store.recordNode(destinationHashHex: "aabb", name: "V2")

        let nodes = await store.allNodes()
        #expect(nodes.count == 1)
        #expect(nodes.first?.name == "V2")
    }

    @Test("Remove node")
    func removeNode() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        await store.recordNode(destinationHashHex: "aabb", name: "Gone")
        await store.removeNode(destinationHashHex: "aabb")

        let node = await store.node(for: "aabb")
        #expect(node == nil)
    }

    @Test("allNodes returns sorted by lastSeen descending")
    func allNodesSorted() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }
        let store = makeStore(dir: dir)

        await store.recordNode(destinationHashHex: "aaaa", name: "First")
        try? await Task.sleep(for: .milliseconds(50))
        await store.recordNode(destinationHashHex: "bbbb", name: "Second")

        let nodes = await store.allNodes()
        #expect(nodes.count == 2)
        #expect(nodes.first?.destinationHashHex == "bbbb", "Most recently seen should be first")
    }

    @Test("Nodes persist across store instances")
    func nodesPersist() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }

        let store1 = makeStore(dir: dir)
        await store1.recordNode(destinationHashHex: "face", name: "Persistent")

        let store2 = makeStore(dir: dir)
        let node = await store2.node(for: "face")
        #expect(node?.name == "Persistent")
    }

    @Test("Corrupted favorites file yields empty list, not crash")
    func corruptedFavorites() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }

        let favFile = dir.appendingPathComponent("favorites.json")
        try? Data("NOT VALID JSON!!!".utf8).write(to: favFile)

        let store = makeStore(dir: dir)
        let all = await store.allFavorites()
        #expect(all.isEmpty, "Corrupted file should yield empty, not crash")
    }

    @Test("Corrupted nodes file yields empty list, not crash")
    func corruptedNodes() async {
        let dir = makeTempDir()
        defer { cleanUp(dir) }

        let nodeFile = dir.appendingPathComponent("nodes.json")
        try? Data("{bad json".utf8).write(to: nodeFile)

        let store = makeStore(dir: dir)
        let nodes = await store.allNodes()
        #expect(nodes.isEmpty, "Corrupted file should yield empty, not crash")
    }
}
