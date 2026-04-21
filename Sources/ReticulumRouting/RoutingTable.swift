import Foundation

public actor RoutingTable {

    private var table: [Data: Path] = [:]

    public init() {}

    /// Inserts `path`, replacing any existing entry only if the new path has fewer hops.
    public func insert(_ path: Path) {
        if let existing = table[path.destinationHash] {
            guard path.hops < existing.hops else { return }
        }
        table[path.destinationHash] = path
    }

    public func path(for destinationHash: Data) -> Path? {
        table[destinationHash]
    }

    public func removeExpired() {
        let now = Date()
        table = table.filter { $0.value.expires > now }
    }

    public var count: Int { table.count }
}
