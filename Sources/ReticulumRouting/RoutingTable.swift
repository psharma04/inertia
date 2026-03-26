import Foundation

/// In-memory routing table mapping destination hashes to resolved paths.
///
/// A new path replaces an existing one only when it has strictly fewer hops,
/// matching the Reticulum reference implementation's route-selection logic.
public actor RoutingTable {

    private var table: [Data: Path] = [:]

    public init() {}

    /// Insert `path`, replacing any existing entry for the same destination
    /// only if the new path is strictly better (fewer hops).
    public func insert(_ path: Path) {
        if let existing = table[path.destinationHash] {
            guard path.hops < existing.hops else { return }
        }
        table[path.destinationHash] = path
    }

    /// Returns the stored path for `destinationHash`, or `nil` if unknown.
    public func path(for destinationHash: Data) -> Path? {
        table[destinationHash]
    }

    /// Removes all paths whose TTL has elapsed.
    public func removeExpired() {
        let now = Date()
        table = table.filter { $0.value.expires > now }
    }

    /// Number of paths currently in the table.
    public var count: Int { table.count }
}
