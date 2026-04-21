import Foundation

public protocol NodeInterface: Sendable {
    /// A stable, unique identifier for this interface (e.g. `"tcp_upstream"`).
    var interfaceID: String { get }

    /// Transmit raw packet bytes onto this interface.
    func transmit(_ data: Data) async
}
