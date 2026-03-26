import Foundation

/// Abstraction over a physical or virtual Reticulum transport medium.
///
/// Implementations must be `Sendable` so they can be shared across actors.
/// `transmit` is declared `async` so actor-backed implementations can satisfy
/// the requirement with their naturally async dispatch.
public protocol NodeInterface: Sendable {
    /// A stable, unique identifier for this interface (e.g. `"tcp_upstream"`).
    var interfaceID: String { get }

    /// Transmit raw packet bytes onto this interface.
    func transmit(_ data: Data) async
}
