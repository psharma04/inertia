import Foundation

/// Common protocol all Reticulum transport interfaces must conform to.
public protocol ReticulumInterface: Actor {
    var name: String { get }
    var isOnline: Bool { get }

    func start() async throws
    func stop() async
    func send(_ data: Data) async throws
}
