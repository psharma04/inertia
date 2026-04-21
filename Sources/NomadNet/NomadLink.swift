import Foundation

public enum NomadError: Error, Sendable {
    case notImplemented
    case invalidResponse
    case pageNotFound(String)
    case invalidMsgpack
    case nodeUnreachable
    case accessDenied
    case invalidPath(String)
}

public protocol NomadLinkProtocol: Sendable {
    /// Send a msgpack-encoded request and return the raw msgpack response bytes.
    func request(payload: Data) async throws -> Data
}
