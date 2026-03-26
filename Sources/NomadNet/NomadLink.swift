import Foundation

// Errors

public enum NomadError: Error, Sendable {
    case notImplemented
    case invalidResponse
    case pageNotFound(String)
    case invalidMsgpack
    case nodeUnreachable
}

// NomadLinkProtocol

/// Abstracts the Reticulum link used to communicate with a NomadNet node.
///
/// In production, backed by a live RNS link (ECDH key exchange + encrypted
/// channel over the established Reticulum link).
///
/// In tests, replaced with a `MockNomadLink` that exercises the
/// request/response message format without a real network.
///
/// The protocol operates at the application-message layer:
///   - Request payload:  msgpack [timestamp_f64, path_hash_bytes16, form_data | nil]
///   - Response payload: msgpack [request_id_bytes16, content_bytes]
public protocol NomadLinkProtocol: Sendable {
    /// Send a msgpack-encoded request and return the raw msgpack response bytes.
    func request(payload: Data) async throws -> Data
}
