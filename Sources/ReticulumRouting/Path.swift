import Foundation

/// Represents a resolved path to a destination in the Reticulum network.
public struct Path: Sendable, Equatable {

    public let destinationHash:    Data
    public let nextHopInterfaceID: String
    public let hops:               Int
    public let expires:            Date

    public init(
        destinationHash:    Data,
        nextHopInterfaceID: String,
        hops:               Int,
        expires:            Date
    ) {
        self.destinationHash    = destinationHash
        self.nextHopInterfaceID = nextHopInterfaceID
        self.hops               = hops
        self.expires            = expires
    }

    /// `true` once the path's TTL has elapsed.
    public var isExpired: Bool {
        Date() >= expires
    }

    /// Quality metric: higher is better.  Simple reciprocal of hop count.
    public var quality: Double {
        1.0 / Double(max(1, hops))
    }
}
