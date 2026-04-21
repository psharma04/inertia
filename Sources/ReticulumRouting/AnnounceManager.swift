import Foundation
import ReticulumPackets

public actor AnnounceManager {

    private let routingTable: RoutingTable
    private var seenRandomHashes: Set<Data> = []
    private let pathTTL: TimeInterval

    public init(
        routingTable: RoutingTable = RoutingTable(),
        pathTTL: TimeInterval = 3_600
    ) {
        self.routingTable = routingTable
        self.pathTTL = pathTTL
    }

    @discardableResult
    public func receive(data: Data, fromInterfaceID: String) async -> Bool {
        guard
            let packet  = try? Packet.deserialize(from: data),
            packet.header.packetType == .announce,
            let payload = try? AnnouncePayload.parse(from: packet.payload)
        else { return false }

        // Deduplication: drop if we've already processed this exact announce.
        guard !seenRandomHashes.contains(payload.randomHash) else { return false }

        // Cryptographic validation.
        let destHash = packet.header.destinationHash
        guard payload.verifySignature(destinationHash: destHash) else { return false }

        // Record as seen and store a path back to the announcing node.
        seenRandomHashes.insert(payload.randomHash)

        let hops = Int(packet.header.hops) + 1
        let path = Path(
            destinationHash: destHash,
            nextHopInterfaceID: fromInterfaceID,
            hops: hops,
            expires: Date(timeIntervalSinceNow: pathTTL)
        )
        await routingTable.insert(path)
        return true
    }

    public func isKnown(destinationHash: Data) async -> Bool {
        await routingTable.path(for: destinationHash) != nil
    }

    public func isDuplicate(data: Data) -> Bool {
        guard
            let packet  = try? Packet.deserialize(from: data),
            packet.header.packetType == .announce,
            let payload = try? AnnouncePayload.parse(from: packet.payload)
        else { return false }
        return seenRandomHashes.contains(payload.randomHash)
    }

    public func path(for destinationHash: Data) async -> Path? {
        await routingTable.path(for: destinationHash)
    }
}
