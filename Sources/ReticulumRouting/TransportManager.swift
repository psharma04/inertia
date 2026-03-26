import Foundation
import ReticulumPackets

/// Central transport manager coordinating packet routing across interfaces.
///
/// Responsibilities:
/// - Register `NodeInterface` implementations
/// - Receive raw bytes from any interface
/// - Forward ANNOUNCE packets (with hops+1) to all *other* interfaces
/// - Forward DATA packets to the interface indicated by the routing table
public actor TransportManager {

    /// Shared routing table — exposed as `nonisolated let` so callers can
    /// access the `RoutingTable` reference without hopping to `TransportManager`'s
    /// executor (the subsequent actor call on `RoutingTable` itself still requires
    /// `await`).
    public nonisolated let routingTable: RoutingTable

    private var interfaces: [String: any NodeInterface] = [:]
    private let pathTTL:    TimeInterval

    public init(
        routingTable: RoutingTable = RoutingTable(),
        pathTTL:      TimeInterval = 3_600
    ) {
        self.routingTable = routingTable
        self.pathTTL      = pathTTL
    }

    // Interface registration

    /// Register a transport interface.  Later calls with the same `interfaceID`
    /// replace the earlier registration.
    public func register(_ interface: any NodeInterface) {
        interfaces[`interface`.interfaceID] = `interface`
    }

    // Packet reception

    /// Process raw bytes arriving on `fromInterfaceID`.
    public func receive(data: Data, fromInterfaceID: String) async {
        guard let packet = try? Packet.deserialize(from: data) else { return }

        switch packet.header.packetType {
        case .announce:
            await handleAnnounce(packet: packet, fromInterfaceID: fromInterfaceID)
        case .data:
            await handleData(packet: packet, data: data)
        default:
            break
        }
    }

    // Private helpers

    private func handleAnnounce(packet: Packet, fromInterfaceID: String) async {
        // Validate signature before acting on the announce.
        guard
            let payload = try? AnnouncePayload.parse(from: packet.payload),
            payload.verifySignature(destinationHash: packet.header.destinationHash)
        else { return }

        // Update the routing table: to reach the announced destination, forward
        // back via the interface the announce arrived on.
        let hops = Int(packet.header.hops) + 1
        let path = Path(
            destinationHash:    packet.header.destinationHash,
            nextHopInterfaceID: fromInterfaceID,
            hops:               hops,
            expires:            Date(timeIntervalSinceNow: pathTTL)
        )
        await routingTable.insert(path)

        // Forward to all other interfaces with the hop count incremented.
        let newHops = packet.header.hops &+ 1
        let forwardedHeader = PacketHeader(
            packetType:      packet.header.packetType,
            destinationType: packet.header.destinationType,
            destinationHash: packet.header.destinationHash,
            hops:            newHops,
            context:         packet.header.context,
            headerType:      packet.header.headerType,
            propagationType: packet.header.propagationType
        )
        let forwardedPacket = Packet(header: forwardedHeader, payload: packet.payload)
        let forwardedData   = forwardedPacket.serialize()

        for (id, iface) in interfaces where id != fromInterfaceID {
            await iface.transmit(forwardedData)
        }
    }

    private func handleData(packet: Packet, data: Data) async {
        guard
            let path    = await routingTable.path(for: packet.header.destinationHash),
            let nextHop = interfaces[path.nextHopInterfaceID]
        else { return }

        await nextHop.transmit(data)
    }
}
