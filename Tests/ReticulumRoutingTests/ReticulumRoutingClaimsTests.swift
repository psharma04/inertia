import Testing
import Foundation
@testable import ReticulumRouting
@testable import ReticulumPackets

private actor ClaimsMockInterface: NodeInterface {
    let interfaceID: String
    private(set) var sent: [Data] = []

    init(_ id: String) { self.interfaceID = id }

    func transmit(_ data: Data) {
        sent.append(data)
    }

    var sentPackets: [Packet] {
        sent.compactMap { try? Packet.deserialize(from: $0) }
    }
}

@Suite("Reticulum Claims — Routing & Interfaces")
struct ReticulumRoutingClaimsTests {

    private func announceRaw() throws -> Data {
        let fixture = try RoutingFixtureLoader.load(subdir: "announces", name: "announce_basic.json")
        return try fixture.hexData(at: "expected.raw_hex")
    }

    private func announceDestHash() throws -> Data {
        let fixture = try RoutingFixtureLoader.load(subdir: "announces", name: "announce_basic.json")
        return try fixture.hexData(at: "expected.destination_hash_hex")
    }

    @Test("Path discovery is hop-aware and self-configuring from announces")
    func pathDiscoveryFromAnnounce() async throws {
        let manager = AnnounceManager()
        let accepted = await manager.receive(data: try announceRaw(), fromInterfaceID: "if_upstream")
        #expect(accepted)

        let path = await manager.path(for: try announceDestHash())
        #expect(path != nil)
        #expect(path?.nextHopInterfaceID == "if_upstream")
        #expect(path?.hops == 1)
    }

    @Test("Transport forwards announces across heterogeneous interfaces")
    func announceForwardingAcrossInterfaces() async throws {
        let transport = TransportManager()
        let tcp = ClaimsMockInterface("tcp")
        let radio = ClaimsMockInterface("radio")

        await transport.register(tcp)
        await transport.register(radio)
        await transport.receive(data: try announceRaw(), fromInterfaceID: "tcp")

        let forwarded = await radio.sentPackets
        #expect(forwarded.count == 1)
        #expect(forwarded[0].header.packetType == .announce)
        #expect(forwarded[0].header.hops == 1)
    }

    @Test("Transport forwards DATA to known next hop only")
    func dataForwardedToKnownRoute() async {
        let transport = TransportManager()
        let ingress = ClaimsMockInterface("ingress")
        let egress = ClaimsMockInterface("egress")
        await transport.register(ingress)
        await transport.register(egress)

        let destination = Data(repeating: 0x55, count: 16)
        let path = Path(destinationHash: destination, nextHopInterfaceID: "egress", hops: 1, expires: .distantFuture)
        await transport.routingTable.insert(path)

        let packet = Packet(
            header: PacketHeader(packetType: .data, destinationType: .single, destinationHash: destination, hops: 0, context: 0x00),
            payload: Data("hello".utf8)
        ).serialize()
        await transport.receive(data: packet, fromInterfaceID: "ingress")

        #expect(await egress.sent.count == 1)
        #expect(await ingress.sent.isEmpty)
    }

    @Test("Routing table prefers better path quality (fewer hops)")
    func betterPathWins() async {
        let table = RoutingTable()
        let dest = Data(repeating: 0x22, count: 16)

        await table.insert(Path(destinationHash: dest, nextHopInterfaceID: "if_slow", hops: 5, expires: .distantFuture))
        await table.insert(Path(destinationHash: dest, nextHopInterfaceID: "if_fast", hops: 1, expires: .distantFuture))

        let selected = await table.path(for: dest)
        #expect(selected?.nextHopInterfaceID == "if_fast")
        #expect(selected?.hops == 1)
    }

    @Test("Routing table expires stale paths")
    func pathExpiry() async {
        let table = RoutingTable()
        let dest = Data(repeating: 0x33, count: 16)
        await table.insert(Path(destinationHash: dest, nextHopInterfaceID: "if_x", hops: 1, expires: Date(timeIntervalSinceNow: -1)))
        await table.removeExpired()
        #expect(await table.path(for: dest) == nil)
    }
}
