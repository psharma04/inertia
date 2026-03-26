import Testing
import Foundation
@testable import ReticulumPackets

@Suite("Reticulum Claims — Packet Format")
struct ReticulumPacketClaimsTests {

    @Test("Packet header carries destination metadata only (no source field)")
    func packetHeaderNoSourceAddress() {
        #expect(PacketHeader.serializedLength == 19)

        let destination = Data(repeating: 0x11, count: 16)
        let header = PacketHeader(
            packetType: .data,
            destinationType: .single,
            destinationHash: destination,
            hops: 2,
            context: 0x00
        )
        let bytes = header.serialize()

        #expect(bytes.count == 19)
        #expect(Data(bytes[2..<18]) == destination)
        #expect(bytes[1] == 2)
    }

    @Test("Packet type set includes DATA, ANNOUNCE, LINKREQUEST, PROOF")
    func packetTypesPresent() {
        #expect(PacketType.data.rawValue == 0x00)
        #expect(PacketType.announce.rawValue == 0x01)
        #expect(PacketType.linkRequest.rawValue == 0x02)
        #expect(PacketType.proof.rawValue == 0x03)
    }
}
