import Testing
import Foundation
@testable import ReticulumPackets


@Suite("Packet — H1 to H2 Transport Conversion")
struct H2TransportRoutingTests {

    private static let testDest = Data(repeating: 0xAA, count: 16)
    private static let testPayload = Data(repeating: 0xCC, count: 67)
    private static let testTransportID = Data(repeating: 0xBB, count: 16)

    private static func makeLinkRequestH1(dest: Data = testDest, payload: Data = testPayload, hops: UInt8 = 0) -> Data {
        let header = PacketHeader(
            packetType: .linkRequest,
            destinationType: .single,
            destinationHash: dest,
            hops: hops,
            context: 0x00
        )
        return Packet(header: header, payload: payload).serialize()
    }

    /// Simulates the H1→H2 conversion done by applyTransportRoutingIfNeeded().
    private func convertH1ToH2(_ h1Raw: Data, transportID: Data = Self.testTransportID) -> Data {
        let originalFlags = h1Raw[h1Raw.startIndex]
        let newFlags: UInt8 =
            (PacketHeader.HeaderType.header2.rawValue << 6) |
            (PacketHeader.PropagationType.transport.rawValue << 4) |
            (originalFlags & 0x0F)

        var routed = Data(capacity: h1Raw.count + 16)
        routed.append(newFlags)
        routed.append(h1Raw[h1Raw.startIndex + 1])
        routed.append(transportID)
        routed.append(h1Raw.dropFirst(2))
        return routed
    }

    @Test("H2 LINKREQUEST has correct flags byte")
    func h2FlagsCorrect() throws {
        let h1Raw = Self.makeLinkRequestH1()
        let h2Raw = convertH1ToH2(h1Raw)

        #expect(h1Raw[0] == 0x02)
        #expect(h2Raw[0] == 0x52)
    }

    @Test("H2 LINKREQUEST is 16 bytes longer than H1")
    func h2SizeCorrect() throws {
        let h1Raw = Self.makeLinkRequestH1()
        let h2Raw = convertH1ToH2(h1Raw)

        #expect(h1Raw.count == 86)
        #expect(h2Raw.count == 102)
        #expect(h2Raw.count == h1Raw.count + 16)
    }

    @Test("H2 transport_id is at bytes 2..17")
    func h2TransportIDPosition() throws {
        let h1Raw = Self.makeLinkRequestH1()
        let h2Raw = convertH1ToH2(h1Raw)

        #expect(Data(h2Raw[2..<18]) == Self.testTransportID)
    }

    @Test("H2 preserves destination hash at bytes 18..33")
    func h2DestinationPreserved() throws {
        let h1Raw = Self.makeLinkRequestH1()
        let h2Raw = convertH1ToH2(h1Raw)

        #expect(Data(h2Raw[18..<34]) == Self.testDest)
    }

    @Test("H2 preserves context and payload after destination")
    func h2PayloadPreserved() throws {
        let h1Raw = Self.makeLinkRequestH1()
        let h2Raw = convertH1ToH2(h1Raw)

        #expect(h2Raw[34] == 0x00)
        #expect(Data(h2Raw[35...]) == Self.testPayload)
    }

    @Test("H2 preserves hops byte")
    func h2HopsPreserved() throws {
        let h1Raw = Self.makeLinkRequestH1(hops: 3)
        let h2Raw = convertH1ToH2(h1Raw)

        #expect(h1Raw[1] == 3)
        #expect(h2Raw[1] == 3)
    }

    @Test("link_id is invariant under H1→H2 conversion")
    func linkIDInvariant() throws {
        let dest = Data((0..<16).map { UInt8($0) })
        let x25519Pub = Data((16..<48).map { UInt8($0) })
        let ed25519Pub = Data((48..<80).map { UInt8($0) })
        let signalling = Data([0x01, 0xF4, 0x20])

        let h1Raw = Self.makeLinkRequestH1(dest: dest, payload: x25519Pub + ed25519Pub + signalling)
        let h2Raw = convertH1ToH2(h1Raw)

        let h1HashablePart = Data([h1Raw[0] & 0x0F]) + h1Raw.dropFirst(2)
        let h2HashablePart = Data([h2Raw[0] & 0x0F]) + h2Raw.dropFirst(18)

        #expect(h1HashablePart == h2HashablePart)
    }

    @Test("H2 flags lower nibble preserved for all packet types")
    func lowerNibblePreserved() throws {
        let dest = Data(repeating: 0xAA, count: 16)
        let payload = Data(repeating: 0xCC, count: 10)

        for packetType: PacketType in [.data, .announce, .linkRequest, .proof] {
            for destType: PacketHeader.DestinationType in [.single, .group, .plain, .link] {
                let header = PacketHeader(
                    packetType: packetType,
                    destinationType: destType,
                    destinationHash: dest,
                    hops: 0,
                    context: 0x00
                )
                let h1Raw = Packet(header: header, payload: payload).serialize()
                let h2Raw = convertH1ToH2(h1Raw)

                let h1Lower = h1Raw[0] & 0x0F
                let h2Lower = h2Raw[0] & 0x0F
                #expect(h1Lower == h2Lower, "Lower nibble mismatch for \(packetType)/\(destType)")
            }
        }
    }
}
