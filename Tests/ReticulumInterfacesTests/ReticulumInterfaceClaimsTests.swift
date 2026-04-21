import Testing
import Foundation
@testable import ReticulumInterfaces

@Suite("Reticulum Claims — Interface Layer")
struct ReticulumInterfaceClaimsTests {

    @Test("TCPClientInterface conforms to MessageTransportInterface contract")
    func tcpInterfaceConformance() async {
        let iface = TCPClientInterface(name: "claims", host: "127.0.0.1", port: 1)
        let asProtocol: any MessageTransportInterface = iface

        #expect(await asProtocol.name == "claims")
        #expect(await asProtocol.isOnline == false)
    }

    @Test("MessageTransportInterface protocol exposes required lifecycle and send methods")
    func interfaceProtocolSurface() async {
        let iface: any MessageTransportInterface = TCPClientInterface(name: "claims2", host: "127.0.0.1", port: 1)
        await iface.stop()
        #expect(await iface.isOnline == false)
    }
}
