import Testing
import Foundation
@testable import ReticulumInterfaces

@Suite("Reticulum Claims — Interface Layer")
struct ReticulumInterfaceClaimsTests {

    @Test("TCPClientInterface conforms to common ReticulumInterface contract")
    func tcpInterfaceConformance() async {
        let iface = TCPClientInterface(name: "claims", host: "127.0.0.1", port: 1)
        let asProtocol: any ReticulumInterface = iface

        #expect(await asProtocol.name == "claims")
        #expect(await asProtocol.isOnline == false)
    }

    @Test("ReticulumInterface protocol exposes required lifecycle and send methods")
    func interfaceProtocolSurface() async {
        let iface: any ReticulumInterface = TCPClientInterface(name: "claims2", host: "127.0.0.1", port: 1)
        await iface.stop()
        #expect(await iface.isOnline == false)
    }
}
