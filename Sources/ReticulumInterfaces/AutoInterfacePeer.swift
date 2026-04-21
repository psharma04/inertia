import Foundation
import Darwin
import ReticulumCrypto

public actor AutoInterfacePeer: ReticulumInterface {

    public let name: String
    let peerAddr: String
    let ifname: String

    public private(set) var isOnline: Bool = false

    private let dataPort: UInt16
    private var cachedSin6: sockaddr_in6? = nil
    private let sendQueue: DispatchQueue
    private let outboundSocketFD: Int32
    private let onReceive: (@Sendable (Data, AutoInterfacePeer) async -> Void)?
    private let isDuplicate: @Sendable (Data, Date) async -> Bool

    init(
        parentName: String,
        peerAddr: String,
        ifname: String,
        dataPort: UInt16,
        sendQueue: DispatchQueue,
        outboundSocketFD: Int32,
        onReceive: (@Sendable (Data, AutoInterfacePeer) async -> Void)?,
        mifDeque: @escaping @Sendable (Data, Date) async -> Bool
    ) {
        self.name = "AutoInterface[\(parentName)]/\(ifname)/\(peerAddr)"
        self.peerAddr = peerAddr
        self.ifname = ifname
        self.dataPort = dataPort
        self.sendQueue = sendQueue
        self.outboundSocketFD = outboundSocketFD
        self.onReceive = onReceive
        self.isDuplicate = mifDeque
    }

    public func start() async throws {
        isOnline = true
    }

    public func stop() async {
        isOnline = false
    }

    public func send(_ data: Data) async throws {
        guard isOnline else { throw AutoInterfaceError.offline }

        let sin6 = try resolveSockAddr()
        let queue = sendQueue
        let payload = data
        let fd = outboundSocketFD

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async {
                guard fd >= 0 else {
                    cont.resume(throwing: AutoInterfaceError.socketFailed)
                    return
                }
                var dest = sin6
                let result = payload.withUnsafeBytes { buf in
                    withUnsafePointer(to: &dest) { saPtr in
                        saPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                            sendto(fd, buf.baseAddress!, buf.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                        }
                    }
                }
                if result < 0 {
                    cont.resume(throwing: AutoInterfaceError.sendFailed(errno))
                } else {
                    cont.resume()
                }
            }
        }
    }

    func processIncoming(_ data: Data) async {
        guard isOnline else { return }

        let dataHash = Hashing.sha256(data)
        let now = Date()

        if await isDuplicate(dataHash, now) { return }

        if let handler = onReceive {
            await handler(data, self)
        }
    }

    private func resolveSockAddr() throws -> sockaddr_in6 {
        if let cached = cachedSin6 { return cached }

        let scopedAddr = "\(peerAddr)%\(ifname)"
        var sin6 = sockaddr_in6()
        guard AutoInterface.fillSockAddr6(&sin6, address: scopedAddr, port: dataPort) else {
            throw AutoInterfaceError.addressResolutionFailed
        }
        cachedSin6 = sin6
        return sin6
    }
}

extension AutoInterfaceError {
    static func sendFailed(_ code: Int32) -> AutoInterfaceError { .udpSendFailed(code) }
}
