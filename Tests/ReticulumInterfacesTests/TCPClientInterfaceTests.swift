import Testing
import Foundation
import Darwin
@testable import ReticulumInterfaces

// HDLC Framing
//
// Reticulum's TCPClientInterface frames packets using HDLC:
//   FLAG (0x7E) + escaped_payload + FLAG (0x7E)
//
// Bytes 0x7E and 0x7D inside the payload are escaped as
//   ESC (0x7D) followed by (byte XOR 0x20).

private enum HDLC {
    static let FLAG:     UInt8 = 0x7E
    static let ESC:      UInt8 = 0x7D
    static let ESC_MASK: UInt8 = 0x20

    /// Wrap `data` in an HDLC frame, escaping reserved bytes.
    static func frame(_ data: Data) -> Data {
        var result = Data([FLAG])
        for byte in data {
            if byte == FLAG || byte == ESC {
                result.append(ESC)
                result.append(byte ^ ESC_MASK)
            } else {
                result.append(byte)
            }
        }
        result.append(FLAG)
        return result
    }

    /// Extract the first complete HDLC frame from `buffer`.
    ///
    /// Returns `(payload, remaining)` or `nil` if no complete frame exists yet.
    static func deframe(_ buffer: Data) -> (Data, Data)? {
        let bytes = Array(buffer)
        guard let start = bytes.firstIndex(of: FLAG) else { return nil }
        let searchFrom = start + 1
        guard searchFrom < bytes.count,
              let end = bytes[searchFrom...].firstIndex(of: FLAG) else { return nil }

        var payload = Data()
        var i = searchFrom
        while i < end {
            if bytes[i] == ESC {
                let next = i + 1
                guard next < end else { break }
                payload.append(bytes[next] ^ ESC_MASK)
                i = next + 1
            } else {
                payload.append(bytes[i])
                i += 1
            }
        }
        let remaining = Data(bytes[(end + 1)...])
        return (payload, remaining)
    }
}

// MockTCPServer
//
// An in-process TCP server using POSIX sockets.
//
// Using BSD sockets instead of NWListener avoids:
//   - async listener-ready state transitions (which require Network.framework)
//   - entitlement / sandbox restrictions that can affect NWListener in tests
//
// All I/O runs on a background DispatchQueue; actor isolation protects state.

private actor MockTCPServer {
    private var listenFd:  Int32 = -1
    private var clientFd:  Int32 = -1

    private(set) var port: UInt16 = 0

    // Packets received from the client after HDLC deframing.
    private(set) var receivedPackets: [Data] = []
    private var receiveBuffer = Data()
    // Packets received before any waiter was registered — consumed in FIFO order.
    private var unreadPackets: [Data] = []

    // Cancellable continuations used to wake waiting tests.
    private var connectionWaiters: [UUID: CheckedContinuation<Void, Error>] = [:]
    private var packetWaiters:     [UUID: CheckedContinuation<Data, Error>] = [:]
    private var packetWaiterOrder: [UUID] = []

    private let bgQueue = DispatchQueue(
        label: "mock.tcp.server.bg",
        qos: .userInitiated,
        attributes: .concurrent
    )

    enum MockServerError: Error {
        case socketFailed
        case bindFailed(Int32)
        case listenFailed
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    /// Bind to `specificPort` (or auto-assign if nil), then start accepting.
    func start(on specificPort: UInt16? = nil) throws {
        listenFd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard listenFd >= 0 else { throw MockServerError.socketFailed }

        var yes: Int32 = 1
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &yes,
                   socklen_t(MemoryLayout<Int32>.size))
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEPORT, &yes,
                   socklen_t(MemoryLayout<Int32>.size))

        var addr       = sockaddr_in()
        addr.sin_family      = sa_family_t(AF_INET)
        addr.sin_port        = in_port_t((specificPort ?? 0).bigEndian)
        addr.sin_addr.s_addr = UInt32(0x7F00_0001).bigEndian  // htonl(INADDR_LOOPBACK)

        let bindResult = withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listenFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else { throw MockServerError.bindFailed(errno) }
        guard Darwin.listen(listenFd, 1) == 0 else { throw MockServerError.listenFailed }

        // Read back the auto-assigned port.
        var actualAddr = sockaddr_in()
        var addrLen    = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &actualAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(listenFd, $0, &addrLen)
            }
        }
        port = actualAddr.sin_port.bigEndian  // ntohs

        // Begin blocking accept on the background queue.
        let fd = listenFd
        bgQueue.async { [weak self] in
            let client = Darwin.accept(fd, nil, nil)
            guard client >= 0 else { return }
            Task { await self?.didAccept(fd: client) }
        }
    }

    func stop() {
        for (_, cont) in connectionWaiters { cont.resume(throwing: CancellationError()) }
        connectionWaiters.removeAll()
        for id in packetWaiterOrder { packetWaiters[id]?.resume(throwing: CancellationError()) }
        packetWaiters.removeAll()
        packetWaiterOrder.removeAll()
        closeConnection()
        if listenFd >= 0 {
            Darwin.close(listenFd)
            listenFd = -1
        }
    }

    func closeConnection() {
        if clientFd >= 0 {
            Darwin.close(clientFd)
            clientFd = -1
        }
    }

    // ── Test synchronisation ───────────────────────────────────────────────

    /// Suspends until a client has connected. Throws `CancellationError` if the
    /// calling task is cancelled (e.g. from `withTimeout`).
    func waitForConnection() async throws {
        if clientFd >= 0 { return }
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                if Task.isCancelled {
 cont.resume(throwing: CancellationError())
                } else {
 connectionWaiters[id] = cont
                }
            }
        } onCancel: {
            Task { await self.cancelConnectionWaiter(id: id) }
        }
    }

    private func cancelConnectionWaiter(id: UUID) {
        connectionWaiters.removeValue(forKey: id)?.resume(throwing: CancellationError())
    }

    /// Suspends until the next complete HDLC-deframed packet arrives. Throws
    /// `CancellationError` if the calling task is cancelled.
    func waitForNextPacket() async throws -> Data {
        // Return a buffered packet immediately if one already arrived.
        if !unreadPackets.isEmpty { return unreadPackets.removeFirst() }
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
                if Task.isCancelled {
 cont.resume(throwing: CancellationError())
                } else {
 packetWaiters[id] = cont
 packetWaiterOrder.append(id)
                }
            }
        } onCancel: {
            Task { await self.cancelPacketWaiter(id: id) }
        }
    }

    private func cancelPacketWaiter(id: UUID) {
        if let cont = packetWaiters.removeValue(forKey: id) {
            packetWaiterOrder.removeAll { $0 == id }
            cont.resume(throwing: CancellationError())
        }
    }

    // ── Sending ────────────────────────────────────────────────────────────

    /// Send `packet` to the connected client, wrapped in an HDLC frame.
    func send(packet: Data) {
        let fd     = clientFd
        guard fd >= 0 else { return }
        let framed = HDLC.frame(packet)
        bgQueue.async {
            framed.withUnsafeBytes { ptr in
                _ = Darwin.write(fd, ptr.baseAddress!, framed.count)
            }
        }
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private func didAccept(fd: Int32) {
        clientFd = fd
        let waiters = connectionWaiters
        connectionWaiters.removeAll()
        for (_, cont) in waiters { cont.resume(returning: ()) }
        startReceiving(fd: fd)
    }

    private func startReceiving(fd: Int32) {
        bgQueue.async { [weak self] in
            var buf = [UInt8](repeating: 0, count: 4_096)
            while true {
                let n = Darwin.read(fd, &buf, 4_096)
                guard n > 0 else { break }
                let data = Data(buf[0..<n])
                guard let server = self else { return }
                Task { await server.didReceive(data) }
            }
        }
    }

    private func didReceive(_ data: Data) {
        receiveBuffer.append(data)
        while let (packet, rest) = HDLC.deframe(receiveBuffer) {
            receivedPackets.append(packet)
            if !packetWaiterOrder.isEmpty {
                let firstId = packetWaiterOrder.removeFirst()
                packetWaiters.removeValue(forKey: firstId)?.resume(returning: packet)
            } else {
                unreadPackets.append(packet)
            }
            receiveBuffer = rest
        }
    }
}

// Test timeout helper

private struct TestTimeoutError: Error, CustomStringConvertible {
    let description = "test timed out waiting for async condition"
}

/// Class wrapper that makes `AsyncStream.AsyncIterator` safe for capture in
/// `@Sendable` closures.  `AsyncStream.AsyncIterator` is a non-Sendable struct;
/// wrapping it in a reference type avoids the actor-isolated `mutating async`
/// restriction while keeping sequential access safe for single-consumer use.
private final class IteratorBox<T: Sendable>: @unchecked Sendable {
    private var iterator: AsyncStream<T>.AsyncIterator

    init(_ stream: AsyncStream<T>) {
        iterator = stream.makeAsyncIterator()
    }

    func next() async -> T? {
        await iterator.next()
    }
}

/// Run `operation` with a hard deadline; throws `TestTimeoutError` if it exceeds `seconds`.
private func withTimeout<T: Sendable>(
    seconds: Double = 5,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw TestTimeoutError()
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Suite 1 — Connection Lifecycle
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("TCPClientInterface — Connection Lifecycle")
struct TCPConnectionLifecycleTests {

    @Test("isOnline is false before start() is called")
    func isOnlineFalseBeforeStart() async {
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: 7777)
        #expect(await iface.isOnline == false,
                "isOnline must be false before the interface is started")
    }

    @Test("start() succeeds when a server is listening")
    func startSucceedsWithServer() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: port)

        await #expect(throws: Never.self) { try await iface.start() }

        await iface.stop()
        await server.stop()
    }

    @Test("isOnline is true after a successful start()")
    func isOnlineTrueAfterStart() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: port)
        try await iface.start()

        #expect(await iface.isOnline == true,
                "isOnline must be true immediately after a successful TCP connect")

        await iface.stop()
        await server.stop()
    }

    @Test("stop() sets isOnline to false")
    func stopSetsIsOnlineToFalse() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: port)
        try await iface.start()
        await iface.stop()

        #expect(await iface.isOnline == false,
                "isOnline must be false after stop()")

        await server.stop()
    }

    @Test("stop() before start() does not crash or hang")
    func stopBeforeStartSafe() async {
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: 7777)
        await iface.stop()  // must return without throwing or hanging
    }

    @Test("start() throws when no server is listening on the target port")
    func startThrowsWhenNoServer() async {
        // Port 19_231 is chosen to be free; no server is bound to it.
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: 19_231)
        await #expect(throws: (any Error).self) {
            try await iface.start()
        }
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Suite 2 — Packet Sending
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("TCPClientInterface — Packet Sending")
struct TCPPacketSendingTests {

    @Test("send() before start() throws an error")
    func sendBeforeStartThrows() async {
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: 7777)
        await #expect(throws: (any Error).self) {
            try await iface.send(Data("hello".utf8))
        }
    }

    @Test("send() delivers HDLC-framed bytes that the server can deframe")
    func sendDeliversToServer() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: port)
        try await iface.start()
        try await withTimeout(seconds: 1) { try await server.waitForConnection() }

        let payload = Data("hello reticulum".utf8)
        try await iface.send(payload)

        let received = try await withTimeout(seconds: 1) {
            try await server.waitForNextPacket()
        }
        #expect(received == payload,
                "server should receive exactly the original bytes after HDLC deframing")

        await iface.stop()
        await server.stop()
    }

    @Test("multiple send() calls are received by the server in order")
    func multiplePacketsSentInOrder() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: port)
        try await iface.start()
        try await withTimeout(seconds: 1) { try await server.waitForConnection() }

        let packets = [
            Data("packet one".utf8),
            Data("packet two".utf8),
            Data("packet three".utf8),
        ]
        for p in packets { try await iface.send(p) }

        var received: [Data] = []
        for _ in packets {
            let pkt = try await withTimeout(seconds: 1) { try await server.waitForNextPacket() }
            received.append(pkt)
        }

        #expect(received == packets,
                "all packets must arrive in send() order")

        await iface.stop()
        await server.stop()
    }

    @Test("send() correctly HDLC-escapes payloads that contain flag bytes (0x7E) and escape bytes (0x7D)")
    func sendEscapesReservedBytes() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: port)
        try await iface.start()
        try await withTimeout(seconds: 1) { try await server.waitForConnection() }

        // Payload with raw 0x7E (FLAG) and 0x7D (ESC) — must survive framing round-trip.
        let payload = Data([0x7E, 0x7D, 0xAA, 0x7E, 0x7D])
        try await iface.send(payload)

        let received = try await withTimeout(seconds: 1) { try await server.waitForNextPacket() }
        #expect(received == payload,
                "bytes equal to HDLC FLAG or ESC must be correctly escaped and then unescaped")

        await iface.stop()
        await server.stop()
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Suite 3 — Packet Receiving
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("TCPClientInterface — Packet Receiving")
struct TCPPacketReceivingTests {

    @Test("HDLC-framed data sent by the server triggers the onReceive handler")
    func serverDataTriggersReceiveHandler() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: port)

        // Wire up the receive handler before connecting.
        let (stream, continuation) = AsyncStream<Data>.makeStream()
        await iface.setOnReceive { data in
            continuation.yield(data)
        }

        try await iface.start()
        try await withTimeout(seconds: 1) { try await server.waitForConnection() }

        let expected = Data("hello from server".utf8)
        await server.send(packet: expected)

        let consumer = IteratorBox(stream)
        let actual = try await withTimeout(seconds: 1) { await consumer.next()! }

        #expect(actual == expected,
                "onReceive must be called with the exact (HDLC-deframed) server bytes")

        continuation.finish()
        await iface.stop()
        await server.stop()
    }

    @Test("each server frame triggers a separate onReceive invocation")
    func eachFrameTriggersSeparateCallback() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: port)

        let (stream, continuation) = AsyncStream<Data>.makeStream()
        await iface.setOnReceive { data in
            continuation.yield(data)
        }

        try await iface.start()
        try await withTimeout(seconds: 1) { try await server.waitForConnection() }

        let frames = [Data([0x01, 0x02]), Data([0x03, 0x04]), Data([0x05, 0x06])]
        for f in frames { await server.send(packet: f) }

        var received: [Data] = []
        let consumer = IteratorBox(stream)
        for _ in frames {
            let pkt = try await withTimeout(seconds: 1) { await consumer.next()! }
            received.append(pkt)
        }

        #expect(received == frames,
                "each server frame must produce exactly one distinct onReceive invocation")

        continuation.finish()
        await iface.stop()
        await server.stop()
    }

    @Test("received bytes containing HDLC special values are correctly unescaped")
    func receivedBytesUnescaped() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(name: "test", host: "127.0.0.1", port: port)

        let (stream, continuation) = AsyncStream<Data>.makeStream()
        await iface.setOnReceive { data in continuation.yield(data) }

        try await iface.start()
        try await withTimeout(seconds: 1) { try await server.waitForConnection() }

        // Send a payload that contains 0x7E and 0x7D — MockTCPServer frames it for us.
        let expected = Data([0x7E, 0x7D, 0xFF, 0x7D, 0x7E])
        await server.send(packet: expected)

        let consumer = IteratorBox(stream)
        let actual = try await withTimeout(seconds: 1) { await consumer.next()! }

        #expect(actual == expected,
                "HDLC-escaped received bytes must be correctly unescaped before delivery")

        continuation.finish()
        await iface.stop()
        await server.stop()
    }
}

// MARK: ─────────────────────────────────────────────────────────────────────
// MARK: Suite 4 — Reconnection
// MARK: ─────────────────────────────────────────────────────────────────────

@Suite("TCPClientInterface — Reconnection")
struct TCPReconnectionTests {

    @Test("isOnline transitions to false when the server closes the connection")
    func isOnlineFalseAfterServerDisconnect() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        // Large reconnectDelay prevents an auto-reconnect during this short test.
        let iface = TCPClientInterface(
            name: "test",
            host: "127.0.0.1",
            port: port,
            reconnectDelay: 60
        )
        try await iface.start()
        try await withTimeout(seconds: 1) { try await server.waitForConnection() }
        #expect(await iface.isOnline == true)

        await server.closeConnection()
        await server.stop()

        // Poll for up to 3 s for isOnline to drop to false.
        var online = true
        for _ in 0..<10 {
            try await Task.sleep(for: .milliseconds(100))
            online = await iface.isOnline
            if !online { break }
        }

        #expect(online == false,
                "isOnline must transition to false within 3 s after the server drops the connection")

        await iface.stop()
    }

    @Test("after explicit stop(), isOnline stays false even if server restarts")
    func noAutoReconnectAfterExplicitStop() async throws {
        let server = MockTCPServer()
        try await server.start()

        let port = await server.port
        let iface = TCPClientInterface(
            name: "test",
            host: "127.0.0.1",
            port: port,
            reconnectDelay: 0.1
        )
        try await iface.start()
        try await withTimeout(seconds: 1) { try await server.waitForConnection() }

        await iface.stop()     // explicit stop — must suppress further reconnects

        // Give the reconnect timer more than enough time to fire if it were enabled.
        try await Task.sleep(for: .milliseconds(500))

        #expect(await iface.isOnline == false,
                "after explicit stop(), the interface must not auto-reconnect")

        await server.stop()
    }

    @Test("interface automatically reconnects after the server restarts on the same port")
    func autoReconnectsAfterServerRestart() async throws {
        // Bind to a specific port so we can restart on the same address.
        let server1 = MockTCPServer()
        try await server1.start()
        let port = await server1.port

        let iface = TCPClientInterface(
            name: "test",
            host: "127.0.0.1",
            port: port,
            reconnectDelay: 0.2   // fast retry for testing
        )
        try await iface.start()
        try await withTimeout(seconds: 1) { try await server1.waitForConnection() }
        #expect(await iface.isOnline == true)

        // Simulate a server crash.
        await server1.stop()

        // Wait for the interface to detect the disconnect.
        try await Task.sleep(for: .milliseconds(300))

        // Restart a fresh server on the same port.
        let server2 = MockTCPServer()
        try await server2.start(on: port)

        // Poll for the interface to reconnect (up to 3 s).
        var online = false
        for _ in 0..<10 {
            try await Task.sleep(for: .milliseconds(100))
            online = await iface.isOnline
            if online { break }
        }

        #expect(online == true,
                "TCPClientInterface must auto-reconnect when the server restarts on the same port")

        await iface.stop()
        await server2.stop()
    }
}
