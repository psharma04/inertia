import Foundation
import Darwin
import os.log
import ReticulumCrypto
import ReticulumPackets

private let tcpLog = OSLog(subsystem: "chat.inertia.app", category: "tcp-interface")

private extension Data {
    /// Compact lowercase hex string for logging.
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

public actor TCPClientInterface: MessageTransportInterface {
    public let name: String
    public private(set) var isOnline: Bool = false

    private let host:           String
    private let port:           UInt16
    private let reconnectDelay: TimeInterval

    private var onReceive: (@Sendable (Data) async -> Void)?

    private var sockFd:        Int32 = -1
    private var receiveBuffer: Data  = Data()
    private var stopped             = false
    private var reconnectTask:       Task<Void, Never>?

    private var identityCache: [Data: Data] = [:]
    private var publicKeyWaiters: [Data: [(id: UUID, cont: CheckedContinuation<Data?, Never>)]] = [:]
    private var linkStates: [Data: Data] = [:]  // link_id → 64-byte derived key
    private var linkSigner: (@Sendable (Data) async -> Data?)?

    public func setLinkSigner(_ signer: @escaping @Sendable (Data) async -> Data?) {
        self.linkSigner = signer
    }

    private let receiveQueue = DispatchQueue(
        label: "reticulum.tcp.client.receive",
        qos:   .userInitiated
    )
    private let sendQueue = DispatchQueue(
        label: "reticulum.tcp.client.send",
        qos:   .userInitiated
    )

    // HDLC framing constants (RFC 1662 / Reticulum wire format)
    private static let hdlcFLAG:     UInt8 = 0x7E
    private static let hdlcESC:      UInt8 = 0x7D
    private static let hdlcESC_MASK: UInt8 = 0x20

    public enum TCPError: Error {
        case socketFailed
        case resolveFailed
        case connectFailed(Int32)
        case notConnected
        case writeFailed
        case noPathToDestination
    }

    public init(
        name:           String,
        host:           String,
        port:           UInt16,
        reconnectDelay: TimeInterval = 5.0
    ) {
        self.name           = name
        self.host           = host
        self.port           = port
        self.reconnectDelay = reconnectDelay
    }

    public func setOnReceive(_ handler: @escaping @Sendable (Data) async -> Void) {
        onReceive = handler
    }

    // MARK: - ReticulumInterface

    public func start() async throws {
        stopped = false
        reconnectTask?.cancel()
        reconnectTask = nil
        try await connectOnce()
    }

    public func stop() async {
        stopped = true
        reconnectTask?.cancel()
        reconnectTask = nil
        closeSocket()
    }

    public func seedIdentityCache(destinationHash: Data, publicKey: Data) {
        if identityCache[destinationHash] == nil {
            identityCache[destinationHash] = publicKey
            print("[TCP/\(name)] Seeded identity cache: dest=\(destinationHash.hex.prefix(8))…")
        }
        resumeWaiters(destinationHash: destinationHash, publicKey: publicKey)
    }

    public func establishLink(linkId: Data, derivedKey: Data) {
        linkStates[linkId] = derivedKey
        print("[TCP/\(name)] Link registered id=\(linkId.hex.prefix(8))…")
    }

    public func removeLink(linkId: Data) {
        linkStates.removeValue(forKey: linkId)
    }

    public func identityPublicKey(for destinationHash: Data) -> Data? {
        identityCache[destinationHash]
    }

    public func waitForIdentityPublicKey(destinationHash: Data, timeout: TimeInterval = 30) async -> Data? {
        await waitForPublicKey(destinationHash: destinationHash, timeout: timeout)
    }

    public func send(_ data: Data) async throws {
        guard isOnline, sockFd >= 0 else { throw TCPError.notConnected }

        // Log the outgoing packet for diagnostics.
        if let packet = try? Packet.deserialize(from: data) {
            let isH2 = packet.header.headerType == .header2
            let actualDest: Data
            let effectivePayload: Data
            if isH2 {
                guard packet.payload.count >= 16 else { return }
                actualDest = Data([packet.header.context]) + packet.payload.prefix(15)
                effectivePayload = Data(packet.payload.dropFirst(16))
            } else {
                actualDest = Data(packet.header.destinationHash)
                effectivePayload = packet.payload
            }
            let headerHex = String(data.prefix(min(PacketHeader.serializedLength, data.count)).hex.prefix(38))
            print(
                "[TCP/\(name)] TX \(packet.header.packetType) H\(isH2 ? "2" : "1") " +
                "destType=\(packet.header.destinationType) hops=\(packet.header.hops) ctx=\(String(format: "0x%02X", packet.header.context)) " +
                "dest=\(actualDest.hex.prefix(8))… rawDest=\(Data(packet.header.destinationHash).hex.prefix(8))… " +
                "payload=\(effectivePayload.count)B header=\(headerHex)…"
            )
        }

        let fd     = sockFd
        let queue  = sendQueue
        let framed = Self.hdlcFrame(data)
        // Wire-level TX hex dump
        let txHex = data.prefix(min(40, data.count)).map { String(format: "%02x", $0) }.joined(separator: " ")
        os_log("RAW TCP TX %d bytes (framed %d): %{public}@%{public}@", log: OSLog(subsystem: "chat.inertia.tcp", category: "wire"), type: .default,
               data.count, framed.count, txHex, data.count > 40 ? "…" : "")
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async {
                var offset = 0
                while offset < framed.count {
 let written = framed.withUnsafeBytes { ptr -> Int in
     write(fd,
           ptr.baseAddress!.advanced(by: offset),
           framed.count - offset)
 }
 guard written > 0 else {
     cont.resume(throwing: TCPError.writeFailed)
     return
 }
 offset += written
                }
                cont.resume()
            }
        }
    }

    // MARK: - Connection Lifecycle

    private func connectOnce() async throws {
        guard !stopped else { throw TCPError.notConnected }
        let host  = self.host
        let port  = self.port
        let queue = receiveQueue

        let fd = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Int32, Error>) in
            queue.async {
                do {
 let fd = try Self.rawConnect(host: host, port: port)
 cont.resume(returning: fd)
                } catch {
 cont.resume(throwing: error)
                }
            }
        }

        if stopped {
            _ = Darwin.close(fd)
            throw TCPError.notConnected
        }

        sockFd    = fd
        isOnline  = true
        startReceiving(fd: fd)
    }

    private func closeSocket() {
        isOnline      = false
        let fd        = sockFd
        sockFd        = -1
        receiveBuffer = Data()
        if fd >= 0 { _ = Darwin.close(fd) }
    }

    // MARK: - Receive Loop

    private func startReceiving(fd: Int32) {
        receiveQueue.async { [weak self] in
            var buf = [UInt8](repeating: 0, count: 4_096)
            var deliveryTask: Task<Void, Never>? = nil
            while true {
                let n = read(fd, &buf, buf.count)
                guard n > 0 else {
 guard let self else { return }
 if let deliveryTask {
     Task {
         await deliveryTask.value
         await self.handleDisconnect(fd: fd)
     }
 } else {
     Task { await self.handleDisconnect(fd: fd) }
 }
 return
                }
                let data = Data(buf[0..<n])
                guard let self else { return }
                // Raw TCP hex dump for wire-level diagnostics
                let hexSnippet = data.prefix(min(40, data.count)).map { String(format: "%02x", $0) }.joined(separator: " ")
                os_log("RAW TCP RX %d bytes: %{public}@%{public}@", log: OSLog(subsystem: "chat.inertia.tcp", category: "wire"), type: .default,
                       n, hexSnippet, n > 40 ? "…" : "")
                // Check for LRPROOF flag pattern (0x0F after HDLC flag 0x7E)
                for i in 0..<(n-1) {
                    if buf[i] == 0x7E && buf[i+1] == 0x0F {
                        os_log("⚡ RAW TCP: possible LRPROOF at offset %d (0x7E 0x0F)", log: OSLog(subsystem: "chat.inertia.tcp", category: "wire"), type: .default, i)
                    }
                }
                // Preserve strict receive ordering. Chaining each chunk behind the
                // previous processing task prevents actor-message reordering under load.
                let previousTask = deliveryTask
                deliveryTask = Task {
 if let previousTask {
     await previousTask.value
 }
 await self.didReceive(data)
                }
            }
        }
    }

    private func handleDisconnect(fd: Int32) {
        guard fd == sockFd else { return }   // stale notification after reconnect
        isOnline      = false
        sockFd        = -1
        receiveBuffer = Data()
        guard !stopped else { return }
        scheduleReconnect()
    }

    private func didReceive(_ data: Data) {
        receiveBuffer.append(data)
        while let (packet, rest) = Self.hdlcDeframe(receiveBuffer) {
            receiveBuffer = rest
            os_log("HDLC deframed %d bytes, flags=0x%02X", log: tcpLog, type: .default, packet.count, packet.first ?? 0)
            // For HEADER_2 packets, reconstruct destination from context + payload prefix.
            guard let parsed = try? Packet.deserialize(from: packet) else {
                os_log("⚠️ Packet.deserialize FAILED on %d bytes: %{public}@", log: tcpLog, type: .error, packet.count, packet.prefix(min(40, packet.count)).hex)
                if let handler = onReceive {
 Task { await handler(packet) }
                }
                continue
            }

            let isH2 = parsed.header.headerType == .header2
            let destHash: Data
            let effectivePayload: Data
            if isH2 {
                guard parsed.payload.count >= 16 else {
                    os_log("H2 payload too short (%d bytes), dropping", log: tcpLog, type: .error, parsed.payload.count)
                    continue
                }
                destHash        = Data([parsed.header.context]) + parsed.payload.prefix(15)
                effectivePayload = Data(parsed.payload.dropFirst(16))
            } else {
                destHash        = Data(parsed.header.destinationHash)
                effectivePayload = parsed.payload
            }
            let headerHex = String(packet.prefix(min(PacketHeader.serializedLength, packet.count)).hex.prefix(38))
            os_log("RX pktType=%d destType=%d H%{public}@ dest=%{public}@ ctx=0x%02X %dB", log: tcpLog, type: .default,
                   parsed.header.packetType.rawValue, parsed.header.destinationType.rawValue,
                   isH2 ? "2" : "1", destHash.hex.prefix(8).description, parsed.header.context, effectivePayload.count)
            print(
                "[TCP/\(name)] RX \(parsed.header.packetType) H\(isH2 ? "2" : "1") " +
                "destType=\(parsed.header.destinationType) hops=\(parsed.header.hops) ctx=\(String(format: "0x%02X", parsed.header.context)) " +
                "dest=\(destHash.hex.prefix(8))… rawDest=\(Data(parsed.header.destinationHash).hex.prefix(8))… " +
                "payload=\(effectivePayload.count)B header=\(headerHex)…"
            )

            switch parsed.header.packetType {

            case .announce where effectivePayload.count >= 64:
                let pubKey = Data(effectivePayload.prefix(64))
                let isNew = identityCache[destHash] == nil
                storeIdentity(destinationHash: destHash, publicKey: pubKey)
                print("[TCP/\(name)] RX ANNOUNCE \(isH2 ? "H2" : "H1") dest=\(destHash.hex.prefix(8))… pubKey=\(pubKey.prefix(4).hex)… \(isNew ? "(new)" : "(refresh)")")

            case .data where parsed.header.destinationType == .link:
                // Link DATA packet handling.
                let context: UInt8
                if isH2 {
 context = parsed.payload.count > 15
     ? parsed.payload[parsed.payload.startIndex + 15]
     : parsed.header.context
                } else {
 context = parsed.header.context
                }
                let linkData = effectivePayload
                os_log("RX LINK pkt id=%{public}@ ctx=0x%02X %dB keys=%d", log: tcpLog, type: .default,
                       destHash.hex.prefix(8).description, context, linkData.count, linkStates.count)

                if context == 0xFE {
 print("[TCP/\(name)] RX LINK RTT id=\(destHash.hex.prefix(8))… (ignored)")
                } else if context == 0xFA {
 print("[TCP/\(name)] RX LINK KEEPALIVE id=\(destHash.hex.prefix(8))… (ignored)")
                } else if let derivedKey = linkStates[destHash] {
 if let plaintext = try? ReticulumToken.decryptLinkData(linkData, key: derivedKey) {
     os_log("LINK DECRYPT OK id=%{public}@ ctx=0x%02X → %dB", log: tcpLog, type: .default,
            destHash.hex.prefix(8).description, context, plaintext.count)
     print(
         "[TCP/\(name)] RX LINK DATA id=\(destHash.hex.prefix(8))… " +
         "ctx=\(String(format: "0x%02X", context)) → \(plaintext.count)B plaintext"
     )

     // For REQUEST context (0x09), compute on-wire request_id and prepend to payload.
     // The server-side request handler needs this to echo it in the response.
     var syntheticPayload = plaintext
     if context == 0x09 {
         let flags = packet[packet.startIndex]
         var hashablePart = Data([flags & 0x0F])
         hashablePart.append(packet[(packet.startIndex + 2)...])
         let requestID = Hashing.truncatedHash(hashablePart, length: 16)
         syntheticPayload = requestID + plaintext
     }

     let syntheticHeader = PacketHeader(
         packetType:      .data,
         destinationType: .link,
         destinationHash: destHash,
         hops:            0,
         context:         context
     )
     let syntheticPacket = Packet(header: syntheticHeader, payload: syntheticPayload)
     let syntheticRaw    = syntheticPacket.serialize()
     if let handler = onReceive {
         Task { await handler(syntheticRaw) }
     }
     // Send explicit delivery proof for regular link DATA context only.
     if context == 0x00 {
         sendLinkProof(for: packet, isHeader2: isH2, linkId: destHash)
     }
 } else {
     print(
         "[TCP/\(name)] RX LINK DATA id=\(destHash.hex.prefix(8))… " +
         "ctx=\(String(format: "0x%02X", context)) decrypt FAILED (\(linkData.count)B)"
     )
     if let handler = onReceive {
         Task { await handler(packet) }
     }
 }
                } else {
 let stateInfo = linkStates[destHash] != nil ? "key registered" : "no key registered"
 print("[TCP/\(name)] RX LINK DATA id=\(destHash.hex.prefix(8))… ctx=\(String(format: "0x%02X", context)) \(stateInfo) — forwarding raw")
 if let handler = onReceive {
     Task { await handler(packet) }
 }
                }
                continue  // skip default onReceive call below

            default:
                break
            }

            if let handler = onReceive {
                Task { await handler(packet) }
            }
        }
    }

    // MARK: - Identity Cache

    private func storeIdentity(destinationHash: Data, publicKey: Data) {
        identityCache[destinationHash] = publicKey
        resumeWaiters(destinationHash: destinationHash, publicKey: publicKey)
    }

    private func resumeWaiters(destinationHash: Data, publicKey: Data) {
        guard let waiters = publicKeyWaiters.removeValue(forKey: destinationHash) else { return }
        print("[TCP/\(name)] Resolving \(waiters.count) waiter(s) for dest=\(destinationHash.hex.prefix(8))…")
        for (_, cont) in waiters { cont.resume(returning: publicKey) }
    }

    private func cancelWaiter(id: UUID, destinationHash: Data) {
        guard var waiters = publicKeyWaiters[destinationHash] else { return }
        guard let idx = waiters.firstIndex(where: { $0.id == id }) else { return }
        let cont = waiters[idx].cont
        waiters.remove(at: idx)
        publicKeyWaiters[destinationHash] = waiters.isEmpty ? nil : waiters
        cont.resume(returning: nil)
    }

    // MARK: - Link Proof

    /// Sends explicit LINK proof: `full_hash(32) + signature(64)`.
    private func sendLinkProof(for rawPacket: Data, isHeader2: Bool, linkId: Data) {
        guard let signer = linkSigner else {
            print("[TCP/\(name)] sendLinkProof: no signer registered, skipping proof")
            return
        }
        guard !rawPacket.isEmpty else { return }

        let flags = rawPacket[rawPacket.startIndex]
        // Python: hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]
        // Always skip only the hops byte (index 1) for both H1 and H2.
        let hashablePart = Data([flags & 0x0F]) + rawPacket.dropFirst(2)
        let fullHash = Hashing.sha256(hashablePart)

        let ifaceName  = name
        let fd         = sockFd
        let queue      = sendQueue

        Task { [weak self] in
            guard let self else { return }
            let currentFd = await self.sockFd
            guard fd == currentFd else { return }
            guard let sig = await signer(fullHash), sig.count == 64 else {
                print("[TCP/\(ifaceName)] sendLinkProof: signing failed")
                return
            }

            var proofPayload = fullHash
            proofPayload.append(sig)

            let proofHeader = PacketHeader(
                packetType:      .proof,
                destinationType: .link,
                destinationHash: linkId,
                hops:            0,
                context:         0x00
            )
            let proofRaw    = Packet(header: proofHeader, payload: proofPayload).serialize()
            let framed      = Self.hdlcFrame(proofRaw)

            queue.async {
                framed.withUnsafeBytes { ptr in
 _ = write(fd, ptr.baseAddress!, framed.count)
                }
                print("[TCP/\(ifaceName)] TX PROOF for link DATA id=\(linkId.hex.prefix(8))… full_hash=\(fullHash.hex.prefix(16))…")
            }
        }
    }

    /// Sends implicit SINGLE proof: `signature(64)` to `full_hash[:16]`.
    public func sendSingleProof(rawPacket: Data, isHeader2: Bool, signer: @escaping @Sendable (Data) async -> Data?) {
        guard !rawPacket.isEmpty else { return }

        let flags = rawPacket[rawPacket.startIndex]
        // Python: hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]
        // Always skip only the hops byte for both H1 and H2.
        let hashablePart = Data([flags & 0x0F]) + rawPacket.dropFirst(2)
        let fullHash      = Hashing.sha256(hashablePart)
        let truncatedHash = Data(fullHash.prefix(16))

        let ifaceName = name
        let fd        = sockFd
        let queue     = sendQueue

        Task { [weak self] in
            guard let self else { return }
            let currentFd = await self.sockFd
            guard fd == currentFd else { return }
            guard let sig = await signer(fullHash), sig.count == 64 else {
                print("[TCP/\(ifaceName)] sendSingleProof: signing failed")
                return
            }

            let proofPayload = sig

            let proofHeader = PacketHeader(
                packetType:      .proof,
                destinationType: .single,
                destinationHash: truncatedHash,
                hops:            0,
                context:         0x00
            )
            let proofRaw = Packet(header: proofHeader, payload: proofPayload).serialize()
            let framed   = Self.hdlcFrame(proofRaw)

            queue.async {
                framed.withUnsafeBytes { ptr in
 _ = write(fd, ptr.baseAddress!, framed.count)
                }
                print("[TCP/\(ifaceName)] TX PROOF for SINGLE DATA dest=\(truncatedHash.hex.prefix(8))… hash=\(fullHash.hex.prefix(16))…")
            }
        }
    }

    /// Waits up to `timeout` seconds for the recipient's public key to arrive via an
    /// announce.  Returns immediately if the key is already cached.
    private func waitForPublicKey(destinationHash: Data, timeout: TimeInterval) async -> Data? {
        if let cached = identityCache[destinationHash] {
            print("[TCP/\(name)] waitForPublicKey dest=\(destinationHash.hex.prefix(8))… → cache hit")
            return cached
        }

        print("[TCP/\(name)] waitForPublicKey dest=\(destinationHash.hex.prefix(8))… → waiting up to \(Int(timeout))s (cache has \(identityCache.count) entries: \(identityCache.keys.map { $0.hex.prefix(6) }.joined(separator: ", ")))")
        let id   = UUID()
        let ifName = name   // capture value; actors can't be referenced from non-isolated closures
        return await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            var waiters = publicKeyWaiters[destinationHash] ?? []
            waiters.append((id: id, cont: cont))
            publicKeyWaiters[destinationHash] = waiters

            // Timeout: resume with nil if the key doesn't arrive in time
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(timeout))
                guard let self else { cont.resume(returning: nil); return }
                let had = await self.identityCache[destinationHash] != nil
                if !had {
 print("[TCP/\(ifName)] waitForPublicKey TIMEOUT dest=\(destinationHash.hex.prefix(8))… after \(Int(timeout))s")
                }
                await self.cancelWaiter(id: id, destinationHash: destinationHash)
            }
        }
    }

    // MARK: - Reconnection

    private func scheduleReconnect() {
        guard !stopped else { return }
        let delay = reconnectDelay
        reconnectTask = Task { [weak self] in
            guard let self else { return }
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch {
                return  // cancelled — stop() was called
            }
            do {
                try await self.connectOnce()
            } catch {
                let isStopped = await self.stopped
                if !isStopped {
 await self.scheduleReconnect()
                }
            }
        }
    }

    // MARK: - HDLC Framing

    private static func hdlcFrame(_ data: Data) -> Data {
        var out = Data([hdlcFLAG])
        for byte in data {
            if byte == hdlcFLAG || byte == hdlcESC {
                out.append(hdlcESC)
                out.append(byte ^ hdlcESC_MASK)
            } else {
                out.append(byte)
            }
        }
        out.append(hdlcFLAG)
        return out
    }

    private static func hdlcDeframe(_ buffer: Data) -> (Data, Data)? {
        let bytes = Array(buffer)
        guard let start = bytes.firstIndex(of: hdlcFLAG) else { return nil }
        let from = start + 1
        guard from < bytes.count,
              let end = bytes[from...].firstIndex(of: hdlcFLAG) else { return nil }

        var payload = Data()
        var i = from
        while i < end {
            if bytes[i] == hdlcESC {
                let next = i + 1
                guard next < end else { break }
                payload.append(bytes[next] ^ hdlcESC_MASK)
                i = next + 1
            } else {
                payload.append(bytes[i])
                i += 1
            }
        }
        return (payload, Data(bytes[(end + 1)...]))
    }

    // MARK: - POSIX Connection

    /// Synchronously opens a TCP socket to `host:port` using `getaddrinfo` for
    /// hostname resolution (handles both IP literals and DNS names).
    private static func rawConnect(host: String, port: UInt16) throws -> Int32 {
        var hints          = addrinfo()
        hints.ai_family    = AF_UNSPEC
        hints.ai_socktype  = SOCK_STREAM
        hints.ai_flags     = AI_NUMERICSERV

        var res: UnsafeMutablePointer<addrinfo>? = nil
        guard getaddrinfo(host, "\(port)", &hints, &res) == 0, let result = res else {
            throw TCPError.resolveFailed
        }
        defer { freeaddrinfo(result) }

        var ptr:       UnsafeMutablePointer<addrinfo>? = result
        var lastErrno: Int32 = ENOENT

        while let p = ptr {
            let fd = socket(p.pointee.ai_family,
         p.pointee.ai_socktype,
         p.pointee.ai_protocol)
            guard fd >= 0 else {
                lastErrno = Darwin.errno
                ptr = p.pointee.ai_next
                continue
            }

            guard let aiAddr = p.pointee.ai_addr else {
                _ = Darwin.close(fd)
                ptr = p.pointee.ai_next
                continue
            }

            let result = Darwin.connect(fd, aiAddr, p.pointee.ai_addrlen)
            if result == 0 { return fd }

            lastErrno = Darwin.errno
            _ = Darwin.close(fd)
            ptr = p.pointee.ai_next
        }

        throw TCPError.connectFailed(lastErrno)
    }
}
