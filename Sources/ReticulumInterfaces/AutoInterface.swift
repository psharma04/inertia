import Foundation
import Darwin
import Network
import os.log
import ReticulumCrypto
import ReticulumPackets

private let autoLog = OSLog(subsystem: "chat.inertia.auto", category: "wire")

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

public actor AutoInterface: MessageTransportInterface {

    // MARK: - Constants

    public static let defaultDiscoveryPort: UInt16 = 29716
    public static let defaultDataPort:      UInt16 = 42671
    public static let defaultGroupID              = "reticulum"

    private static let hwMTU:               Int    = 1196
    private static let bitrateGuess:        Int    = 10_000_000

    private static let peeringTimeout:       TimeInterval = 22.0
    private static let announceInterval:     TimeInterval =  1.6
    private static let peerJobInterval:      TimeInterval =  4.0
    private static let mcastEchoTimeout:     TimeInterval =  6.5

    private static let multiIfDequeLen:  Int          = 48
    private static let multiIfDequeTTL:  TimeInterval =  0.75

    // Interfaces to ignore on Darwin (macOS/iOS)
    private static let darwinIgnoredInterfaces: Set<String> = ["awdl0", "llw0", "lo0", "en5"]
    private static let allIgnoredInterfaces:    Set<String> = ["lo0"]

    // IPv6 multicast scope nibbles
    private static let scopeLink         = "2"
    private static let scopeAdmin        = "4"
    private static let scopeSite         = "5"
    private static let scopeOrganisation = "8"
    private static let scopeGlobal       = "e"

    // IPv6 multicast address type nibbles
    private static let mcastTemporary = "1"
    private static let mcastPermanent = "0"

    // MARK: - Configuration

    public let name: String

    private let groupID:          Data
    private let discoveryPort:    UInt16
    private let dataPort:         UInt16
    private let discoveryScope:   String
    private let mcastType:        String
    private let allowedIfs:       Set<String>
    private let ignoredIfs:       Set<String>

    private let mcastDiscoveryAddress: String

    private var unicastDiscoveryPort: UInt16 { discoveryPort + 1 }

    // MARK: - State

    public private(set) var isOnline: Bool = false

    private var onReceive: (@Sendable (Data, AutoInterfacePeer) async -> Void)?

    private var adoptedInterfaces: [String: String] = [:]

    private var multicastEchoes: [String: Date] = [:]
    private var initialEchoes: [String: Date] = [:]
    private var timedOutInterfaces: [String: Bool] = [:]

    private var peers: [String: (ifname: String, addr: String, lastHeard: Date, lastOutbound: Date)] = [:]

    /// Number of currently active peers.
    public var peerCount: Int { peers.count }

    private(set) var spawnedInterfaces: [String: AutoInterfacePeer] = [:]

    // Used to detect own multicast echoes
    private var linkLocalAddresses: Set<String> = []

    private var openFDs: [Int32] = []

    private var mifDeque: [(hash: Data, time: Date)] = []

    private var stopped = false
    private var addressChangeHandler: (@Sendable () async -> Void)?

    private var tasks: [Task<Void, Never>] = []

    private let socketQueue = DispatchQueue(
        label: "reticulum.auto.socket",
        qos:   .userInitiated,
        attributes: .concurrent
    )
    private let sendQueue = DispatchQueue(
        label: "reticulum.auto.send",
        qos:   .userInitiated
    )

    // Shared outbound UDP socket (lazy)
    private var outboundSocketFD: Int32 = -1

    // MARK: - Identity & link state

    private var identityCache: [Data: Data] = [:]
    private var publicKeyWaiters: [Data: [(id: UUID, cont: CheckedContinuation<Data?, Never>)]] = [:]
    private var linkStates: [Data: Data] = [:]
    private var linkSigner: (@Sendable (Data) async -> Data?)?
    private var unifiedOnReceive: (@Sendable (Data) async -> Void)?

    // MARK: - Public API

    public init(
        name:                 String,
        groupID:              String     = AutoInterface.defaultGroupID,
        discoveryPort:        UInt16     = AutoInterface.defaultDiscoveryPort,
        dataPort:             UInt16     = AutoInterface.defaultDataPort,
        discoveryScope:       String     = "link",
        multicastAddressType: String     = "temporary",
        allowedInterfaces:    [String]   = [],
        ignoredInterfaces:    [String]   = []
    ) {
        self.name          = name
        self.groupID       = groupID.data(using: .utf8)!
        self.discoveryPort = discoveryPort
        self.dataPort      = dataPort
        self.allowedIfs    = Set(allowedInterfaces)
        self.ignoredIfs    = Set(ignoredInterfaces)

        switch discoveryScope.lowercased() {
        case "admin":        self.discoveryScope = AutoInterface.scopeAdmin
        case "site":         self.discoveryScope = AutoInterface.scopeSite
        case "organisation": self.discoveryScope = AutoInterface.scopeOrganisation
        case "global":       self.discoveryScope = AutoInterface.scopeGlobal
        default:             self.discoveryScope = AutoInterface.scopeLink
        }

        switch multicastAddressType.lowercased() {
        case "permanent":    self.mcastType = AutoInterface.mcastPermanent
        default:             self.mcastType = AutoInterface.mcastTemporary
        }

        self.mcastDiscoveryAddress = AutoInterface.computeMulticastAddress(
            groupID:       groupID.data(using: .utf8)!,
            type:          self.mcastType,
            scope:         self.discoveryScope
        )
    }

    /// Register a handler called when link-local addresses change (e.g. WiFi roam).
    /// The caller should stop and restart the interface.
    public func setOnAddressChange(_ handler: @escaping @Sendable () async -> Void) {
        addressChangeHandler = handler
    }

    /// Register a handler invoked with each inbound packet (protocol-conforming).
    public func setOnReceive(_ handler: @escaping @Sendable (Data) async -> Void) {
        unifiedOnReceive = handler
        // Wire internal peer-aware handler through link DATA decryption
        onReceive = { [weak self] data, peer in
            guard let self else { return }
            let result = await self.decryptLinkDataIfNeeded(data)
            await handler(result.processed)

            // Send delivery proof for successfully decrypted link DATA with context 0x00.
            if let proofInfo = result.proofInfo {
                await self.sendLinkProof(
                    rawPacket: data,
                    linkId: proofInfo.linkId,
                    viaPeer: peer
                )
            }
        }
    }

    /// Register a handler invoked with each inbound packet and the peer it arrived on.
    public func setOnReceiveWithPeer(_ handler: @escaping @Sendable (Data, AutoInterfacePeer) async -> Void) {
        onReceive = handler
    }

    // MARK: - Link DATA decryption

    private struct LinkProofInfo {
        let linkId: Data
    }

    private struct DecryptResult {
        let processed: Data
        let proofInfo: LinkProofInfo?
    }

    private func decryptLinkDataIfNeeded(_ data: Data) -> DecryptResult {
        guard let parsed = try? Packet.deserialize(from: data) else {
            return DecryptResult(processed: data, proofInfo: nil)
        }
        guard parsed.header.packetType == .data,
              parsed.header.destinationType == .link else {
            return DecryptResult(processed: data, proofInfo: nil)
        }

        let isH2 = parsed.header.headerType == .header2
        let destHash: Data
        let context: UInt8
        let linkData: Data

        if isH2 {
            guard parsed.payload.count >= 16 else {
                os_log("H2 payload too short (%d bytes), dropping", log: autoLog, type: .error, parsed.payload.count)
                return DecryptResult(processed: data, proofInfo: nil)
            }
            destHash = Data([parsed.header.context]) + parsed.payload.prefix(15)
            linkData = Data(parsed.payload.dropFirst(16))
            context = parsed.payload[parsed.payload.startIndex + 15]
        } else {
            destHash = Data(parsed.header.destinationHash)
            linkData = parsed.payload
            context = parsed.header.context
        }

        // Ignore keepalive / RTT contexts
        guard context != 0xFA, context != 0xFE else {
            return DecryptResult(processed: data, proofInfo: nil)
        }

        guard let derivedKey = linkStates[destHash] else {
            return DecryptResult(processed: data, proofInfo: nil)
        }

        guard let plaintext = try? ReticulumToken.decryptLinkData(linkData, key: derivedKey) else {
            os_log("RX LINK DATA id=%{public}@ ctx=0x%02X decrypt FAILED (%dB)", log: autoLog, type: .error, destHash.hex.prefix(8).description, context, linkData.count)
            return DecryptResult(processed: data, proofInfo: nil)
        }

        os_log("RX LINK DATA id=%{public}@ ctx=0x%02X → %dB plaintext", log: autoLog, type: .default, destHash.hex.prefix(8).description, context, plaintext.count)

        // For REQUEST context (0x09), prepend on-wire request_id to payload.
        var syntheticPayload = plaintext
        if context == 0x09 {
            let flags = data[data.startIndex]
            var hashablePart = Data([flags & 0x0F])
            hashablePart.append(data[(data.startIndex + 2)...])
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
        let syntheticRaw = syntheticPacket.serialize()

        // Only send delivery proof for regular link DATA (context 0x00).
        let proofInfo = (context == 0x00) ? LinkProofInfo(linkId: destHash) : nil
        return DecryptResult(processed: syntheticRaw, proofInfo: proofInfo)
    }

    // MARK: - Identity cache (MessageTransportInterface)

    public func identityPublicKey(for destinationHash: Data) -> Data? {
        identityCache[destinationHash]
    }

    public func waitForIdentityPublicKey(destinationHash: Data, timeout: TimeInterval = 30) async -> Data? {
        if let cached = identityCache[destinationHash] { return cached }

        let waiterID = UUID()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
                publicKeyWaiters[destinationHash, default: []].append((id: waiterID, cont: cont))

                Task {
                    try? await Task.sleep(for: .seconds(timeout))
                    cancelWaiter(id: waiterID, destinationHash: destinationHash)
                }
            }
        } onCancel: {
            Task { [weak self] in
                await self?.cancelWaiter(id: waiterID, destinationHash: destinationHash)
            }
        }
    }

    public func seedIdentityCache(destinationHash: Data, publicKey: Data) {
        if identityCache[destinationHash] == nil {
            identityCache[destinationHash] = publicKey
            os_log("Seeded identity cache: dest=%{public}@", log: autoLog, type: .default, destinationHash.hex.prefix(8).description)
        }
        resumeWaiters(destinationHash: destinationHash, publicKey: publicKey)
    }

    // MARK: - Link state (MessageTransportInterface)

    public func establishLink(linkId: Data, derivedKey: Data) {
        linkStates[linkId] = derivedKey
        os_log("Link registered id=%{public}@", log: autoLog, type: .default, linkId.hex.prefix(8).description)
    }

    public func removeLink(linkId: Data) {
        linkStates.removeValue(forKey: linkId)
    }

    public func setLinkSigner(_ signer: @escaping @Sendable (Data) async -> Data?) {
        self.linkSigner = signer
    }

    public func sendSingleProof(rawPacket: Data, isHeader2: Bool, signer: @escaping @Sendable (Data) async -> Data?) {
        guard !rawPacket.isEmpty else { return }

        let flags = rawPacket[rawPacket.startIndex]
        // Python: hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]
        // Always skip only the hops byte for both H1 and H2.
        let hashablePart = Data([flags & 0x0F]) + rawPacket.dropFirst(2)
        let fullHash      = Hashing.sha256(hashablePart)
        let truncatedHash = Data(fullHash.prefix(16))

        Task { [weak self] in
            guard let self else { return }
            guard await self.isOnline else { return }
            guard let sig = await signer(fullHash), sig.count == 64 else {
                os_log("sendSingleProof: signing failed", log: autoLog, type: .error)
                return
            }

            let proofHeader = PacketHeader(
                packetType:      .proof,
                destinationType: .single,
                destinationHash: truncatedHash,
                hops:            0,
                context:         0x00
            )
            let proofRaw = Packet(header: proofHeader, payload: sig).serialize()
            try? await self.send(proofRaw)
        }
    }

    /// Send a link delivery proof back to the peer that sent the DATA packet.
    /// Mirrors TCPClientInterface.sendLinkProof — proof is sent unicast via the peer.
    private func sendLinkProof(rawPacket: Data, linkId: Data, viaPeer peer: AutoInterfacePeer) {
        guard !rawPacket.isEmpty else { return }
        guard let signer = linkSigner else {
            os_log("sendLinkProof: no signer registered", log: autoLog, type: .error)
            return
        }

        let flags = rawPacket[rawPacket.startIndex]
        let hashablePart = Data([flags & 0x0F]) + rawPacket.dropFirst(2)
        let fullHash = Hashing.sha256(hashablePart)

        Task {
            guard let sig = await signer(fullHash), sig.count == 64 else {
                os_log("sendLinkProof: signing failed", log: autoLog, type: .error)
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
            let proofRaw = Packet(header: proofHeader, payload: proofPayload).serialize()
            try? await peer.send(proofRaw)
            os_log("TX PROOF for link DATA id=%{public}@", log: autoLog, type: .default, linkId.hex.prefix(8).description)
        }
    }

    // MARK: - Identity waiter helpers

    private func resumeWaiters(destinationHash: Data, publicKey: Data) {
        guard let waiters = publicKeyWaiters.removeValue(forKey: destinationHash) else { return }
        for (_, cont) in waiters { cont.resume(returning: publicKey) }
    }

    private func cancelWaiter(id: UUID, destinationHash: Data) {
        guard var waiters = publicKeyWaiters[destinationHash] else { return }
        guard let idx = waiters.firstIndex(where: { $0.id == id }) else { return }
        let cont = waiters.remove(at: idx)
        if waiters.isEmpty {
            publicKeyWaiters.removeValue(forKey: destinationHash)
        } else {
            publicKeyWaiters[destinationHash] = waiters
        }
        cont.cont.resume(returning: nil)
    }

    // MARK: - ReticulumInterface

    public func start() async {
        guard !isOnline else { return }
        stopped = false

        let ifaddrs = Self.enumerateIPv6LinkLocal()
        var suitableCount = 0

        for (ifname, linkLocalAddr) in ifaddrs {
            if Self.darwinIgnoredInterfaces.contains(ifname), !allowedIfs.contains(ifname) {
                os_log("Skipping Darwin system interface %{public}@", log: autoLog, type: .debug, ifname)
                continue
            }
            if Self.allIgnoredInterfaces.contains(ifname) {
                os_log("Skipping interface %{public}@", log: autoLog, type: .debug, ifname)
                continue
            }
            if ignoredIfs.contains(ifname) {
                os_log("Ignoring disallowed interface %{public}@", log: autoLog, type: .debug, ifname)
                continue
            }
            if !allowedIfs.isEmpty, !allowedIfs.contains(ifname) {
                os_log("Ignoring interface %{public}@ (not in allowed list)", log: autoLog, type: .debug, ifname)
                continue
            }

            guard let ifIndex = Self.ifNameToIndex(ifname) else {
                os_log("Could not resolve interface index for %{public}@, skipping", log: autoLog, type: .error, ifname)
                continue
            }

            os_log("Adopting %{public}@ with link-local %{public}@", log: autoLog, type: .info, ifname, linkLocalAddr)
        os_log("Multicast group: %{public}@, discovery port: %d", log: autoLog, type: .info, mcastDiscoveryAddress, discoveryPort)
            adoptedInterfaces[ifname]   = linkLocalAddr
            multicastEchoes[ifname]     = Date()
            linkLocalAddresses.insert(linkLocalAddr)

            // Multicast discovery socket
            guard let mcastFD = setupMulticastDiscoverySocket(
                ifname: ifname, ifIndex: ifIndex, linkLocalAddr: linkLocalAddr
            ) else {
                os_log("Could not set up multicast socket for %{public}@, skipping", log: autoLog, type: .error, ifname)
                adoptedInterfaces.removeValue(forKey: ifname)
                linkLocalAddresses.remove(linkLocalAddr)
                continue
            }
            openFDs.append(mcastFD)

            // Unicast discovery socket
            guard let ucastFD = setupUnicastDiscoverySocket(
                ifname: ifname, linkLocalAddr: linkLocalAddr
            ) else {
                os_log("Could not set up unicast discovery socket for %{public}@, skipping", log: autoLog, type: .error, ifname)
                // Roll back the multicast FD we just opened
                Darwin.close(mcastFD)
                if let idx = openFDs.lastIndex(of: mcastFD) { openFDs.remove(at: idx) }
                adoptedInterfaces.removeValue(forKey: ifname)
                linkLocalAddresses.remove(linkLocalAddr)
                continue
            }
            openFDs.append(ucastFD)

            // Start multicast discovery listener + announce loop
            let mFD = mcastFD
            let iname = ifname
            let t1 = Task.detached(priority: .utility) { [weak self] in
                guard let self else { return }
                await self.discoveryLoop(fd: mFD, ifname: iname, sendAnnounces: true)
            }
            tasks.append(t1)

            // Start unicast discovery listener (no announces; only receives reverse peering)
            let uFD = ucastFD
            let t2 = Task.detached(priority: .utility) { [weak self] in
                guard let self else { return }
                await self.discoveryLoop(fd: uFD, ifname: iname, sendAnnounces: false)
            }
            tasks.append(t2)

            suitableCount += 1
        }

        if suitableCount == 0 {
            os_log("No suitable interfaces found. Interface provides no connectivity.", log: autoLog, type: .error)
            return
        }

        // Start UDP data listeners after all interfaces are adopted
        for (ifname, linkLocalAddr) in adoptedInterfaces {
            guard let ifIndex = Self.ifNameToIndex(ifname),
                  let dataFD = setupDataSocket(ifname: ifname, ifIndex: ifIndex, linkLocalAddr: linkLocalAddr)
            else {
                os_log("Could not set up data socket for %{public}@", log: autoLog, type: .error, ifname)
                continue
            }
            openFDs.append(dataFD)
            let dFD = dataFD
            let iname = ifname
            let t3 = Task.detached(priority: .utility) { [weak self] in
                guard let self else { return }
                await self.dataLoop(fd: dFD, ifname: iname)
            }
            tasks.append(t3)
        }

        // Peer maintenance loop
        let t4 = Task.detached(priority: .utility) { [weak self] in
            guard let self else { return }
            await self.peerJobLoop()
        }
        tasks.append(t4)

        // All sockets are open and loops are running — report online immediately.
        // Peer discovery happens asynchronously via the running loops.
        isOnline = true
        os_log("Online with %d interface(s)", log: autoLog, type: .info, adoptedInterfaces.count)
    }

    public func stop() async {
        stopped  = true
        isOnline = false
        // Close FDs first to unblock any poll() calls
        let fds = openFDs
        openFDs.removeAll()
        for fd in fds { _ = Darwin.close(fd) }
        if outboundSocketFD >= 0 {
            Darwin.close(outboundSocketFD)
            outboundSocketFD = -1
        }
        // Cancel and await all tasks to ensure full quiescence
        let currentTasks = tasks
        tasks.removeAll()
        currentTasks.forEach { $0.cancel() }
        for t in currentTasks { _ = await t.result }
        for peer in spawnedInterfaces.values { await peer.stop() }
        spawnedInterfaces.removeAll()
        peers.removeAll()
        adoptedInterfaces.removeAll()
        linkLocalAddresses.removeAll()
        multicastEchoes.removeAll()
        initialEchoes.removeAll()
    }

    public func send(_ data: Data) async throws {
        guard isOnline else { throw AutoInterfaceError.offline }
        for peer in spawnedInterfaces.values {
            try await peer.send(data)
        }
    }

    // MARK: - Socket Setup (private)

    private func setupMulticastDiscoverySocket(
        ifname: String, ifIndex: UInt32, linkLocalAddr: String
    ) -> Int32? {
        let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size))

        // Set outbound multicast interface
        var ifIdx = ifIndex
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifIdx, socklen_t(MemoryLayout<UInt32>.size))

        // Join multicast group
        var mreq = ipv6_mreq()
        guard inet_pton(AF_INET6, mcastDiscoveryAddress, &mreq.ipv6mr_multiaddr) == 1 else {
            Darwin.close(fd)
            return nil
        }
        mreq.ipv6mr_interface = ifIndex
        let mreqLen = socklen_t(MemoryLayout<ipv6_mreq>.size)
        guard setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, mreqLen) == 0 else {
            os_log("Could not join multicast group on %{public}@: %{public}@", log: autoLog, type: .error, ifname, String(cString: strerror(errno)))
            Darwin.close(fd)
            return nil
        }

        // Bind to [mcastAddr%ifname]:discoveryPort
        let bindAddr = "\(mcastDiscoveryAddress)%\(ifname)"
        var sin6 = sockaddr_in6()
        guard Self.fillSockAddr6(&sin6, address: bindAddr, port: discoveryPort) else {
            Darwin.close(fd)
            return nil
        }
        let bindResult = withUnsafePointer(to: sin6) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bindResult == 0 else {
            os_log("Could not bind multicast socket on %{public}@: %{public}@", log: autoLog, type: .error, ifname, String(cString: strerror(errno)))
            Darwin.close(fd)
            return nil
        }

        return fd
    }

    private func setupUnicastDiscoverySocket(
        ifname: String, linkLocalAddr: String
    ) -> Int32? {
        let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size))

        let bindAddr = "\(linkLocalAddr)%\(ifname)"
        var sin6 = sockaddr_in6()
        guard Self.fillSockAddr6(&sin6, address: bindAddr, port: unicastDiscoveryPort) else {
            Darwin.close(fd)
            return nil
        }
        let bindResult = withUnsafePointer(to: sin6) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bindResult == 0 else {
            os_log("Could not bind unicast discovery socket on %{public}@: %{public}@", log: autoLog, type: .error, ifname, String(cString: strerror(errno)))
            Darwin.close(fd)
            return nil
        }
        return fd
    }

    private func setupDataSocket(
        ifname: String, ifIndex: UInt32, linkLocalAddr: String
    ) -> Int32? {
        let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size))

        let bindAddr = "\(linkLocalAddr)%\(ifname)"
        var sin6 = sockaddr_in6()
        guard Self.fillSockAddr6(&sin6, address: bindAddr, port: dataPort) else {
            Darwin.close(fd)
            return nil
        }
        let bindResult = withUnsafePointer(to: sin6) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bindResult == 0 else {
            os_log("Could not bind data socket on %{public}@: %{public}@", log: autoLog, type: .error, ifname, String(cString: strerror(errno)))
            Darwin.close(fd)
            return nil
        }
        return fd
    }

    // MARK: - Discovery Loop

    private func discoveryLoop(fd: Int32, ifname: String, sendAnnounces: Bool) async {
        if sendAnnounces {
            // Run the announce loop on a separate task so receive loop is not blocked
            let iname = ifname
            let t = Task.detached(priority: .utility) { [weak self] in
                guard let self else { return }
                await self.announceLoop(ifname: iname)
            }
            // Track task on the actor (safe because we're already running detached)
            appendTask(t)
        }

        var buf = [UInt8](repeating: 0, count: 1_024)
        // Make socket non-blocking so recvfrom never stalls the actor
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        while !stopped && !Task.isCancelled {
            // Poll with 100ms timeout — yields the actor between checks
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&pfd, 1, 100)
            guard ready > 0 else {
                await Task.yield()
                continue
            }
            var senderStorage = sockaddr_storage()
            var senderLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &senderStorage) { storagePtr in
                storagePtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    recvfrom(fd, &buf, buf.count, 0, saPtr, &senderLen)
                }
            }
            guard n > 0 else {
                if errno == EAGAIN || errno == EWOULDBLOCK { continue }
                break
            }
            let data = Data(buf[..<n])

            // Extract sender IPv6 address string
            guard senderStorage.ss_family == UInt8(AF_INET6) else { continue }
            let senderAddr = withUnsafePointer(to: senderStorage) { ptr in
                ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6Ptr in
                    Self.inet6ntop(addr: sin6Ptr.pointee.sin6_addr)
                }
            }
            guard let senderAddr else { continue }

            await handleDiscoveryPacket(data: data, senderAddr: senderAddr, ifname: ifname)
        }
    }

    private func handleDiscoveryPacket(data: Data, senderAddr: String, ifname: String) async {
        let expectedToken = Hashing.sha256(groupID + senderAddr.data(using: .utf8)!)
        let tokenMatch = data == expectedToken
        os_log("Discovery from %{public}@ on %{public}@ (%dB) token %{public}@", log: autoLog, type: .debug, senderAddr, ifname, data.count, tokenMatch ? "✓" : "✗")
        guard tokenMatch else { return }

        // Self-echo detection: the sender is one of our own link-local addresses
        if linkLocalAddresses.contains(senderAddr) {
            // Update echo timestamp for carrier detection
            for (iname, addr) in adoptedInterfaces where addr == senderAddr {
                multicastEchoes[iname] = Date()
                if initialEchoes[iname] == nil { initialEchoes[iname] = Date() }
            }
            return
        }

        addOrRefreshPeer(addr: senderAddr, ifname: ifname)
    }

    // MARK: - Announce Loop

    private func announceLoop(ifname: String) async {
        while !stopped && !Task.isCancelled {
            sendPeerAnnounce(ifname: ifname)
            // ±10% jitter to prevent synchronized announces
            let jitter = Double.random(in: -0.1...0.1) * Self.announceInterval
            let interval = Self.announceInterval + jitter
            try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
        }
    }

    private func sendPeerAnnounce(ifname: String) {
        guard let linkLocalAddr = adoptedInterfaces[ifname] else { return }
        let token = Hashing.sha256(groupID + linkLocalAddr.data(using: .utf8)!)
        guard let ifIndex = Self.ifNameToIndex(ifname) else { return }
        let mcastAddr   = mcastDiscoveryAddress
        let port        = discoveryPort
        let idx         = ifIndex

        let iname = ifname

        sendQueue.async {
            let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
            guard fd >= 0 else { return }
            defer { Darwin.close(fd) }

            var ifIdx = idx
            setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifIdx, socklen_t(MemoryLayout<UInt32>.size))

            var sin6 = sockaddr_in6()
            guard AutoInterface.fillSockAddr6(&sin6, address: mcastAddr, port: port) else { return }
            let result = token.withUnsafeBytes { buf in
                withUnsafePointer(to: sin6) { saPtr in
                    saPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        sendto(fd, buf.baseAddress!, buf.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
            }
            if result < 0 {
                let err = String(cString: strerror(errno))
                os_log("Announce sendto failed on %{public}@: %{public}@", log: autoLog, type: .error, iname, err)
            }
        }
    }

    private func sendReversePeerAnnounce(ifname: String, peerAddr: String) {
        guard let linkLocalAddr = adoptedInterfaces[ifname] else { return }

        let token       = Hashing.sha256(groupID + linkLocalAddr.data(using: .utf8)!)
        let targetAddr  = "\(peerAddr)%\(ifname)"
        let port        = unicastDiscoveryPort

        sendQueue.async {
            let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
            guard fd >= 0 else { return }
            defer { Darwin.close(fd) }

            var sin6 = sockaddr_in6()
            guard AutoInterface.fillSockAddr6(&sin6, address: targetAddr, port: port) else { return }
            let result = token.withUnsafeBytes { buf in
                withUnsafePointer(to: sin6) { saPtr in
                    saPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        sendto(fd, buf.baseAddress!, buf.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
            }
            if result < 0 {
                let err = String(cString: strerror(errno))
                os_log("Reverse announce sendto failed on %{public}@: %{public}@", log: autoLog, type: .error, ifname, err)
            }
        }
    }

    // MARK: - Data Loop

    private func dataLoop(fd: Int32, ifname: String) async {
        var buf = [UInt8](repeating: 0, count: Self.hwMTU + 64)
        // Make socket non-blocking so recvfrom never stalls the actor
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        while !stopped && !Task.isCancelled {
            // Poll with 100ms timeout — yields the actor between checks
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&pfd, 1, 100)
            guard ready > 0 else {
                await Task.yield()
                continue
            }
            var senderStorage = sockaddr_storage()
            var senderLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &senderStorage) { storagePtr in
                storagePtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    recvfrom(fd, &buf, buf.count, 0, saPtr, &senderLen)
                }
            }
            guard n > 0 else {
                if errno == EAGAIN || errno == EWOULDBLOCK { continue }
                break
            }
            let data = Data(buf[..<n])

            guard senderStorage.ss_family == UInt8(AF_INET6) else { continue }
            let senderAddr = withUnsafePointer(to: senderStorage) { ptr in
                ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6Ptr in
                    Self.inet6ntop(addr: sin6Ptr.pointee.sin6_addr)
                }
            }
            guard let senderAddr else { continue }

            if isOnline {
                let key = Self.peerKey(addr: senderAddr, ifname: ifname)
                if let peer = spawnedInterfaces[key] {
                    await peer.processIncoming(data)
                    refreshPeer(key: key)
                }
            }
        }
    }

    // MARK: - Peer Management

    static func peerKey(addr: String, ifname: String) -> String {
        "\(addr)%\(ifname)"
    }

    private func addOrRefreshPeer(addr: String, ifname: String) {
        let key = Self.peerKey(addr: addr, ifname: ifname)
        if let _ = peers[key] {
            refreshPeer(key: key)
            return
        }

        peers[key] = (ifname: ifname, addr: addr, lastHeard: Date(), lastOutbound: Date())

        // Lazily create shared outbound socket (matches Python's outbound_udp_socket)
        if outboundSocketFD < 0 {
            outboundSocketFD = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        }

        let peer = AutoInterfacePeer(
            parentName:       name,
            peerAddr:         addr,
            ifname:           ifname,
            dataPort:         dataPort,
            sendQueue:        sendQueue,
            outboundSocketFD: outboundSocketFD,
            onReceive:        onReceive,
            mifDeque:         { [weak self] hash, timestamp in
                await self?.dequeCheck(hash: hash, timestamp: timestamp) ?? false
            }
        )
        spawnedInterfaces[key] = peer
        Task { try? await peer.start() }

        os_log("Added peer %{public}@ on %{public}@", log: autoLog, type: .info, addr, ifname)
    }

    private func refreshPeer(key: String) {
        peers[key]?.lastHeard = Date()
    }

    // MARK: - Deduplication ring buffer

    private func dequeCheck(hash: Data, timestamp: Date) async -> Bool {
        // Evict stale entries
        let cutoff = Date().addingTimeInterval(-Self.multiIfDequeTTL)
        mifDeque.removeAll { $0.time < cutoff }

        if mifDeque.contains(where: { $0.hash == hash }) {
            return true
        }
        if mifDeque.count >= Self.multiIfDequeLen {
            mifDeque.removeFirst()
        }
        mifDeque.append((hash: hash, time: timestamp))
        return false
    }

    /// Test-only entry point for deduplication ring buffer.
    func testDequeCheck(hash: Data, timestamp: Date) async -> Bool {
        await dequeCheck(hash: hash, timestamp: timestamp)
    }

    // MARK: - Peer Job Loop

    private func peerJobLoop() async {
        let reverseInterval = Self.announceInterval * 3.25
        var addressCheckCounter = 0
        while !stopped && !Task.isCancelled {
            try? await Task.sleep(nanoseconds: UInt64(Self.peerJobInterval * 1_000_000_000))
            let now = Date()

            // Every ~5 cycles (~20s), check for link-local address changes
            addressCheckCounter += 1
            if addressCheckCounter >= 5 {
                addressCheckCounter = 0
                let current = Self.enumerateIPv6LinkLocal()
                let currentByName = Dictionary(current, uniquingKeysWith: { first, _ in first })
                var changed = false
                for (ifname, oldAddr) in adoptedInterfaces {
                    if currentByName[ifname] != oldAddr {
                        os_log("Link-local address changed on %{public}@ (%{public}@ → %{public}@)",
                               log: autoLog, type: .info,
                               ifname, oldAddr, currentByName[ifname] ?? "gone")
                        changed = true
                    }
                }
                if changed, let handler = addressChangeHandler {
                    os_log("Address change detected, requesting restart", log: autoLog, type: .info)
                    await handler()
                    return
                }
            }

            // Collect timed-out peers
            var timedOut: [String] = []
            for (key, peer) in peers {
                if now.timeIntervalSince(peer.lastHeard) > Self.peeringTimeout {
                    timedOut.append(key)
                }
            }

            // Remove timed-out peers
            for key in timedOut {
                peers.removeValue(forKey: key)
                if let spawned = spawnedInterfaces.removeValue(forKey: key) {
                    await spawned.stop()
                    os_log("Removed timed-out peer %{public}@", log: autoLog, type: .info, key)
                }
            }

            // Send reverse peering packets to known peers
            for (key, var peer) in peers {
                if now.timeIntervalSince(peer.lastOutbound) > reverseInterval {
                    sendReversePeerAnnounce(ifname: peer.ifname, peerAddr: peer.addr)
                    peer.lastOutbound = now
                    peers[key] = peer
                }
            }

            // Check multicast echo timeouts (carrier detection) per adopted interface
            for ifname in adoptedInterfaces.keys {
                let lastEcho = multicastEchoes[ifname] ?? Date.distantPast
                let echoAge  = now.timeIntervalSince(lastEcho)

                if echoAge > Self.mcastEchoTimeout {
                    if timedOutInterfaces[ifname] == false {
                        os_log("Multicast echo timeout on %{public}@. Carrier lost.", log: autoLog, type: .error, ifname)
                    }
                    timedOutInterfaces[ifname] = true
                } else {
                    if timedOutInterfaces[ifname] == true {
                        os_log("Carrier recovered on %{public}@.", log: autoLog, type: .info, ifname)
                    }
                    timedOutInterfaces[ifname] = false
                }

                if initialEchoes[ifname] == nil {
                    os_log("No multicast echoes on %{public}@. Firewall may be blocking multicast.", log: autoLog, type: .error, ifname)
                }
            }
        }
    }

    // MARK: - Task bookkeeping helper

    private func appendTask(_ task: Task<Void, Never>) {
        tasks.append(task)
    }

    // MARK: - Static Helpers

    static func computeMulticastAddress(groupID: Data, type: String, scope: String) -> String {
        let g = Hashing.sha256(groupID)
        // Python: g[3]+(g[2]<<8)  →  g[2] is the high byte, g[3] is the low byte.
        // Parameters: first arg = index of high byte, second = index of low byte.
        func word(_ hi: Int, _ lo: Int) -> String {
            String(format: "%x", (Int(g[hi]) << 8) | Int(g[lo]))
        }
        return "ff\(type)\(scope):0:\(word(2,3)):\(word(4,5)):\(word(6,7)):\(word(8,9)):\(word(10,11)):\(word(12,13))"
    }

    static func enumerateIPv6LinkLocal() -> [(ifname: String, linkLocalAddr: String)] {
        let wifiNames = currentWiFiInterfaceNames()
        var results: [(String, String)] = []
        var ifap: UnsafeMutablePointer<ifaddrs>? = nil
        guard getifaddrs(&ifap) == 0, let base = ifap else { return results }
        defer { freeifaddrs(base) }

        var cursor = base
        while true {
            let ifa = cursor.pointee
            if ifa.ifa_addr != nil,
               ifa.ifa_addr.pointee.sa_family == UInt8(AF_INET6),
               let ifname = ifa.ifa_name.map({ String(cString: $0) }),
               wifiNames.contains(ifname)
            {
                let addr6 = ifa.ifa_addr.withMemoryRebound(
                    to: sockaddr_in6.self, capacity: 1
                ) { $0.pointee }

                if let addrStr = inet6ntop(addr: addr6.sin6_addr),
                   addrStr.hasPrefix("fe80:")
                {
                    // Drop scope specifier if present (e.g. fe80::1%en0 → fe80::1)
                    let clean = addrStr.split(separator: "%").first.map(String.init) ?? addrStr
                    results.append((ifname, clean))
                }
            }
            guard let next = ifa.ifa_next else { break }
            cursor = next
        }
        return results
    }

    static func currentWiFiInterfaceNames() -> Set<String> {
        let monitor = NWPathMonitor()
        let sem     = DispatchSemaphore(value: 0)
        // nonisolated(unsafe): the semaphore guarantees the closure completes
        // before sem.wait() returns, so there is no actual data race here.
        nonisolated(unsafe) var names = Set<String>()
        monitor.pathUpdateHandler = { path in
            for iface in path.availableInterfaces where iface.type == .wifi || iface.type == .wiredEthernet {
                names.insert(iface.name)
            }
            sem.signal()
        }
        monitor.start(queue: .global())
        _ = sem.wait(timeout: .now() + 2.0)
        monitor.cancel()
        return names
    }

    /// Resolves an interface name to its kernel index using `if_nametoindex`.
    static func ifNameToIndex(_ ifname: String) -> UInt32? {
        let idx = if_nametoindex(ifname)
        return idx != 0 ? idx : nil
    }

    /// Converts an `in6_addr` to its string representation using `inet_ntop`.
    static func inet6ntop(addr: in6_addr) -> String? {
        var a = addr
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &a, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil else {
            return nil
        }
        return String(decoding: buf.prefix(while: { $0 != 0 }).map(UInt8.init(bitPattern:)), as: UTF8.self)
    }

    @discardableResult
    static func fillSockAddr6(_ sin6: inout sockaddr_in6, address: String, port: UInt16) -> Bool {
        // Separate address from optional scope specifier
        let parts = address.split(separator: "%", maxSplits: 1)
        let addrStr = String(parts[0])
        let scopeId: UInt32
        if parts.count == 2 {
            // Scope can be an interface name or a numeric index
            let scopePart = String(parts[1])
            if let idx = UInt32(scopePart) {
                scopeId = idx
            } else {
                scopeId = if_nametoindex(scopePart)
            }
        } else {
            scopeId = 0
        }

        sin6 = sockaddr_in6()
        sin6.sin6_len    = UInt8(MemoryLayout<sockaddr_in6>.size)
        sin6.sin6_family = UInt8(AF_INET6)
        sin6.sin6_port   = port.bigEndian
        sin6.sin6_scope_id = scopeId
        return inet_pton(AF_INET6, addrStr, &sin6.sin6_addr) == 1
    }
}

// MARK: - Errors

public enum AutoInterfaceError: Error {
    case offline
    case socketFailed
    case addressResolutionFailed
    case udpSendFailed(Int32)
}
