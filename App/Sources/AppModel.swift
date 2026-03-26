import Foundation
import Security
import CryptoKit
import LocalAuthentication
import UserNotifications
#if canImport(UIKit)
import UIKit
#endif
import ReticulumCrypto
import ReticulumPackets
import ReticulumInterfaces
import LXMF
import NomadNet

// Domain models

struct DiscoveredPeer: Identifiable, Codable, Sendable {
    let id: UUID
    let destinationHash: Data
    var publicKey: Data
    let discoveredAt: Date

    /// Display name broadcast by this peer in their announce app_data.
    /// Updated automatically unless `aliasSet` is `true`.
    var displayName: String?

    /// Display name manually set by the local user. Takes precedence over
    /// `displayName` when `aliasSet` is `true`.
    var alias: String?

    /// `true` when the user has explicitly set `alias`; prevents automatic
    /// `displayName` updates from overwriting it.
    var aliasSet: Bool = false

    /// `true` only when this peer was discovered from an `lxmf.delivery` announce.
    var isLXMFPeer: Bool = true

    /// `true` if this destination announced itself as `lxmf.propagation`.
    var isPropagationNode: Bool = false

    /// `true` if this destination announced itself as `nomadnetwork.node`.
    var isNomadNode: Bool = false

    /// Last time we received an announce for this destination hash.
    var lastAnnounceAt: Date?

    /// Current known path length to this destination, derived from announce hops.
    var pathHops: Int?

    /// Last connected server ID that delivered a valid announce for this peer.
    var lastAnnounceServerID: UUID?

    /// Last transport-ID seen in a HEADER_2 announce for this destination.
    /// Used as next-hop when injecting transport headers for multi-hop sends.
    var lastAnnounceTransportID: Data?

    /// Announced inbound stamp cost for `lxmf.delivery` destinations.
    var announcedStampCost: Int?

    /// Announced propagation target stamp cost for `lxmf.propagation` destinations.
    var announcedPropagationStampCost: Int?

    /// Announced propagation-node enabled state (`node_state` from app_data).
    /// `nil` means unknown / not yet announced.
    var announcedPropagationEnabled: Bool?

    init(
        destinationHash: Data,
        publicKey: Data,
        displayName: String? = nil,
        isLXMFPeer: Bool = true,
        isPropagationNode: Bool = false,
        isNomadNode: Bool = false,
        lastAnnounceAt: Date? = nil,
        pathHops: Int? = nil,
        lastAnnounceServerID: UUID? = nil,
        lastAnnounceTransportID: Data? = nil,
        announcedStampCost: Int? = nil,
        announcedPropagationStampCost: Int? = nil,
        announcedPropagationEnabled: Bool? = nil
    ) {
        self.id              = UUID()
        self.destinationHash = destinationHash
        self.publicKey       = publicKey
        self.discoveredAt    = .now
        self.displayName     = displayName
        self.isLXMFPeer      = isLXMFPeer
        self.isPropagationNode = isPropagationNode
        self.isNomadNode = isNomadNode
        self.lastAnnounceAt    = lastAnnounceAt
        self.pathHops          = pathHops
        self.lastAnnounceServerID = lastAnnounceServerID
        self.lastAnnounceTransportID = lastAnnounceTransportID
        self.announcedStampCost = announcedStampCost
        self.announcedPropagationStampCost = announcedPropagationStampCost
        self.announcedPropagationEnabled = announcedPropagationEnabled
    }

    var hashHex: String { destinationHash.hexString }
    var shortHash: String { String(hashHex.prefix(8)) }
    var hasValidPublicKey: Bool { publicKey.count == Identity.publicKeyLength }
    var identityHash: Data { Hashing.truncatedHash(publicKey, length: Identity.hashLength) }
    var identityHashHex: String { Hashing.truncatedHash(publicKey, length: 16).hexString }

    /// Human-readable name for this peer.
    /// Priority: user alias > announce display name > "Anonymous Peer".
    var effectiveName: String {
        if aliasSet, let a = alias, !a.isEmpty { return a }
        if let d = displayName, !d.isEmpty { return d }
        return "Anonymous Peer (\(shortHash))"
    }

    /// Whether any name (display or alias) is known for this peer.
    var hasName: Bool { aliasSet ? (alias != nil && !alias!.isEmpty) : (displayName != nil && !displayName!.isEmpty) }

    private enum CodingKeys: String, CodingKey {
        case id
        case destinationHash
        case publicKey
        case discoveredAt
        case displayName
        case alias
        case aliasSet
        case isLXMFPeer
        case isPropagationNode
        case isNomadNode
        case lastAnnounceAt
        case pathHops
        case lastAnnounceServerID
        case lastAnnounceTransportID
        case announcedStampCost
        case announcedPropagationStampCost
        case announcedPropagationEnabled
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        self.destinationHash = try container.decode(Data.self, forKey: .destinationHash)
        self.publicKey = try container.decode(Data.self, forKey: .publicKey)
        self.discoveredAt = try container.decodeIfPresent(Date.self, forKey: .discoveredAt) ?? .now
        self.displayName = try container.decodeIfPresent(String.self, forKey: .displayName)
        self.alias = try container.decodeIfPresent(String.self, forKey: .alias)
        self.aliasSet = try container.decodeIfPresent(Bool.self, forKey: .aliasSet) ?? false
        self.isLXMFPeer = try container.decodeIfPresent(Bool.self, forKey: .isLXMFPeer) ?? true
        self.isPropagationNode = try container.decodeIfPresent(Bool.self, forKey: .isPropagationNode) ?? false
        self.isNomadNode = try container.decodeIfPresent(Bool.self, forKey: .isNomadNode) ?? false
        self.lastAnnounceAt = try container.decodeIfPresent(Date.self, forKey: .lastAnnounceAt)
        self.pathHops = try container.decodeIfPresent(Int.self, forKey: .pathHops)
        self.lastAnnounceServerID = try container.decodeIfPresent(UUID.self, forKey: .lastAnnounceServerID)
        self.lastAnnounceTransportID = try container.decodeIfPresent(Data.self, forKey: .lastAnnounceTransportID)
        self.announcedStampCost = try container.decodeIfPresent(Int.self, forKey: .announcedStampCost)
        self.announcedPropagationStampCost = try container.decodeIfPresent(Int.self, forKey: .announcedPropagationStampCost)
        self.announcedPropagationEnabled = try container.decodeIfPresent(Bool.self, forKey: .announcedPropagationEnabled)
    }
}

struct ConversationMessage: Identifiable, Codable, Sendable {
    let id: UUID
    let content: String
    let timestamp: Date
    let isOutbound: Bool
    var deliveryStatus: OutboundDeliveryStatus?

    private enum CodingKeys: String, CodingKey {
        case id
        case content
        case timestamp
        case isOutbound
        case deliveryStatus
    }

    init(
        id: UUID = UUID(),
        content: String,
        timestamp: Date,
        isOutbound: Bool,
        deliveryStatus: OutboundDeliveryStatus? = nil
    ) {
        self.id         = id
        self.content    = content
        self.timestamp  = timestamp
        self.isOutbound = isOutbound
        self.deliveryStatus = isOutbound ? (deliveryStatus ?? .sent) : nil
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        self.content = try container.decode(String.self, forKey: .content)
        self.timestamp = try container.decode(Date.self, forKey: .timestamp)
        self.isOutbound = try container.decode(Bool.self, forKey: .isOutbound)
        let decodedStatus = try container.decodeIfPresent(OutboundDeliveryStatus.self, forKey: .deliveryStatus)
        self.deliveryStatus = isOutbound ? (decodedStatus ?? .sent) : nil
    }
}

struct Conversation: Identifiable, Codable, Sendable {
    let destinationHash: Data
    var messages: [ConversationMessage]

    var id: String { destinationHash.hexString }
    var hashHex: String { destinationHash.hexString }
    var shortHash: String { String(hashHex.prefix(8)) }
    var lastMessage: ConversationMessage? { messages.last }
}

struct LogEntry: Identifiable, Sendable {
    let id = UUID()
    let message: String
    let timestamp: Date = .now
}

enum MessageDeliveryMethod: String, CaseIterable, Codable, Sendable {
    case opportunistic
    case direct
    case propagated
}

enum OutboundDeliveryStatus: String, Codable, Sendable {
    case sent
    case delivered
    case failed
}

// Errors

enum AppError: LocalizedError {
    case notConnected
    case noIdentity
    case noPath
    case linkEstablishmentFailed
    case propagationNodeRequired
    case encryptionFailed
    case messageTooLarge
    case deliveryProofTimeout
    case nomadResponseTimeout
    case identityBackupUnavailable
    case identityBackupFailed
    case identityRestoreFailed
    case biometricNotAvailable
    case biometricAuthFailed
    case lockRequired

    var errorDescription: String? {
        switch self {
        case .notConnected:     "Not connected to any Reticulum node"
        case .noIdentity:       "No local identity"
        case .noPath:           "No path to destination — wait for a fresh announce"
        case .linkEstablishmentFailed: "Could not establish a direct link to destination"
        case .propagationNodeRequired: "Propagation delivery requires a propagation node destination hash"
        case .encryptionFailed: "Failed to encrypt message"
        case .messageTooLarge:  "Message is too large for the selected LXMF delivery method"
        case .deliveryProofTimeout: "Delivery proof timed out"
        case .nomadResponseTimeout: "Nomad node did not return a response in time"
        case .identityBackupUnavailable: "No exportable identity key is available"
        case .identityBackupFailed: "Failed to create identity backup"
        case .identityRestoreFailed: "Failed to restore identity backup"
        case .biometricNotAvailable: "Biometric authentication is not available on this device"
        case .biometricAuthFailed: "Biometric authentication failed"
        case .lockRequired: "Unlock is required to continue"
        }
    }
}

// AppModel

@MainActor
@Observable
final class AppModel {
    private static let defaultAnnounceDisplayName = "Anonymous Inertia User"
    private static let defaultPropagationNodeHashHex = "4c59456b269469fb44bc62c125e8db36"
    private static let defaultPropagationNodeName = "use.inertia.chat"
    private static let onboardingCompletedDefaultsKey = "onboardingCompleted"
    private static let identityPrivateKeyDefaultsKey = "identityPrivateKey"
    private static let identityPrivateKeyKeychainService = "chat.inertia.identity"
    private static let identityPrivateKeyKeychainAccount = "privateKey"
    private static let selectedPropagationNodeHashDefaultsKey = "selectedPropagationNodeHash"
    private static let autoSelectPropagationNodeDefaultsKey = "autoSelectBestPropagationNode"
    private static let inboundNotificationsEnabledDefaultsKey = "inboundNotificationsEnabled"
    private static let biometricLockEnabledDefaultsKey = "biometricLockEnabled"
    private static let biometricLockOnBackgroundDefaultsKey = "biometricLockOnBackground"
    private static let inboundDeliveredTransientIDsDefaultsKey = "inboundDeliveredTransientIDs"
    private static let autoPropagationSelectionInterval: TimeInterval = 300
    private static let autoPropagationSelectionStartupDelay: TimeInterval = 10
    private static let autoPropagationProbeTimeout: TimeInterval = 5
    private static let defaultPropagationNodeHash: Data = {
        guard let hash = Data(hexString: defaultPropagationNodeHashHex),
              hash.count == Destination.hashLength else {
            preconditionFailure("Invalid default propagation node hash")
        }
        return hash
    }()

    // Server state
    var servers: [ServerConfig] = []
    /// Tracks which server IDs are currently connected.
    var serverStatuses: [UUID: Bool] = [:]

    var isAnyConnected: Bool { serverStatuses.values.contains(true) }
    var connectedCount: Int  { serverStatuses.values.filter { $0 }.count }

    // Network discovery
    var peers: [DiscoveredPeer] = []
    var conversations: [Conversation] = []
    var activityLog: [LogEntry] = []

    // Identity
    private(set) var identity: Identity?

    var identityHashHex: String { identity?.hash.hexString ?? "—" }

    var lxmfDestinationHash: Data? {
        guard let identity else { return nil }
        return Destination.hash(appName: "lxmf", aspects: ["delivery"], identityHash: identity.hash)
    }
    var lxmfAddressHex: String { lxmfDestinationHash?.hexString ?? "—" }

    // Announce settings
    var autoAnnounce: Bool = false {
        didSet {
            UserDefaults.standard.set(autoAnnounce, forKey: "autoAnnounce")
            scheduleAnnounceTimer()
        }
    }
    /// Interval in seconds between automatic announces.
    var announceInterval: TimeInterval = 300 {
        didSet {
            UserDefaults.standard.set(announceInterval, forKey: "announceInterval")
            scheduleAnnounceTimer()
        }
    }
    /// Human-readable display name broadcast with every announce.
    var displayName: String = "" {
        didSet {
            UserDefaults.standard.set(displayName, forKey: "displayName")
        }
    }

    /// Local notifications for inbound LXMF messages while app is inactive/backgrounded.
    var inboundNotificationsEnabled: Bool = true {
        didSet {
            UserDefaults.standard.set(inboundNotificationsEnabled, forKey: Self.inboundNotificationsEnabledDefaultsKey)
            if inboundNotificationsEnabled {
                requestNotificationPermissionsIfNeeded()
            }
        }
    }

    /// Require local biometric authentication before using the app.
    var biometricLockEnabled: Bool = false {
        didSet {
            UserDefaults.standard.set(biometricLockEnabled, forKey: Self.biometricLockEnabledDefaultsKey)
            if biometricLockEnabled {
                lockState = .locked
            } else {
                lockState = .unlocked
            }
        }
    }

    /// If enabled, lock app whenever scene transitions away from `.active`.
    var biometricLockOnBackground: Bool = true {
        didSet {
            UserDefaults.standard.set(biometricLockOnBackground, forKey: Self.biometricLockOnBackgroundDefaultsKey)
        }
    }

    enum LockState: Equatable {
        case unlocked
        case locked
        case unlocking
    }

    var lockState: LockState = .unlocked
    var isAppLocked: Bool { biometricLockEnabled && lockState != .unlocked }
    var biometricTypeLabel: String {
        switch availableBiometry {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        default: "Biometrics"
        }
    }
    var biometricSystemImageName: String {
        switch availableBiometry {
        case .faceID: "faceid"
        case .touchID: "touchid"
        default: "lock.fill"
        }
    }

    /// Optional inbound stamp cost announced to other peers for messages to us.
    /// `nil` disables stamp requirement.
    var inboundStampCost: Int? {
        didSet {
            if let inboundStampCost, inboundStampCost > 0, inboundStampCost < 255 {
                UserDefaults.standard.set(inboundStampCost, forKey: "inboundStampCost")
            } else {
                UserDefaults.standard.removeObject(forKey: "inboundStampCost")
            }
        }
    }
    private(set) var selectedPropagationNodeHash: Data = AppModel.defaultPropagationNodeHash
    var selectedPropagationNode: DiscoveredPeer? {
        peers.first(where: { $0.destinationHash == selectedPropagationNodeHash })
    }
    var selectedPropagationNodeHashHex: String { selectedPropagationNodeHash.hexString }
    var autoSelectBestPropagationNode: Bool = false {
        didSet {
            UserDefaults.standard.set(autoSelectBestPropagationNode, forKey: Self.autoSelectPropagationNodeDefaultsKey)
            scheduleAutoPropagationSelectionTask()
            if autoSelectBestPropagationNode {
                requestAutoPropagationSelectionEvaluation(reason: "settings")
            }
        }
    }
    var hasCompletedOnboarding: Bool = false {
        didSet {
            UserDefaults.standard.set(hasCompletedOnboarding, forKey: Self.onboardingCompletedDefaultsKey)
        }
    }
    var shouldShowOnboarding: Bool { !hasCompletedOnboarding }

    // Private state
    @ObservationIgnored private var interfaces:       [UUID: TCPClientInterface]    = [:]
    @ObservationIgnored private var connectionTasks:  [UUID: Task<Void, Never>]     = [:]
    @ObservationIgnored private var announceTask:     Task<Void, Never>?            = nil
    @ObservationIgnored private var autoPropagationSelectionTask: Task<Void, Never>? = nil
    @ObservationIgnored private var autoPropagationEvaluationTask: Task<Void, Never>? = nil
    @ObservationIgnored private var propagationSyncTask: Task<Void, Never>? = nil
    @ObservationIgnored private var lastPropagationSyncAttemptAt: Date?
    @ObservationIgnored private var outboundProofExpectations: [Data: Date] = [:] // proof dest hash (truncated packet hash) -> sent time
    @ObservationIgnored private var outboundDirectProofExpectations: [Data: Date] = [:] // full packet hash -> sent time
    @ObservationIgnored private var outboundSingleProofMessageByHash: [Data: UUID] = [:] // proof dest hash -> conversation message id
    @ObservationIgnored private var outboundDirectProofMessageByHash: [Data: UUID] = [:] // full packet hash -> conversation message id
    @ObservationIgnored private var pendingDeliveredOutboundMessageIDs: Set<UUID> = [] // proofs arriving before message upsert
    @ObservationIgnored private var ratchetPublicKeysByDestination: [Data: Data] = [:] // destination hash -> X25519 ratchet pubkey (32 bytes)
    @ObservationIgnored private let lxmfRouter = LXMFRouter()
    @ObservationIgnored private var pendingDirectRecipientKeysByLinkID: [Data: Data] = [:] // link_id -> recipient identity pubkey
    @ObservationIgnored private var pendingDirectDestinationByLinkID: [Data: Data] = [:] // link_id -> destination hash
    @ObservationIgnored private var pendingDirectLinkByDestination: [Data: Data] = [:] // destination hash -> link_id
    @ObservationIgnored private var directLinkRouteSignatureByDestination: [Data: DirectLinkRouteSignature] = [:] // destination hash -> route signature at link establishment
    @ObservationIgnored private var directLinkWaiters: [Data: [(id: UUID, cont: CheckedContinuation<LXMFRouter.DirectLinkState?, Never>)]] = [:]
    @ObservationIgnored private var activeReceiveServerID: UUID?
    @ObservationIgnored private var outboundTicketsByDestination: [Data: Data] = [:] // source lxmf dest -> 16-byte ticket
    @ObservationIgnored private var nomadLinkIDs: Set<Data> = [] // active link_ids used for Nomad requests
    @ObservationIgnored private var nomadResponseWaiters: [Data: [(id: UUID, cont: CheckedContinuation<Data?, Never>)]] = [:]
    @ObservationIgnored private var bufferedNomadResponsesByLinkID: [Data: [Data]] = [:]
    @ObservationIgnored private var propagationLinkIDs: Set<Data> = [] // active link_ids used for propagation /get requests
    @ObservationIgnored private var propagationResponseWaiters: [Data: [(id: UUID, cont: CheckedContinuation<Data?, Never>)]] = [:]
    @ObservationIgnored private var bufferedPropagationResponsesByLinkID: [Data: [Data]] = [:]
    @ObservationIgnored private var inboundDeliveredTransientIDs: [Data: Date] = [:] // transient_id -> first delivery time
    private(set) var availableBiometry: LABiometryType = .none

    // Init

    init() {
        servers       = Self.loadServers()
        peers         = Self.loadPeers()
        conversations = Self.loadConversations()
        identity      = loadOrCreateIdentity()
        autoAnnounce  = UserDefaults.standard.bool(forKey: "autoAnnounce")
        let stored    = UserDefaults.standard.double(forKey: "announceInterval")
        announceInterval = stored > 0 ? stored : 300
        let savedDisplayName = UserDefaults.standard
            .string(forKey: "displayName")?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        displayName = savedDisplayName.isEmpty ? Self.defaultAnnounceDisplayName : savedDisplayName
        if UserDefaults.standard.object(forKey: Self.inboundNotificationsEnabledDefaultsKey) != nil {
            inboundNotificationsEnabled = UserDefaults.standard.bool(forKey: Self.inboundNotificationsEnabledDefaultsKey)
        } else {
            inboundNotificationsEnabled = true
            UserDefaults.standard.set(true, forKey: Self.inboundNotificationsEnabledDefaultsKey)
        }
        if UserDefaults.standard.object(forKey: Self.biometricLockEnabledDefaultsKey) != nil {
            biometricLockEnabled = UserDefaults.standard.bool(forKey: Self.biometricLockEnabledDefaultsKey)
        } else {
            biometricLockEnabled = false
            UserDefaults.standard.set(false, forKey: Self.biometricLockEnabledDefaultsKey)
        }
        if UserDefaults.standard.object(forKey: Self.biometricLockOnBackgroundDefaultsKey) != nil {
            biometricLockOnBackground = UserDefaults.standard.bool(forKey: Self.biometricLockOnBackgroundDefaultsKey)
        } else {
            biometricLockOnBackground = true
            UserDefaults.standard.set(true, forKey: Self.biometricLockOnBackgroundDefaultsKey)
        }
        hasCompletedOnboarding = Self.loadOnboardingCompletionState(savedDisplayName: savedDisplayName)
        let storedInboundStampCost = UserDefaults.standard.integer(forKey: "inboundStampCost")
        if (1..<255).contains(storedInboundStampCost) {
            inboundStampCost = storedInboundStampCost
        } else {
            inboundStampCost = nil
        }
        refreshBiometryAvailability()
        autoSelectBestPropagationNode = UserDefaults.standard.bool(forKey: Self.autoSelectPropagationNodeDefaultsKey)
        selectedPropagationNodeHash = Self.loadSelectedPropagationNodeHash()
        ensureSelectedPropagationNodeConfigured()
        inboundDeliveredTransientIDs = Self.loadInboundDeliveredTransientIDs()
        purgeExpiredPropagationTransientIDs()
        scheduleAutoPropagationSelectionTask()
        requestNotificationPermissionsIfNeeded()
    }

    func requestNotificationPermissionsIfNeeded() {
        guard inboundNotificationsEnabled else { return }
        Task { [weak self] in
            guard let self else { return }
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()
            guard settings.authorizationStatus == .notDetermined else { return }
            do {
                let granted = try await center.requestAuthorization(options: [.alert, .sound, .badge])
                if !granted {
                    log(.info, "Notifications: permission denied by user")
                }
            } catch {
                log(.warn, "Notifications: permission request failed (\(error.localizedDescription))")
            }
        }
    }

    func refreshBiometryAvailability() {
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            availableBiometry = context.biometryType
        } else {
            availableBiometry = .none
        }
    }

    func setBiometricLockEnabled(_ enabled: Bool) async throws {
        refreshBiometryAvailability()
        if enabled {
            guard availableBiometry != .none else {
                throw AppError.biometricNotAvailable
            }
            lockState = .unlocking
            let authenticated = await evaluateAuthentication(
                reason: "Enable \(biometricTypeLabel) lock",
                policy: .deviceOwnerAuthentication
            )
            guard authenticated else {
                lockState = .unlocked
                throw AppError.biometricAuthFailed
            }
            biometricLockEnabled = true
            lockState = .unlocked
        } else {
            biometricLockEnabled = false
            lockState = .unlocked
        }
    }

    @discardableResult
    func unlockWithBiometricsIfNeeded(reason: String = "Unlock Inertia") async -> Bool {
        guard biometricLockEnabled else {
            lockState = .unlocked
            return true
        }
        guard lockState != .unlocked else {
            return true
        }
        if lockState == .unlocking {
            return false
        }

        lockState = .unlocking
        let didEvaluate = await evaluateAuthentication(
            reason: reason,
            policy: .deviceOwnerAuthentication
        )

        lockState = didEvaluate ? .unlocked : .locked
        return didEvaluate
    }

    private func evaluateAuthentication(reason: String, policy: LAPolicy) async -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        var error: NSError?
        guard context.canEvaluatePolicy(policy, error: &error) else {
            return false
        }

        do {
            return try await context.evaluatePolicy(policy, localizedReason: reason)
        } catch {
            return false
        }
    }

    // Server management

    func addServer(_ config: ServerConfig) {
        servers.append(config)
        saveServers()
    }

    func updateServer(_ config: ServerConfig) {
        guard let idx = servers.firstIndex(where: { $0.id == config.id }) else { return }
        servers[idx] = config
        saveServers()
    }

    func removeServer(id: UUID) {
        disconnect(serverId: id)
        servers.removeAll { $0.id == id }
        saveServers()
    }

    // Connection

    func connect(serverId: UUID) {
        guard let config = servers.first(where: { $0.id == serverId }),
              config.isValidPort,
              let port = UInt16(exactly: config.port) else { return }

        // Idempotent: if a connection task is already running for this server,
        // don't cancel and restart it (which would wipe the identityCache in the
        // TCPClientInterface and cause waitForPublicKey to time out).
        guard connectionTasks[serverId] == nil else { return }

        let interface = TCPClientInterface(name: config.displayName, host: config.host, port: port)
        interfaces[serverId] = interface
        serverStatuses[serverId] = false

        connectionTasks[serverId] = Task {
            await interface.setOnReceive { [weak self] data in
                await self?.handleIncoming(data, fromServerID: serverId)
            }
            // Provide a signing callback so the interface can send PROOF packets
            // for link DATA packets (acknowledging DIRECT delivery to the sender).
            await interface.setLinkSigner { [weak self] data in
                guard let self else { return nil }
                return await MainActor.run { try? self.identity?.sign(data) }
            }
            appendLog("Connecting to \(config.host):\(String(config.port))…")
            do {
                try await interface.start()
                serverStatuses[serverId] = true
                appendLog("Connected to \(config.displayName) ✓")

                sendAnnounce()
                scheduleAnnounceTimer()
                scheduleAutoPropagationSelectionTask()
                requestAutoPropagationSelectionEvaluation(reason: "connected")
                requestPropagationInboxSync(reason: "connected")
            } catch {
                serverStatuses[serverId] = false
                appendLog("\(config.displayName): \(error.localizedDescription)")
                // Clear the task so the next connect() call or scenePhase
                // active transition can retry.
                connectionTasks[serverId] = nil
                scheduleAutoPropagationSelectionTask()
            }
        }
    }

    func disconnect(serverId: UUID) {
        connectionTasks[serverId]?.cancel()
        connectionTasks[serverId] = nil
        if let iface = interfaces[serverId] {
            Task { await iface.stop() }
        }
        interfaces[serverId]     = nil
        serverStatuses[serverId] = nil
        appendLog("Disconnected from \(servers.first(where: { $0.id == serverId })?.displayName ?? "server")")
        scheduleAnnounceTimer()
        scheduleAutoPropagationSelectionTask()
    }

    func connectAll() {
        servers.forEach { connect(serverId: $0.id) }
    }

    func disconnectAll() {
        servers.forEach { disconnect(serverId: $0.id) }
    }

    func completeOnboarding(nickname: String) {
        let trimmed = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        displayName = trimmed.isEmpty ? Self.defaultAnnounceDisplayName : trimmed
        hasCompletedOnboarding = true
        connectAll()
    }

    func restartOnboarding() {
        hasCompletedOnboarding = false
    }

    func appSceneDidChange(isActive: Bool) {
        if isActive {
            if biometricLockEnabled && lockState == .locked {
                Task {
                    _ = await unlockWithBiometricsIfNeeded(reason: "Unlock Inertia")
                }
            }
            return
        }

        guard biometricLockEnabled, biometricLockOnBackground else { return }
        guard lockState != .unlocking else { return }
        lockState = .locked
    }

    // Announce sending

    func sendAnnounce() {
        guard let identity else {
            log(.warn, "Announce skipped: no local identity")
            return
        }

        let connectedInterfaces = interfaces
            .filter { serverStatuses[$0.key] == true }
            .map { ($0.key, $0.value) }
        guard !connectedInterfaces.isEmpty else {
            log(.warn, "Announce skipped: no connected interfaces")
            return
        }

        let destHash  = Destination.hash(appName: "lxmf", aspects: ["delivery"], identityHash: identity.hash)
        let nameHash  = Destination.nameHash(appName: "lxmf", aspects: ["delivery"])

        var randomHash = Data(count: 10)
        _ = randomHash.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 5, $0.baseAddress!) }
        // Encode current Unix timestamp in randomHash[5...9] per Reticulum announce format.
        let ts = UInt64(Date().timeIntervalSince1970)
        randomHash[5] = UInt8((ts >> 32) & 0xff)
        randomHash[6] = UInt8((ts >> 24) & 0xff)
        randomHash[7] = UInt8((ts >> 16) & 0xff)
        randomHash[8] = UInt8((ts >>  8) & 0xff)
        randomHash[9] = UInt8( ts        & 0xff)

        // Build app_data first so it is included in announce signature input.
        let sanitizedName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let announceName = sanitizedName.isEmpty ? Self.defaultAnnounceDisplayName : sanitizedName
        let appData = MsgPack.encodeDeliveryAnnounce(
            displayName: announceName,
            stampCost: inboundStampCost
        )

        var signedData = destHash
        signedData.append(identity.publicKey)
        signedData.append(nameHash)
        signedData.append(randomHash)
        signedData.append(appData)

        guard let sig = try? identity.sign(signedData) else { return }

        var payload = identity.publicKey
        payload.append(nameHash)
        payload.append(randomHash)
        payload.append(sig)
        payload.append(appData)

        let header = PacketHeader(
            packetType:      .announce,
            destinationType: .single,
            destinationHash: destHash
        )
        let packet = Packet(header: header, payload: payload)
        let rawPacket = packet.serialize()
        let interfaceCount = connectedInterfaces.count

        Task {
            var sentCount = 0
            for (serverID, iface) in connectedInterfaces {
                do {
                    try await iface.send(rawPacket)
                    sentCount += 1
                    log(.debug, "Announce TX via server \(serverID.uuidString.prefix(8))…")
                } catch {
                    log(
                        .warn,
                        "Announce TX failed via server \(serverID.uuidString.prefix(8))…: \(error.localizedDescription)"
                    )
                }
            }

            if sentCount > 0 {
                appendLog(
                    "Announced lxmf.delivery: \(destHash.hexString.prefix(8))… (\(sentCount)/\(interfaceCount) interfaces)"
                )
            } else {
                log(.warn, "Announce TX failed on all \(interfaceCount) connected interfaces")
            }
        }
    }

    // Messaging

    private static let pathFreshnessWindow: TimeInterval = 3_600
    private static let directPathFreshnessWindow: TimeInterval = 120
    private static let propagationSyncMinInterval: TimeInterval = 20
    private static let propagationDeliveredTransientRetention: TimeInterval = 30 * 24 * 60 * 60
    private static let minimumDeliveryProofTimeout: TimeInterval = 12
    private static let perHopDeliveryProofTimeout: TimeInterval = 6
    private static let maxDeliveryProofTimeout: TimeInterval = 60
    private static let proofPollIntervalNanoseconds: UInt64 = 200_000_000
    private static let announceWaitPollIntervalNanoseconds: UInt64 = 200_000_000

    private struct DirectLinkRouteSignature: Equatable {
        let pathHops: Int?
        let lastAnnounceServerID: UUID?
        let lastAnnounceTransportID: Data?
    }

    private func resolveRecipientDestinationHash(_ destinationHash: Data) -> Data {
        guard destinationHash.count == Destination.hashLength else { return destinationHash }
        let knownDestinations = Set(peers.map(\.destinationHash))
        let knownIdentities   = Set(peers.filter(\.hasValidPublicKey).map(\.identityHash))
        let resolvedDestination = LXMFAddressing.resolveRecipientHash(
            destinationHash,
            knownDestinationHashes: knownDestinations,
            knownIdentityHashes: knownIdentities
        )
        if resolvedDestination == destinationHash,
           let peerByIdentity = peers.first(where: { $0.identityHash == destinationHash }) {
            return peerByIdentity.destinationHash
        }
        return resolvedDestination
    }

    private func hasRecentDirectAnnounce(for destinationHash: Data) -> Bool {
        guard let peer = peers.first(where: { $0.destinationHash == destinationHash }) else {
            return false
        }
        guard let pathHops = peer.pathHops else { return false }
        // DIRECT must only be used for 0/1-hop destinations.
        guard pathHops <= 1 else { return false }
        guard let announcedAt = peer.lastAnnounceAt else { return false }
        return Date().timeIntervalSince(announcedAt) <= Self.directPathFreshnessWindow
    }

    private func directLinkRouteSignature(for destinationHash: Data) -> DirectLinkRouteSignature {
        let peer = peers.first(where: { $0.destinationHash == destinationHash })
        return DirectLinkRouteSignature(
            pathHops: peer?.pathHops,
            lastAnnounceServerID: peer?.lastAnnounceServerID,
            lastAnnounceTransportID: peer?.lastAnnounceTransportID
        )
    }

    private func hasFreshAnnounce(for destinationHash: Data) -> Bool {
        guard let peer = peers.first(where: { $0.destinationHash == destinationHash }) else {
            return false
        }
        guard let announcedAt = peer.lastAnnounceAt else {
            return false
        }
        return Date().timeIntervalSince(announcedAt) <= Self.pathFreshnessWindow
    }

    private func freshAnnouncedPublicKey(
        for destinationHash: Data,
        allowPropagationDestination: Bool = false
    ) -> Data? {
        guard hasFreshAnnounce(for: destinationHash) else { return nil }
        guard let peer = peers.first(where: { $0.destinationHash == destinationHash }) else {
            return nil
        }
        guard peer.publicKey.count == Identity.publicKeyLength else { return nil }
        guard isValidLXMFDestinationKey(
            peer.publicKey,
            for: destinationHash,
            allowPropagationDestination: allowPropagationDestination
        ) else { return nil }
        return peer.publicKey
    }

    private func freshNomadAnnouncedPublicKey(for destinationHash: Data) -> Data? {
        guard hasFreshAnnounce(for: destinationHash) else { return nil }
        guard let peer = peers.first(where: { $0.destinationHash == destinationHash }) else {
            return nil
        }
        guard peer.isNomadNode else { return nil }
        guard peer.publicKey.count == Identity.publicKeyLength else { return nil }
        guard isValidNomadNodeKey(peer.publicKey, for: destinationHash) else { return nil }
        return peer.publicKey
    }

    /// Computes delivery-proof timeout from latest announced hop count.
    private func deliveryProofTimeout(for destinationHash: Data) -> TimeInterval {
        let announcedHops = peers.first(where: { $0.destinationHash == destinationHash })?.pathHops ?? 1
        let hops = max(1, announcedHops)
        let scaled = Self.perHopDeliveryProofTimeout * Double(hops + 1)
        return min(Self.maxDeliveryProofTimeout, max(Self.minimumDeliveryProofTimeout, scaled))
    }

    private func activeRatchetPublicKey(for destinationHash: Data) -> Data? {
        guard hasFreshAnnounce(for: destinationHash) else { return nil }
        guard let key = ratchetPublicKeysByDestination[destinationHash], key.count == 32 else {
            return nil
        }
        return key
    }

    private func isValidLXMFDeliveryKey(_ publicKey: Data, for destinationHash: Data) -> Bool {
        guard publicKey.count == Identity.publicKeyLength else { return false }
        let identityHash = Hashing.truncatedHash(publicKey, length: Identity.hashLength)
        return LXMFAddressing.deliveryDestinationHash(identityHash: identityHash) == destinationHash
    }

    private func isValidLXMFDestinationKey(
        _ publicKey: Data,
        for destinationHash: Data,
        allowPropagationDestination: Bool = false
    ) -> Bool {
        guard publicKey.count == Identity.publicKeyLength else { return false }
        let identityHash = Hashing.truncatedHash(publicKey, length: Identity.hashLength)
        if LXMFAddressing.deliveryDestinationHash(identityHash: identityHash) == destinationHash {
            return true
        }
        if allowPropagationDestination,
           LXMFAddressing.propagationDestinationHash(identityHash: identityHash) == destinationHash {
            return true
        }
        return false
    }

    private func peerKeyFingerprint(_ publicKey: Data) -> String {
        guard publicKey.count == Identity.publicKeyLength else { return "invalid" }
        let identityHash = Hashing.truncatedHash(publicKey, length: Identity.hashLength)
        return String(identityHash.hexString.prefix(8))
    }

    private func shortHash(_ data: Data, bytes: Int = 4) -> String {
        guard !data.isEmpty else { return "empty" }
        return String(data.hexString.prefix(max(2, bytes * 2)))
    }

    private func peerRouteSnapshot(for destinationHash: Data) -> String {
        guard let peer = peers.first(where: { $0.destinationHash == destinationHash }) else {
            return "peer=missing"
        }

        let hops = peer.pathHops.map(String.init) ?? "n/a"
        let announceAge: String
        if let last = peer.lastAnnounceAt {
            announceAge = "\(Int(Date().timeIntervalSince(last)))s"
        } else {
            announceAge = "n/a"
        }

        let kind: String
        if peer.isLXMFPeer {
            kind = "lxmf.delivery"
        } else if peer.isPropagationNode {
            kind = "lxmf.propagation"
        } else if peer.isNomadNode {
            kind = "nomadnetwork.node"
        } else {
            kind = "non-lxmf"
        }

        let keyFP = peer.publicKey.count == Identity.publicKeyLength ? peerKeyFingerprint(peer.publicKey) : "invalid"
        let ratchetFP = ratchetPublicKeysByDestination[destinationHash].map { shortHash($0) } ?? "none"
        let stampCost = peer.announcedStampCost.map(String.init) ?? "none"
        return "kind=\(kind) hops=\(hops) announceAge=\(announceAge) key=\(keyFP) ratchet=\(ratchetFP) stampCost=\(stampCost)"
    }

    private func tokenLayoutSummary(_ token: Data) -> String {
        guard token.count >= ReticulumToken.minimumOverhead else {
            return "token=\(token.count)B (too short for ReticulumToken)"
        }
        let ephemeral = Data(token.prefix(32))
        let iv = Data(token[32..<48])
        let hmac = Data(token.suffix(32))
        let ciphertextLen = token.count - ReticulumToken.minimumOverhead
        return "token=\(token.count)B eph=\(shortHash(ephemeral)) iv=\(shortHash(iv)) ct=\(ciphertextLen)B hmac=\(shortHash(hmac))"
    }

    private func lxmfPackedSummary(_ packed: Data) -> String {
        guard packed.count >= 96 else {
            return "packed=\(packed.count)B (too short)"
        }
        guard let msg = try? LXMFMessage(packed: packed) else {
            return "packed=\(packed.count)B (parse failed)"
        }
        let stampLen = msg.stamp?.count ?? 0
        return "packed=\(packed.count)B msgID=\(shortHash(msg.hash)) src=\(shortHash(msg.sourceHash)) sig=\(shortHash(msg.signature)) fields=\(msg.fields.count) stamp=\(stampLen)B"
    }

    private func awaitingProofsSummary(limit: Int = 20) -> String {
        let all = outboundProofExpectations.keys.map { "\($0.hexString.prefix(8))…" }
        guard !all.isEmpty else { return "none" }
        let shown = all.prefix(limit)
        let suffix = all.count > limit ? " +\(all.count - limit) more" : ""
        return shown.joined(separator: ", ") + suffix
    }

    private func waitForFreshPeerPublicKey(
        for destinationHash: Data,
        timeout: TimeInterval,
        allowPropagationDestination: Bool = false
    ) async -> Data? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let peer = peers.first(where: { $0.destinationHash == destinationHash }),
               peer.publicKey.count == Identity.publicKeyLength,
               hasFreshAnnounce(for: destinationHash),
               isValidLXMFDestinationKey(
                peer.publicKey,
                for: destinationHash,
                allowPropagationDestination: allowPropagationDestination
               ) {
                return peer.publicKey
            }
            try? await Task.sleep(nanoseconds: Self.announceWaitPollIntervalNanoseconds)
        }
        return nil
    }

    private func isValidAnnounce(_ announce: AnnouncePayload, destinationHash: Data) -> Bool {
        guard announce.identityPublicKey.count == Identity.publicKeyLength else { return false }
        guard announce.verifySignature(destinationHash: destinationHash) else { return false }
        let identityHash = Hashing.truncatedHash(announce.identityPublicKey, length: Identity.hashLength)
        let expectedDestinationHash = Hashing.truncatedHash(
            announce.nameHash + identityHash,
            length: Destination.hashLength
        )
        return expectedDestinationHash == destinationHash
    }

    private func propagationNodeCandidates() -> [DiscoveredPeer] {
        var candidates = peers.filter(\.isPropagationNode)
        if !candidates.contains(where: { $0.destinationHash == selectedPropagationNodeHash }),
           let selectedPeer = peers.first(where: { $0.destinationHash == selectedPropagationNodeHash }) {
            candidates.append(selectedPeer)
        }

        return candidates.sorted { lhs, rhs in
            let lhsHops = lhs.pathHops ?? .max
            let rhsHops = rhs.pathHops ?? .max
            if lhsHops != rhsHops { return lhsHops < rhsHops }
            let lhsSeen = lhs.lastAnnounceAt ?? lhs.discoveredAt
            let rhsSeen = rhs.lastAnnounceAt ?? rhs.discoveredAt
            return lhsSeen > rhsSeen
        }
    }

    private func autoPropagationEligibleCandidates() -> [DiscoveredPeer] {
        propagationNodeCandidates()
            .filter { peer in
                // Unknown state is treated as eligible to avoid excluding nodes
                // that do not publish node_state in app_data.
                peer.announcedPropagationEnabled != false
            }
    }

    private func isPropagationCandidateReachable(_ peer: DiscoveredPeer) -> Bool {
        guard hasFreshAnnounce(for: peer.destinationHash) else { return false }
        guard let hops = peer.pathHops, hops > 0 else { return false }
        // In this client hop accounting includes a local/shared hop offset.
        // Treat <=2 as directly reachable equivalents for selection confidence.
        return hops <= 2 || peer.lastAnnounceTransportID != nil
    }

    private func betterPropagationCandidate(
        current: DiscoveredPeer?,
        best: DiscoveredPeer
    ) -> Bool {
        guard let current else { return true }
        guard current.destinationHash != best.destinationHash else { return false }
        if current.announcedPropagationEnabled == false { return true }
        if !isPropagationCandidateReachable(current) { return true }

        let currentHops = current.pathHops ?? .max
        let bestHops = best.pathHops ?? .max
        return bestHops < currentHops
    }

    private func requestAutoPropagationSelectionEvaluation(reason: String) {
        guard autoSelectBestPropagationNode else { return }
        guard isAnyConnected else { return }
        autoPropagationEvaluationTask?.cancel()
        autoPropagationEvaluationTask = Task { [weak self] in
            // Coalesce bursts of announces/settings changes.
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard !Task.isCancelled else { return }
            await self?.runAutoPropagationSelection(reason: reason)
        }
    }

    private func scheduleAutoPropagationSelectionTask() {
        autoPropagationSelectionTask?.cancel()
        autoPropagationEvaluationTask?.cancel()
        autoPropagationSelectionTask = nil
        autoPropagationEvaluationTask = nil

        guard autoSelectBestPropagationNode, isAnyConnected else { return }
        let interval = Self.autoPropagationSelectionInterval
        let startupDelay = Self.autoPropagationSelectionStartupDelay
        autoPropagationSelectionTask = Task { [weak self] in
            // Allow announces/path info to accumulate before first decision.
            try? await Task.sleep(nanoseconds: UInt64(startupDelay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await self?.runAutoPropagationSelection(reason: "startup")
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard !Task.isCancelled else { break }
                await self?.runAutoPropagationSelection(reason: "periodic")
            }
        }
    }

    private func runAutoPropagationSelection(reason: String) async {
        guard autoSelectBestPropagationNode else { return }
        guard isAnyConnected else { return }

        let candidates = autoPropagationEligibleCandidates()
        guard !candidates.isEmpty else {
            log(.debug, "Auto-propagation: no eligible candidates (reason=\(reason))")
            return
        }

        let reachable = candidates.filter(isPropagationCandidateReachable(_:))
        guard !reachable.isEmpty else {
            log(.debug, "Auto-propagation: candidates announced but not reachable (reason=\(reason))")
            return
        }

        guard let best = reachable.min(by: { lhs, rhs in
            if (lhs.pathHops ?? .max) != (rhs.pathHops ?? .max) {
                return (lhs.pathHops ?? .max) < (rhs.pathHops ?? .max)
            }
            let lhsSeen = lhs.lastAnnounceAt ?? lhs.discoveredAt
            let rhsSeen = rhs.lastAnnounceAt ?? rhs.discoveredAt
            if lhsSeen != rhsSeen { return lhsSeen > rhsSeen }
            return lhs.destinationHash.lexicographicallyPrecedes(rhs.destinationHash)
        }) else {
            return
        }

        let current = peers.first(where: { $0.destinationHash == selectedPropagationNodeHash })
        guard betterPropagationCandidate(current: current, best: best) else {
            return
        }

        let probeOK = await probePropagationNodeReachability(best.destinationHash)
        guard probeOK else {
            log(
                .info,
                "Auto-propagation: best candidate \(best.destinationHash.hexString.prefix(8))… failed probe, keeping current"
            )
            return
        }

        selectedPropagationNodeHash = best.destinationHash
        persistSelectedPropagationNodeHash(best.destinationHash)
        savePeers()
        requestPropagationInboxSync(reason: "auto-selection")
        log(
            .info,
            "Auto-propagation: selected \(best.destinationHash.hexString.prefix(8))… (\(best.pathHops ?? -1) hops) reason=\(reason)"
        )
    }

    private func probePropagationNodeReachability(_ destinationHash: Data) async -> Bool {
        let candidateInterfaces = connectedInterfacesForDestination(destinationHash)
        guard !candidateInterfaces.isEmpty else { return false }
        let timeout = Self.autoPropagationProbeTimeout

        for (_, iface) in candidateInterfaces {
            _ = await sendPathRequest(for: destinationHash, via: iface)
            if await waitForFreshPeerPublicKey(
                for: destinationHash,
                timeout: timeout,
                allowPropagationDestination: true
            ) != nil {
                return true
            }
        }
        return false
    }

    private func requestPropagationInboxSync(reason: String) {
        guard isAnyConnected else { return }
        if propagationSyncTask != nil { return }
        if let lastAttempt = lastPropagationSyncAttemptAt,
           Date().timeIntervalSince(lastAttempt) < Self.propagationSyncMinInterval {
            return
        }

        lastPropagationSyncAttemptAt = Date()
        propagationSyncTask = Task { [weak self] in
            guard let self else { return }
            await self.runPropagationInboxSync(reason: reason)
        }
    }

    private func runPropagationInboxSync(reason: String) async {
        defer { propagationSyncTask = nil }
        guard let propagationNodeHash = preferredPropagationNode(excluding: Data()) else {
            return
        }

        let candidateInterfaces = connectedInterfacesForDestination(propagationNodeHash)
        guard !candidateInterfaces.isEmpty else { return }

        for (_, iface) in candidateInterfaces {
            do {
                _ = await sendPathRequest(for: propagationNodeHash, via: iface)
                let propagationNodePublicKey = try await resolvePeerPublicKey(
                    for: propagationNodeHash,
                    via: iface,
                    requireFreshAnnounce: true,
                    allowPropagationDestination: true
                )
                let linkState = try await ensureDirectLink(
                    destinationHash: propagationNodeHash,
                    recipientPublicKey: propagationNodePublicKey,
                    iface: iface
                )
                propagationLinkIDs.insert(linkState.linkID)
                let fetched = try await syncFromPropagationNode(linkState: linkState, via: iface)
                if fetched > 0 {
                    log(
                        .info,
                        "Propagation sync[\(reason)] fetched \(fetched) message(s) from \(propagationNodeHash.hexString.prefix(8))…"
                    )
                }
                return
            } catch {
                log(
                    .debug,
                    "Propagation sync[\(reason)] via interface failed: \(error.localizedDescription)"
                )
            }
        }
    }

    private func preferredPropagationNode(excluding destinationHash: Data) -> Data? {
        guard selectedPropagationNodeHash.count == Destination.hashLength else { return nil }
        guard selectedPropagationNodeHash != destinationHash else { return nil }
        return selectedPropagationNodeHash
    }

    private func propagationNodeStampCost(for propagationNodeHash: Data) -> Int? {
        guard let selected = peers.first(where: { $0.destinationHash == propagationNodeHash }) else {
            return nil
        }
        guard let cost = selected.announcedPropagationStampCost, (1..<255).contains(cost) else {
            return nil
        }
        return cost
    }

    private func destinationStampCost(for destinationHash: Data) -> Int? {
        guard let peer = peers.first(where: { $0.destinationHash == destinationHash }) else { return nil }
        guard let cost = peer.announcedStampCost, (1..<255).contains(cost) else { return nil }
        return cost
    }

    private func outboundTicket(for destinationHash: Data) -> Data? {
        guard let ticket = outboundTicketsByDestination[destinationHash], ticket.count == Destination.hashLength else {
            return nil
        }
        return ticket
    }

    private func rememberOutboundTicket(from sourceHash: Data, fields: [Int: Data]) {
        let ticketFieldID = 0x0C
        guard let raw = fields[ticketFieldID] else { return }
        guard let decoded = MsgPack.decodeTicketField(raw) else { return }
        guard decoded.expires > Date().timeIntervalSince1970 else { return }
        outboundTicketsByDestination[sourceHash] = decoded.ticket
    }

    private func inboundTickets(for sourceHash: Data) -> [Data]? {
        guard let ticket = outboundTicketsByDestination[sourceHash], ticket.count == Destination.hashLength else {
            return nil
        }
        return [ticket]
    }

    private func rememberPropagationDeliveredTransientID(_ transientID: Data) {
        guard transientID.count == 32 else { return }
        inboundDeliveredTransientIDs[transientID] = Date()
        persistInboundDeliveredTransientIDs()
    }

    private func hasDeliveredPropagationTransientID(_ transientID: Data) -> Bool {
        guard let deliveredAt = inboundDeliveredTransientIDs[transientID] else { return false }
        return Date().timeIntervalSince(deliveredAt) <= Self.propagationDeliveredTransientRetention
    }

    private func purgeExpiredPropagationTransientIDs(now: Date = Date()) {
        inboundDeliveredTransientIDs = inboundDeliveredTransientIDs.filter { _, deliveredAt in
            now.timeIntervalSince(deliveredAt) <= Self.propagationDeliveredTransientRetention
        }
        persistInboundDeliveredTransientIDs()
    }

    private func persistInboundDeliveredTransientIDs() {
        let payload = inboundDeliveredTransientIDs.reduce(into: [String: Double]()) { partial, entry in
            partial[entry.key.hexString] = entry.value.timeIntervalSince1970
        }
        UserDefaults.standard.set(payload, forKey: Self.inboundDeliveredTransientIDsDefaultsKey)
    }

    private static func loadInboundDeliveredTransientIDs() -> [Data: Date] {
        guard let raw = UserDefaults.standard.dictionary(forKey: inboundDeliveredTransientIDsDefaultsKey) as? [String: Double] else {
            return [:]
        }
        var decoded: [Data: Date] = [:]
        for (key, timestamp) in raw {
            guard let transientID = Data(hexString: key), transientID.count == 32 else { continue }
            decoded[transientID] = Date(timeIntervalSince1970: timestamp)
        }
        return decoded
    }

    private func notifyInboundMessageIfNeeded(_ msg: LXMFMessage) {
        guard inboundNotificationsEnabled else { return }

#if canImport(UIKit)
        guard UIApplication.shared.applicationState != .active else { return }
#endif

        let sender = peerName(for: msg.sourceHash) ?? "New LXMF message"
        let body = msg.content.isEmpty ? "(No content)" : msg.content
        let notificationID = "inbound-lxmf-\(msg.hash.hexString)"

        Task { [weak self] in
            guard let self else { return }
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()

            if settings.authorizationStatus == .notDetermined {
                let granted: Bool
                do {
                    granted = try await center.requestAuthorization(options: [.alert, .sound, .badge])
                } catch {
                    log(.warn, "Notifications: authorization request failed (\(error.localizedDescription))")
                    return
                }
                guard granted else { return }
            } else if settings.authorizationStatus != .authorized &&
                        settings.authorizationStatus != .provisional &&
                        settings.authorizationStatus != .ephemeral {
                return
            }

            let content = UNMutableNotificationContent()
            content.title = sender
            content.body = body
            content.sound = .default
            content.userInfo = ["sourceHash": msg.sourceHash.hexString]

            let request = UNNotificationRequest(identifier: notificationID, content: content, trigger: nil)
            do {
                try await center.add(request)
            } catch {
                log(.warn, "Notifications: failed to schedule inbound alert (\(error.localizedDescription))")
            }
        }
    }

    private func persistedPeerPublicKey(for destinationHash: Data) -> Data? {
        peers.first(where: { $0.destinationHash == destinationHash })?.publicKey
    }

    private func isValidNomadNodeKey(_ publicKey: Data, for destinationHash: Data) -> Bool {
        guard publicKey.count == Identity.publicKeyLength else { return false }
        let identityHash = Hashing.truncatedHash(publicKey, length: Identity.hashLength)
        return NomadNode.destinationHash(for: identityHash) == destinationHash
    }

    private func resolveNomadNodePublicKey(
        for destinationHash: Data,
        via iface: TCPClientInterface
    ) async throws -> Data {
        if let announced = freshNomadAnnouncedPublicKey(for: destinationHash) {
            await iface.seedIdentityCache(destinationHash: destinationHash, publicKey: announced)
            log(.info, "Nomad key source: nomad announce \(destinationHash.hexString.prefix(8))… key=\(peerKeyFingerprint(announced))…")
            return announced
        }

        if let cached = await iface.identityPublicKey(for: destinationHash),
           cached.count == Identity.publicKeyLength,
           isValidNomadNodeKey(cached, for: destinationHash) {
            log(.info, "Nomad key source: interface cache \(destinationHash.hexString.prefix(8))… key=\(peerKeyFingerprint(cached))…")
            return cached
        }

        if let persisted = persistedPeerPublicKey(for: destinationHash),
           persisted.count == Identity.publicKeyLength,
           isValidNomadNodeKey(persisted, for: destinationHash) {
            await iface.seedIdentityCache(destinationHash: destinationHash, publicKey: persisted)
            log(.info, "Nomad key source: persisted peer \(destinationHash.hexString.prefix(8))… key=\(peerKeyFingerprint(persisted))…")
            return persisted
        }

        _ = await sendPathRequest(for: destinationHash, via: iface)
        log(.info, "Nomad key source: awaiting nomadnetwork.node announce \(destinationHash.hexString.prefix(8))…")
        if let awaited = await iface.waitForIdentityPublicKey(destinationHash: destinationHash, timeout: 30),
           awaited.count == Identity.publicKeyLength,
           isValidNomadNodeKey(awaited, for: destinationHash) {
            await iface.seedIdentityCache(destinationHash: destinationHash, publicKey: awaited)
            if let idx = peers.firstIndex(where: { $0.destinationHash == destinationHash }) {
                peers[idx].publicKey = awaited
                peers[idx].isNomadNode = true
                peers[idx].lastAnnounceAt = Date()
                peers[idx].lastAnnounceServerID = activeReceiveServerID ?? peers[idx].lastAnnounceServerID
            } else {
                peers.insert(
 DiscoveredPeer(
     destinationHash: destinationHash,
     publicKey: awaited,
     displayName: nil,
     isLXMFPeer: false,
     isNomadNode: true,
     lastAnnounceAt: Date(),
     lastAnnounceServerID: activeReceiveServerID
 ),
 at: 0
                )
            }
            savePeers()
            log(.info, "Nomad key source: announce \(destinationHash.hexString.prefix(8))… key=\(peerKeyFingerprint(awaited))…")
            return awaited
        }

        throw AppError.noPath
    }

    private func connectedInterfacesForDestination(_ destinationHash: Data) -> [(UUID, TCPClientInterface)] {
        let connected = interfaces
            .filter { serverStatuses[$0.key] == true }
            .map { ($0.key, $0.value) }

        guard !connected.isEmpty else { return [] }

        if let peer = peers.first(where: { $0.destinationHash == destinationHash }),
           let preferredServerID = peer.lastAnnounceServerID,
           let preferred = connected.first(where: { $0.0 == preferredServerID }) {
            let others = connected.filter { $0.0 != preferredServerID }
            return [preferred] + others
        }

        return connected
    }

    /// Injects HEADER_2 transport routing for known multi-hop destinations.
    private func applyTransportRoutingIfNeeded(
        to h1RawPacket: Data,
        destinationHash: Data
    ) throws -> (rawPacket: Data, isHeader2: Bool) {
        guard h1RawPacket.count > 2 else { return (h1RawPacket, false) }
        guard let peer = peers.first(where: { $0.destinationHash == destinationHash }) else {
            return (h1RawPacket, false)
        }
        let hops = peer.pathHops ?? 1
        guard hops > 1 else { return (h1RawPacket, false) }

        guard let nextHopTransportID = peer.lastAnnounceTransportID,
              nextHopTransportID.count == Destination.hashLength else {
            log(
                .warn,
                "TX transport path missing next-hop transport ID for \(destinationHash.hexString.prefix(8))… hops=\(hops)"
            )
            throw AppError.noPath
        }

        let originalFlags = h1RawPacket[h1RawPacket.startIndex]
        let newFlags: UInt8 =
            (PacketHeader.HeaderType.header2.rawValue << 6) |
            (PacketHeader.PropagationType.transport.rawValue << 4) |
            (originalFlags & 0x0F)

        var routed = Data(capacity: h1RawPacket.count + Destination.hashLength)
        routed.append(newFlags)
        routed.append(h1RawPacket[h1RawPacket.startIndex + 1]) // hops
        routed.append(nextHopTransportID)   // transport_id
        routed.append(h1RawPacket.dropFirst(2))               // destination + context + payload

        log(
            .debug,
            "TX transport route: dest=\(destinationHash.hexString.prefix(8))… hops=\(hops) nextHop=\(nextHopTransportID.hexString.prefix(8))… H1=\(h1RawPacket.count)B -> H2=\(routed.count)B"
        )
        return (routed, true)
    }

    func send(
        to destinationHash: Data,
        content: String,
        method: MessageDeliveryMethod,
        propagationNodeHash: Data? = nil,
        outboundMessageID: UUID? = nil,
        outboundTimestamp: Date? = nil
    ) async throws {
        guard let identity else { throw AppError.noIdentity }
        log(.info, "TX send() invoked: input=\(destinationHash.hexString.prefix(8))… len=\(content.count) method=\(method.rawValue)")

        let finalDestination = resolveRecipientDestinationHash(destinationHash)
        if finalDestination != destinationHash {
            log(.info, "Resolved identity hash → lxmf.delivery dest \(finalDestination.hexString.prefix(8))…")
        } else {
            log(.info, "Recipient interpreted as lxmf.delivery dest \(finalDestination.hexString.prefix(8))…")
        }

        let candidateInterfaces = connectedInterfacesForDestination(finalDestination)
        guard !candidateInterfaces.isEmpty else {
            throw AppError.notConnected
        }

        var lastError: Error?
        for (serverID, iface) in candidateInterfaces {
            do {
                switch method {
                case .opportunistic:
 // Keep transport paths warm even when we already have a cached
 // recipient key. Opportunistic delivery depends on current path state.
 _ = await sendPathRequest(for: finalDestination, via: iface)
 let peerPublicKey = try await resolvePeerPublicKey(
     for: finalDestination,
     via: iface,
     requireFreshAnnounce: true
 )
 try await sendOpportunistic(
     to: finalDestination,
     recipientPublicKey: peerPublicKey,
     content: content,
     identity: identity,
     iface: iface,
     outboundMessageID: outboundMessageID
 )

                case .direct:
 let peerPublicKey = try await resolvePeerPublicKey(
     for: finalDestination,
     via: iface,
     requireFreshAnnounce: true
 )
 try await sendDirect(
     to: finalDestination,
     recipientPublicKey: peerPublicKey,
     content: content,
     identity: identity,
     iface: iface,
     outboundMessageID: outboundMessageID
 )

                case .propagated:
 let recipientPublicKey: Data
 if let ifaceCached = await iface.identityPublicKey(for: finalDestination),
    ifaceCached.count == Identity.publicKeyLength {
     recipientPublicKey = ifaceCached
 } else if let persisted = persistedPeerPublicKey(for: finalDestination),
           persisted.count == Identity.publicKeyLength,
           isValidLXMFDeliveryKey(persisted, for: finalDestination) {
     // Propagated delivery can work without a live path to the recipient
     // as long as we have a previously announced identity key.
     recipientPublicKey = persisted
     await iface.seedIdentityCache(destinationHash: finalDestination, publicKey: persisted)
     log(
         .info,
         "TX recipient key source: persisted cache \(finalDestination.hexString.prefix(8))… key=\(peerKeyFingerprint(persisted))…"
     )
 } else {
     _ = await sendPathRequest(for: finalDestination, via: iface)
     recipientPublicKey = try await resolvePeerPublicKey(for: finalDestination, via: iface)
 }

 guard let propagationNodeHash else {
     throw AppError.propagationNodeRequired
 }
 _ = await sendPathRequest(for: propagationNodeHash, via: iface)
 let propagationNodePublicKey = try await resolvePeerPublicKey(
     for: propagationNodeHash,
     via: iface,
     requireFreshAnnounce: true,
     allowPropagationDestination: true
 )
 try await sendPropagated(
     to: finalDestination,
     recipientPublicKey: recipientPublicKey,
     propagationNodeHash: propagationNodeHash,
     propagationNodePublicKey: propagationNodePublicKey,
     content: content,
     identity: identity,
     iface: iface,
     outboundMessageID: outboundMessageID
 )
                }
                log(.debug, "TX method \(method.rawValue) used interface \(serverID.uuidString.prefix(8))…")
                let status: OutboundDeliveryStatus = method == .opportunistic ? .delivered : .sent
                let msg = ConversationMessage(
 id: outboundMessageID ?? UUID(),
 content: content,
 timestamp: outboundTimestamp ?? .now,
 isOutbound: true,
 deliveryStatus: status
                )
                upsertConversation(destinationHash: finalDestination, message: msg)
                appendLog("Sent (\(method.rawValue)) → \(finalDestination.hexString.prefix(8))…")
                return
            } catch {
                lastError = error
                log(.warn, "TX \(method.rawValue) via interface \(serverID.uuidString.prefix(8))… failed: \(error.localizedDescription)")
            }
        }

        throw lastError ?? AppError.noPath
    }

    func send(to destinationHash: Data, content: String) async throws {
        guard interfaces.first(where: { serverStatuses[$0.key] == true })?.value != nil else {
            throw AppError.notConnected
        }

        let finalDestination = resolveRecipientDestinationHash(destinationHash)
        let outboundMessageID = UUID()
        let outboundTimestamp = Date()
        let propagationNodeHash = preferredPropagationNode(excluding: finalDestination)
        let directEligible = hasRecentDirectAnnounce(for: finalDestination)

        var attempts: [MessageDeliveryMethod] = []
        if directEligible {
            attempts.append(.direct)
        }
        attempts.append(.opportunistic)
        if propagationNodeHash != nil {
            attempts.append(.propagated)
        }

        let attemptStr = attempts.map(\.rawValue).joined(separator: " -> ")
        log(
            .info,
            "TX auto delivery plan: recipient=\(finalDestination.hexString.prefix(8))… directEligible=\(directEligible ? "yes" : "no") attempts=\(attemptStr)"
        )

        var lastError: Error?
        for method in attempts {
            do {
                try await send(
 to: finalDestination,
 content: content,
 method: method,
 propagationNodeHash: method == .propagated ? propagationNodeHash : nil,
 outboundMessageID: outboundMessageID,
 outboundTimestamp: outboundTimestamp
                )
                return
            } catch {
                lastError = error
                log(.warn, "TX \(method.rawValue) attempt failed for \(finalDestination.hexString.prefix(8))…: \(error.localizedDescription)")
            }
        }

        let failed = ConversationMessage(
            id: outboundMessageID,
            content: content,
            timestamp: outboundTimestamp,
            isOutbound: true,
            deliveryStatus: .failed
        )
        upsertConversation(destinationHash: finalDestination, message: failed)
        throw lastError ?? AppError.noPath
    }

    // Identity management

    // Path requests

    /// Sends `targetHash + requestTag` to modern and legacy path-request endpoints.
    @discardableResult
    private func sendPathRequest(for targetHash: Data, via iface: TCPClientInterface) async -> Bool {
        // Modern path request endpoint.
        let pathRequestDest = Data([
            0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa,
            0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27, 0x61
        ])
        // Legacy endpoint used by older stacks / examples.
        let legacyPathfinderDest = Data([
            0xd5, 0x85, 0xfa, 0x7a, 0xd2, 0xe0, 0xf2, 0x7b,
            0xed, 0x1b, 0xd2, 0x92, 0xa1, 0x13, 0x0e, 0x04
        ])

        var requestTag = Data(count: Destination.hashLength)
        _ = requestTag.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, Destination.hashLength, $0.baseAddress!)
        }

        // Python request_path payload:
        //   destination_hash(16) + request_tag(16)
        let payload = targetHash + requestTag

        let destinations = [pathRequestDest, legacyPathfinderDest]
        var sentAny = false
        for dest in destinations {
            let header = PacketHeader(
                packetType:      .data,
                destinationType: .plain,
                destinationHash: dest,
                hops:            0,
                context:         0x00    // NONE
            )
            let packet = Packet(header: header, payload: payload)
            do {
                try await iface.send(packet.serialize())
                sentAny = true
                let endpointRole = dest == pathRequestDest
 ? "rnstransport.path.request"
 : "rnstransport.pathfinder"
                log(
 .info,
 "PATH REQUEST[\(dest.hexString.prefix(8))… role=\(endpointRole)] → \(targetHash.hexString.prefix(8))… tag=\(requestTag.hexString.prefix(8))… payload=\(payload.count)B"
                )
            } catch {
                log(.warn, "PATH REQUEST[\(dest.hexString.prefix(8))…] failed: \(error)")
            }
        }
        return sentAny
    }

    /// Resolve a peer's full 64-byte identity public key for `destinationHash`.
    ///
    /// Mirrors inertia-original `resolveIdentity(hash:)` behavior:
    /// request path and then wait for the identity to appear.
    private func resolvePeerPublicKey(
        for destinationHash: Data,
        via iface: TCPClientInterface,
        requireFreshAnnounce: Bool = false,
        allowPropagationDestination: Bool = false
    ) async throws -> Data {
        let cached = await iface.identityPublicKey(for: destinationHash)

        if requireFreshAnnounce,
           let announced = freshAnnouncedPublicKey(
            for: destinationHash,
            allowPropagationDestination: allowPropagationDestination
           ),
           let cached,
           cached.count == Identity.publicKeyLength,
           isValidLXMFDestinationKey(
            cached,
            for: destinationHash,
            allowPropagationDestination: allowPropagationDestination
           ),
           cached != announced {
            log(
                .warn,
                "TX recipient key mismatch: interface=\(peerKeyFingerprint(cached))… announce=\(peerKeyFingerprint(announced))… using announce"
            )
            await iface.seedIdentityCache(destinationHash: destinationHash, publicKey: announced)
            log(
                .info,
                "TX recipient key source: fresh announce \(destinationHash.hexString.prefix(8))… key=\(peerKeyFingerprint(announced))…"
            )
            log(.debug, "TX key context: \(peerRouteSnapshot(for: destinationHash))")
            return announced
        }

        if let cached,
           cached.count == Identity.publicKeyLength,
           isValidLXMFDestinationKey(
            cached,
            for: destinationHash,
            allowPropagationDestination: allowPropagationDestination
           ),
           (!requireFreshAnnounce || hasFreshAnnounce(for: destinationHash)) {
            log(
                .info,
                "TX recipient key source: interface cache \(destinationHash.hexString.prefix(8))… key=\(peerKeyFingerprint(cached))…"
            )
            log(.debug, "TX key context: \(peerRouteSnapshot(for: destinationHash))")
            if let idx = peers.firstIndex(where: { $0.destinationHash == destinationHash }) {
                peers[idx].publicKey = cached
                peers[idx].isLXMFPeer = true
            } else {
                peers.insert(
 DiscoveredPeer(
     destinationHash: destinationHash,
     publicKey: cached,
     displayName: nil,
     isLXMFPeer: true
 ),
 at: 0
                )
            }
            savePeers()
            return cached
        }

        if requireFreshAnnounce {
            _ = await sendPathRequest(for: destinationHash, via: iface)
            log(.info, "TX recipient key source: awaiting fresh announce \(destinationHash.hexString.prefix(8))…")
            if let awaited = await waitForFreshPeerPublicKey(
                for: destinationHash,
                timeout: 30,
                allowPropagationDestination: allowPropagationDestination
            ) {
                await iface.seedIdentityCache(destinationHash: destinationHash, publicKey: awaited)
                log(
 .info,
 "TX recipient key source: fresh announce \(destinationHash.hexString.prefix(8))… key=\(peerKeyFingerprint(awaited))…"
                )
                log(.debug, "TX key context: \(peerRouteSnapshot(for: destinationHash))")
                return awaited
            }
            appendLog("⚠ No path to \(destinationHash.hexString.prefix(8))… — wait for a fresh announce")
            throw AppError.noPath
        }

        // Prefer route-fresh announce keys over persisted cache to avoid stale keys
        // causing outbound encryption mismatches.
        _ = await sendPathRequest(for: destinationHash, via: iface)
        log(.info, "TX recipient key source: awaiting announce \(destinationHash.hexString.prefix(8))…")
        if let awaited = await iface.waitForIdentityPublicKey(destinationHash: destinationHash, timeout: 30),
           awaited.count == Identity.publicKeyLength,
           isValidLXMFDestinationKey(
            awaited,
            for: destinationHash,
            allowPropagationDestination: allowPropagationDestination
           ) {
            log(
                .info,
                "TX recipient key source: announce \(destinationHash.hexString.prefix(8))… key=\(peerKeyFingerprint(awaited))…"
            )
            log(.debug, "TX key context: \(peerRouteSnapshot(for: destinationHash))")
            if let idx = peers.firstIndex(where: { $0.destinationHash == destinationHash }) {
                peers[idx].publicKey = awaited
                peers[idx].isLXMFPeer = true
            } else {
                peers.insert(
 DiscoveredPeer(
     destinationHash: destinationHash,
     publicKey: awaited,
     displayName: nil,
     isLXMFPeer: true
 ),
 at: 0
                )
            }
            savePeers()
            return awaited
        }

        appendLog("⚠ No path to \(destinationHash.hexString.prefix(8))… — wait for a fresh announce")
        throw AppError.noPath
    }

    /// Encrypt opportunistic payload with the recipient identity.
    private func encryptOpportunisticPayload(
        _ plaintext: Data,
        recipientPublicKey: Data,
        destinationHash: Data
    ) throws -> Data {
        let x25519Pub    = Data(recipientPublicKey.prefix(32))
        let identityHash = Hashing.truncatedHash(recipientPublicKey, length: Identity.hashLength)

        let encrypted: Data
        do {
            encrypted = try ReticulumToken.encrypt(
                plaintext,
                recipientX25519PublicKey: x25519Pub,
                identityHash: identityHash
            )
        } catch {
            appendLog("⚠ Encryption failed for \(destinationHash.hexString.prefix(8))…: \(error)")
            throw AppError.encryptionFailed
        }

        let totalPacketSize = 19 + encrypted.count
        if totalPacketSize > 500 {
            appendLog("⚠ LXMF OPPORTUNISTIC too large (\(totalPacketSize)B > 500B MTU)")
            throw AppError.messageTooLarge
        }

        log(.debug, "TX encrypted → token=\(encrypted.count)B (ephPub32+iv16+ct\(encrypted.count - 80)+hmac32)")
        return encrypted
    }

    private func sendOpportunistic(
        to destinationHash: Data,
        recipientPublicKey: Data,
        content: String,
        identity: Identity,
        iface: TCPClientInterface,
        outboundMessageID: UUID? = nil
    ) async throws {
        let messageStampCost = destinationStampCost(for: destinationHash)
        let outboundTicket = outboundTicket(for: destinationHash)
        let ratchetKey = activeRatchetPublicKey(for: destinationHash)
        let encryptionAttempts: [Data?] = ratchetKey != nil ? [ratchetKey, nil] : [nil]
        var activeRecipientPublicKey = recipientPublicKey

        for (index, attemptRatchetKey) in encryptionAttempts.enumerated() {
            let attemptNumber = index + 1
            let ratchetLabel = attemptRatchetKey.map { shortHash($0) } ?? "none"
            let ticketLabel = outboundTicket.map { shortHash($0) } ?? "none"
            let stampLabel = messageStampCost.map(String.init) ?? "none"
            log(
                .info,
                "OPPORTUNISTIC attempt \(attemptNumber)/\(encryptionAttempts.count): dest=\(destinationHash.hexString.prefix(8))… key=\(peerKeyFingerprint(activeRecipientPublicKey))… ratchet=\(ratchetLabel) stamp=\(stampLabel) ticket=\(ticketLabel)"
            )
            log(.debug, "OPPORTUNISTIC route context: \(peerRouteSnapshot(for: destinationHash))")

            if index == 1 {
                log(.warn, "OPPORTUNISTIC retry without ratchet key for \(destinationHash.hexString.prefix(8))…")
                _ = await sendPathRequest(for: destinationHash, via: iface)

                // Re-resolve recipient identity key before retry. The first
                // attempt can fail if we encrypted to a stale cached key.
                do {
 let refreshedKey = try await resolvePeerPublicKey(
     for: destinationHash,
     via: iface,
     requireFreshAnnounce: true
 )
 if refreshedKey != activeRecipientPublicKey {
     activeRecipientPublicKey = refreshedKey
     log(
         .info,
         "OPPORTUNISTIC retry refreshed recipient key=\(peerKeyFingerprint(refreshedKey))…"
     )
 } else {
     log(.info, "OPPORTUNISTIC retry key unchanged=\(peerKeyFingerprint(refreshedKey))…")
 }
                } catch {
 log(
     .warn,
     "OPPORTUNISTIC retry key refresh failed for \(destinationHash.hexString.prefix(8))…: \(error.localizedDescription)"
 )
                }
            }

            let outbound = try await lxmfRouter.createOpportunisticOutbound(
                destinationHash: destinationHash,
                sourceIdentity: identity,
                recipientIdentityPublicKey: activeRecipientPublicKey,
                recipientRatchetPublicKey: attemptRatchetKey,
                messageStampCost: messageStampCost,
                outboundTicket: outboundTicket,
                content: content,
                title: "",
                timestamp: Date().timeIntervalSince1970
            )

            let packed = outbound.packedMessage
            let srcHash = Destination.hash(appName: "lxmf", aspects: ["delivery"], identityHash: identity.hash)
            log(.debug, "TX LXMF packed=\(packed.count)B dest=\(destinationHash.hexString.prefix(8))… src=\(srcHash.hexString.prefix(8))…")
            log(.debug, "TX LXMF details: \(lxmfPackedSummary(packed))")
            log(.info, "TX route: OPPORTUNISTIC (\(packed.count)B packed)")
            log(.debug, "TX token details: \(tokenLayoutSummary(outbound.encryptedPayload))")

            let totalPacketSize = 19 + outbound.encryptedPayload.count
            if totalPacketSize > 500 {
                appendLog("⚠ LXMF OPPORTUNISTIC too large (\(totalPacketSize)B > 500B MTU)")
                throw AppError.messageTooLarge
            }

            let header = PacketHeader(
                packetType: .data,
                destinationType: .single,
                destinationHash: destinationHash,
                hops: 0,
                context: 0x00
            )
            let serializedH1 = Packet(header: header, payload: outbound.encryptedPayload).serialize()
            let (serialized, proofIsHeader2) = try applyTransportRoutingIfNeeded(
                to: serializedH1,
                destinationHash: destinationHash
            )
            let headerPreviewLength = proofIsHeader2 ? (PacketHeader.serializedLength + Destination.hashLength) : PacketHeader.serializedLength
            log(
                .debug,
                "TX packet=\(serialized.count)B \(proofIsHeader2 ? "H2" : "H1") header=\(serialized.prefix(min(headerPreviewLength, serialized.count)).hexString)"
            )

            guard let proofHash = computeSingleProofDestinationHash(fromRawPacket: serialized, isHeader2: proofIsHeader2) else {
                throw AppError.deliveryProofTimeout
            }
            outboundProofExpectations[proofHash] = Date()
            if let outboundMessageID {
                outboundSingleProofMessageByHash[proofHash] = outboundMessageID
            }
            let proofTimeout = deliveryProofTimeout(for: destinationHash)
            log(
                .debug,
                "TX delivery proof target=\(proofHash.hexString.prefix(8))… timeout=\(Int(proofTimeout))s"
            )
            log(
                .debug,
                "TX proof awaiting (\(outboundProofExpectations.count)): [\(awaitingProofsSummary())]"
            )

            do {
                try await iface.send(serialized)
            } catch {
                outboundProofExpectations.removeValue(forKey: proofHash)
                outboundSingleProofMessageByHash.removeValue(forKey: proofHash)
                appendLog("⚠ Send failed: \(error)")
                throw error
            }

            if await waitForSingleDeliveryProof(proofHash, timeout: proofTimeout) {
                return
            }
        }

        throw AppError.deliveryProofTimeout
    }

    private func sendDirect(
        to destinationHash: Data,
        recipientPublicKey: Data,
        content: String,
        identity: Identity,
        iface: TCPClientInterface,
        outboundMessageID: UUID? = nil
    ) async throws {
        guard hasRecentDirectAnnounce(for: destinationHash) else {
            log(.warn, "DIRECT skipped: destination \(destinationHash.hexString.prefix(8))… is not 0/1-hop fresh path")
            throw AppError.noPath
        }

        let packed = try LXMFMessage.create(
            destinationHash: destinationHash,
            sourceIdentity: identity,
            content: content,
            title: "",
            timestamp: Date().timeIntervalSince1970,
            stampCost: destinationStampCost(for: destinationHash)
        )

        // Use current link state if route signature still matches; if proof is not
        // returned, rebuild once and retry to recover from stale-link transitions.
        for attempt in 1...2 {
            let forceReestablish = attempt > 1
            if forceReestablish {
                log(.warn, "DIRECT retry re-establishing link for \(destinationHash.hexString.prefix(8))…")
            }

            let linkState = try await ensureDirectLink(
                destinationHash: destinationHash,
                recipientPublicKey: recipientPublicKey,
                iface: iface,
                forceReestablish: forceReestablish
            )

            let encrypted = try await lxmfRouter.encryptDirectPayload(
                destinationHash: destinationHash,
                lxmfPackedMessage: packed
            )

            let header = PacketHeader(
                packetType: .data,
                destinationType: .link,
                destinationHash: linkState.linkID,
                hops: 0,
                context: 0x00
            )
            let serialized = Packet(header: header, payload: encrypted).serialize()
            log(.info, "TX route: DIRECT link=\(linkState.linkID.hexString.prefix(8))… packet=\(serialized.count)B")

            let directProofHash = Hashing.sha256(
                Data([serialized[0] & UInt8(0x0F)]) + serialized.dropFirst(2)
            )
            outboundDirectProofExpectations[directProofHash] = Date()
            if let outboundMessageID {
                outboundDirectProofMessageByHash[directProofHash] = outboundMessageID
            }

            do {
                try await iface.send(serialized)
            } catch {
                outboundDirectProofExpectations.removeValue(forKey: directProofHash)
                outboundDirectProofMessageByHash.removeValue(forKey: directProofHash)
                appendLog("⚠ DIRECT send failed: \(error)")
                throw error
            }

            let proofTimeout = deliveryProofTimeout(for: destinationHash)
            if await waitForDirectDeliveryProof(directProofHash, timeout: proofTimeout, pollOnly: !forceReestablish) {
                return
            }
        }

        throw AppError.deliveryProofTimeout
    }

    private func sendPropagated(
        to destinationHash: Data,
        recipientPublicKey: Data,
        propagationNodeHash: Data,
        propagationNodePublicKey: Data,
        content: String,
        identity: Identity,
        iface: TCPClientInterface,
        outboundMessageID: UUID? = nil
    ) async throws {
        let outboundTicket = outboundTicket(for: destinationHash)
        let outbound = try await lxmfRouter.createPropagatedOutbound(
            destinationHash: destinationHash,
            sourceIdentity: identity,
            recipientIdentityPublicKey: recipientPublicKey,
            recipientRatchetPublicKey: activeRatchetPublicKey(for: destinationHash),
            propagationNodeIdentityPublicKey: propagationNodePublicKey,
            propagationNodeRatchetPublicKey: activeRatchetPublicKey(for: propagationNodeHash),
            messageStampCost: destinationStampCost(for: destinationHash),
            propagationStampCost: propagationNodeStampCost(for: propagationNodeHash),
            outboundTicket: outboundTicket,
            content: content,
            title: "",
            messageTimestamp: Date().timeIntervalSince1970,
            propagationTimestamp: Date().timeIntervalSince1970
        )

        let header = PacketHeader(
            packetType: .data,
            destinationType: .single,
            destinationHash: propagationNodeHash,
            hops: 0,
            context: 0x00
        )
        let serializedH1 = Packet(header: header, payload: outbound.encryptedContainer).serialize()
        let (serialized, proofIsHeader2) = try applyTransportRoutingIfNeeded(
            to: serializedH1,
            destinationHash: propagationNodeHash
        )
        log(
            .info,
            "TX route: PROPAGATED node=\(propagationNodeHash.hexString.prefix(8))… transient=\(outbound.transientID.hexString.prefix(8))… packet=\(serialized.count)B"
        )

        if let proofHash = computeSingleProofDestinationHash(fromRawPacket: serialized, isHeader2: proofIsHeader2) {
            outboundProofExpectations[proofHash] = Date()
            if let outboundMessageID {
                outboundSingleProofMessageByHash[proofHash] = outboundMessageID
            }
        }

        do {
            try await iface.send(serialized)
        } catch {
            if let proofHash = computeSingleProofDestinationHash(fromRawPacket: serialized, isHeader2: proofIsHeader2) {
                outboundProofExpectations.removeValue(forKey: proofHash)
                outboundSingleProofMessageByHash.removeValue(forKey: proofHash)
            }
            appendLog("⚠ PROPAGATED send failed: \(error)")
            throw error
        }
    }

    private func ensureDirectLink(
        destinationHash: Data,
        recipientPublicKey: Data,
        iface: TCPClientInterface,
        forceReestablish: Bool = false
    ) async throws -> LXMFRouter.DirectLinkState {
        let currentSignature = directLinkRouteSignature(for: destinationHash)
        let establishedSignature = directLinkRouteSignatureByDestination[destinationHash]
        let routeChanged = establishedSignature != nil && establishedSignature != currentSignature

        if forceReestablish || routeChanged {
            if routeChanged {
                log(
 .info,
 "DIRECT link invalidated for \(destinationHash.hexString.prefix(8))… due to route change"
                )
            }
            await lxmfRouter.removeDirectLink(for: destinationHash)
            directLinkRouteSignatureByDestination.removeValue(forKey: destinationHash)
            if let staleRequestLinkID = pendingDirectLinkByDestination.removeValue(forKey: destinationHash) {
                pendingDirectRecipientKeysByLinkID.removeValue(forKey: staleRequestLinkID)
                pendingDirectDestinationByLinkID.removeValue(forKey: staleRequestLinkID)
            }
            if let waiters = directLinkWaiters.removeValue(forKey: destinationHash) {
                for (_, cont) in waiters { cont.resume(returning: nil) }
            }
        }

        if let existing = await lxmfRouter.directLink(for: destinationHash) {
            return existing
        }
        if let pendingLinkID = pendingDirectLinkByDestination[destinationHash] {
            if let link = await waitForDirectLink(destinationHash: destinationHash, timeout: 20) {
                return link
            }
            clearPendingDirectLink(linkID: pendingLinkID)
        }

        let request = try await lxmfRouter.createDirectLinkRequest(destinationHash: destinationHash)
        pendingDirectRecipientKeysByLinkID[request.linkID] = recipientPublicKey
        pendingDirectDestinationByLinkID[request.linkID] = destinationHash
        pendingDirectLinkByDestination[destinationHash] = request.linkID

        let header = PacketHeader(
            packetType: .linkRequest,
            destinationType: .single,
            destinationHash: destinationHash,
            hops: 0,
            context: 0x00
        )
        let packet = Packet(header: header, payload: request.payload)
        log(.info, "TX LINKREQUEST dest=\(destinationHash.hexString.prefix(8))… link=\(request.linkID.hexString.prefix(8))…")
        try await iface.send(packet.serialize())

        if let link = await waitForDirectLink(destinationHash: destinationHash, timeout: 20) {
            directLinkRouteSignatureByDestination[destinationHash] = currentSignature
            return link
        }
        throw AppError.linkEstablishmentFailed
    }

    private func waitForDirectLink(destinationHash: Data, timeout: TimeInterval) async -> LXMFRouter.DirectLinkState? {
        if let existing = await lxmfRouter.directLink(for: destinationHash) {
            return existing
        }

        let waiterID = UUID()
        return await withCheckedContinuation { (cont: CheckedContinuation<LXMFRouter.DirectLinkState?, Never>) in
            var waiters = directLinkWaiters[destinationHash] ?? []
            waiters.append((id: waiterID, cont: cont))
            directLinkWaiters[destinationHash] = waiters

            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                guard let self else { cont.resume(returning: nil); return }
                self.cancelDirectLinkWaiter(id: waiterID, destinationHash: destinationHash)
            }
        }
    }

    private func cancelDirectLinkWaiter(id: UUID, destinationHash: Data) {
        guard var waiters = directLinkWaiters[destinationHash] else { return }
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        let cont = waiters[index].cont
        waiters.remove(at: index)
        directLinkWaiters[destinationHash] = waiters.isEmpty ? nil : waiters
        cont.resume(returning: nil)
    }

    private func resolveDirectLinkWaiters(destinationHash: Data, link: LXMFRouter.DirectLinkState) {
        guard let waiters = directLinkWaiters.removeValue(forKey: destinationHash) else { return }
        for (_, cont) in waiters {
            cont.resume(returning: link)
        }
    }

    private func enqueueNomadResponse(payload: Data, linkID: Data) {
        if var waiters = nomadResponseWaiters[linkID], !waiters.isEmpty {
            let waiter = waiters.removeFirst()
            nomadResponseWaiters[linkID] = waiters.isEmpty ? nil : waiters
            waiter.cont.resume(returning: payload)
            return
        }

        var buffered = bufferedNomadResponsesByLinkID[linkID] ?? []
        buffered.append(payload)
        bufferedNomadResponsesByLinkID[linkID] = buffered
    }

    private func enqueuePropagationResponse(payload: Data, linkID: Data) {
        if var waiters = propagationResponseWaiters[linkID], !waiters.isEmpty {
            let waiter = waiters.removeFirst()
            propagationResponseWaiters[linkID] = waiters.isEmpty ? nil : waiters
            waiter.cont.resume(returning: payload)
            return
        }

        var buffered = bufferedPropagationResponsesByLinkID[linkID] ?? []
        buffered.append(payload)
        bufferedPropagationResponsesByLinkID[linkID] = buffered
    }

    private func cancelNomadResponseWaiter(id: UUID, linkID: Data) {
        guard var waiters = nomadResponseWaiters[linkID] else { return }
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        let cont = waiters[index].cont
        waiters.remove(at: index)
        nomadResponseWaiters[linkID] = waiters.isEmpty ? nil : waiters
        cont.resume(returning: nil)
    }

    private func cancelPropagationResponseWaiter(id: UUID, linkID: Data) {
        guard var waiters = propagationResponseWaiters[linkID] else { return }
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        let cont = waiters[index].cont
        waiters.remove(at: index)
        propagationResponseWaiters[linkID] = waiters.isEmpty ? nil : waiters
        cont.resume(returning: nil)
    }

    private func waitForNomadResponse(linkID: Data, timeout: TimeInterval) async -> Data? {
        if var buffered = bufferedNomadResponsesByLinkID[linkID], !buffered.isEmpty {
            let first = buffered.removeFirst()
            bufferedNomadResponsesByLinkID[linkID] = buffered.isEmpty ? nil : buffered
            return first
        }

        let waiterID = UUID()
        return await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            var waiters = nomadResponseWaiters[linkID] ?? []
            waiters.append((id: waiterID, cont: cont))
            nomadResponseWaiters[linkID] = waiters

            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                guard let self else {
 cont.resume(returning: nil)
 return
                }
                self.cancelNomadResponseWaiter(id: waiterID, linkID: linkID)
            }
        }
    }

    private func waitForPropagationResponse(linkID: Data, timeout: TimeInterval) async -> Data? {
        if var buffered = bufferedPropagationResponsesByLinkID[linkID], !buffered.isEmpty {
            let first = buffered.removeFirst()
            bufferedPropagationResponsesByLinkID[linkID] = buffered.isEmpty ? nil : buffered
            return first
        }

        let waiterID = UUID()
        return await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            var waiters = propagationResponseWaiters[linkID] ?? []
            waiters.append((id: waiterID, cont: cont))
            propagationResponseWaiters[linkID] = waiters

            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                guard let self else {
                    cont.resume(returning: nil)
                    return
                }
                self.cancelPropagationResponseWaiter(id: waiterID, linkID: linkID)
            }
        }
    }

    private func sendNomadRequestPayload(
        _ payload: Data,
        linkState: LXMFRouter.DirectLinkState,
        via iface: TCPClientInterface
    ) async throws {
        let encrypted = try ReticulumToken.encryptLinkData(payload, key: linkState.derivedKey)
        let header = PacketHeader(
            packetType: .data,
            destinationType: .link,
            destinationHash: linkState.linkID,
            hops: 0,
            context: 0x00
        )
        let serialized = Packet(header: header, payload: encrypted).serialize()
        try await iface.send(serialized)
    }

    private func sendLinkRequestPayload(
        _ payload: Data,
        context: UInt8,
        linkState: LXMFRouter.DirectLinkState,
        via iface: TCPClientInterface
    ) async throws {
        let encrypted = try ReticulumToken.encryptLinkData(payload, key: linkState.derivedKey)
        let header = PacketHeader(
            packetType: .data,
            destinationType: .link,
            destinationHash: linkState.linkID,
            hops: 0,
            context: context
        )
        let serialized = Packet(header: header, payload: encrypted).serialize()
        try await iface.send(serialized)
    }

    private func sendLinkIdentify(
        linkState: LXMFRouter.DirectLinkState,
        via iface: TCPClientInterface
    ) async throws {
        guard let identity else { throw AppError.noIdentity }
        var signedData = Data()
        signedData.append(linkState.linkID)
        signedData.append(identity.publicKey)
        let signature = try identity.sign(signedData)

        var identifyPayload = Data()
        identifyPayload.append(identity.publicKey)
        identifyPayload.append(signature)
        try await sendLinkRequestPayload(
            identifyPayload,
            context: 0xFB, // LINKIDENTIFY
            linkState: linkState,
            via: iface
        )
    }

    private func propagationRequestID(for requestPayload: Data) -> Data {
        Hashing.truncatedHash(requestPayload, length: Destination.hashLength)
    }

    private func sendPropagationGetRequest(
        wants: [Data]?,
        haves: [Data]?,
        limitKilobytes: Double?,
        linkState: LXMFRouter.DirectLinkState,
        via iface: TCPClientInterface,
        timeout: TimeInterval = 20
    ) async throws -> MsgPack.PropagationGetResponse {
        let requestPayload = MsgPack.encodePropagationGetLinkRequest(
            wants: wants,
            haves: haves,
            limitKilobytes: limitKilobytes
        )
        let expectedRequestID = propagationRequestID(for: requestPayload)
        try await sendLinkRequestPayload(
            requestPayload,
            context: 0x09, // REQUEST
            linkState: linkState,
            via: iface
        )

        guard let responsePayload = await waitForPropagationResponse(linkID: linkState.linkID, timeout: timeout) else {
            throw AppError.nomadResponseTimeout
        }
        guard let decoded = MsgPack.decodePropagationGetLinkResponse(responsePayload) else {
            throw AppError.nomadResponseTimeout
        }
        guard decoded.requestID == expectedRequestID else {
            log(
                .warn,
                "Propagation /get response request-id mismatch expected=\(expectedRequestID.hexString.prefix(8))… got=\(decoded.requestID.hexString.prefix(8))…"
            )
            throw AppError.nomadResponseTimeout
        }
        return decoded.response
    }

    @discardableResult
    private func syncFromPropagationNode(
        linkState: LXMFRouter.DirectLinkState,
        via iface: TCPClientInterface
    ) async throws -> Int {
        try await sendLinkIdentify(linkState: linkState, via: iface)
        purgeExpiredPropagationTransientIDs()

        let listResponse = try await sendPropagationGetRequest(
            wants: nil,
            haves: nil,
            limitKilobytes: nil,
            linkState: linkState,
            via: iface
        )

        switch listResponse {
        case .error(let code):
            log(.warn, "Propagation list request failed with code=\(code)")
            return 0
        case .messages:
            log(.warn, "Propagation list returned unexpected message payloads")
            return 0
        case .transientIDs(let transientIDs):
            guard !transientIDs.isEmpty else { return 0 }

            let haves = transientIDs.filter(hasDeliveredPropagationTransientID(_:))
            let wants = transientIDs.filter { !hasDeliveredPropagationTransientID($0) }

            if wants.isEmpty {
                if !haves.isEmpty {
                    _ = try await sendPropagationGetRequest(
                        wants: nil,
                        haves: haves,
                        limitKilobytes: nil,
                        linkState: linkState,
                        via: iface
                    )
                }
                return 0
            }

            let getResponse = try await sendPropagationGetRequest(
                wants: wants,
                haves: haves,
                limitKilobytes: 1000,
                linkState: linkState,
                via: iface
            )

            switch getResponse {
            case .error(let code):
                log(.warn, "Propagation message get failed with code=\(code)")
                return 0
            case .transientIDs:
                log(.warn, "Propagation get returned transient ID list instead of messages")
                return 0
            case .messages(let messageBlobs):
                guard !messageBlobs.isEmpty else { return 0 }

                var deliveredTransientIDs: [Data] = []
                var deliveredCount = 0
                for lxmData in messageBlobs {
                    guard lxmData.count > Destination.hashLength else { continue }
                    let transientID = Hashing.sha256(lxmData)
                    guard !hasDeliveredPropagationTransientID(transientID) else {
                        deliveredTransientIDs.append(transientID)
                        continue
                    }

                    let destination = Data(lxmData.prefix(Destination.hashLength))
                    let encryptedPayload = Data(lxmData.dropFirst(Destination.hashLength))
                    guard let identity, destination == lxmfDestinationHash,
                          let privateKeyData = identity.privateKeyData else {
                        continue
                    }

                    let x25519Priv = Data(privateKeyData.prefix(32))
                    guard let decrypted = try? ReticulumToken.decrypt(
                        encryptedPayload,
                        recipientX25519PrivateKey: x25519Priv,
                        identityHash: identity.hash
                    ) else {
                        continue
                    }

                    var packed = destination
                    packed.append(decrypted)
                    guard let msg = try? LXMFMessage(packed: packed) else { continue }

                    if let requiredStampCost = inboundStampCost {
                        let validation = msg.validateStamp(
                            targetCost: requiredStampCost,
                            tickets: inboundTickets(for: msg.sourceHash)
                        )
                        guard validation.valid else { continue }
                    }

                    rememberOutboundTicket(from: msg.sourceHash, fields: msg.fields)
                    let convoMsg = ConversationMessage(
                        content: msg.content,
                        timestamp: Date(timeIntervalSince1970: msg.timestamp),
                        isOutbound: false
                    )
                    upsertConversation(destinationHash: msg.sourceHash, message: convoMsg)
                    notifyInboundMessageIfNeeded(msg)
                    rememberPropagationDeliveredTransientID(transientID)
                    deliveredTransientIDs.append(transientID)
                    deliveredCount += 1
                }

                if !deliveredTransientIDs.isEmpty {
                    _ = try await sendPropagationGetRequest(
                        wants: nil,
                        haves: deliveredTransientIDs,
                        limitKilobytes: nil,
                        linkState: linkState,
                        via: iface
                    )
                }

                return deliveredCount
            }
        }
    }

    func fetchNomadPage(destinationHash: Data, path: String) async throws -> NomadPage {
        guard destinationHash.count == Destination.hashLength else { throw AppError.noPath }
        guard !path.isEmpty else { throw NomadError.pageNotFound(path) }
        guard identity != nil else { throw AppError.noIdentity }

        let candidateInterfaces = connectedInterfacesForDestination(destinationHash)
        guard !candidateInterfaces.isEmpty else { throw AppError.notConnected }

        var lastError: Error?
        for (serverID, iface) in candidateInterfaces {
            do {
                let recipientPublicKey = try await resolveNomadNodePublicKey(for: destinationHash, via: iface)
                let linkState = try await ensureDirectLink(
 destinationHash: destinationHash,
 recipientPublicKey: recipientPublicKey,
 iface: iface
                )

                nomadLinkIDs.insert(linkState.linkID)
                let requestPayload = NomadClient.buildRequestPayload(
 path: path,
 timestamp: Date().timeIntervalSince1970,
 formData: nil
                )

                log(
 .info,
 "Nomad TX request: dest=\(destinationHash.hexString.prefix(8))… path=\(path) link=\(linkState.linkID.hexString.prefix(8))… payload=\(requestPayload.count)B iface=\(serverID.uuidString.prefix(8))…"
                )
                try await sendNomadRequestPayload(requestPayload, linkState: linkState, via: iface)

                guard let responsePayload = await waitForNomadResponse(linkID: linkState.linkID, timeout: 20) else {
 throw AppError.nomadResponseTimeout
                }
                let (requestID, content) = try NomadClient.parsePageResponse(responsePayload)
                log(
 .info,
 "Nomad RX response: dest=\(destinationHash.hexString.prefix(8))… req=\(requestID.hexString.prefix(8))… content=\(content.count)B"
                )
                return NomadPage(path: path, requestID: requestID, content: content)
            } catch {
                lastError = error
                log(.warn, "Nomad fetch via interface \(serverID.uuidString.prefix(8))… failed: \(error.localizedDescription)")
            }
        }

        throw lastError ?? AppError.noPath
    }


    func regenerateIdentity() {
        guard let newIdentity = try? Identity.generate() else { return }
        if let keyData = newIdentity.privateKeyData {
            if Self.storeIdentityPrivateKey(keyData) {
                UserDefaults.standard.removeObject(forKey: Self.identityPrivateKeyDefaultsKey)
            } else {
                UserDefaults.standard.set(keyData.hexString, forKey: Self.identityPrivateKeyDefaultsKey)
            }
        }
        identity = newIdentity
        appendLog("New identity: \(newIdentity.hash.hexString.prefix(8))…")
    }

    func exportIdentityBackup(password: String?) throws -> Data {
        guard let identity else {
            throw AppError.noIdentity
        }
        do {
            return try IdentityBackupCodec.encode(identity: identity, password: password)
        } catch let error as IdentityBackupCodecError {
            throw error
        } catch {
            throw AppError.identityBackupFailed
        }
    }

    func restoreIdentityBackup(from backupData: Data, password: String?) throws {
        let restored: IdentityBackupCodec.RestoredBackup
        do {
            restored = try IdentityBackupCodec.decode(backupData, password: password)
        } catch let error as IdentityBackupCodecError {
            throw error
        } catch {
            throw AppError.identityRestoreFailed
        }

        guard Self.storeIdentityPrivateKey(restored.privateKeyData) else {
            throw AppError.identityRestoreFailed
        }
        UserDefaults.standard.removeObject(forKey: Self.identityPrivateKeyDefaultsKey)
        identity = restored.identity
        appendLog("Identity restored from backup: \(restored.identity.hash.hexString.prefix(8))…")
    }

    // Peer alias management

    /// Sets a user-defined alias for the peer with `destinationHash`.
    /// Once set, automatic display name updates from announces are suppressed.
    func setPeerAlias(_ alias: String, for destinationHash: Data) {
        guard let idx = peers.firstIndex(where: { $0.destinationHash == destinationHash }) else { return }
        peers[idx].alias    = alias.isEmpty ? nil : alias
        peers[idx].aliasSet = !alias.isEmpty
        savePeers()
    }

    /// Clears the user alias for the peer with `destinationHash`,
    /// reverting to the automatically discovered display name.
    func clearPeerAlias(for destinationHash: Data) {
        guard let idx = peers.firstIndex(where: { $0.destinationHash == destinationHash }) else { return }
        peers[idx].alias    = nil
        peers[idx].aliasSet = false
        savePeers()
    }

    /// Returns the effective display name for a given destination hash,
    /// or `nil` if the peer is not in the peers list.
    func peerName(for destinationHash: Data) -> String? {
        peers.first(where: { $0.destinationHash == destinationHash })?.effectiveName
    }

    var configuredPropagationNodes: [DiscoveredPeer] {
        propagationNodeCandidates()
    }

    func selectPropagationNode(hash: Data) {
        guard hash.count == Destination.hashLength else { return }
        selectedPropagationNodeHash = hash
        persistSelectedPropagationNodeHash(hash)
        _ = upsertPropagationNodeCandidate(
            hash: hash,
            displayName: hash == Self.defaultPropagationNodeHash ? Self.defaultPropagationNodeName : nil
        )
        savePeers()
        requestPropagationInboxSync(reason: "selected-node")
        if autoSelectBestPropagationNode {
            requestAutoPropagationSelectionEvaluation(reason: "manual-selection")
        }
    }

    func addPropagationNode(hash: Data, displayName: String?) {
        guard hash.count == Destination.hashLength else { return }
        _ = upsertPropagationNodeCandidate(hash: hash, displayName: displayName)
        selectedPropagationNodeHash = hash
        persistSelectedPropagationNodeHash(hash)
        savePeers()
        requestPropagationInboxSync(reason: "added-node")
        if autoSelectBestPropagationNode {
            requestAutoPropagationSelectionEvaluation(reason: "manual-add")
        }
    }

    private func ensureSelectedPropagationNodeConfigured() {
        let hash = selectedPropagationNodeHash
        persistSelectedPropagationNodeHash(hash)
        _ = upsertPropagationNodeCandidate(
            hash: hash,
            displayName: hash == Self.defaultPropagationNodeHash ? Self.defaultPropagationNodeName : nil
        )
        savePeers()
    }

    private func persistSelectedPropagationNodeHash(_ hash: Data) {
        UserDefaults.standard.set(hash.hexString, forKey: Self.selectedPropagationNodeHashDefaultsKey)
    }

    @discardableResult
    private func upsertPropagationNodeCandidate(hash: Data, displayName: String?) -> Bool {
        guard hash.count == Destination.hashLength else { return false }

        let trimmedDisplayName = displayName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if let idx = peers.firstIndex(where: { $0.destinationHash == hash }) {
            var didChange = false
            if peers[idx].isPropagationNode == false {
                peers[idx].isPropagationNode = true
                didChange = true
            }
            if peers[idx].announcedPropagationEnabled == nil {
                peers[idx].announcedPropagationEnabled = true
                didChange = true
            }
            if !peers[idx].aliasSet,
               !trimmedDisplayName.isEmpty,
               peers[idx].displayName != trimmedDisplayName {
                peers[idx].displayName = trimmedDisplayName
                didChange = true
            }
            return didChange
        }

        peers.insert(
            DiscoveredPeer(
                destinationHash: hash,
                publicKey: Data(),
                displayName: trimmedDisplayName.isEmpty ? nil : trimmedDisplayName,
                isLXMFPeer: false,
                isPropagationNode: true,
                announcedPropagationEnabled: true
            ),
            at: 0
        )
        return true
    }

    // Announce timer

    private func scheduleAnnounceTimer() {
        announceTask?.cancel()
        guard autoAnnounce, isAnyConnected else { return }
        let interval = announceInterval
        announceTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard !Task.isCancelled else { break }
                self?.sendAnnounce()
            }
        }
    }

    // Private helpers

    private func handleIncoming(_ data: Data) {
        handleIncoming(data, fromServerID: nil)
    }

    private func handleIncoming(_ data: Data, fromServerID: UUID?) {
        activeReceiveServerID = fromServerID
        defer { activeReceiveServerID = nil }
        guard let packet = try? Packet.deserialize(from: data) else {
            log(.warn, "RX: failed to parse packet (\(data.count) bytes)")
            return
        }

        // HEADER_2 includes a 16-byte transport-id before destination hash.
        // Reconstruct actual destination/payload from context + payload prefix.

        let isHeader2 = packet.header.headerType == .header2
        let destHash: Data
        let effectivePayload: Data
        let packetContext: UInt8

        if isHeader2 {
            destHash        = Data([packet.header.context]) + packet.payload.prefix(15)
            effectivePayload = Data(packet.payload.dropFirst(16))
            packetContext = packet.payload.count > 15
                ? packet.payload[packet.payload.startIndex + 15]
                : 0
        } else {
            destHash        = Data(packet.header.destinationHash)
            effectivePayload = packet.payload
            packetContext = packet.header.context
        }

        let hdrStr = isHeader2 ? "H2" : "H1"
        log(.debug, "RX \(hdrStr) \(packet.header.packetType) dest=\(destHash.hexString.prefix(8))… payload=\(effectivePayload.count)B hops=\(packet.header.hops)")

        if packet.header.packetType == .data,
           packet.header.destinationType == .link {
            if packetContext == 0x00,
               nomadLinkIDs.contains(destHash) {
                if (try? NomadClient.parsePageResponse(effectivePayload)) != nil {
 enqueueNomadResponse(payload: effectivePayload, linkID: destHash)
                }
            } else if packetContext == 0x0A,
                      propagationLinkIDs.contains(destHash) {
                enqueuePropagationResponse(payload: effectivePayload, linkID: destHash)
                return
            }
        }

        switch packet.header.packetType {

        // ── ANNOUNCE ────────────────────────────────────────────────────────
        // Reticulum announce payload layout:
        //   pubKey(64) + nameHash(10) + randomHash(10) + sig(64) + app_data(variable)
        // LXMF app_data formats seen in clients:
        //   - map:  {0x01: display_name, ...}
        //   - list: [display_name, stamp_cost]
        case .announce where effectivePayload.count >= 64:
            // Parse announce payload with ratchet-awareness (contextFlag).
            guard let announce = try? AnnouncePayload.parse(
                from: effectivePayload,
                hasRatchet: packet.header.contextFlag
            ) else {
                log(.warn, "RX ANNOUNCE parse failed (\(effectivePayload.count)B), ignoring")
                return
            }

            guard isValidAnnounce(announce, destinationHash: destHash) else {
                log(.warn, "RX ANNOUNCE failed signature/hash validation for \(destHash.hexString.prefix(8))…, ignoring")
                return
            }

            let pubKey = announce.identityPublicKey
            let announcedNameHash = announce.nameHash
            let lxmfNameHash = LXMFAddressing.deliveryNameHash()
            let lxmfPropagationNameHash = LXMFAddressing.propagationNameHash()
            let nomadNodeNameHash = NomadNode.announceNameHash()
            let isLXMFDelivery = announcedNameHash == lxmfNameHash
            let isPropagationNode = announcedNameHash == lxmfPropagationNameHash
            let isNomadNode = announcedNameHash == nomadNodeNameHash
            let announcedPathHops = Int(packet.header.hops) + 1
            let announcedAt = Date()
            let announcedRatchet = announce.ratchetKey
            let announceTransportID: Data? = isHeader2 ? Data(packet.header.destinationHash) : nil

            let deliveryMeta = MsgPack.decodeDisplayNameAndStampCost(announce.appData)
            let announcedName: String?
            if isNomadNode {
                let rawName = String(data: announce.appData, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                announcedName = rawName?.isEmpty == true ? nil : rawName
            } else {
                announcedName = deliveryMeta.displayName
            }
            let announcedStampCost = isLXMFDelivery ? deliveryMeta.stampCost : nil
            let announcedPropagationStampCost = isPropagationNode
                ? MsgPack.decodePropagationNodeStampCost(announce.appData)
                : nil
            let announcedPropagationEnabled = isPropagationNode
                ? MsgPack.decodePropagationNodeEnabled(announce.appData)
                : nil

            if let idx = peers.firstIndex(where: { $0.destinationHash == destHash }) {
                if peers[idx].publicKey.count == Identity.publicKeyLength,
                   peers[idx].publicKey != pubKey {
 log(.warn, "RX ANNOUNCE pubkey mismatch for known destination \(destHash.hexString.prefix(8))…, ignoring")
 return
                }
                // Peer already known — update display name unless user set an alias.
                if !peers[idx].aliasSet {
 peers[idx].displayName = announcedName
                }
                peers[idx].publicKey = pubKey
                peers[idx].isLXMFPeer = peers[idx].isLXMFPeer || isLXMFDelivery
                peers[idx].isPropagationNode = peers[idx].isPropagationNode || isPropagationNode
                peers[idx].isNomadNode = peers[idx].isNomadNode || isNomadNode
                peers[idx].lastAnnounceAt = announcedAt
                peers[idx].pathHops = announcedPathHops
                peers[idx].lastAnnounceServerID = activeReceiveServerID ?? peers[idx].lastAnnounceServerID
                if let announceTransportID {
 peers[idx].lastAnnounceTransportID = announceTransportID
                } else if announcedPathHops <= 1 {
 peers[idx].lastAnnounceTransportID = nil
                }
                if isLXMFDelivery {
 peers[idx].announcedStampCost = announcedStampCost
                }
                if isPropagationNode {
 peers[idx].announcedPropagationStampCost = announcedPropagationStampCost
 peers[idx].announcedPropagationEnabled = announcedPropagationEnabled
                } else {
 peers[idx].announcedPropagationEnabled = nil
                }
                if let announcedRatchet, announcedRatchet.count == 32 {
 ratchetPublicKeysByDestination[destHash] = announcedRatchet
                } else {
 ratchetPublicKeysByDestination.removeValue(forKey: destHash)
                }
                log(
 .debug,
 "Peer re-announced: \(destHash.hexString.prefix(8))… name=\(announcedName ?? "(none)") hops=\(announcedPathHops)"
                )
            } else {
                let peer = DiscoveredPeer(
 destinationHash: destHash,
 publicKey: pubKey,
 displayName: announcedName,
 isLXMFPeer: isLXMFDelivery,
 isPropagationNode: isPropagationNode,
 isNomadNode: isNomadNode,
 lastAnnounceAt: announcedAt,
 pathHops: announcedPathHops,
 lastAnnounceServerID: activeReceiveServerID,
 lastAnnounceTransportID: announceTransportID,
 announcedStampCost: announcedStampCost,
 announcedPropagationStampCost: announcedPropagationStampCost,
 announcedPropagationEnabled: announcedPropagationEnabled
                )
                peers.insert(peer, at: 0)
                if let announcedRatchet, announcedRatchet.count == 32 {
 ratchetPublicKeysByDestination[destHash] = announcedRatchet
                } else {
 ratchetPublicKeysByDestination.removeValue(forKey: destHash)
                }
                let nameStr = announcedName.map { " \"\($0)\"" } ?? ""
                let kind: String
                if isLXMFDelivery {
 kind = "lxmf.delivery"
                } else if isPropagationNode {
 kind = "lxmf.propagation"
                } else if isNomadNode {
 kind = "nomadnetwork.node"
                } else {
 kind = "non-lxmf"
                }
                log(.info, "Peer discovered (\(kind)): \(destHash.hexString.prefix(8))…\(nameStr) hops=\(announcedPathHops)")
            }
            savePeers()
            if isPropagationNode, autoSelectBestPropagationNode {
                requestAutoPropagationSelectionEvaluation(reason: "announce")
            }
            if isPropagationNode, destHash == selectedPropagationNodeHash {
                requestPropagationInboxSync(reason: "announce")
            }

        case .announce:
            log(.warn, "RX ANNOUNCE too short (\(effectivePayload.count)B), ignoring")

        // ── LINKREQUEST ──────────────────────────────────────────────────────
        case .linkRequest:
            handleLinkRequest(packet: packet, destHash: destHash,
           effectivePayload: effectivePayload, isHeader2: isHeader2)

        // ── PROOF (SINGLE delivery receipts) ─────────────────────────────────
        case .proof where packet.header.destinationType == .single:
            let proofHash = destHash
            if let outboundMessageID = outboundSingleProofMessageByHash.removeValue(forKey: proofHash) {
                markOutboundMessageDelivered(id: outboundMessageID)
            }
            if let sentAt = outboundProofExpectations.removeValue(forKey: proofHash) {
                let rttMs = Int(Date().timeIntervalSince(sentAt) * 1000)
                log(.info, "✓ Delivery proof received for \(proofHash.hexString.prefix(8))… (\(rttMs) ms)")
            } else {
                let signaturePreview = String(effectivePayload.prefix(8).hexString.prefix(16))
                log(
 .debug,
 "RX SINGLE PROOF unknown=\(proofHash.hexString.prefix(8))… ctx=\(String(format: "0x%02X", packetContext)) hops=\(packet.header.hops) payload=\(effectivePayload.count)B sig=\(signaturePreview)… awaiting(\(outboundProofExpectations.count))=[\(awaitingProofsSummary())]"
                )
            }

        case .proof where packet.header.destinationType == .link:
            if packetContext == 0xFF {
                handleLinkProof(destHash: destHash, effectivePayload: effectivePayload)
            } else if packetContext == 0x00 {
                handleDirectDataProof(effectivePayload: effectivePayload)
            } else {
                log(.debug, "RX LINK PROOF context=\(String(format: "0x%02X", packetContext)) ignored")
            }

        // ── DATA (DIRECT, over link) ─────────────────────────────────────────
        // TCPClientInterface decrypts link DATA and re-emits as a synthetic
        // packet with destinationType = .link and plaintext LXMF payload.
        case .data where packet.header.destinationType == .link:
            if nomadLinkIDs.contains(destHash),
               (try? NomadClient.parsePageResponse(effectivePayload)) != nil {
                log(.info, "Nomad RX link payload accepted id=\(destHash.hexString.prefix(8))… bytes=\(effectivePayload.count)")
                return
            }
            guard let msg = try? LXMFMessage(packed: effectivePayload) else {
                log(.warn, "RX LINK DATA: LXMF parse failed — \(effectivePayload.count)B hex=\(effectivePayload.prefix(16).hexString)…")
                return
            }
            if let requiredStampCost = inboundStampCost {
                let validation = msg.validateStamp(
                    targetCost: requiredStampCost,
                    tickets: inboundTickets(for: msg.sourceHash)
                )
                if !validation.valid {
 log(.warn, "RX LINK DATA: invalid stamp from \(msg.sourceHash.hexString.prefix(8))… required=\(requiredStampCost)")
 return
                }
            }
            rememberOutboundTicket(from: msg.sourceHash, fields: msg.fields)
            let convoMsg = ConversationMessage(
                content: msg.content,
                timestamp: Date(timeIntervalSince1970: msg.timestamp),
                isOutbound: false
            )
            upsertConversation(destinationHash: msg.sourceHash, message: convoMsg)
            notifyInboundMessageIfNeeded(msg)
            log(.info, "✓ DIRECT message received ← \(msg.sourceHash.hexString.prefix(8))… \"\(msg.content.prefix(40))\"")

        // ── DATA (OPPORTUNISTIC, to our LXMF destination) ───────────────────
        case .data:
            guard let identity else {
                log(.warn, "RX DATA: no local identity, dropping")
                return
            }
            guard let lxmfDest = lxmfDestinationHash else {
                log(.warn, "RX DATA: no LXMF destination hash computed, dropping")
                return
            }

            guard destHash == lxmfDest else {
                log(.debug, "RX DATA: dest=\(destHash.hexString.prefix(8))… ≠ our lxmf=\(lxmfDest.hexString.prefix(8))… — not for us")
                return
            }

            guard let privKeyData = identity.privateKeyData else {
                log(.warn, "RX DATA: identity has no private key, cannot decrypt")
                return
            }

            let x25519Priv = Data(privKeyData.prefix(32))
            log(.debug, "RX DATA: attempting decrypt, ciphertext=\(effectivePayload.count)B")
            log(.debug, "RX DATA token details: \(tokenLayoutSummary(effectivePayload))")

            guard let plaintext = try? ReticulumToken.decrypt(
                effectivePayload,
                recipientX25519PrivateKey: x25519Priv,
                identityHash: identity.hash
            ) else {
                log(.warn, "RX DATA: decryption failed — ciphertext=\(effectivePayload.count)B, identity=\(identity.hash.hexString.prefix(8))… \(tokenLayoutSummary(effectivePayload))")
                return
            }

            log(.debug, "RX DATA: decrypted \(plaintext.count)B, prepending lxmfDest for LXMF parse")

            // Opportunistic payload omits destination hash; prepend local LXMF destination.
            var fullPacked = lxmfDest
            fullPacked.append(plaintext)
            guard let msg = try? LXMFMessage(packed: fullPacked) else {
                log(.warn, "RX DATA: LXMF parse failed — packed=\(fullPacked.count)B hex=\(fullPacked.prefix(16).hexString)…")
                return
            }

            if let requiredStampCost = inboundStampCost {
                let validation = msg.validateStamp(
                    targetCost: requiredStampCost,
                    tickets: inboundTickets(for: msg.sourceHash)
                )
                if !validation.valid {
 log(.warn, "RX DATA: invalid stamp from \(msg.sourceHash.hexString.prefix(8))… required=\(requiredStampCost)")
 return
                }
            }

            rememberOutboundTicket(from: msg.sourceHash, fields: msg.fields)

            let convoMsg = ConversationMessage(
                content: msg.content,
                timestamp: Date(timeIntervalSince1970: msg.timestamp),
                isOutbound: false
            )
            upsertConversation(destinationHash: msg.sourceHash, message: convoMsg)
            notifyInboundMessageIfNeeded(msg)
            log(.info, "✓ Message received ← \(msg.sourceHash.hexString.prefix(8))… \"\(msg.content.prefix(40))\"")

            // Send implicit SINGLE proof after successful decrypt/parse.
            sendSingleProof(rawPacket: data, isHeader2: isHeader2)
            requestPropagationInboxSync(reason: "inbound")

        default:
            log(.debug, "RX \(hdrStr) \(packet.header.packetType): unhandled")
        }
    }

    // SINGLE proof (delivery receipt for OPPORTUNISTIC messages)

    /// Send an implicit delivery proof for a received SINGLE DATA packet.
    ///
    /// Dispatches the signing + proof-sending work to each connected interface.
    private func sendSingleProof(rawPacket: Data, isHeader2: Bool) {
        guard let identity else { return }
        let ifacesCopy = interfaces
        Task {
            for (_, iface) in ifacesCopy {
                await iface.sendSingleProof(rawPacket: rawPacket, isHeader2: isHeader2) { data in
 return await MainActor.run { try? identity.sign(data) }
                }
            }
        }
    }

    private func waitForSingleDeliveryProof(_ proofHash: Data, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        var nextReport = Date().addingTimeInterval(2)
        while Date() < deadline {
            if outboundProofExpectations[proofHash] == nil {
                return true
            }
            if Date() >= nextReport {
                log(
 .debug,
 "TX waiting proof=\(proofHash.hexString.prefix(8))… pending(\(outboundProofExpectations.count))=[\(awaitingProofsSummary(limit: 10))]"
                )
                nextReport = Date().addingTimeInterval(2)
            }
            try? await Task.sleep(nanoseconds: Self.proofPollIntervalNanoseconds)
        }

        if outboundProofExpectations.removeValue(forKey: proofHash) != nil {
            outboundSingleProofMessageByHash.removeValue(forKey: proofHash)
            log(.warn, "No delivery proof for \(proofHash.hexString.prefix(8))… after \(Int(timeout))s pending=[\(awaitingProofsSummary(limit: 10))]")
            return false
        }

        return true
    }

    private func waitForDirectDeliveryProof(
        _ packetHash: Data,
        timeout: TimeInterval,
        pollOnly: Bool
    ) async -> Bool {
        if pollOnly {
            // Fast path for normal direct sends: don't block UX waiting for proof.
            // Keep expectation registered and rely on inbound proof processing.
            return true
        }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if outboundDirectProofExpectations[packetHash] == nil {
                return true
            }
            try? await Task.sleep(nanoseconds: Self.proofPollIntervalNanoseconds)
        }

        if outboundDirectProofExpectations.removeValue(forKey: packetHash) != nil {
            outboundDirectProofMessageByHash.removeValue(forKey: packetHash)
            log(.warn, "No DIRECT delivery proof for \(packetHash.hexString.prefix(8))… after \(Int(timeout))s")
            return false
        }
        return true
    }

    /// Computes the destination hash used by an implicit SINGLE proof for `rawPacket`.
    ///
    /// Header-1 formula (Python): `SHA256([raw[0]&0x0F] + raw[2:])[:16]`
    /// Header-2 formula (Python): `SHA256([raw[0]&0x0F] + raw[18:])[:16]`
    private func computeSingleProofDestinationHash(fromRawPacket raw: Data, isHeader2: Bool) -> Data? {
        guard !raw.isEmpty else { return nil }
        let flags = raw[raw.startIndex]
        let hashable: Data
        if isHeader2 {
            guard raw.count > 18 else { return nil }
            hashable = Data([flags & 0x0F]) + raw.dropFirst(18)
        } else {
            guard raw.count > 2 else { return nil }
            hashable = Data([flags & 0x0F]) + raw.dropFirst(2)
        }
        return Data(Hashing.sha256(hashable).prefix(16))
    }

    // Link establishment (incoming only)

    /// Reticulum MTU (default 500 bytes).
    private static let reticulumMTU = 500

    /// Computes signalling bytes for link mode negotiation.
    ///
    /// Encoding: 3 bytes from big-endian representation of:
    ///   `(mtu & 0x1FFFFF) + (((mode << 5) & 0xE0) << 16)`
    /// where `mode = 0x01` for AES-256-CBC.
    private static func linkSignallingBytes(mtu: Int = reticulumMTU) -> Data {
        let mode = 0x01  // MODE_AES256_CBC
        let sv   = (mtu & 0x1FFFFF) + (((mode << 5) & 0xE0) << 16)
        let bytes = withUnsafeBytes(of: UInt32(sv).bigEndian) { Data($0) }
        return Data(bytes.dropFirst(1))  // Take last 3 bytes
    }

    /// Computes the link_id from a LINKREQUEST according to Reticulum protocol.
    ///
    /// `link_id = SHA256(([flags&0x0F] + destHash + context + peerX25519 + peerEd25519))[:16]`
    private static func computeLinkId(
        destHash: Data,
        context: UInt8 = 0,
        peerX25519Pub: Data,
        peerEd25519Pub: Data
    ) -> Data {
        // For LINKREQUEST to SINGLE destination, flags&0x0F = 0x02.
        var hashable = Data([0x02])
        hashable.append(destHash)
        hashable.append(context)
        hashable.append(peerX25519Pub)
        hashable.append(peerEd25519Pub)
        return Hashing.truncatedHash(hashable, length: 16)
    }

    /// Handles an incoming LINKREQUEST packet from a remote peer and replies with LRPROOF.
    private func handleLinkRequest(packet _: Packet, destHash: Data, effectivePayload: Data, isHeader2 _: Bool) {
        guard let identity else {
            log(.warn, "RX LINKREQUEST: no local identity")
            return
        }
        guard let lxmfDest = lxmfDestinationHash else {
            log(.warn, "RX LINKREQUEST: no LXMF destination")
            return
        }
        guard destHash == lxmfDest else {
            log(.debug, "RX LINKREQUEST: not for us (dest=\(destHash.hexString.prefix(8))…)")
            return
        }
        guard effectivePayload.count >= 64 else {
            log(.warn, "RX LINKREQUEST: payload too short (\(effectivePayload.count)B)")
            return
        }

        let peerX25519Pub  = Data(effectivePayload[effectivePayload.startIndex ..< effectivePayload.startIndex + 32])
        let peerEd25519Pub = Data(effectivePayload[effectivePayload.startIndex + 32 ..< effectivePayload.startIndex + 64])

        // LINKREQUEST context is 0x00 for normal link requests.
        let lrContext: UInt8 = 0x00

        let linkId = Self.computeLinkId(
            destHash: destHash,
            context: lrContext,
            peerX25519Pub: peerX25519Pub,
            peerEd25519Pub: peerEd25519Pub
        )
        log(.info, "RX LINKREQUEST from \(peerX25519Pub.hexString.prefix(8))… linkId=\(linkId.hexString.prefix(8))…")

        // Generate responder ephemeral X25519 keypair.
        let ourEphemeralPriv = Curve25519.KeyAgreement.PrivateKey()
        let ourEphemeralPub  = ourEphemeralPriv.publicKey.rawRepresentation

        // ECDH.
        guard
            let peerPubKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerX25519Pub),
            let sharedSecret = try? ourEphemeralPriv.sharedSecretFromKeyAgreement(with: peerPubKey)
        else {
            log(.error, "RX LINKREQUEST: ECDH failed")
            return
        }

        // Derive link key and register it for all active interfaces so link DATA decrypt works.
        let derivedKey = sharedSecret.hkdfDerivedSymmetricKey(
            using:           SHA256.self,
            salt:            linkId,
            sharedInfo:      Data(),
            outputByteCount: 64
        )
        let derivedKeyBytes = derivedKey.withUnsafeBytes { Data($0) }

        let linkIdCopy  = linkId
        let keyCopy     = derivedKeyBytes
        for (serverId, iface) in interfaces {
            guard serverStatuses[serverId] == true else { continue }
            Task { await iface.establishLink(linkId: linkIdCopy, derivedKey: keyCopy) }
        }

        // LRPROOF signed data: link_id + responder_x25519_pub + responder_ed25519_pub + signalling(3).
        let signalling    = Self.linkSignallingBytes()
        let ourEd25519Pub = Data(identity.publicKey[identity.publicKey.startIndex + 32 ..< identity.publicKey.startIndex + 64])
        var signedData    = linkId
        signedData.append(ourEphemeralPub)
        signedData.append(ourEd25519Pub)
        signedData.append(signalling)

        guard let signature = try? identity.sign(signedData) else {
            log(.error, "RX LINKREQUEST: Ed25519 signing failed")
            return
        }

        // LRPROOF payload: signature + responder pubkey + signalling
        var proofPayload = signature
        proofPayload.append(ourEphemeralPub)
        proofPayload.append(signalling)

        let proofHeader = PacketHeader(
            packetType:      .proof,
            destinationType: .link,
            destinationHash: linkId,
            hops:            0,
            context:         0xFF   // LRPROOF
        )
        let proofRaw = Packet(header: proofHeader, payload: proofPayload).serialize()

        for (serverId, iface) in interfaces {
            guard serverStatuses[serverId] == true else { continue }
            Task {
                do {
 try await iface.send(proofRaw)
 log(.info, "✓ LINKPROOF sent for link \(linkId.hexString.prefix(8))…")
                } catch {
 log(.warn, "LINKPROOF send failed: \(error)")
                }
            }
        }
    }

    private func handleLinkProof(destHash: Data, effectivePayload: Data) {
        guard let recipientPublicKey = pendingDirectRecipientKeysByLinkID[destHash] else {
            log(.debug, "RX LINKPROOF ignored (unknown link id) id=\(destHash.hexString.prefix(8))…")
            return
        }

        Task { [weak self] in
            guard let self else { return }
            do {
                let link = try await self.completeLinkFromProof(
 linkID: destHash,
 proofPayload: effectivePayload,
 recipientIdentityPublicKey: recipientPublicKey
                )
                self.log(.info, "✓ DIRECT link established id=\(link.linkID.hexString.prefix(8))…")
            } catch {
                self.log(.warn, "LINKPROOF validation failed for \(destHash.hexString.prefix(8))…: \(error)")
                self.clearPendingDirectLink(linkID: destHash)
            }
        }
    }

    private func completeLinkFromProof(
        linkID: Data,
        proofPayload: Data,
        recipientIdentityPublicKey: Data
    ) async throws -> LXMFRouter.DirectLinkState {
        let link = try await lxmfRouter.completeDirectLink(
            linkID: linkID,
            proofPayload: proofPayload,
            recipientIdentityPublicKey: recipientIdentityPublicKey
        )

        let linkIDCopy = link.linkID
        let keyCopy = link.derivedKey
        for (serverId, iface) in interfaces {
            guard serverStatuses[serverId] == true else { continue }
            Task { await iface.establishLink(linkId: linkIDCopy, derivedKey: keyCopy) }
        }

        pendingDirectRecipientKeysByLinkID.removeValue(forKey: linkID)
        if let destination = pendingDirectDestinationByLinkID.removeValue(forKey: linkID) {
            pendingDirectLinkByDestination.removeValue(forKey: destination)
            directLinkRouteSignatureByDestination.removeValue(forKey: destination)
            resolveDirectLinkWaiters(destinationHash: destination, link: link)
        }
        return link
    }

    private func clearPendingDirectLink(linkID: Data) {
        pendingDirectRecipientKeysByLinkID.removeValue(forKey: linkID)
        if let destination = pendingDirectDestinationByLinkID.removeValue(forKey: linkID) {
            pendingDirectLinkByDestination.removeValue(forKey: destination)
            directLinkRouteSignatureByDestination.removeValue(forKey: destination)
            if let waiters = directLinkWaiters.removeValue(forKey: destination) {
                for (_, cont) in waiters { cont.resume(returning: nil) }
            }
        }
    }

    private func handleDirectDataProof(effectivePayload: Data) {
        // Link proofs for DATA packets are explicit: packet_hash(32) + signature(64).
        guard effectivePayload.count >= 32 else {
            log(.debug, "RX LINK DATA PROOF too short (\(effectivePayload.count)B)")
            return
        }

        let packetHash = Data(effectivePayload.prefix(32))
        if let outboundMessageID = outboundDirectProofMessageByHash.removeValue(forKey: packetHash) {
            markOutboundMessageDelivered(id: outboundMessageID)
        }
        if let sentAt = outboundDirectProofExpectations.removeValue(forKey: packetHash) {
            let rttMs = Int(Date().timeIntervalSince(sentAt) * 1000)
            log(.info, "✓ DIRECT delivery proof received hash=\(packetHash.hexString.prefix(8))… (\(rttMs) ms)")
        } else {
            log(.debug, "RX LINK DATA PROOF for unknown hash=\(packetHash.hexString.prefix(8))…")
        }
    }

    private func upsertConversation(destinationHash: Data, message: ConversationMessage) {
        var message = message
        if message.isOutbound,
           pendingDeliveredOutboundMessageIDs.remove(message.id) != nil {
            message.deliveryStatus = .delivered
        }

        if let idx = conversations.firstIndex(where: { $0.destinationHash == destinationHash }) {
            conversations[idx].messages.append(message)
        } else {
            conversations.append(Conversation(destinationHash: destinationHash, messages: [message]))
        }
        saveConversations()
    }

    private func markOutboundMessageDelivered(id: UUID) {
        if updateOutboundMessageStatus(id: id, status: .delivered) { return }
        pendingDeliveredOutboundMessageIDs.insert(id)
    }

    @discardableResult
    private func updateOutboundMessageStatus(id: UUID, status: OutboundDeliveryStatus) -> Bool {
        for cIndex in conversations.indices {
            guard let mIndex = conversations[cIndex].messages.firstIndex(where: { $0.id == id && $0.isOutbound }) else {
                continue
            }
            conversations[cIndex].messages[mIndex].deliveryStatus = status
            saveConversations()
            return true
        }
        return false
    }

    // Logging

    enum LogLevel: String { case debug = "🔍", info = "ℹ", warn = "⚠️", error = "🔴" }

    private func log(_ level: LogLevel, _ msg: String) {
        let entry = "\(level.rawValue) \(msg)"
        // Always show warn/error/info; suppress debug unless verbose mode added later
        if level != .debug {
            activityLog.insert(LogEntry(message: entry), at: 0)
        }
        // Always print to console for Xcode debugger
        print("[Inertia] \(entry)")
        if activityLog.count > 500 { activityLog = Array(activityLog.prefix(500)) }
    }

    private func appendLog(_ msg: String) {
        log(.info, msg)
    }

    // Persistence

    private func saveServers() {
        if let data = try? JSONEncoder().encode(servers) {
            UserDefaults.standard.set(data, forKey: "servers")
        }
    }

    private static func loadServers() -> [ServerConfig] {
        if let data = UserDefaults.standard.data(forKey: "servers"),
           let servers = try? JSONDecoder().decode([ServerConfig].self, from: data),
           !servers.isEmpty {
            return servers
        }
        // Migrate legacy single-server settings, or use the default public node.
        let host = UserDefaults.standard.string(forKey: "serverHost") ?? "rns.inertia.chat"
        let port = UserDefaults.standard.integer(forKey: "serverPort").nonZero ?? 4242
        return [ServerConfig(name: "Default", host: host, port: port)]
    }

    private func savePeers() {
        if let data = try? JSONEncoder().encode(peers) {
            UserDefaults.standard.set(data, forKey: "peers")
        }
    }

    private static func loadPeers() -> [DiscoveredPeer] {
        guard let data = UserDefaults.standard.data(forKey: "peers"),
              let peers = try? JSONDecoder().decode([DiscoveredPeer].self, from: data) else {
            return []
        }
        return peers
    }

    private func saveConversations() {
        if let data = try? JSONEncoder().encode(conversations) {
            UserDefaults.standard.set(data, forKey: "conversations")
        }
    }

    private static func loadConversations() -> [Conversation] {
        guard let data = UserDefaults.standard.data(forKey: "conversations"),
              let convos = try? JSONDecoder().decode([Conversation].self, from: data) else {
            return []
        }
        return convos
    }

    private static func loadSelectedPropagationNodeHash() -> Data {
        guard
            let hex = UserDefaults.standard.string(forKey: selectedPropagationNodeHashDefaultsKey),
            let hash = Data(hexString: hex),
            hash.count == Destination.hashLength
        else {
            return defaultPropagationNodeHash
        }
        return hash
    }

    private static func loadOnboardingCompletionState(savedDisplayName: String) -> Bool {
        if UserDefaults.standard.object(forKey: onboardingCompletedDefaultsKey) != nil {
            return UserDefaults.standard.bool(forKey: onboardingCompletedDefaultsKey)
        }

        let hasLegacyData =
            UserDefaults.standard.data(forKey: "servers") != nil ||
            UserDefaults.standard.data(forKey: "peers") != nil ||
            UserDefaults.standard.data(forKey: "conversations") != nil ||
            (!savedDisplayName.isEmpty && savedDisplayName != defaultAnnounceDisplayName)

        if hasLegacyData {
            UserDefaults.standard.set(true, forKey: onboardingCompletedDefaultsKey)
            return true
        }

        return false
    }

    private static func identityPrivateKeyKeychainQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: identityPrivateKeyKeychainService,
            kSecAttrAccount as String: identityPrivateKeyKeychainAccount,
        ]
    }

    @discardableResult
    private static func storeIdentityPrivateKey(_ privateKey: Data) -> Bool {
        var addQuery = identityPrivateKeyKeychainQuery()
        addQuery[kSecValueData as String] = privateKey
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess {
            return true
        }
        guard addStatus == errSecDuplicateItem else {
            return false
        }

        let attributesToUpdate: [String: Any] = [
            kSecValueData as String: privateKey,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(identityPrivateKeyKeychainQuery() as CFDictionary, attributesToUpdate as CFDictionary)
        return updateStatus == errSecSuccess
    }

    private static func loadIdentityPrivateKey() -> Data? {
        var query = identityPrivateKeyKeychainQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            return nil
        }
        return result as? Data
    }

    private func loadOrCreateIdentity() -> Identity? {
        if let keyData = Self.loadIdentityPrivateKey(),
           let id = try? Identity(privateKey: keyData) {
            return id
        }

        if let hex = UserDefaults.standard.string(forKey: Self.identityPrivateKeyDefaultsKey),
           let keyData = Data(hexString: hex),
           let id = try? Identity(privateKey: keyData) {
            if Self.storeIdentityPrivateKey(keyData) {
                UserDefaults.standard.removeObject(forKey: Self.identityPrivateKeyDefaultsKey)
            }
            return id
        }

        guard let id = try? Identity.generate() else { return nil }
        if let keyData = id.privateKeyData {
            if Self.storeIdentityPrivateKey(keyData) {
                UserDefaults.standard.removeObject(forKey: Self.identityPrivateKeyDefaultsKey)
            } else {
                UserDefaults.standard.set(keyData.hexString, forKey: Self.identityPrivateKeyDefaultsKey)
            }
        }
        return id
    }
}

enum IdentityBackupCodecError: LocalizedError, Equatable {
    case missingPrivateIdentity
    case invalidBackupFile
    case unsupportedVersion(Int)
    case passwordRequired
    case decryptionFailed
    case invalidPrivateKey
    case identityMismatch

    var errorDescription: String? {
        switch self {
        case .missingPrivateIdentity:
            "This identity cannot be exported because no private key is available."
        case .invalidBackupFile:
            "The selected file is not a valid Inertia identity backup."
        case .unsupportedVersion(let version):
            "This backup uses unsupported version \(version)."
        case .passwordRequired:
            "This backup is password-protected. Enter the backup password to continue."
        case .decryptionFailed:
            "Could not decrypt backup. Check the password and try again."
        case .invalidPrivateKey:
            "Backup does not contain a valid Reticulum private identity key."
        case .identityMismatch:
            "Backup integrity check failed: identity hash mismatch."
        }
    }
}

enum IdentityBackupCodec {
    private static let envelopeKind = "chat.inertia.identity-backup"
    private static let envelopeVersion = 1
    private static let protectedMode = "password-aes-gcm-sha256"
    private static let unprotectedMode = "none"
    private static let passwordKDFRounds = 65_536
    private static let saltLength = 16

    struct RestoredBackup {
        let identity: Identity
        let privateKeyData: Data
    }

    private struct BackupEnvelope: Codable {
        let kind: String
        let version: Int
        let createdAt: TimeInterval
        let protection: String
        let payloadBase64: String?
        let saltBase64: String?
        let kdfRounds: Int?
        let sealedBoxBase64: String?
    }

    private struct BackupPayload: Codable {
        let identityPrivateKeyHex: String
        let identityHashHex: String
    }

    static func encode(identity: Identity, password: String?) throws -> Data {
        guard let privateKeyData = identity.privateKeyData else {
            throw IdentityBackupCodecError.missingPrivateIdentity
        }

        let payload = BackupPayload(
            identityPrivateKeyHex: privateKeyData.hexString,
            identityHashHex: identity.hash.hexString
        )
        let payloadData = try JSONEncoder().encode(payload)
        let normalizedPassword = password?.trimmingCharacters(in: .whitespacesAndNewlines)

        let envelope: BackupEnvelope
        if let normalizedPassword, !normalizedPassword.isEmpty {
            let salt = try secureRandomBytes(length: saltLength)
            let key = derivePasswordKey(password: normalizedPassword, salt: salt, rounds: passwordKDFRounds)
            let sealed = try AES.GCM.seal(payloadData, using: key)
            guard let combined = sealed.combined else {
                throw IdentityBackupCodecError.decryptionFailed
            }
            envelope = BackupEnvelope(
                kind: envelopeKind,
                version: envelopeVersion,
                createdAt: Date().timeIntervalSince1970,
                protection: protectedMode,
                payloadBase64: nil,
                saltBase64: salt.base64EncodedString(),
                kdfRounds: passwordKDFRounds,
                sealedBoxBase64: combined.base64EncodedString()
            )
        } else {
            envelope = BackupEnvelope(
                kind: envelopeKind,
                version: envelopeVersion,
                createdAt: Date().timeIntervalSince1970,
                protection: unprotectedMode,
                payloadBase64: payloadData.base64EncodedString(),
                saltBase64: nil,
                kdfRounds: nil,
                sealedBoxBase64: nil
            )
        }

        return try JSONEncoder().encode(envelope)
    }

    static func decode(_ backupData: Data, password: String?) throws -> RestoredBackup {
        let envelope: BackupEnvelope
        do {
            envelope = try JSONDecoder().decode(BackupEnvelope.self, from: backupData)
        } catch {
            throw IdentityBackupCodecError.invalidBackupFile
        }

        guard envelope.kind == envelopeKind else {
            throw IdentityBackupCodecError.invalidBackupFile
        }
        guard envelope.version == envelopeVersion else {
            throw IdentityBackupCodecError.unsupportedVersion(envelope.version)
        }

        let payloadData: Data
        switch envelope.protection {
        case unprotectedMode:
            guard let payloadBase64 = envelope.payloadBase64,
                  let decoded = Data(base64Encoded: payloadBase64) else {
                throw IdentityBackupCodecError.invalidBackupFile
            }
            payloadData = decoded

        case protectedMode:
            let normalizedPassword = password?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !normalizedPassword.isEmpty else {
                throw IdentityBackupCodecError.passwordRequired
            }
            guard let saltBase64 = envelope.saltBase64,
                  let salt = Data(base64Encoded: saltBase64),
                  let sealedBoxBase64 = envelope.sealedBoxBase64,
                  let sealedBytes = Data(base64Encoded: sealedBoxBase64) else {
                throw IdentityBackupCodecError.invalidBackupFile
            }
            let rounds = max(1, envelope.kdfRounds ?? passwordKDFRounds)
            let key = derivePasswordKey(password: normalizedPassword, salt: salt, rounds: rounds)
            let sealedBox: AES.GCM.SealedBox
            do {
                sealedBox = try AES.GCM.SealedBox(combined: sealedBytes)
                payloadData = try AES.GCM.open(sealedBox, using: key)
            } catch {
                throw IdentityBackupCodecError.decryptionFailed
            }

        default:
            throw IdentityBackupCodecError.invalidBackupFile
        }

        let payload: BackupPayload
        do {
            payload = try JSONDecoder().decode(BackupPayload.self, from: payloadData)
        } catch {
            throw IdentityBackupCodecError.invalidBackupFile
        }

        guard let privateKeyData = Data(hexString: payload.identityPrivateKeyHex),
              privateKeyData.count == Identity.privateKeyLength else {
            throw IdentityBackupCodecError.invalidPrivateKey
        }
        guard let expectedHash = Data(hexString: payload.identityHashHex),
              expectedHash.count == Identity.hashLength else {
            throw IdentityBackupCodecError.invalidBackupFile
        }

        let identity: Identity
        do {
            identity = try Identity(privateKey: privateKeyData)
        } catch {
            throw IdentityBackupCodecError.invalidPrivateKey
        }
        guard identity.hash == expectedHash else {
            throw IdentityBackupCodecError.identityMismatch
        }

        return RestoredBackup(identity: identity, privateKeyData: privateKeyData)
    }

    private static func derivePasswordKey(password: String, salt: Data, rounds: Int) -> SymmetricKey {
        let normalizedRounds = max(1, rounds)
        var digestInput = Data(password.utf8)
        digestInput.append(salt)

        var digestData = Data(SHA256.hash(data: digestInput))
        if normalizedRounds > 1 {
            for _ in 1..<normalizedRounds {
                var roundInput = digestData
                roundInput.append(salt)
                digestData = Data(SHA256.hash(data: roundInput))
            }
        }
        return SymmetricKey(data: digestData)
    }

    private static func secureRandomBytes(length: Int) throws -> Data {
        var data = Data(count: length)
        let status = data.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, length, base)
        }
        guard status == errSecSuccess else {
            throw IdentityBackupCodecError.invalidBackupFile
        }
        return data
    }
}

// Int helper

private extension Int {
    var nonZero: Int? { self == 0 ? nil : self }
}
