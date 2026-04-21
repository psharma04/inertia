import Foundation
import Security
import CryptoKit
import LocalAuthentication
import UserNotifications
import BackgroundTasks
import Network
import os.log
#if canImport(UIKit)
import UIKit
#endif
import ReticulumCrypto
import ReticulumPackets
import ReticulumInterfaces
import LXMF
import NomadNet
import Persistence

private let inertiaLog = OSLog(subsystem: "chat.inertia.app", category: "protocol")

// Tab selection for deep-link navigation

enum AppTab: String, Hashable {
    case messages, peers, nomad, settings
}

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

    /// Preferred propagation node hash announced by this delivery peer (16 bytes).
    var announcedPreferredPropagationNode: Data?

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
        announcedPropagationEnabled: Bool? = nil,
        announcedPreferredPropagationNode: Data? = nil
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
        self.announcedPreferredPropagationNode = announcedPreferredPropagationNode
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
    var hasName: Bool {
        if aliasSet {
            if let a = alias, !a.isEmpty { return true }
            return false
        }
        if let d = displayName, !d.isEmpty { return true }
        return false
    }

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

/// LXMF field keys matching the Python reference implementation.
enum LXMFFieldKey {
    static let fileAttachments = 0x05
    static let image           = 0x06
    static let audio           = 0x07
}

/// A file attachment embedded in an LXMF message.
struct MessageAttachment: Codable, Sendable {
    let name: String
    let size: Int
    /// Relative path to file data stored under Documents/attachments/<messageID>/
    let storagePath: String?
}

/// An inline image embedded in an LXMF message.
struct MessageImage: Codable, Sendable {
    let type: String   // "jpg", "png", "webp"
    let size: Int
    /// Relative path to image data stored under Documents/attachments/<messageID>/
    let storagePath: String?
}

struct ConversationMessage: Identifiable, Codable, Sendable {
    let id: UUID
    let content: String
    let timestamp: Date
    let isOutbound: Bool
    var deliveryStatus: OutboundDeliveryStatus?
    var attachments: [MessageAttachment]?
    var image: MessageImage?
    /// LXMF message hash for deduplication (hex string, inbound only).
    var lxmfHash: String?

    private enum CodingKeys: String, CodingKey {
        case id
        case content
        case timestamp
        case isOutbound
        case deliveryStatus
        case attachments
        case image
        case lxmfHash
    }

    init(
        id: UUID = UUID(),
        content: String,
        timestamp: Date,
        isOutbound: Bool,
        deliveryStatus: OutboundDeliveryStatus? = nil,
        attachments: [MessageAttachment]? = nil,
        image: MessageImage? = nil,
        lxmfHash: String? = nil
    ) {
        self.id         = id
        self.content    = content
        self.timestamp  = timestamp
        self.isOutbound = isOutbound
        self.deliveryStatus = isOutbound ? (deliveryStatus ?? .sent) : nil
        self.attachments = attachments
        self.image = image
        self.lxmfHash = lxmfHash
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        self.content = try container.decode(String.self, forKey: .content)
        self.timestamp = try container.decode(Date.self, forKey: .timestamp)
        self.isOutbound = try container.decode(Bool.self, forKey: .isOutbound)
        let decodedStatus = try container.decodeIfPresent(OutboundDeliveryStatus.self, forKey: .deliveryStatus)
        self.deliveryStatus = isOutbound ? (decodedStatus ?? .sent) : nil
        self.attachments = try container.decodeIfPresent([MessageAttachment].self, forKey: .attachments)
        self.image = try container.decodeIfPresent(MessageImage.self, forKey: .image)
        self.lxmfHash = try container.decodeIfPresent(String.self, forKey: .lxmfHash)
    }

    /// Whether this message has any media content beyond text.
    var hasMedia: Bool { image != nil || !(attachments ?? []).isEmpty }
}

struct Conversation: Identifiable, Codable, Sendable {
    let destinationHash: Data
    var messages: [ConversationMessage]
    /// Local timestamp updated each time a message is added (for reliable sort ordering).
    var lastActivityAt: Date?

    var id: String { destinationHash.hexString }
    var hashHex: String { destinationHash.hexString }
    var shortHash: String { String(hashHex.prefix(8)) }
    var lastMessage: ConversationMessage? { messages.last }

    /// Best available sort date — prefers local activity timestamp over sender timestamp.
    var sortDate: Date {
        lastActivityAt ?? lastMessage?.timestamp ?? .distantPast
    }
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
    case sending
    case sent
    case delivered
    case failed
}

struct OutboundRetryJob: Codable, Identifiable {
    let id: UUID
    let destinationHash: Data
    let content: String
    let fields: [String: Data]
    let attachmentData: Data?
    let imageData: Data?
    let createdAt: Date
    var attempts: Int
    var lastAttemptAt: Date?
    var nextAttemptAt: Date

    static let maxAttempts = 12
    static let initialBackoff: TimeInterval = 15
    static let maxBackoff: TimeInterval = 600

    var isExpired: Bool {
        attempts >= Self.maxAttempts
    }

    mutating func recordAttempt() {
        attempts += 1
        lastAttemptAt = Date()
        let backoff = min(
            Self.initialBackoff * pow(2.0, Double(attempts - 1)),
            Self.maxBackoff
        )
        nextAttemptAt = Date().addingTimeInterval(backoff)
    }

    var intFields: [Int: Data] {
        var result: [Int: Data] = [:]
        for (k, v) in fields {
            if let key = Int(k) { result[key] = v }
        }
        return result
    }

    init(
        destinationHash: Data,
        content: String,
        fields: [Int: Data] = [:],
        attachmentData: Data? = nil,
        imageData: Data? = nil,
        messageID: UUID = UUID()
    ) {
        self.id = messageID
        self.destinationHash = destinationHash
        self.content = content
        self.fields = Dictionary(uniqueKeysWithValues: fields.map { (String($0.key), $0.value) })
        self.attachmentData = attachmentData
        self.imageData = imageData
        self.createdAt = Date()
        self.attempts = 0
        self.lastAttemptAt = nil
        self.nextAttemptAt = Date()
    }
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
    private static let outboundPropagatedTransientIDsDefaultsKey = "outboundPropagatedTransientIDs"
    private static let autoPropagationSelectionInterval: TimeInterval = 300
    private static let autoPropagationSelectionStartupDelay: TimeInterval = 10
    private static let autoPropagationProbeTimeout: TimeInterval = 5
    // swiftlint:disable:next force_unwrapping
    private static let appSupportDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    private static let defaultPropagationNodeHash: Data = {
        guard let hash = Data(hexString: defaultPropagationNodeHashHex),
              hash.count == Destination.hashLength else {
            preconditionFailure("Invalid default propagation node hash")
        }
        return hash
    }()

    // MARK: - Server State
    var servers: [ServerConfig] = []
    var serverStatuses: [UUID: Bool] = [:]

    var isAnyConnected: Bool { serverStatuses.values.contains(true) || autoInterfaceOnline == true }
    var connectedCount: Int  {
        servers.filter { serverStatuses[$0.id] == true }.count
    }

    // MARK: - AutoInterface State
    var autoInterfaceConfig: AutoInterfaceConfig = AutoInterfaceConfig() {
        didSet {
            saveAutoInterfaceConfig()
            if autoInterfaceConfig != oldValue { applyAutoInterfaceConfig() }
        }
    }
    /// nil = not started, true = online, false = failed to start
    var autoInterfaceOnline: Bool? = nil
    var autoInterfacePeerCount: Int = 0

    let nomadStore = NomadStore()
    var peers: [DiscoveredPeer] = []
    var conversations: [Conversation] = []
    var activityLog: [LogEntry] = []

    private(set) var identity: Identity?

    var identityHashHex: String { identity?.hash.hexString ?? "—" }

    var lxmfDestinationHash: Data? {
        guard let identity else { return nil }
        return Destination.hash(appName: "lxmf", aspects: ["delivery"], identityHash: identity.hash)
    }
    var lxmfAddressHex: String { lxmfDestinationHash?.hexString ?? "—" }

    // MARK: - Announce Settings
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

    var activeConversationHash: Data? = nil {
        didSet { notificationDelegate.activeConversationHash = activeConversationHash }
    }

    /// Set by the notification delegate when the user taps a notification.
    /// ConversationsView observes this and navigates to the conversation.
    var pendingOpenConversation: Data? = nil

    /// Programmatic tab selection for deep-link navigation.
    var selectedTab: AppTab = .messages

    /// Set by nomadnet:// deep links — NomadBrowserView observes and navigates.
    var pendingNomadAddress: String? = nil

    /// User-facing error from a failed deep link (shown as alert).
    var deepLinkError: String? = nil

    // MARK: - Contact Blocking & Pinning

    /// Set of hex destination hashes for blocked contacts.
    var blockedHashes: Set<String> = [] {
        didSet {
            UserDefaults.standard.set(Array(blockedHashes), forKey: "blockedHashes")
        }
    }

    /// Ordered list of hex destination hashes for pinned conversations (first = top).
    var pinnedHashes: [String] = [] {
        didSet {
            UserDefaults.standard.set(pinnedHashes, forKey: "pinnedHashes")
        }
    }

    func isBlocked(_ destinationHash: Data) -> Bool {
        blockedHashes.contains(destinationHash.hexString)
    }

    func isPinned(_ destinationHash: Data) -> Bool {
        pinnedHashes.contains(destinationHash.hexString)
    }

    func blockContact(hash: Data) {
        blockedHashes.insert(hash.hexString)
    }

    func unblockContact(hash: Data) {
        blockedHashes.remove(hash.hexString)
    }

    func pinConversation(hash: Data) {
        let hex = hash.hexString
        guard !pinnedHashes.contains(hex) else { return }
        pinnedHashes.append(hex)
    }

    func unpinConversation(hash: Data) {
        pinnedHashes.removeAll { $0 == hash.hexString }
    }

    /// Conversations sorted: pinned first (in pin order), then unpinned by most recent activity.
    var sortedConversations: [Conversation] {
        let pinned = pinnedHashes.compactMap { hex in
            conversations.first { $0.hashHex == hex }
        }
        let unpinned = conversations
            .filter { !pinnedHashes.contains($0.hashHex) }
            .sorted { $0.sortDate > $1.sortDate }
        return pinned + unpinned
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
    var autoSelectBestPropagationNode: Bool = true {
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

    // ── Propagation node hosting ──
    var propagationNodeEnabled: Bool = false {
        didSet {
            UserDefaults.standard.set(propagationNodeEnabled, forKey: "propagationNodeEnabled")
            if propagationNodeEnabled {
                Task { await enablePropagationNode() }
            } else {
                disablePropagationNode()
            }
        }
    }
    var propagationNodeName: String = "" {
        didSet { UserDefaults.standard.set(propagationNodeName, forKey: "propagationNodeName") }
    }
    var propagationStorageLimitMB: Int = 50 {
        didSet { UserDefaults.standard.set(propagationStorageLimitMB, forKey: "propagationStorageLimitMB") }
    }
    var propagationNodeStampCost: Int = 0 {
        didSet { UserDefaults.standard.set(propagationNodeStampCost, forKey: "propagationNodeStampCost") }
    }
    private(set) var propagationStorageUsedBytes: Int = 0

    @ObservationIgnored private var interfaces: [UUID: any MessageTransportInterface] = [:]
    @ObservationIgnored private var connectionTasks: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var autoInterface: AutoInterface? = nil
    @ObservationIgnored private var autoInterfaceTask: Task<Void, Never>? = nil
    @ObservationIgnored private var wifiMonitor: NWPathMonitor? = nil
    private(set) var isWiFiAvailable: Bool = false

    static let autoInterfaceUUID = UUID(uuidString: "00000000-0000-0000-0000-A010FACE0001")!
    @ObservationIgnored private var announceTask: Task<Void, Never>? = nil
    @ObservationIgnored private var notificationBadgeCount: Int = 0
    @ObservationIgnored private let notificationDelegate = NotificationDelegateProxy()
    @ObservationIgnored private var autoPropagationSelectionTask: Task<Void, Never>? = nil
    @ObservationIgnored private var autoPropagationEvaluationTask: Task<Void, Never>? = nil
    @ObservationIgnored private var propagationSyncTask: Task<Void, Never>? = nil
    @ObservationIgnored private var propagationPeriodicTimer: Task<Void, Never>? = nil
    @ObservationIgnored private var lastPropagationSyncAttemptAt: Date?
    var isSyncingPropagation = false
    /// When `true`, connection-triggered sync is suppressed so background refresh
    /// can run its own dedicated sync with shorter timeouts.
    @ObservationIgnored private var isPerformingBackgroundRefresh = false
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
    @ObservationIgnored private var linkRequestSentAt: [Data: Date] = [:] // link_id -> when LINKREQUEST was sent
    @ObservationIgnored private var activeReceiveServerID: UUID?
    @ObservationIgnored private var outboundTicketsByDestination: [Data: Data] = [:] // source lxmf dest -> 16-byte ticket
    @ObservationIgnored private var nomadLinkIDs: Set<Data> = [] // active link_ids used for Nomad requests
    @ObservationIgnored private var inboundDeliveryLinkIDs: Set<Data> = [] // inbound link_ids for LXMF delivery (resource transfers)
    @ObservationIgnored private var nomadResponseWaiters: [Data: [(id: UUID, cont: CheckedContinuation<Data?, Never>)]] = [:]
    @ObservationIgnored private var bufferedNomadResponsesByLinkID: [Data: [Data]] = [:]
    @ObservationIgnored private var propagationLinkIDs: Set<Data> = [] // active link_ids used for propagation /get requests
    @ObservationIgnored private var propagationResponseWaiters: [Data: [(id: UUID, cont: CheckedContinuation<Data?, Never>)]] = [:]
    @ObservationIgnored private var bufferedPropagationResponsesByLinkID: [Data: [Data]] = [:]
    @ObservationIgnored private var propagationHostLinkIDs: Set<Data> = [] // inbound link_ids for our propagation node
    @ObservationIgnored private var propagationHostLinkStates: [Data: LXMFRouter.DirectLinkState] = [:]
    @ObservationIgnored private var propagationHostLinkIdentities: [Data: Data] = [:] // linkID → remote identity hash (set by LINKIDENTIFY)
    @ObservationIgnored private var inboundDeliveredTransientIDs: [Data: Date] = [:] // transient_id -> first delivery time
    @ObservationIgnored private var outboundPropagatedTransientIDs: [Data: UUID] = [:]
    @ObservationIgnored private var linkDerivedKeys: [Data: Data] = [:] // linkID -> 64-byte derived key (for resource-level decryption)
    @ObservationIgnored private var activeResources: [Data: IncomingResource] = [:] // resourceHash -> state machine
    @ObservationIgnored private var retryQueue: [UUID: OutboundRetryJob] = [:]
    @ObservationIgnored private var retryTimerTask: Task<Void, Never>?
    /// Observable resource transfer progress description (e.g. "Receiving part 5/24").
    private(set) var resourceTransferStatus: String?
    private(set) var availableBiometry: LABiometryType = .none

    // MARK: - Init

    init() {
        servers = Self.loadServers()
        peers = Self.loadPeers()
        conversations = Self.loadConversations()
        identity = loadOrCreateIdentity()
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
        if UserDefaults.standard.object(forKey: Self.autoSelectPropagationNodeDefaultsKey) != nil {
            autoSelectBestPropagationNode = UserDefaults.standard.bool(forKey: Self.autoSelectPropagationNodeDefaultsKey)
        } else {
            autoSelectBestPropagationNode = true
            UserDefaults.standard.set(true, forKey: Self.autoSelectPropagationNodeDefaultsKey)
        }
        selectedPropagationNodeHash = Self.loadSelectedPropagationNodeHash()
        ensureSelectedPropagationNodeConfigured()
        inboundDeliveredTransientIDs = Self.loadInboundDeliveredTransientIDs()
        outboundPropagatedTransientIDs = Self.loadOutboundPropagatedTransientIDs()
        purgeExpiredPropagationTransientIDs()
        autoInterfaceConfig = Self.loadAutoInterfaceConfig()
        blockedHashes = Set(UserDefaults.standard.stringArray(forKey: "blockedHashes") ?? [])
        pinnedHashes = UserDefaults.standard.stringArray(forKey: "pinnedHashes") ?? []
        // Load propagation node hosting settings.
        propagationNodeName = UserDefaults.standard.string(forKey: "propagationNodeName") ?? ""
        let savedStorageLimit = UserDefaults.standard.integer(forKey: "propagationStorageLimitMB")
        propagationStorageLimitMB = savedStorageLimit > 0 ? savedStorageLimit : 50
        propagationNodeStampCost = UserDefaults.standard.integer(forKey: "propagationNodeStampCost")
        // Propagation node enable deferred to connectServers (after interfaces are up).
        scheduleAutoPropagationSelectionTask()
        requestNotificationPermissionsIfNeeded()
        retryQueue = Self.loadRetryQueue()
        // Clean up orphaned attachment files on launch
        Task { cleanupOrphanedAttachments() }
    }

    func requestNotificationPermissionsIfNeeded() {
        guard inboundNotificationsEnabled else { return }
        let center = UNUserNotificationCenter.current()
        notificationDelegate.model = self
        center.delegate = notificationDelegate
        Task { [weak self] in
            guard let self else { return }
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

    // MARK: - Server Management

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

    // MARK: - Connection

    func connect(serverId: UUID) {
        guard let config = servers.first(where: { $0.id == serverId }),
              config.isValidPort,
              let port = UInt16(exactly: config.port) else { return }

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
                // Skip connection-triggered sync during background refresh — the
                // background path runs its own dedicated sync with tighter timeouts.
                if !isPerformingBackgroundRefresh {
                    requestPropagationInboxSync(reason: "connected")
                }
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
        startWiFiMonitor()
        applyAutoInterfaceConfig()
        startRetryTimer()
        // Enable propagation node hosting if previously enabled.
        if UserDefaults.standard.bool(forKey: "propagationNodeEnabled") {
            propagationNodeEnabled = true
        }
    }

    func disconnectAll() {
        servers.forEach { disconnect(serverId: $0.id) }
        stopAutoInterface()
        stopWiFiMonitor()
        stopRetryTimer()
    }

    // MARK: - AutoInterface Lifecycle

    func applyAutoInterfaceConfig() {
        if autoInterfaceConfig.enabled, isWiFiAvailable {
            startAutoInterface()
        } else {
            stopAutoInterface()
        }
    }

    /// Starts an `NWPathMonitor` for WiFi. When WiFi becomes available and
    /// AutoInterface is enabled, starts it; when WiFi is lost, stops it.
    func startWiFiMonitor() {
        guard wifiMonitor == nil else { return }
        let monitor = NWPathMonitor(requiredInterfaceType: .wifi)
        wifiMonitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor [weak self] in
                guard let self else { return }
                let available = path.status == .satisfied
                let changed = available != self.isWiFiAvailable
                self.isWiFiAvailable = available
                if changed {
                    if available {
                        self.appendLog("WiFi available — evaluating AutoInterface")
                    } else {
                        self.appendLog("WiFi lost — stopping AutoInterface")
                    }
                    self.applyAutoInterfaceConfig()
                }
            }
        }
        monitor.start(queue: .global(qos: .utility))
    }

    func stopWiFiMonitor() {
        wifiMonitor?.cancel()
        wifiMonitor = nil
    }

    func startAutoInterface() {
        // Skip restart if already running — connectAll() calls this on every activation.
        if autoInterfaceTask != nil { return }

        // Tear down any stale instance before starting fresh.
        stopAutoInterface()

        let config = autoInterfaceConfig
        let iface = AutoInterface(
            name:                 "AutoInterface",
            groupID:              config.groupID.isEmpty ? "reticulum" : config.groupID,
            discoveryPort:        config.discoveryPort > 0 ? UInt16(clamping: config.discoveryPort) : 29716,
            dataPort:             config.dataPort > 0 ? UInt16(clamping: config.dataPort) : 42671,
            discoveryScope:       config.discoveryScope,
            multicastAddressType: config.multicastAddressType,
            allowedInterfaces:    config.allowedInterfaceList,
            ignoredInterfaces:    config.ignoredInterfaceList
        )
        autoInterface = iface

        let autoID = Self.autoInterfaceUUID
        interfaces[autoID] = iface
        serverStatuses[autoID] = false

        autoInterfaceTask = Task { [weak self] in
            guard let self else { return }
            await iface.setOnReceive { [weak self] data in
                await self?.handleIncoming(data, fromServerID: autoID)
            }
            await iface.setLinkSigner { [weak self] data in
                guard let self else { return nil }
                return await MainActor.run { try? self.identity?.sign(data) }
            }
            await iface.setOnAddressChange { [weak self] in
                guard let self else { return }
                await MainActor.run {
                    self.appendLog("AutoInterface: address changed, restarting…")
                    self.stopAutoInterface()
                    self.startAutoInterface()
                }
            }
            appendLog("AutoInterface: starting…")
            await iface.start()
            serverStatuses[autoID] = true
            autoInterfaceOnline = true
            appendLog("AutoInterface: online")
            sendAnnounce()

            // Poll peer count every 5 seconds for the settings UI.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                let count = await iface.peerCount
                self.autoInterfacePeerCount = count
            }
        }
    }

    func stopAutoInterface() {
        let autoID = Self.autoInterfaceUUID
        autoInterfaceTask?.cancel()
        autoInterfaceTask = nil
        if let iface = autoInterface {
            Task { await iface.stop() }
        }
        autoInterface = nil
        interfaces.removeValue(forKey: autoID)
        serverStatuses.removeValue(forKey: autoID)
        autoInterfaceOnline = nil
        autoInterfacePeerCount = 0
    }

    private static let autoInterfaceConfigDefaultsKey = "autoInterfaceConfig"

    private func saveAutoInterfaceConfig() {
        if let data = try? JSONEncoder().encode(autoInterfaceConfig) {
            UserDefaults.standard.set(data, forKey: Self.autoInterfaceConfigDefaultsKey)
        }
    }

    private static func loadAutoInterfaceConfig() -> AutoInterfaceConfig {
        guard let data = UserDefaults.standard.data(forKey: autoInterfaceConfigDefaultsKey),
              let config = try? JSONDecoder().decode(AutoInterfaceConfig.self, from: data)
        else { return AutoInterfaceConfig() }
        return config
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
        notificationDelegate.isAppActive = isActive
        if isActive {
            if biometricLockEnabled && lockState == .locked {
                Task {
                    _ = await unlockWithBiometricsIfNeeded(reason: "Unlock Inertia")
                }
            }
            // Sync propagation inbox immediately when foregrounded
            syncPropagationInboxNow()
            // Start periodic 10-minute sync timer while app is active
            startPropagationPeriodicTimer()
            return
        }

        // Entering background — stop the periodic timer
        stopPropagationPeriodicTimer()
        scheduleBackgroundRefresh()

        guard biometricLockEnabled, biometricLockOnBackground else { return }
        guard lockState != .unlocking else { return }
        lockState = .locked
    }

    // MARK: - Background Refresh

    static let backgroundRefreshTaskID = "chat.inertia.background-refresh"

    /// Submits a BGAppRefreshTask request so iOS can wake the app periodically
    /// even after it has been terminated by the user.
    func scheduleBackgroundRefresh() {
        let request = BGAppRefreshTaskRequest(identifier: Self.backgroundRefreshTaskID)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    func performBackgroundRefresh() async {
        isPerformingBackgroundRefresh = true
        // Cancel any orphaned foreground sync task and wait for it to finish
        // so two syncs never overlap on shared link/buffer state.
        if let oldTask = propagationSyncTask {
            oldTask.cancel()
            propagationSyncTask = nil
            isSyncingPropagation = false  // take ownership; cancelled task's cleanup is now harmless
            await oldTask.value
        }
        defer {
            isPerformingBackgroundRefresh = false
            disconnectAll()
            scheduleBackgroundRefresh()
        }

        connectAll()

        // Wait for at least one TCP connection to come up (poll up to 12s).
        var connectWait = 0
        while !isAnyConnected && connectWait < 12 {
            try? await Task.sleep(for: .seconds(1))
            connectWait += 1
        }
        guard isAnyConnected else { return }

        // Run propagation sync directly — bypasses throttle and uses shorter timeouts.
        await runBackgroundPropagationSync()
    }

    /// Dedicated propagation sync for background refresh with tight timeouts.
    /// Bypasses the throttle and `propagationSyncTask` gate used by foreground syncs.
    private func runBackgroundPropagationSync() async {
        cleanupStaleProofExpectations()
        guard let propagationNodeHash = preferredPropagationNode(excluding: Data()) else { return }

        let candidateInterfaces = connectedInterfacesForDestination(propagationNodeHash)
        guard !candidateInterfaces.isEmpty else { return }

        for (_, iface) in candidateInterfaces {
            do {
                _ = await sendPathRequest(for: propagationNodeHash, via: iface)

                // Use cached/persisted key first, fall back to a short announce wait.
                let propagationNodePublicKey = try await resolvePropagationNodeKeyForBackground(
                    for: propagationNodeHash,
                    via: iface
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
                        "Propagation sync[background] fetched \(fetched) message(s) from \(propagationNodeHash.hexString.prefix(8))…"
                    )
                }
                return
            } catch {
                log(
                    .debug,
                    "Propagation sync[background] via interface failed: \(error.localizedDescription)"
                )
            }
        }
    }

    /// Resolves the propagation node's public key using caches first (interface cache,
    /// fresh announce, persisted peer key) to avoid 30s announce waits in background.
    private func resolvePropagationNodeKeyForBackground(
        for destinationHash: Data,
        via iface: any MessageTransportInterface
    ) async throws -> Data {
        // 1. Interface cache with fresh announce validation
        if let cached = await iface.identityPublicKey(for: destinationHash),
           cached.count == Identity.publicKeyLength,
           isValidLXMFDestinationKey(cached, for: destinationHash, allowPropagationDestination: true) {
            return cached
        }

        // 2. Fresh announce key already in memory
        if let announced = freshAnnouncedPublicKey(for: destinationHash, allowPropagationDestination: true) {
            await iface.seedIdentityCache(destinationHash: destinationHash, publicKey: announced)
            return announced
        }

        // 3. Persisted peer key (from a previous announce)
        if let persisted = persistedPeerPublicKey(for: destinationHash),
           persisted.count == Identity.publicKeyLength,
           isValidLXMFDestinationKey(persisted, for: destinationHash, allowPropagationDestination: true) {
            await iface.seedIdentityCache(destinationHash: destinationHash, publicKey: persisted)
            return persisted
        }

        // 4. Short wait for a fresh announce (8s instead of the normal 30s)
        if let awaited = await iface.waitForIdentityPublicKey(destinationHash: destinationHash, timeout: 8),
           awaited.count == Identity.publicKeyLength,
           isValidLXMFDestinationKey(awaited, for: destinationHash, allowPropagationDestination: true) {
            return awaited
        }

        throw AppError.noPath
    }

    // MARK: - Announce Sending

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
            stampCost: inboundStampCost,
            propagationNodeHash: selectedPropagationNodeHash.count == 16 ? selectedPropagationNodeHash : nil
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
                appendLog("Announced lxmf.delivery: \(destHash.hexString.prefix(8))… (\(sentCount) interface(s))")
            } else {
                log(.warn, "Announce TX failed on all interfaces")
            }
        }
    }

    // MARK: - Messaging

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
            log(.debug, "DIRECT eligibility: no peer for \(destinationHash.hexString.prefix(8))…")
            return false
        }
        guard let pathHops = peer.pathHops else {
            log(.debug, "DIRECT eligibility: no pathHops for \(destinationHash.hexString.prefix(8))…")
            return false
        }
        guard pathHops <= 1 else {
            log(.debug, "DIRECT eligibility: pathHops=\(pathHops) > 1 for \(destinationHash.hexString.prefix(8))…")
            return false
        }
        guard let announcedAt = peer.lastAnnounceAt else {
            log(.debug, "DIRECT eligibility: no lastAnnounceAt for \(destinationHash.hexString.prefix(8))…")
            return false
        }
        let age = Date().timeIntervalSince(announcedAt)
        let fresh = age <= Self.directPathFreshnessWindow
        log(.debug, "DIRECT eligibility: \(destinationHash.hexString.prefix(8))… hops=\(pathHops) age=\(Int(age))s fresh=\(fresh)")
        return fresh
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

    /// Remove stale outbound proof expectations older than 120 seconds.
    private func cleanupStaleProofExpectations() {
        let cutoff = Date().addingTimeInterval(-120)
        var removed = 0
        for (hash, date) in outboundProofExpectations {
            if date < cutoff {
                outboundProofExpectations.removeValue(forKey: hash)
                outboundSingleProofMessageByHash.removeValue(forKey: hash)
                removed += 1
            }
        }
        for (hash, date) in outboundDirectProofExpectations {
            if date < cutoff {
                outboundDirectProofExpectations.removeValue(forKey: hash)
                outboundDirectProofMessageByHash.removeValue(forKey: hash)
                removed += 1
            }
        }
        if removed > 0 {
            log(.debug, "Cleaned up \(removed) stale proof expectations")
        }
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

    /// Manual sync trigger, bypasses throttle
    func syncPropagationInboxNow() {
        guard isAnyConnected, propagationSyncTask == nil else {
            log(.debug, "syncPropagationInboxNow: skipped (connected=\(isAnyConnected), taskRunning=\(propagationSyncTask != nil))")
            return
        }
        isSyncingPropagation = true
        lastPropagationSyncAttemptAt = Date()
        propagationSyncTask = Task { [weak self] in
            guard let self else { return }
            await self.runPropagationInboxSync(reason: "manual")
            self.isSyncingPropagation = false
        }
    }

    /// Interval for periodic foreground propagation sync (10 minutes).
    private static let propagationPeriodicInterval: TimeInterval = 10 * 60

    /// Starts a repeating 10-minute timer that syncs the propagation inbox
    /// while the app is in the foreground.
    private func startPropagationPeriodicTimer() {
        propagationPeriodicTimer?.cancel()
        propagationPeriodicTimer = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(Self.propagationPeriodicInterval * 1_000_000_000))
                guard !Task.isCancelled else { break }
                self?.requestPropagationInboxSync(reason: "periodic")
            }
        }
    }

    /// Cancels the periodic propagation sync timer.
    private func stopPropagationPeriodicTimer() {
        propagationPeriodicTimer?.cancel()
        propagationPeriodicTimer = nil
    }

    private func requestPropagationInboxSync(reason: String) {
        log(.debug, "requestPropagationInboxSync(\(reason)): connected=\(isAnyConnected) taskRunning=\(propagationSyncTask != nil)")
        guard isAnyConnected else { return }
        if propagationSyncTask != nil { return }
        if let lastAttempt = lastPropagationSyncAttemptAt,
           Date().timeIntervalSince(lastAttempt) < Self.propagationSyncMinInterval {
            return
        }

        isSyncingPropagation = true
        lastPropagationSyncAttemptAt = Date()
        propagationSyncTask = Task { [weak self] in
            guard let self else { return }
            await self.runPropagationInboxSync(reason: reason)
            self.isSyncingPropagation = false
        }
    }

    private func runPropagationInboxSync(reason: String) async {
        defer { propagationSyncTask = nil }
        cleanupStaleProofExpectations()
        guard let propagationNodeHash = preferredPropagationNode(excluding: Data()) else {
            log(.info, "Propagation sync[\(reason)]: no preferred node configured")
            return
        }

        let candidateInterfaces = connectedInterfacesForDestination(propagationNodeHash)
        guard !candidateInterfaces.isEmpty else {
            log(.info, "Propagation sync[\(reason)]: no connected interfaces for \(propagationNodeHash.hexString.prefix(8))…")
            return
        }
        log(.info, "Propagation sync[\(reason)]: starting with \(candidateInterfaces.count) interface(s) for \(propagationNodeHash.hexString.prefix(8))…")

        for (_, iface) in candidateInterfaces {
            guard !Task.isCancelled else {
                log(.debug, "Propagation sync[\(reason)] cancelled before next interface attempt")
                return
            }
            do {
                _ = await sendPathRequest(for: propagationNodeHash, via: iface)

                // Try cached/persisted key first for speed; fall back to fresh announce.
                let propagationNodePublicKey: Data
                if let cached = await iface.identityPublicKey(for: propagationNodeHash),
                   cached.count == Identity.publicKeyLength,
                   isValidLXMFDestinationKey(cached, for: propagationNodeHash, allowPropagationDestination: true) {
                    propagationNodePublicKey = cached
                } else if let persisted = persistedPeerPublicKey(for: propagationNodeHash),
                          persisted.count == Identity.publicKeyLength,
                          isValidLXMFDestinationKey(persisted, for: propagationNodeHash, allowPropagationDestination: true) {
                    await iface.seedIdentityCache(destinationHash: propagationNodeHash, publicKey: persisted)
                    propagationNodePublicKey = persisted
                } else {
                    propagationNodePublicKey = try await resolvePeerPublicKey(
                        for: propagationNodeHash,
                        via: iface,
                        requireFreshAnnounce: true,
                        allowPropagationDestination: true
                    )
                }

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
                    .info,
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
        let staleOutbound = outboundPropagatedTransientIDs.count
        if staleOutbound > 100 {
            // Safety valve: if we accumulated >100 unconfirmed, clear all.
            outboundPropagatedTransientIDs.removeAll()
            persistOutboundPropagatedTransientIDs()
        }
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

    private func confirmOutboundPropagatedDelivery(nodeTransientIDs: [Data]) {
        guard !outboundPropagatedTransientIDs.isEmpty else { return }
        let nodeSet = Set(nodeTransientIDs)
        // Collect confirmed keys first to avoid mutating during iteration.
        var confirmedKeys: [Data] = []
        for (transientID, messageID) in outboundPropagatedTransientIDs {
            if nodeSet.contains(transientID) {
                log(.info, "⚡ Outbound transient \(transientID.hexString.prefix(8))… confirmed on propagation node — marking delivered")
                markOutboundMessageDelivered(id: messageID)
                confirmedKeys.append(transientID)
            }
        }
        if !confirmedKeys.isEmpty {
            for key in confirmedKeys {
                outboundPropagatedTransientIDs.removeValue(forKey: key)
            }
            persistOutboundPropagatedTransientIDs()
        }
    }

    private func persistOutboundPropagatedTransientIDs() {
        var payload: [String: String] = [:]
        for (transientID, messageID) in outboundPropagatedTransientIDs {
            payload[transientID.hexString] = messageID.uuidString
        }
        UserDefaults.standard.set(payload, forKey: Self.outboundPropagatedTransientIDsDefaultsKey)
    }

    private static func loadOutboundPropagatedTransientIDs() -> [Data: UUID] {
        guard let raw = UserDefaults.standard.dictionary(forKey: outboundPropagatedTransientIDsDefaultsKey) as? [String: String] else {
            return [:]
        }
        var decoded: [Data: UUID] = [:]
        for (hexID, uuidString) in raw {
            guard let transientID = Data(hexString: hexID), transientID.count == 32,
                  let uuid = UUID(uuidString: uuidString) else { continue }
            decoded[transientID] = uuid
        }
        return decoded
    }

    private func notifyInboundMessageIfNeeded(_ msg: LXMFMessage) {
        guard inboundNotificationsEnabled else { return }

        let sender = peerName(for: msg.sourceHash) ?? "New message"
        let body = msg.content.isEmpty ? "(No content)" : msg.content
        let notificationID = "inbound-lxmf-\(msg.hash.hexString)"
        notificationBadgeCount += 1
        let badge = notificationBadgeCount

        Task { [weak self] in
            guard let self else { return }
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()

            switch settings.authorizationStatus {
            case .notDetermined:
                let granted: Bool
                do {
                    granted = try await center.requestAuthorization(options: [.alert, .sound, .badge])
                } catch {
                    log(.warn, "Notifications: authorization request failed (\(error.localizedDescription))")
                    return
                }
                guard granted else { return }
            case .authorized, .provisional, .ephemeral:
                break
            default:
                return
            }

            let content = UNMutableNotificationContent()
            content.title = sender
            content.body = body
            content.sound = .default
            content.badge = badge as NSNumber
            content.threadIdentifier = msg.sourceHash.hexString
            content.categoryIdentifier = "LXMF_MESSAGE"
            content.userInfo = ["sourceHash": msg.sourceHash.hexString]

            let request = UNNotificationRequest(identifier: notificationID, content: content, trigger: nil)
            do {
                try await center.add(request)
            } catch {
                log(.warn, "Notifications: failed to schedule inbound alert (\(error.localizedDescription))")
            }
        }
    }

    func clearBadge() {
        notificationBadgeCount = 0
        Task {
            try? await UNUserNotificationCenter.current().setBadgeCount(0)
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
        via iface: any MessageTransportInterface
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

    private func connectedInterfacesForDestination(_ destinationHash: Data) -> [(UUID, any MessageTransportInterface)] {
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

        guard let nextHopTransportID = peer.lastAnnounceTransportID,
              nextHopTransportID.count == Destination.hashLength else {
            // No transport ID: only an error if destination is multi-hop
            let hops = peer.pathHops ?? 1
            if hops > 1 {
                log(
                    .warn,
                    "TX transport path missing next-hop transport ID for \(destinationHash.hexString.prefix(8))… hops=\(hops)"
                )
                throw AppError.noPath
            }
            return (h1RawPacket, false)
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
            "TX transport route: dest=\(destinationHash.hexString.prefix(8))… hops=\(peer.pathHops ?? 0) nextHop=\(nextHopTransportID.hexString.prefix(8))… H1=\(h1RawPacket.count)B -> H2=\(routed.count)B"
        )
        return (routed, true)
    }

    func send(
        to destinationHash: Data,
        content: String,
        method: MessageDeliveryMethod,
        propagationNodeHash: Data? = nil,
        outboundMessageID: UUID? = nil,
        outboundTimestamp: Date? = nil,
        fields: [Int: Data] = [:],
        attachments: [MessageAttachment]? = nil,
        image: MessageImage? = nil
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
     fields: fields,
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
     fields: fields,
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
     fields: fields,
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
 deliveryStatus: status,
 attachments: attachments,
 image: image
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

    func send(
        to destinationHash: Data,
        content: String,
        fields: [Int: Data] = [:],
        attachments: [MessageAttachment]? = nil,
        image: MessageImage? = nil,
        outboundMessageID: UUID? = nil
    ) async throws {
        guard interfaces.first(where: { serverStatuses[$0.key] == true })?.value != nil else {
            throw AppError.notConnected
        }

        let finalDestination = resolveRecipientDestinationHash(destinationHash)
        let outboundMessageID = outboundMessageID ?? UUID()
        let outboundTimestamp = Date()
        let propagationNodeHash = preferredPropagationNode(excluding: finalDestination)
        let directEligible = hasRecentDirectAnnounce(for: finalDestination)
        let hasAttachments = !fields.isEmpty

        var attempts: [MessageDeliveryMethod] = []
        if !hasAttachments {
            attempts.append(.opportunistic)
        }
        if directEligible {
            attempts.append(.direct)
        }
        if propagationNodeHash != nil {
            attempts.append(.propagated)
        }
        // Fallback to opportunistic even with attachments if nothing else works
        if hasAttachments && !attempts.contains(.opportunistic) {
            attempts.append(.opportunistic)
        }

        let attemptStr = attempts.map(\.rawValue).joined(separator: " -> ")
        log(
            .info,
            "TX auto delivery plan: recipient=\(finalDestination.hexString.prefix(8))… directEligible=\(directEligible ? "yes" : "no") attachments=\(hasAttachments) attempts=\(attemptStr)"
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
 outboundTimestamp: outboundTimestamp,
 fields: fields,
 attachments: attachments,
 image: image
                )
                return
            } catch {
                lastError = error
                log(.warn, "TX \(method.rawValue) attempt failed for \(finalDestination.hexString.prefix(8))…: \(error.localizedDescription)")
            }
        }

        // All immediate attempts failed — enqueue for retry
        let isRetry = retryQueue[outboundMessageID] != nil
        if !isRetry {
            let job = OutboundRetryJob(
                destinationHash: finalDestination,
                content: content,
                fields: fields,
                messageID: outboundMessageID
            )
            enqueueRetry(job: job)

            let pending = ConversationMessage(
                id: outboundMessageID,
                content: content,
                timestamp: outboundTimestamp,
                isOutbound: true,
                deliveryStatus: .sending,
                attachments: attachments,
                image: image
            )
            upsertConversation(destinationHash: finalDestination, message: pending)
        }
        throw lastError ?? AppError.noPath
    }

    // MARK: - Identity Management

    // MARK: - Deep Link Handling

    /// Handle an incoming URL from onOpenURL.
    func handleDeepLink(_ url: URL) {
        log(.info, "Deep link received: \(url.absoluteString)")
        let scheme = url.scheme?.lowercased() ?? ""
        switch scheme {
        case "lxm", "lxmf":
            deepLinkError = nil
            ingestLXMUri(url.absoluteString)
        case "nomadnet", "nn":
            let raw = url.absoluteString
            let prefix = "\(scheme)://"
            guard raw.count > prefix.count else {
                deepLinkError = "Invalid \(scheme):// URL."
                return
            }
            deepLinkError = nil
            let address = String(raw.dropFirst(prefix.count))
            log(.info, "NomadNet deep link address: \(address)")
            pendingNomadAddress = address
            selectedTab = .nomad
        default:
            log(.warn, "Unhandled deep link scheme: \(scheme)")
        }
    }

    /// Decode and import an LXM paper message URI (`lxm://…` or `lxmf://…`).
    private func ingestLXMUri(_ uriString: String) {
        // Strip scheme prefix
        var encoded = uriString
        for prefix in ["lxm://", "lxmf://", "LXM://", "LXMF://"] {
            if encoded.hasPrefix(prefix) {
                encoded = String(encoded.dropFirst(prefix.count))
                break
            }
        }
        // Also handle case-insensitive scheme via lowercased check
        let lower = encoded.lowercased()
        for prefix in ["lxm://", "lxmf://"] {
            if lower.hasPrefix(prefix) {
                encoded = String(encoded.dropFirst(prefix.count))
                break
            }
        }

        // Base64url → standard base64
        var base64 = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }

        guard let rawData = Data(base64Encoded: base64) else {
            deepLinkError = "Invalid paper message: could not decode data."
            log(.warn, "LXM URI: invalid base64 encoding")
            return
        }

        guard rawData.count > 16 else {
            deepLinkError = "Invalid paper message: data too short."
            log(.warn, "LXM URI: data too short (\(rawData.count) bytes)")
            return
        }

        let destHash = Data(rawData.prefix(16))
        let encryptedData = Data(rawData.dropFirst(16))

        // Check if this message is addressed to us
        guard let lxmfDest = lxmfDestinationHash, destHash == lxmfDest else {
            deepLinkError = "This paper message is not addressed to your identity."
            log(.warn, "LXM URI: not for us (dest=\(destHash.hexString.prefix(8))…, ours=\(lxmfDestinationHash?.hexString.prefix(8) ?? "nil"))")
            return
        }

        guard let identity else {
            deepLinkError = "No identity available to decrypt this message."
            log(.warn, "LXM URI: no identity for decryption")
            return
        }

        do {
            let decrypted = try identity.decrypt(encryptedData)

            // Reconstruct full packed LXMF message: destHash + decrypted(srcHash + sig + payload)
            var packed = Data(capacity: 16 + decrypted.count)
            packed.append(destHash)
            packed.append(decrypted)

            let msg = try LXMFMessage(packed: packed)

            let msgID = UUID()
            let parsed = parseAttachmentFields(from: msg.fields, messageID: msgID.uuidString)
            let convoMsg = ConversationMessage(
                id: msgID,
                content: msg.content,
                timestamp: Date(timeIntervalSince1970: msg.timestamp),
                isOutbound: false,
                attachments: parsed.attachments,
                image: parsed.image,
                lxmfHash: msg.hash.hexString
            )
            guard acceptInboundMessage(from: msg.sourceHash, message: convoMsg, lxmfMessage: msg) else {
                deepLinkError = "Message was blocked or already imported."
                return
            }

            log(.info, "✓ Paper message imported: src=\(msg.sourceHash.hexString.prefix(8))… \"\(msg.content.prefix(40))\"")

            selectedTab = .messages
            pendingOpenConversation = msg.sourceHash
        } catch {
            deepLinkError = "Could not decrypt paper message: \(error.localizedDescription)"
            log(.warn, "LXM URI: decrypt/parse failed: \(error)")
        }
    }

    // MARK: - Path Requests

    /// Sends `targetHash + requestTag` to modern and legacy path-request endpoints.
    @discardableResult
    private func sendPathRequest(for targetHash: Data, via iface: any MessageTransportInterface) async -> Bool {
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

    private func resolvePeerPublicKey(
        for destinationHash: Data,
        via iface: any MessageTransportInterface,
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
        fields: [Int: Data] = [:],
        identity: Identity,
        iface: any MessageTransportInterface,
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
                fields: fields,
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
        fields: [Int: Data] = [:],
        identity: Identity,
        iface: any MessageTransportInterface,
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
            fields: fields,
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
        fields: [Int: Data] = [:],
        identity: Identity,
        iface: any MessageTransportInterface,
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
            fields: fields,
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
            outboundPropagatedTransientIDs.removeValue(forKey: outbound.transientID)
            persistOutboundPropagatedTransientIDs()
            appendLog("⚠ PROPAGATED send failed: \(error)")
            throw error
        }

        // Track transient ID → message ID so sync can confirm delivery if the
        // one-shot SINGLE proof was missed (e.g. app backgrounded before proof arrived).
        if let outboundMessageID {
            outboundPropagatedTransientIDs[outbound.transientID] = outboundMessageID
            persistOutboundPropagatedTransientIDs()
        }
    }

    private func ensureDirectLink(
        destinationHash: Data,
        recipientPublicKey: Data,
        iface: any MessageTransportInterface,
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
        let h1Raw = Packet(header: header, payload: request.payload).serialize()
        let (serialized, isH2) = try applyTransportRoutingIfNeeded(
            to: h1Raw,
            destinationHash: destinationHash
        )
        log(.info, "TX LINKREQUEST \(isH2 ? "H2" : "H1") dest=\(destinationHash.hexString.prefix(8))… link=\(request.linkID.hexString.prefix(8))…")
        linkRequestSentAt[request.linkID] = Date()
        try await iface.send(serialized)

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
                // Don't capture cont directly — always go through the dictionary
                // to avoid double-resume if resolveDirectLinkWaiters already ran.
                self?.cancelDirectLinkWaiter(id: waiterID, destinationHash: destinationHash)
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
                guard let self else { return }
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
                guard let self else { return }
                self.cancelPropagationResponseWaiter(id: waiterID, linkID: linkID)
            }
        }
    }

    @discardableResult
    private func sendLinkRequestPayload(
        _ payload: Data,
        context: UInt8,
        linkState: LXMFRouter.DirectLinkState,
        via iface: any MessageTransportInterface
    ) async throws -> Data {
        let encrypted = try ReticulumToken.encryptLinkData(payload, key: linkState.derivedKey)
        let header = PacketHeader(
            packetType: .data,
            destinationType: .link,
            destinationHash: linkState.linkID,
            hops: 0,
            context: context
        )
        let serialized = Packet(header: header, payload: encrypted).serialize()

        // Python-compatible request ID: truncated_hash(hashable_part).
        // For H1 packets: hashable_part = [flags & 0x0F] + raw[2:]
        let flags = serialized[serialized.startIndex]
        var hashablePart = Data([flags & 0x0F])
        hashablePart.append(serialized[(serialized.startIndex + 2)...])
        let requestID = Hashing.truncatedHash(hashablePart, length: Destination.hashLength)

        try await iface.send(serialized)
        return requestID
    }

    private func sendLinkIdentify(
        linkState: LXMFRouter.DirectLinkState,
        via iface: any MessageTransportInterface
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


    private func sendPropagationGetRequest(
        wants: [Data]?,
        haves: [Data]?,
        limitKilobytes: Double?,
        linkState: LXMFRouter.DirectLinkState,
        via iface: any MessageTransportInterface,
        timeout: TimeInterval = 20
    ) async throws -> MsgPack.PropagationGetResponse {
        let requestPayload = MsgPack.encodePropagationGetLinkRequest(
            wants: wants,
            haves: haves,
            limitKilobytes: limitKilobytes
        )
        let expectedRequestID = try await sendLinkRequestPayload(
            requestPayload,
            context: 0x09, // REQUEST
            linkState: linkState,
            via: iface
        )

        guard let responsePayload = await waitForPropagationResponse(linkID: linkState.linkID, timeout: timeout) else {
            throw AppError.nomadResponseTimeout
        }
        guard let decoded = MsgPack.decodePropagationGetLinkResponse(responsePayload) else {
            log(.warn, "Propagation GET: response decode failed (\(responsePayload.count)B)")
            throw AppError.nomadResponseTimeout
        }
        guard decoded.requestID == expectedRequestID else {
            log(
                .warn,
                "Propagation /get request-id mismatch expected=\(expectedRequestID.hexString.prefix(8))… got=\(decoded.requestID.hexString.prefix(8))…"
            )
            throw AppError.nomadResponseTimeout
        }
        return decoded.response
    }

    @discardableResult
    private func syncFromPropagationNode(
        linkState: LXMFRouter.DirectLinkState,
        via iface: any MessageTransportInterface
    ) async throws -> Int {
        try await sendLinkIdentify(linkState: linkState, via: iface)
        purgeExpiredPropagationTransientIDs()
        // Clear stale buffered responses for this link to avoid request-ID mismatches
        // from prior sessions or interrupted syncs.
        bufferedPropagationResponsesByLinkID.removeValue(forKey: linkState.linkID)

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
            confirmOutboundPropagatedDelivery(nodeTransientIDs: transientIDs)

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
                    let msgID = UUID()
                    let parsed = parseAttachmentFields(from: msg.fields, messageID: msgID.uuidString)
                    let convoMsg = ConversationMessage(
                        id: msgID,
                        content: msg.content,
                        timestamp: Date(timeIntervalSince1970: msg.timestamp),
                        isOutbound: false,
                        attachments: parsed.attachments,
                        image: parsed.image,
                        lxmfHash: msg.hash.hexString
                    )
                    guard acceptInboundMessage(from: msg.sourceHash, message: convoMsg, lxmfMessage: msg) else {
                        continue
                    }
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

    func fetchNomadPage(destinationHash: Data, path: String, formData: [String: String]? = nil) async throws -> NomadPage {
        log(.info, "fetchNomadPage ENTER dest=\(destinationHash.hexString.prefix(8))… path=\(path)")
        guard destinationHash.count == Destination.hashLength else { log(.warn, "fetchNomadPage: bad hash length \(destinationHash.count)"); throw AppError.noPath }
        guard !path.isEmpty else { throw NomadError.pageNotFound(path) }
        guard identity != nil else { log(.warn, "fetchNomadPage: no identity"); throw AppError.noIdentity }

        var candidateInterfaces = connectedInterfacesForDestination(destinationHash)
        if candidateInterfaces.isEmpty {
            log(.info, "fetchNomadPage: waiting for interface connection…")
            for attempt in 1...20 {
                try await Task.sleep(nanoseconds: 500_000_000) // 0.5s
                candidateInterfaces = connectedInterfacesForDestination(destinationHash)
                if !candidateInterfaces.isEmpty { break }
                if attempt % 4 == 0 {
                    log(.info, "fetchNomadPage: still waiting… attempt \(attempt)/20")
                }
            }
        }
        log(.info, "fetchNomadPage: \(candidateInterfaces.count) candidate interface(s)")
        guard !candidateInterfaces.isEmpty else { log(.warn, "fetchNomadPage: not connected after 10s"); throw AppError.notConnected }

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
 formData: formData
                )

                log(
 .info,
 "Nomad TX request: dest=\(destinationHash.hexString.prefix(8))… path=\(path) link=\(linkState.linkID.hexString.prefix(8))… payload=\(requestPayload.count)B iface=\(serverID.uuidString.prefix(8))…"
                )
                let expectedRequestID = try await sendLinkRequestPayload(
 requestPayload,
 context: 0x09,
 linkState: linkState,
 via: iface
                )

                guard let responsePayload = await waitForNomadResponse(linkID: linkState.linkID, timeout: 60) else {
 throw AppError.nomadResponseTimeout
                }
                let (requestID, content) = try NomadClient.parsePageResponse(responsePayload)
                if requestID != expectedRequestID {
 log(.warn, "Nomad response request-id mismatch expected=\(expectedRequestID.hexString.prefix(8))… got=\(requestID.hexString.prefix(8))…")
                }
                log(
 .info,
 "Nomad RX response: dest=\(destinationHash.hexString.prefix(8))… req=\(requestID.hexString.prefix(8))… content=\(content.count)B"
                )
                return NomadPage(path: path, requestID: requestID, content: content)
            } catch {
                lastError = error
                log(.warn, "Nomad fetch via interface \(serverID.uuidString.prefix(8))… failed: \(error.localizedDescription)")
                // Invalidate stale link on timeout so the next attempt creates a fresh one
                if case AppError.nomadResponseTimeout = error {
                    log(.info, "Tearing down stale link for dest=\(destinationHash.hexString.prefix(8))…")
                    await lxmfRouter.removeDirectLink(for: destinationHash)
                    directLinkRouteSignatureByDestination.removeValue(forKey: destinationHash)
                    if let staleLinkID = pendingDirectLinkByDestination.removeValue(forKey: destinationHash) {
                        nomadLinkIDs.remove(staleLinkID)
                        pendingDirectRecipientKeysByLinkID.removeValue(forKey: staleLinkID)
                        pendingDirectDestinationByLinkID.removeValue(forKey: staleLinkID)
                    }
                }
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

    // MARK: - Peer Aliases

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

    // MARK: - Announce Timer

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

    // MARK: - Incoming Resource State Machine

    private struct IncomingResource {
        let adv: MsgPack.ResourceAdvertisement
        let linkID: Data
        let derivedKey: Data
        var hashmap: [Data?]         // 4-byte part hashes in order; nil = not yet known
        var parts: [Data?]           // received part data, indexed by part number
        var consecutiveCompleted: Int // highest contiguous received index (-1 = none)
        var outstandingParts: Int    // number of parts requested but not yet received
        var window: Int              // current sliding window size
        var windowMin: Int
        var windowMax: Int
        var retriesLeft: Int
        var lastRequestTime: Date

        static let maphashLen = 4
        static let windowInit = 4
        static let windowMinDefault = 2
        static let windowMaxSlow = 10
        static let maxRetries = 16

        init(adv: MsgPack.ResourceAdvertisement, linkID: Data, derivedKey: Data) {
            self.adv = adv
            self.linkID = linkID
            self.derivedKey = derivedKey
            self.hashmap = Self.parseHashmap(adv.hashmapRaw)
            self.parts = Array(repeating: nil, count: adv.numParts)
            self.consecutiveCompleted = -1
            self.outstandingParts = 0
            self.window = Self.windowInit
            self.windowMin = Self.windowMinDefault
            self.windowMax = Self.windowMaxSlow
            self.retriesLeft = Self.maxRetries
            self.lastRequestTime = Date()
        }

        static func parseHashmap(_ raw: Data) -> [Data?] {
            var result: [Data?] = []
            var i = raw.startIndex
            while i + maphashLen <= raw.endIndex {
                result.append(Data(raw[i..<(i + maphashLen)]))
                i += maphashLen
            }
            return result
        }

        /// Index of the part matching a 4-byte hash, searching from consecutiveCompleted onward.
        func partIndex(forHash hash: Data) -> Int? {
            for idx in 0..<hashmap.count {
                if hashmap[idx] == hash { return idx }
            }
            return nil
        }

        /// Returns true when all parts have been received.
        var isComplete: Bool { consecutiveCompleted == parts.count - 1 }

        /// Whether the hashmap has been exhausted (need HMU).
        var hashmapExhausted: Bool {
            let nextNeeded = consecutiveCompleted + 1
            return nextNeeded < parts.count && nextNeeded >= hashmap.count
        }

        /// Part hashes to request next (up to `window` parts starting from consecutiveCompleted+1).
        mutating func nextRequestHashes() -> [Data] {
            var hashes: [Data] = []
            let start = consecutiveCompleted + 1
            let end = min(start + window, parts.count)
            for idx in start..<end {
                guard idx < hashmap.count else { break }
                guard let hash = hashmap[idx] else { continue }
                if parts[idx] == nil {
                    hashes.append(hash)
                }
            }
            outstandingParts = hashes.count
            lastRequestTime = Date()
            return hashes
        }

        /// Store a received part. Returns the index if stored, nil if unrecognised.
        mutating func storePart(_ data: Data, hash partHash: Data) -> Int? {
            guard let idx = partIndex(forHash: partHash) else { return nil }
            parts[idx] = data
            outstandingParts = max(0, outstandingParts - 1)
            // Advance consecutive pointer
            while consecutiveCompleted + 1 < parts.count,
                  parts[consecutiveCompleted + 1] != nil {
                consecutiveCompleted += 1
            }
            return idx
        }

        /// Extend the hashmap with new hashes from an HMU packet.
        mutating func extendHashmap(segment segNum: Int, raw: Data) {
            let newHashes = Self.parseHashmap(raw)
            let expectedStart = segNum * Self.hashmapMaxLen
            while hashmap.count < expectedStart && hashmap.count < parts.count {
                hashmap.append(nil)
            }
            for (offset, h) in newHashes.enumerated() {
                let idx = expectedStart + offset
                guard idx < parts.count else { break }
                if idx < hashmap.count {
                    hashmap[idx] = h
                } else {
                    hashmap.append(h)
                }
            }
        }

        /// Hashmap max length per segment (matches Python: floor((MDU - 134) / 4)).
        static let hashmapMaxLen = 74

        /// Assemble all parts into a single Data blob.
        func assemble() -> Data {
            var result = Data()
            for part in parts {
                if let p = part { result.append(p) }
            }
            return result
        }
    }

    // MARK: - Resource Transfer Handling

    /// Handle a RESOURCE_ADV (0x02) packet: parse advertisement, create resource state, request first parts.
    private func handleResourceAdvertisement(linkID: Data, payload: Data) {
        guard let adv = MsgPack.decodeResourceAdvertisement(payload) else {
            log(.warn, "Resource: failed to parse advertisement (\(payload.count)B)")
            return
        }
        guard let derivedKey = linkDerivedKeys[linkID] else {
            log(.warn, "Resource: no derived key for link \(linkID.hexString.prefix(8))…, dropping ADV")
            return
        }

        log(.info, "Resource ADV: hash=\(adv.resourceHash.hexString.prefix(8))… parts=\(adv.numParts) " +
            "size=\(adv.transferSize) flags=\(String(format: "0x%02X", adv.flags)) " +
            "seg=\(adv.segmentIndex)/\(adv.totalSegments) hashmap=\(adv.hashmapRaw.count / 4) hashes")

        var resource = IncomingResource(adv: adv, linkID: linkID, derivedKey: derivedKey)
        activeResources[adv.resourceHash] = resource

        // Request first batch of parts.
        sendResourceRequest(&resource)
        activeResources[adv.resourceHash] = resource
    }

    /// Handle a RESOURCE (0x01) packet: store part data, request more or complete.
    private func handleResourcePart(linkID: Data, payload: Data) {
        guard payload.count > IncomingResource.maphashLen else {
            log(.warn, "Resource: part too small (\(payload.count)B)")
            return
        }

        // Part format: [part_data]. The part hash is SHA256(part_data + random_hash)[:4].
        // We need to try matching against active resources.
        let partData = payload

        for (resourceHash, var resource) in activeResources {
            guard resource.linkID == linkID else { continue }

            // Compute part hash: SHA256(partData + randomHash)[:4]
            var hashInput = partData
            hashInput.append(resource.adv.randomHash)
            let partHash = Hashing.sha256(hashInput).prefix(IncomingResource.maphashLen)

            if let idx = resource.storePart(partData, hash: Data(partHash)) {
                activeResources[resourceHash] = resource
                let received = resource.consecutiveCompleted + 1
                resourceTransferStatus = "Receiving data: \(received)/\(resource.adv.numParts)"
                log(.debug, "Resource: stored part \(idx)/\(resource.adv.numParts) " +
                    "consecutive=\(resource.consecutiveCompleted) hash=\(resourceHash.hexString.prefix(8))…")

                if resource.isComplete {
                    completeResource(resourceHash: resourceHash)
                } else if resource.hashmapExhausted {
                    requestHashmapUpdate(resourceHash: resourceHash)
                } else if resource.outstandingParts == 0 {
                    // All requested parts received — grow window and request next batch.
                    resource.window = min(resource.window + 1, resource.windowMax)
                    if (resource.window - resource.windowMin) > 0 {
                        resource.windowMin += 1
                    }
                    activeResources[resourceHash] = resource
                    sendResourceRequest(&resource)
                    activeResources[resourceHash] = resource
                }
                return
            }
        }

        log(.debug, "Resource: no active resource matched part on link \(linkID.hexString.prefix(8))… (\(payload.count)B)")
    }

    /// Handle RESOURCE_HMU (0x04): hashmap update from sender.
    private func handleResourceHashmapUpdate(linkID: Data, payload: Data) {
        // Format: resourceHash(32) + msgpack([segmentNumber, hashmapBytes])
        guard payload.count > 32 else {
            log(.warn, "Resource HMU: payload too small (\(payload.count)B)")
            return
        }
        let resourceHash = Data(payload.prefix(32))
        let msgpackData = Data(payload.dropFirst(32))

        guard var resource = activeResources[resourceHash] else {
            log(.warn, "Resource HMU: no active resource for hash \(resourceHash.hexString.prefix(8))…")
            return
        }

        // Parse msgpack [segment_number, hashmap_bytes]
        guard let parsed = MsgPack.decodeAny(msgpackData) as? [Any?],
              parsed.count >= 2,
              let segNum = parsed[0] as? Int,
              let hmBytes = parsed[1] as? Data else {
            log(.warn, "Resource HMU: failed to parse msgpack")
            return
        }

        resource.extendHashmap(segment: segNum, raw: hmBytes)
        activeResources[resourceHash] = resource
        log(.info, "Resource HMU: extended hashmap to \(resource.hashmap.count) hashes (segment \(segNum))")

        // Request next parts with the new hashes.
        sendResourceRequest(&resource)
        activeResources[resourceHash] = resource
    }

    /// Handle RESOURCE_ICL (0x06) or RESOURCE_RCL (0x07): cancellation.
    private func handleResourceCancel(linkID: Data, payload: Data, context: UInt8) {
        guard payload.count >= 32 else { return }
        let resourceHash = Data(payload.prefix(32))
        if activeResources.removeValue(forKey: resourceHash) != nil {
            let label = context == 0x06 ? "ICL" : "RCL"
            log(.warn, "Resource \(label): transfer cancelled by sender, hash=\(resourceHash.hexString.prefix(8))…")
        }
    }

    /// Send a RESOURCE_REQ (0x03) for the next batch of parts.
    private func sendResourceRequest(_ resource: inout IncomingResource) {
        let hashes = resource.nextRequestHashes()
        guard !hashes.isEmpty else {
            log(.debug, "Resource: no hashes to request for \(resource.adv.resourceHash.hexString.prefix(8))…")
            return
        }

        // REQ format: [0x00 (normal)] + resource_hash(32) + requested_part_hashes(N×4)
        var reqPayload = Data([0x00])
        reqPayload.append(resource.adv.resourceHash)
        for h in hashes {
            reqPayload.append(h)
        }

        log(.debug, "Resource REQ: requesting \(hashes.count) parts for \(resource.adv.resourceHash.hexString.prefix(8))…")
        sendResourcePacket(linkID: resource.linkID, payload: reqPayload, context: 0x03)
    }

    /// Request a hashmap update by sending an exhaustion request.
    private func requestHashmapUpdate(resourceHash: Data) {
        guard var resource = activeResources[resourceHash] else { return }

        // HMU request format: [0xFF (exhaustion flag)] + last_received_hash(4) + resource_hash(32)
        let lastHash: Data
        if resource.consecutiveCompleted >= 0, resource.consecutiveCompleted < resource.hashmap.count,
           let h = resource.hashmap[resource.consecutiveCompleted] {
            lastHash = h
        } else {
            lastHash = Data(repeating: 0, count: IncomingResource.maphashLen)
        }

        var reqPayload = Data([0xFF])
        reqPayload.append(lastHash)
        reqPayload.append(resource.adv.resourceHash)

        log(.info, "Resource: requesting HMU for \(resourceHash.hexString.prefix(8))… (hashmap exhausted at \(resource.hashmap.count))")
        sendResourcePacket(linkID: resource.linkID, payload: reqPayload, context: 0x03)
        resource.lastRequestTime = Date()
        activeResources[resourceHash] = resource
    }

    /// Assemble, decrypt, decompress, verify, prove, and route a completed resource.
    private func completeResource(resourceHash: Data) {
        guard let resource = activeResources[resourceHash] else { return }

        log(.info, "Resource: assembling \(resource.adv.numParts) parts for \(resourceHash.hexString.prefix(8))…")
        let assembled = resource.assemble()

        // Step 1: Decrypt resource-level encryption.
        var decrypted: Data
        if resource.adv.isEncrypted {
            guard let dec = try? ReticulumToken.decryptLinkData(assembled, key: resource.derivedKey) else {
                log(.error, "Resource: decryption failed for \(resourceHash.hexString.prefix(8))… (\(assembled.count)B)")
                activeResources.removeValue(forKey: resourceHash)
                return
            }
            decrypted = dec
        } else {
            decrypted = assembled
        }

        // Step 2: Strip inner random hash prefix (4 bytes).
        guard decrypted.count > IncomingResource.maphashLen else {
            log(.error, "Resource: decrypted data too small (\(decrypted.count)B)")
            activeResources.removeValue(forKey: resourceHash)
            return
        }
        let strippedData = Data(decrypted.dropFirst(IncomingResource.maphashLen))

        // Step 3: Decompress if flagged (MUST happen before hash verification —
        // Python computes the hash on the ORIGINAL uncompressed data).
        var finalData: Data
        if resource.adv.isCompressed {
            guard let decompressed = try? BZ2.decompress(strippedData) else {
                log(.error, "Resource: bz2 decompression failed for \(resourceHash.hexString.prefix(8))…")
                activeResources.removeValue(forKey: resourceHash)
                return
            }
            finalData = decompressed
        } else {
            finalData = strippedData
        }

        // Step 4: Verify hash — SHA256(final_data + outer_random_hash) == resource_hash.
        var hashInput = finalData
        hashInput.append(resource.adv.randomHash)
        let computedHash = Hashing.sha256(hashInput)
        guard computedHash == resource.adv.resourceHash else {
            log(.error, "Resource: hash mismatch! expected=\(resource.adv.resourceHash.hexString.prefix(16)) got=\(computedHash.hexString.prefix(16))")
            activeResources.removeValue(forKey: resourceHash)
            return
        }

        log(.info, "Resource: complete! \(finalData.count)B for \(resourceHash.hexString.prefix(8))… (enc=\(resource.adv.isEncrypted) comp=\(resource.adv.isCompressed))")

        // Step 5: Send completion proof over decompressed data.
        guard sendResourceProof(resource: resource, decryptedData: finalData) else {
            activeResources.removeValue(forKey: resourceHash)
            resourceTransferStatus = nil
            return
        }

        // Step 6: Route to the appropriate handler.
        routeCompletedResource(resource: resource, data: finalData)

        activeResources.removeValue(forKey: resourceHash)
        resourceTransferStatus = nil
    }

    /// Send the RESOURCE_PRF (resource proof) to the sender. Returns true on success.
    @discardableResult
    private func sendResourceProof(resource: IncomingResource, decryptedData: Data) -> Bool {
        // Proof = resourceHash(32) + SHA256(decryptedData + resourceHash)(32)
        var proofHashInput = decryptedData
        proofHashInput.append(resource.adv.resourceHash)
        let proofHash = Hashing.sha256(proofHashInput)

        var proofPayload = resource.adv.resourceHash
        proofPayload.append(proofHash)

        // Send as encrypted PROOF packet with context 0x05 (RESOURCE_PRF).
        // Python RNS uses packet_type=RNS.Packet.PROOF directly (not link.send()).
        if let encrypted = try? ReticulumToken.encryptLinkData(proofPayload, key: resource.derivedKey) {
            let header = PacketHeader(
                packetType: .proof,
                destinationType: .link,
                destinationHash: resource.linkID,
                hops: 0,
                context: 0x05
            )
            let packet = Packet(header: header, payload: encrypted).serialize()
            broadcastToActiveInterfaces(packet)
            log(.debug, "Resource: sent proof for \(resource.adv.resourceHash.hexString.prefix(8))…")
            return true
        } else {
            // Encryption failed — send RCL to tell sender we're cancelling (best-effort).
            let rclPayload = resource.adv.resourceHash
            sendResourcePacket(linkID: resource.linkID, payload: rclPayload, context: 0x07)
            log(.warn, "Resource: proof encryption failed, sent RCL for \(resource.adv.resourceHash.hexString.prefix(8))…")
            return false
        }
    }

    /// Route a completed resource to the NomadNet or propagation handler.
    private func routeCompletedResource(resource: IncomingResource, data: Data) {
        let linkID = resource.linkID

        if nomadLinkIDs.contains(linkID) {
            log(.info, "Resource: routing to NomadNet handler, link=\(linkID.hexString.prefix(8))… \(data.count)B")
            enqueueNomadResponse(payload: data, linkID: linkID)
        } else if propagationLinkIDs.contains(linkID) {
            log(.info, "Resource: routing to propagation handler, link=\(linkID.hexString.prefix(8))… \(data.count)B")
            enqueuePropagationResponse(payload: data, linkID: linkID)
        } else if inboundDeliveryLinkIDs.contains(linkID) {
            log(.info, "Resource: routing to LXMF delivery handler, link=\(linkID.hexString.prefix(8))… \(data.count)B")
            handleInboundDeliveryResource(data: data, linkID: linkID)
        } else {
            // Fallback: try parsing as LXMF (resource could arrive on any delivery link)
            log(.info, "Resource: unrecognised link \(linkID.hexString.prefix(8))… (\(data.count)B), attempting LXMF parse")
            handleInboundDeliveryResource(data: data, linkID: linkID)
        }
    }

    /// Parse a completed resource as an inbound LXMF message (direct delivery via resource transfer).
    private func handleInboundDeliveryResource(data: Data, linkID: Data) {
        guard let msg = try? LXMFMessage(packed: data) else {
            log(.warn, "Resource: LXMF parse failed for delivery resource on link \(linkID.hexString.prefix(8))… (\(data.count)B)")
            return
        }
        if let requiredStampCost = inboundStampCost {
            let validation = msg.validateStamp(
                targetCost: requiredStampCost,
                tickets: inboundTickets(for: msg.sourceHash)
            )
            if !validation.valid {
                log(.warn, "Resource: invalid stamp from \(msg.sourceHash.hexString.prefix(8))… required=\(requiredStampCost)")
                return
            }
        }
        rememberOutboundTicket(from: msg.sourceHash, fields: msg.fields)
        let msgID = UUID()
        let parsed = parseAttachmentFields(from: msg.fields, messageID: msgID.uuidString)
        let convoMsg = ConversationMessage(
            id: msgID,
            content: msg.content,
            timestamp: Date(timeIntervalSince1970: msg.timestamp),
            isOutbound: false,
            attachments: parsed.attachments,
            image: parsed.image,
            lxmfHash: msg.hash.hexString
        )
        acceptInboundMessage(from: msg.sourceHash, message: convoMsg, lxmfMessage: msg)
        log(.info, "Resource: accepted LXMF delivery from \(msg.sourceHash.hexString.prefix(8))… via resource transfer")
    }

    /// Send a resource-related packet (encrypted) on a link.
    private func sendResourcePacket(linkID: Data, payload: Data, context: UInt8) {
        guard let derivedKey = linkDerivedKeys[linkID] else {
            log(.warn, "Resource: no key for link \(linkID.hexString.prefix(8))…, cannot send context=\(String(format: "0x%02X", context))")
            return
        }
        guard let encrypted = try? ReticulumToken.encryptLinkData(payload, key: derivedKey) else {
            log(.warn, "Resource: encryption failed for context=\(String(format: "0x%02X", context))")
            return
        }
        let header = PacketHeader(
            packetType: .data,
            destinationType: .link,
            destinationHash: linkID,
            hops: 0,
            context: context
        )
        let packet = Packet(header: header, payload: encrypted).serialize()
        broadcastToActiveInterfaces(packet)
    }

    /// Broadcast a serialized packet to all active interfaces.
    private func broadcastToActiveInterfaces(_ data: Data) {
        for (serverId, iface) in interfaces {
            guard serverStatuses[serverId] == true else { continue }
            Task { try? await iface.send(data) }
        }
    }

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
            if packetContext == 0x0A,
               nomadLinkIDs.contains(destHash) {
                // Reticulum RESPONSE context (0x0A) — NomadNet page response
                // Enqueue regardless of parse result; fetchNomadPage will parse and log errors
                log(.info, "Nomad RX link response: link=\(destHash.hexString.prefix(8))… \(effectivePayload.count)B hex=\(effectivePayload.prefix(min(32, effectivePayload.count)).hexString)")
                enqueueNomadResponse(payload: effectivePayload, linkID: destHash)
                return
            } else if packetContext == 0x0A,
                      propagationLinkIDs.contains(destHash) {
                enqueuePropagationResponse(payload: effectivePayload, linkID: destHash)
                return
            }
        }

        switch packet.header.packetType {

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
            let announcedPrefPropNode = isLXMFDelivery
                ? MsgPack.decodeAnnouncedPropagationNode(announce.appData)
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
 peers[idx].announcedPreferredPropagationNode = announcedPrefPropNode
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
 announcedPropagationEnabled: announcedPropagationEnabled,
 announcedPreferredPropagationNode: announcedPrefPropNode
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
            if isNomadNode {
                Task {
                    await nomadStore.recordNode(
                        destinationHashHex: destHash.hexString,
                        name: announcedName ?? ""
                    )
                }
            }
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
           effectivePayload: effectivePayload, isHeader2: isHeader2,
           ingressServerID: fromServerID)

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

        case .data where packet.header.destinationType == .link:
            // NomadNet RESPONSE (0x0A) and propagation RESPONSE are handled in
            // the pre-switch block above.

            // LINKIDENTIFY (0xFB): remote peer identifying itself on a link.
            if packetContext == 0xFB {
                handleLinkIdentifyPacket(linkID: destHash, payload: effectivePayload)
                return
            }

            // REQUEST (0x09) on a propagation host link: /get or /offer from clients.
            if packetContext == 0x09, propagationHostLinkIDs.contains(destHash) {
                handlePropagationRequest(linkID: destHash, payload: effectivePayload)
                return
            }

            // Resource transfer contexts (0x01-0x07).
            switch packetContext {
            case 0x01: // RESOURCE — data part
                handleResourcePart(linkID: destHash, payload: effectivePayload)
                return
            case 0x02: // RESOURCE_ADV — advertisement
                handleResourceAdvertisement(linkID: destHash, payload: effectivePayload)
                return
            case 0x04: // RESOURCE_HMU — hashmap update
                handleResourceHashmapUpdate(linkID: destHash, payload: effectivePayload)
                return
            case 0x06, 0x07: // RESOURCE_ICL / RESOURCE_RCL — cancel
                handleResourceCancel(linkID: destHash, payload: effectivePayload, context: packetContext)
                return
            case 0x05: // RESOURCE_PRF — resource proof (no action needed on client)
                return
            case 0x08: // CACHE_REQUEST — transport cache request (no action needed)
                return
            case 0x0E: // CHANNEL — link channel data (not implemented)
                return
            case 0xFC: // LINKCLOSE — remote end closed the link
                handleLinkClose(linkID: destHash)
                return
            case 0xFA: // KEEPALIVE — link keepalive (no action needed)
                return
            default:
                break
            }

            // Only context 0x00 (NONE) carries LXMF direct messages.
            guard packetContext == 0x00 else {
                log(.debug, "RX LINK DATA: unhandled context=\(String(format: "0x%02X", packetContext)) link=\(destHash.hexString.prefix(8))… \(effectivePayload.count)B")
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
            let msgID = UUID()
            let parsed = parseAttachmentFields(from: msg.fields, messageID: msgID.uuidString)
            let convoMsg = ConversationMessage(
                id: msgID,
                content: msg.content,
                timestamp: Date(timeIntervalSince1970: msg.timestamp),
                isOutbound: false,
                attachments: parsed.attachments,
                image: parsed.image,
                lxmfHash: msg.hash.hexString
            )
            acceptInboundMessage(from: msg.sourceHash, message: convoMsg, lxmfMessage: msg)
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

            let msgID = UUID()
            let parsed = parseAttachmentFields(from: msg.fields, messageID: msgID.uuidString)
            let convoMsg = ConversationMessage(
                id: msgID,
                content: msg.content,
                timestamp: Date(timeIntervalSince1970: msg.timestamp),
                isOutbound: false,
                attachments: parsed.attachments,
                image: parsed.image,
                lxmfHash: msg.hash.hexString
            )
            acceptInboundMessage(from: msg.sourceHash, message: convoMsg, lxmfMessage: msg)
            log(.info, "✓ Message received ← \(msg.sourceHash.hexString.prefix(8))… \"\(msg.content.prefix(40))\"")

            // Send implicit SINGLE proof after successful decrypt/parse.
            sendSingleProof(rawPacket: data, isHeader2: isHeader2)
            requestPropagationInboxSync(reason: "inbound")

        default:
            log(.debug, "RX \(hdrStr) \(packet.header.packetType): unhandled")
        }
    }

    // SINGLE proof (delivery receipt for OPPORTUNISTIC messages)

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

    // MARK: - Link Establishment

    /// Reticulum MTU (default 500 bytes).
    private static let reticulumMTU = 500

    private static func linkSignallingBytes(mtu: Int = reticulumMTU) -> Data {
        let mode = 0x01  // MODE_AES256_CBC
        let sv   = (mtu & 0x1FFFFF) + (((mode << 5) & 0xE0) << 16)
        let bytes = withUnsafeBytes(of: UInt32(sv).bigEndian) { Data($0) }
        return Data(bytes.dropFirst(1))  // Take last 3 bytes
    }

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
    private func handleLinkRequest(
        packet _: Packet, destHash: Data, effectivePayload: Data,
        isHeader2 _: Bool, ingressServerID: UUID?
    ) {
        guard let identity else {
            log(.warn, "RX LINKREQUEST: no local identity")
            return
        }
        guard let lxmfDest = lxmfDestinationHash else {
            log(.warn, "RX LINKREQUEST: no LXMF destination")
            return
        }

        // Accept links to our LXMF delivery destination or our propagation destination.
        let propDest = LXMFAddressing.propagationDestinationHash(identityHash: identity.hash)
        let isForLXMF = (destHash == lxmfDest)
        let isForPropagation = (propagationNodeEnabled && destHash == propDest)

        guard isForLXMF || isForPropagation else {
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
        log(.info, "RX LINKREQUEST from \(peerX25519Pub.hexString.prefix(8))… linkId=\(linkId.hexString.prefix(8))… forPropagation=\(isForPropagation)")

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

        // Derive link key.
        let derivedKey = sharedSecret.hkdfDerivedSymmetricKey(
            using:           SHA256.self,
            salt:            linkId,
            sharedInfo:      Data(),
            outputByteCount: 64
        )
        let derivedKeyBytes = derivedKey.withUnsafeBytes { Data($0) }
        linkDerivedKeys[linkId] = derivedKeyBytes

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

        // Track propagation host links for /get and /offer routing.
        if isForPropagation {
            propagationHostLinkIDs.insert(linkId)
            propagationHostLinkStates[linkId] = LXMFRouter.DirectLinkState(
                destinationHash: destHash, linkID: linkId, derivedKey: derivedKeyBytes
            )
        } else {
            inboundDeliveryLinkIDs.insert(linkId)
        }

        // Register link key on ALL interfaces first, then send proof only on ingress.
        // Sequential awaits prevent the race where DATA arrives before key is registered.
        let linkIdCopy = linkId
        let keyCopy = derivedKeyBytes
        Task {
            // Step 1: Register link key on all active interfaces.
            for (serverId, iface) in interfaces {
                guard serverStatuses[serverId] == true else { continue }
                await iface.establishLink(linkId: linkIdCopy, derivedKey: keyCopy)
            }
            // Step 2: Send proof only on the ingress interface.
            if let serverID = ingressServerID, let iface = interfaces[serverID] {
                do {
                    try await iface.send(proofRaw)
                    let ifaceName = await iface.name
                    log(.info, "✓ LINKPROOF sent for link \(linkIdCopy.hexString.prefix(8))… via \(ifaceName)")
                } catch {
                    log(.warn, "LINKPROOF send failed: \(error)")
                }
            } else {
                // Fallback: send on all if no ingress identified
                for (serverId, iface) in interfaces {
                    guard serverStatuses[serverId] == true else { continue }
                    do {
                        try await iface.send(proofRaw)
                        log(.info, "✓ LINKPROOF sent for link \(linkIdCopy.hexString.prefix(8))…")
                    } catch {
                        log(.warn, "LINKPROOF send failed: \(error)")
                    }
                }
            }
        }
    }

    private func handleLinkProof(destHash: Data, effectivePayload: Data) {
        log(.info, "RX LINKPROOF link=\(destHash.hexString.prefix(8))… payload=\(effectivePayload.count)B pending=\(pendingDirectRecipientKeysByLinkID.keys.map { $0.hexString.prefix(8) })")
        guard let recipientPublicKey = pendingDirectRecipientKeysByLinkID[destHash] else {
            log(.warn, "RX LINKPROOF ignored (unknown link id) id=\(destHash.hexString.prefix(8))…")
            return
        }

        Task { [weak self] in
            guard let self else { os_log("[LRPROOF-TASK] self is nil", log: OSLog(subsystem: "chat.inertia.app", category: "protocol"), type: .default); return }
            self.log(.info, "[LRPROOF-TASK] starting completion for \(destHash.hexString.prefix(8))")
            do {
                let link = try await self.completeLinkFromProof(
 linkID: destHash,
 proofPayload: effectivePayload,
 recipientIdentityPublicKey: recipientPublicKey
                )
                os_log("[LRPROOF-TASK] SUCCESS link=%{public}@", log: OSLog(subsystem: "chat.inertia.app", category: "protocol"), type: .default, link.linkID.hexString.prefix(8).description)
                self.log(.info, "✓ DIRECT link established id=\(link.linkID.hexString.prefix(8))…")
            } catch {
                os_log("[LRPROOF-TASK] ERROR=%{public}@", log: OSLog(subsystem: "chat.inertia.app", category: "protocol"), type: .default, "\(error)")
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
        os_log("CLF step 1: calling completeDirectLink", log: inertiaLog, type: .default)
        let link = try await lxmfRouter.completeDirectLink(
            linkID: linkID,
            proofPayload: proofPayload,
            recipientIdentityPublicKey: recipientIdentityPublicKey
        )
        os_log("CLF step 2: completeDirectLink returned", log: inertiaLog, type: .default)

        let linkIDCopy = link.linkID
        let keyCopy = link.derivedKey
        linkDerivedKeys[linkIDCopy] = keyCopy
        os_log("CLF step 3: registering link on %d interfaces", log: inertiaLog, type: .default, interfaces.count)
        for (serverId, iface) in interfaces {
            guard serverStatuses[serverId] == true else { continue }
            await iface.establishLink(linkId: linkIDCopy, derivedKey: keyCopy)
        }

        // CLF step 3b: Send LRRTT to transition server-side link from HANDSHAKE → ACTIVE.
        // Python RNS requires this packet before it will process any REQUEST on the link.
        let rtt: TimeInterval
        if let sentAt = linkRequestSentAt.removeValue(forKey: linkID) {
            rtt = max(Date().timeIntervalSince(sentAt), 0.001)
        } else {
            rtt = 0.1
        }
        var rttPayload = Data([0xcb]) // msgpack float64
        let rttBits = rtt.bitPattern.bigEndian
        withUnsafeBytes(of: rttBits) { rttPayload.append(contentsOf: $0) }
        if let (_, iface) = interfaces.first(where: { serverStatuses[$0.key] == true }) {
            do {
                let _ = try await sendLinkRequestPayload(
                    rttPayload,
                    context: 0xFE, // LRRTT
                    linkState: link,
                    via: iface
                )
                os_log("CLF step 3b: LRRTT sent (%.3fs)", log: inertiaLog, type: .default, rtt)
            } catch {
                os_log("CLF step 3b: LRRTT send failed: %{public}@", log: inertiaLog, type: .default, "\(error)")
            }
        }

        os_log("CLF step 4: cleaning up pending state", log: inertiaLog, type: .default)
        pendingDirectRecipientKeysByLinkID.removeValue(forKey: linkID)
        if let destination = pendingDirectDestinationByLinkID.removeValue(forKey: linkID) {
            pendingDirectLinkByDestination.removeValue(forKey: destination)
            directLinkRouteSignatureByDestination.removeValue(forKey: destination)
            os_log("CLF step 5: resolving waiters for %{public}@", log: inertiaLog, type: .default, destination.hexString.prefix(8).description)
            resolveDirectLinkWaiters(destinationHash: destination, link: link)
            os_log("CLF step 6: waiters resolved", log: inertiaLog, type: .default)
        } else {
            os_log("CLF step 5: no destination found for linkID — waiters NOT resolved", log: inertiaLog, type: .default)
        }
        return link
    }

    private func clearPendingDirectLink(linkID: Data) {
        pendingDirectRecipientKeysByLinkID.removeValue(forKey: linkID)
        linkRequestSentAt.removeValue(forKey: linkID)
        if let destination = pendingDirectDestinationByLinkID.removeValue(forKey: linkID) {
            pendingDirectLinkByDestination.removeValue(forKey: destination)
            directLinkRouteSignatureByDestination.removeValue(forKey: destination)
            if let waiters = directLinkWaiters.removeValue(forKey: destination) {
                for (_, cont) in waiters { cont.resume(returning: nil) }
            }
        }
    }

    /// Handle LINKCLOSE (0xFC) from the remote end. Clean up link state so the
    /// next page request will establish a fresh link.
    private func handleLinkClose(linkID: Data) {
        log(.info, "RX LINKCLOSE link=\(linkID.hexString.prefix(8))… — cleaning up")
        linkDerivedKeys.removeValue(forKey: linkID)
        nomadLinkIDs.remove(linkID)
        propagationLinkIDs.remove(linkID)
        inboundDeliveryLinkIDs.remove(linkID)
        // Clear stale buffered responses so a reused link doesn't pick up old data.
        bufferedNomadResponsesByLinkID.removeValue(forKey: linkID)
        bufferedPropagationResponsesByLinkID.removeValue(forKey: linkID)
        // Drain any blocked propagation response waiters so they fail fast
        // instead of stalling until their timeout fires.
        if let waiters = propagationResponseWaiters.removeValue(forKey: linkID) {
            for (_, cont) in waiters { cont.resume(returning: nil) }
        }
        activeResources = activeResources.filter { $0.value.linkID != linkID }
        for (serverId, iface) in interfaces {
            guard serverStatuses[serverId] == true else { continue }
            Task { await iface.removeLink(linkId: linkID) }
        }
        // Also remove from directLinks if this was a direct link
        Task { [weak self] in
            guard let self else { return }
            await self.lxmfRouter.removeDirectLinkByLinkID(linkID)
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
            conversations[idx].lastActivityAt = .now
        } else {
            conversations.append(Conversation(destinationHash: destinationHash, messages: [message], lastActivityAt: .now))
        }
        saveConversations()
    }

    /// Accepts an inbound message only if the sender is not blocked.
    /// Returns `true` if the message was accepted (not blocked).
    @discardableResult
    private func acceptInboundMessage(from sourceHash: Data, message: ConversationMessage, lxmfMessage: LXMFMessage? = nil) -> Bool {
        guard !isBlocked(sourceHash) else {
            log(.info, "Blocked inbound message from \(sourceHash.hexString.prefix(8))…")
            return false
        }
        // Dedup by LXMF message hash
        if let hash = message.lxmfHash,
           let convo = conversations.first(where: { $0.destinationHash == sourceHash }),
           convo.messages.contains(where: { $0.lxmfHash == hash }) {
            log(.info, "Duplicate message from \(sourceHash.hexString.prefix(8))… hash=\(hash.prefix(8))… — skipping")
            return false
        }
        upsertConversation(destinationHash: sourceHash, message: message)
        if let lxmfMessage {
            notifyInboundMessageIfNeeded(lxmfMessage)
        }
        return true
    }

    // MARK: - Attachment Helpers

    /// Base directory for attachment file storage.
    private var attachmentsBaseDir: URL {
        Self.appSupportDir.appendingPathComponent("attachments", isDirectory: true)
    }

    /// Saves attachment data to disk and returns the relative storage path.
    func saveAttachmentData(_ data: Data, messageID: String, filename: String) -> String? {
        let dir = attachmentsBaseDir.appendingPathComponent(messageID, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let filePath = dir.appendingPathComponent(filename)
            try data.write(to: filePath)
            return "\(messageID)/\(filename)"
        } catch {
            log(.warn, "Failed to save attachment \(filename): \(error.localizedDescription)")
            return nil
        }
    }

    /// Loads attachment data from a storage path.
    func loadAttachmentData(storagePath: String) -> Data? {
        let url = attachmentsBaseDir.appendingPathComponent(storagePath)
        return try? Data(contentsOf: url)
    }

    /// Removes orphaned attachment directories not referenced by any conversation.
    func cleanupOrphanedAttachments() {
        let fm = FileManager.default
        let baseDir = attachmentsBaseDir
        guard let subdirs = try? fm.contentsOfDirectory(at: baseDir, includingPropertiesForKeys: nil) else { return }
        var referencedIDs = Set<String>()
        for convo in conversations {
            for msg in convo.messages {
                if let path = msg.image?.storagePath, let id = path.split(separator: "/").first {
                    referencedIDs.insert(String(id))
                }
                for att in msg.attachments ?? [] {
                    if let path = att.storagePath, let id = path.split(separator: "/").first {
                        referencedIDs.insert(String(id))
                    }
                }
            }
        }
        for dir in subdirs where dir.hasDirectoryPath {
            let dirName = dir.lastPathComponent
            if !referencedIDs.contains(dirName) {
                try? fm.removeItem(at: dir)
            }
        }
    }

    /// Maximum inbound image size: 5 MB
    private static let maxInboundImageSize = 5 * 1024 * 1024
    /// Maximum inbound file attachment size: 10 MB
    private static let maxInboundFileSize = 10 * 1024 * 1024

    /// Parses LXMF fields for image and file attachments, saves to disk, returns model objects.
    private func parseAttachmentFields(
        from fields: [Int: Data],
        messageID: String
    ) -> (image: MessageImage?, attachments: [MessageAttachment]?) {
        var parsedImage: MessageImage? = nil
        var parsedAttachments: [MessageAttachment]? = nil

        // FIELD_IMAGE (0x06): msgpack array [type_str, image_bytes]
        if let imageFieldData = fields[LXMFFieldKey.image] {
            parsedImage = parseImageField(imageFieldData, messageID: messageID)
        }

        // FIELD_FILE_ATTACHMENTS (0x05): msgpack array of [filename_str, file_bytes]
        if let fileFieldData = fields[LXMFFieldKey.fileAttachments] {
            parsedAttachments = parseFileAttachmentsField(fileFieldData, messageID: messageID)
        }

        return (parsedImage, parsedAttachments)
    }

    /// Parses a FIELD_IMAGE msgpack value: [type_str, image_bytes]
    private func parseImageField(_ data: Data, messageID: String) -> MessageImage? {
        // The field value is raw msgpack: fixarray(2) + str(type) + bin(data)
        var cursor = data.startIndex
        guard cursor < data.endIndex else { return nil }
        let tag = data[cursor]
        cursor += 1

        // Must be a 2-element array
        let arrayCount: Int
        if tag >= 0x90 && tag <= 0x9F {
            arrayCount = Int(tag & 0x0F)
        } else if tag == 0xDC, cursor + 2 <= data.endIndex {
            arrayCount = Int(data[cursor]) << 8 | Int(data[cursor + 1])
            cursor += 2
        } else { return nil }
        guard arrayCount == 2 else { return nil }

        // Read image type string
        guard let (imageType, nextCursor) = readMsgpackString(from: data, at: cursor) else { return nil }
        cursor = nextCursor

        // Read image bytes
        guard let (imageBytes, _) = readMsgpackBin(from: data, at: cursor) else { return nil }
        guard imageBytes.count <= Self.maxInboundImageSize else {
            log(.warn, "Inbound image too large: \(imageBytes.count)B (max \(Self.maxInboundImageSize))")
            return nil
        }

        let filename = "image.\(imageType.isEmpty ? "jpg" : imageType)"
        guard let path = saveAttachmentData(imageBytes, messageID: messageID, filename: filename) else { return nil }
        return MessageImage(type: imageType, size: imageBytes.count, storagePath: path)
    }

    /// Parses a FIELD_FILE_ATTACHMENTS msgpack value: [[filename_str, file_bytes], ...]
    private func parseFileAttachmentsField(_ data: Data, messageID: String) -> [MessageAttachment]? {
        var cursor = data.startIndex
        guard cursor < data.endIndex else { return nil }
        let tag = data[cursor]
        cursor += 1

        let arrayCount: Int
        if tag >= 0x90 && tag <= 0x9F {
            arrayCount = Int(tag & 0x0F)
        } else if tag == 0xDC, cursor + 2 <= data.endIndex {
            arrayCount = Int(data[cursor]) << 8 | Int(data[cursor + 1])
            cursor += 2
        } else { return nil }

        var attachments: [MessageAttachment] = []
        for _ in 0..<arrayCount {
            guard cursor < data.endIndex else { break }
            let innerTag = data[cursor]
            cursor += 1

            let innerCount: Int
            if innerTag >= 0x90 && innerTag <= 0x9F {
                innerCount = Int(innerTag & 0x0F)
            } else if innerTag == 0xDC, cursor + 2 <= data.endIndex {
                innerCount = Int(data[cursor]) << 8 | Int(data[cursor + 1])
                cursor += 2
            } else { continue }
            guard innerCount >= 2 else { continue }

            guard let (filename, nextCursor1) = readMsgpackString(from: data, at: cursor) else { continue }
            cursor = nextCursor1
            guard let (fileBytes, nextCursor2) = readMsgpackBin(from: data, at: cursor) else { continue }
            cursor = nextCursor2
            // Skip extra elements
            for _ in 2..<innerCount {
                cursor = skipMsgpackValue(in: data, at: cursor) ?? cursor
            }

            guard fileBytes.count <= Self.maxInboundFileSize else {
                log(.warn, "Inbound file \(filename) too large: \(fileBytes.count)B")
                continue
            }

            let safeName = filename.isEmpty ? "attachment" : filename.replacingOccurrences(of: "/", with: "_")
            if let path = saveAttachmentData(fileBytes, messageID: messageID, filename: safeName) {
                attachments.append(MessageAttachment(name: safeName, size: fileBytes.count, storagePath: path))
            }
        }
        return attachments.isEmpty ? nil : attachments
    }

    // MARK: - Msgpack Encoding Helpers

    /// Encode a Swift string as msgpack str type
    private func msgpackStr(_ s: String) -> Data {
        let utf8 = Data(s.utf8)
        let count = utf8.count
        var out = Data()
        if count <= 31 {
            out.append(UInt8(0xA0 | count))
        } else if count <= 0xFF {
            out.append(0xD9)
            out.append(UInt8(count))
        } else if count <= 0xFFFF {
            out.append(0xDA)
            out.append(UInt8(count >> 8))
            out.append(UInt8(count & 0xFF))
        } else {
            out.append(0xDB)
            out.append(UInt8((count >> 24) & 0xFF))
            out.append(UInt8((count >> 16) & 0xFF))
            out.append(UInt8((count >> 8) & 0xFF))
            out.append(UInt8(count & 0xFF))
        }
        out.append(utf8)
        return out
    }

    /// Encode raw bytes as msgpack bin type
    private func msgpackBinField(_ d: Data) -> Data {
        var out = Data()
        let count = d.count
        if count <= 0xFF {
            out.append(0xC4)
            out.append(UInt8(count))
        } else if count <= 0xFFFF {
            out.append(0xC5)
            out.append(UInt8(count >> 8))
            out.append(UInt8(count & 0xFF))
        } else {
            out.append(0xC6)
            out.append(UInt8((count >> 24) & 0xFF))
            out.append(UInt8((count >> 16) & 0xFF))
            out.append(UInt8((count >> 8) & 0xFF))
            out.append(UInt8(count & 0xFF))
        }
        out.append(d)
        return out
    }

    /// Encode FIELD_IMAGE value: msgpack fixarray(2) of [str(type), bin(data)]
    func encodeImageField(type imageType: String, data imageData: Data) -> Data {
        var out = Data()
        out.append(0x92) // fixarray of 2
        out.append(msgpackStr(imageType))
        out.append(msgpackBinField(imageData))
        return out
    }

    /// Encode FIELD_FILE_ATTACHMENTS value: msgpack array of [str(name), bin(data)] pairs
    func encodeFileAttachmentsField(files: [(name: String, data: Data)]) -> Data {
        var out = Data()
        let count = files.count
        if count <= 15 {
            out.append(UInt8(0x90 | count))
        } else if count <= 0xFFFF {
            out.append(0xDC)
            out.append(UInt8(count >> 8))
            out.append(UInt8(count & 0xFF))
        } else {
            out.append(0xDD)
            out.append(UInt8((count >> 24) & 0xFF))
            out.append(UInt8((count >> 16) & 0xFF))
            out.append(UInt8((count >> 8) & 0xFF))
            out.append(UInt8(count & 0xFF))
        }
        for file in files {
            out.append(0x92) // fixarray of 2
            out.append(msgpackStr(file.name))
            out.append(msgpackBinField(file.data))
        }
        return out
    }

    // MARK: - Image Compression

    /// Compress a UIImage for LXMF transport: max 640px, JPEG 0.6 quality
    func compressImageForTransport(_ image: UIImage, maxDimension: CGFloat = 640, quality: CGFloat = 0.6) -> Data? {
        let size = image.size
        let scale: CGFloat
        if size.width > maxDimension || size.height > maxDimension {
            scale = maxDimension / max(size.width, size.height)
        } else {
            scale = 1.0
        }
        let newSize = CGSize(width: size.width * scale, height: size.height * scale)
        let renderer = UIGraphicsImageRenderer(size: newSize)
        let resized = renderer.image { _ in
            image.draw(in: CGRect(origin: .zero, size: newSize))
        }
        return resized.jpegData(compressionQuality: quality)
    }

    // MARK: - Msgpack Micro-Readers

    private func readMsgpackString(from data: Data, at offset: Int) -> (String, Int)? {
        guard offset < data.endIndex else { return nil }
        let tag = data[offset]
        var cursor = offset + 1
        let length: Int
        if tag >= 0xA0 && tag <= 0xBF {
            length = Int(tag & 0x1F)
        } else if tag == 0xD9, cursor < data.endIndex {
            length = Int(data[cursor]); cursor += 1
        } else if tag == 0xDA, cursor + 2 <= data.endIndex {
            length = Int(data[cursor]) << 8 | Int(data[cursor + 1]); cursor += 2
        } else {
            // Also accept bin types — Python sometimes serializes strings as bin
            if tag == 0xC4, cursor < data.endIndex {
                length = Int(data[cursor]); cursor += 1
            } else if tag == 0xC5, cursor + 2 <= data.endIndex {
                length = Int(data[cursor]) << 8 | Int(data[cursor + 1]); cursor += 2
            } else { return nil }
        }
        guard cursor + length <= data.endIndex else { return nil }
        let str = String(data: data[cursor..<cursor + length], encoding: .utf8) ?? ""
        return (str, cursor + length)
    }

    private func readMsgpackBin(from data: Data, at offset: Int) -> (Data, Int)? {
        guard offset < data.endIndex else { return nil }
        let tag = data[offset]
        var cursor = offset + 1
        let length: Int
        if tag == 0xC4, cursor < data.endIndex {
            length = Int(data[cursor]); cursor += 1
        } else if tag == 0xC5, cursor + 2 <= data.endIndex {
            length = Int(data[cursor]) << 8 | Int(data[cursor + 1]); cursor += 2
        } else if tag == 0xC6, cursor + 4 <= data.endIndex {
            length = Int(data[cursor]) << 24 | Int(data[cursor + 1]) << 16 | Int(data[cursor + 2]) << 8 | Int(data[cursor + 3])
            cursor += 4
        } else if tag >= 0xA0 && tag <= 0xBF {
            // Accept str types too — Python msgpack may encode bytes as str in some versions
            length = Int(tag & 0x1F)
        } else if tag == 0xD9, cursor < data.endIndex {
            length = Int(data[cursor]); cursor += 1
        } else if tag == 0xDA, cursor + 2 <= data.endIndex {
            length = Int(data[cursor]) << 8 | Int(data[cursor + 1]); cursor += 2
        } else { return nil }
        guard cursor + length <= data.endIndex else { return nil }
        return (Data(data[cursor..<cursor + length]), cursor + length)
    }

    private func skipMsgpackValue(in data: Data, at offset: Int) -> Int? {
        guard offset < data.endIndex else { return nil }
        let tag = data[offset]
        var cursor = offset + 1
        switch tag {
        case 0xC0, 0xC2, 0xC3, 0x00...0x7F, 0xE0...0xFF: return cursor
        case 0xCC, 0xD0: return cursor + 1
        case 0xCD, 0xD1: return cursor + 2
        case 0xCA, 0xCE, 0xD2: return cursor + 4
        case 0xCB, 0xCF, 0xD3: return cursor + 8
        case 0xA0...0xBF: return cursor + Int(tag & 0x1F)
        case 0xD9:
            guard cursor < data.endIndex else { return nil }
            return cursor + 1 + Int(data[cursor])
        case 0xDA:
            guard cursor + 2 <= data.endIndex else { return nil }
            return cursor + 2 + (Int(data[cursor]) << 8 | Int(data[cursor + 1]))
        case 0xC4:
            guard cursor < data.endIndex else { return nil }
            return cursor + 1 + Int(data[cursor])
        case 0xC5:
            guard cursor + 2 <= data.endIndex else { return nil }
            return cursor + 2 + (Int(data[cursor]) << 8 | Int(data[cursor + 1]))
        case 0xC6:
            guard cursor + 4 <= data.endIndex else { return nil }
            let len = Int(data[cursor]) << 24 | Int(data[cursor + 1]) << 16 | Int(data[cursor + 2]) << 8 | Int(data[cursor + 3])
            return cursor + 4 + len
        case 0x90...0x9F:
            let count = Int(tag & 0x0F)
            for _ in 0..<count { guard let next = skipMsgpackValue(in: data, at: cursor) else { return nil }; cursor = next }
            return cursor
        case 0xDC:
            guard cursor + 2 <= data.endIndex else { return nil }
            let count = Int(data[cursor]) << 8 | Int(data[cursor + 1]); cursor += 2
            for _ in 0..<count { guard let next = skipMsgpackValue(in: data, at: cursor) else { return nil }; cursor = next }
            return cursor
        case 0x80...0x8F:
            let count = Int(tag & 0x0F)
            for _ in 0..<count { guard let next = skipMsgpackValue(in: data, at: cursor) else { return nil }; cursor = next; guard let next2 = skipMsgpackValue(in: data, at: cursor) else { return nil }; cursor = next2 }
            return cursor
        default: return nil
        }
    }

    /// Marks an outbound message as delivered (from proof receipt).
    func markOutboundMessageDelivered(id: UUID) {
        if updateOutboundMessageStatus(id: id, status: .delivered) { return }
        pendingDeliveredOutboundMessageIDs.insert(id)
        // Clean up the transient ID mapping for this message (whether delivery
        // was confirmed via SINGLE proof or propagation node cross-reference).
        if let key = outboundPropagatedTransientIDs.first(where: { $0.value == id })?.key {
            outboundPropagatedTransientIDs.removeValue(forKey: key)
            persistOutboundPropagatedTransientIDs()
        }
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

    // MARK: - Logging

    enum LogLevel: String { case debug = "🔍", info = "ℹ", warn = "⚠️", error = "🔴" }

    private func log(_ level: LogLevel, _ msg: String) {
        let entry = "\(level.rawValue) \(msg)"
        // Always show warn/error/info; suppress debug unless verbose mode added later
        if level != .debug {
            activityLog.insert(LogEntry(message: entry), at: 0)
        }
        // Always print to console for Xcode debugger
        print("[Inertia] \(entry)")
        // Also log to os_log for simulator log capture
        os_log("%{public}@", log: inertiaLog, type: .default, "[Inertia] \(entry)")
        if activityLog.count > 500 { activityLog = Array(activityLog.prefix(500)) }
    }

    private func appendLog(_ msg: String) {
        log(.info, msg)
    }

    // MARK: - Persistence

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

    private static let retryQueueDefaultsKey = "outboundRetryQueue"

    private func saveRetryQueue() {
        if retryQueue.isEmpty {
            UserDefaults.standard.removeObject(forKey: Self.retryQueueDefaultsKey)
            return
        }
        if let data = try? JSONEncoder().encode(Array(retryQueue.values)) {
            UserDefaults.standard.set(data, forKey: Self.retryQueueDefaultsKey)
        }
    }

    private static func loadRetryQueue() -> [UUID: OutboundRetryJob] {
        guard let data = UserDefaults.standard.data(forKey: retryQueueDefaultsKey),
              let jobs = try? JSONDecoder().decode([OutboundRetryJob].self, from: data)
        else { return [:] }
        return Dictionary(uniqueKeysWithValues: jobs.map { ($0.id, $0) })
    }

    func enqueueRetry(job: OutboundRetryJob) {
        retryQueue[job.id] = job
        saveRetryQueue()
        log(.info, "RETRY enqueued \(job.id.uuidString.prefix(8))… to \(job.destinationHash.hexString.prefix(8))… (attempt \(job.attempts))")
    }

    func dequeueRetry(id: UUID) {
        retryQueue.removeValue(forKey: id)
        saveRetryQueue()
    }

    func processRetryQueue() async {
        let now = Date()
        let ready = retryQueue.values.filter { $0.nextAttemptAt <= now && !$0.isExpired }
        for job in ready {
            var mutableJob = job
            mutableJob.recordAttempt()
            retryQueue[job.id] = mutableJob

            do {
                try await send(
                    to: job.destinationHash,
                    content: job.content,
                    fields: job.intFields,
                    outboundMessageID: job.id
                )
                dequeueRetry(id: job.id)
                log(.info, "RETRY delivered \(job.id.uuidString.prefix(8))… after \(mutableJob.attempts) attempts")
            } catch {
                if mutableJob.isExpired {
                    dequeueRetry(id: job.id)
                    _ = updateOutboundMessageStatus(id: job.id, status: .failed)
                    log(.warn, "RETRY expired \(job.id.uuidString.prefix(8))… after \(mutableJob.attempts) attempts")
                } else {
                    saveRetryQueue()
                    log(.info, "RETRY attempt \(mutableJob.attempts) failed for \(job.id.uuidString.prefix(8))…: \(error.localizedDescription)")
                }
            }
        }

        let expired = retryQueue.values.filter(\.isExpired)
        for job in expired {
            dequeueRetry(id: job.id)
            _ = updateOutboundMessageStatus(id: job.id, status: .failed)
        }
    }

    func startRetryTimer() {
        retryTimerTask?.cancel()
        retryTimerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                guard !Task.isCancelled else { break }
                await self?.processRetryQueue()
            }
        }
    }

    func stopRetryTimer() {
        retryTimerTask?.cancel()
        retryTimerTask = nil
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

    // MARK: - LINKIDENTIFY (0xFB) handler

    private func handleLinkIdentifyPacket(linkID: Data, payload: Data) {
        // LINKIDENTIFY payload: public_key(64) + signature(64)
        guard payload.count >= 128 else {
            log(.debug, "RX LINKIDENTIFY: payload too short (\(payload.count)B) link=\(linkID.hexString.prefix(8))…")
            return
        }

        let publicKey = Data(payload.prefix(64))
        let signature = Data(payload[payload.startIndex + 64 ..< payload.startIndex + 128])

        // Verify: signature covers link_id + public_key
        var signedData = linkID
        signedData.append(publicKey)
        let identityHash = Hashing.truncatedHash(publicKey, length: 16)

        // Try to verify the signature using Ed25519.
        let ed25519PubBytes = Data(publicKey[publicKey.startIndex + 32 ..< publicKey.startIndex + 64])
        if let ed25519Key = try? Curve25519.Signing.PublicKey(rawRepresentation: ed25519PubBytes) {
            guard ed25519Key.isValidSignature(signature, for: signedData) else {
                log(.warn, "RX LINKIDENTIFY: invalid signature link=\(linkID.hexString.prefix(8))… identity=\(identityHash.hexString.prefix(8))…")
                return
            }
        }

        propagationHostLinkIdentities[linkID] = identityHash
        log(.info, "RX LINKIDENTIFY: authenticated identity=\(identityHash.hexString.prefix(8))… on link=\(linkID.hexString.prefix(8))…")
    }

    // MARK: - Propagation Node Hosting

    /// Message store directory URL.
    private var propagationMessageStorePath: URL {
        Self.appSupportDir.appendingPathComponent("propagation/messagestore", isDirectory: true)
    }

    /// In-memory index of stored propagation messages.
    /// Key: 32-byte transient ID, Value: entry tuple.
    @ObservationIgnored private var propagationEntries: [Data: PropagationEntry] = [:]

    struct PropagationEntry {
        let destinationHash: Data // 16-byte LXMF delivery destination of the recipient
        let filePath: URL
        let receivedAt: Date
        let messageSize: Int
        var stampValue: Int
    }

    /// Enables propagation node: creates storage directory, indexes existing messages,
    /// registers the propagation destination, and announces.
    func enablePropagationNode() async {
        guard identity != nil else { return }

        // Create storage directory
        let storePath = propagationMessageStorePath
        try? FileManager.default.createDirectory(at: storePath, withIntermediateDirectories: true)

        // Index existing messages from disk
        indexPropagationMessageStore()

        // Announce as propagation node
        announcePropagationNode()

        log(.info, "Propagation node enabled: \(propagationEntries.count) stored messages, \(propagationStorageUsedBytes) bytes")
    }

    /// Disables the propagation node: clears link tracking state.
    func disablePropagationNode() {
        propagationHostLinkIDs.removeAll()
        propagationHostLinkStates.removeAll()
        propagationHostLinkIdentities.removeAll()
        log(.info, "Propagation node disabled")
    }

    /// Indexes the propagation message store from disk.
    /// Filename format: `<transientID_hex>_<timestamp>_<stampValue>`
    private func indexPropagationMessageStore() {
        let storePath = propagationMessageStorePath
        propagationEntries.removeAll()
        var totalSize = 0

        guard let files = try? FileManager.default.contentsOfDirectory(
            at: storePath, includingPropertiesForKeys: [.fileSizeKey]
        ) else { return }

        let fm = FileManager.default
        for fileURL in files {
            let filename = fileURL.lastPathComponent
            let components = filename.split(separator: "_")
            guard components.count >= 3 else { continue }

            let hexStr = String(components[0])
            guard hexStr.count == 64, let transientID = Data(hexString: hexStr) else { continue }
            guard let timestamp = Double(components[1]), timestamp > 0 else { continue }
            let stampValue = Int(components[2]) ?? 0

            // Read first 16 bytes of file to get destination hash
            guard let fileHandle = try? FileHandle(forReadingFrom: fileURL) else { continue }
            defer { try? fileHandle.close() }
            guard let destData = try? fileHandle.read(upToCount: 16), destData.count == 16 else { continue }

            let attrs = try? fm.attributesOfItem(atPath: fileURL.path)
            let size = (attrs?[.size] as? Int) ?? 0

            propagationEntries[transientID] = PropagationEntry(
                destinationHash: destData,
                filePath: fileURL,
                receivedAt: Date(timeIntervalSince1970: timestamp),
                messageSize: size,
                stampValue: stampValue
            )
            totalSize += size
        }

        propagationStorageUsedBytes = totalSize
    }

    /// Stores an LXMF message blob for propagation.
    /// Returns the transient ID if stored successfully, nil if duplicate or over limit.
    @discardableResult
    func storePropagationMessage(_ lxmfData: Data) -> Data? {
        let transientID = Hashing.sha256(lxmfData)
        guard propagationEntries[transientID] == nil else { return nil }

        // Check storage limit
        let limitBytes = propagationStorageLimitMB * 1_000_000
        if propagationStorageUsedBytes + lxmfData.count > limitBytes {
            purgePropagationExpiredMessages()
            if propagationStorageUsedBytes + lxmfData.count > limitBytes {
                purgeOldestPropagationMessages(targetFreeBytes: lxmfData.count)
            }
            if propagationStorageUsedBytes + lxmfData.count > limitBytes {
                log(.warn, "Propagation store full, rejecting message (\(lxmfData.count)B)")
                return nil
            }
        }

        // Extract destination hash (first 16 bytes of LXMF packed data)
        guard lxmfData.count >= 16 else { return nil }
        let destHash = Data(lxmfData.prefix(16))

        let now = Date()
        let stampValue = 0
        let filename = "\(transientID.hexString)_\(Int(now.timeIntervalSince1970))_\(stampValue)"
        let filePath = propagationMessageStorePath.appendingPathComponent(filename)

        do {
            try lxmfData.write(to: filePath)
        } catch {
            log(.error, "Failed to store propagation message: \(error)")
            return nil
        }

        propagationEntries[transientID] = PropagationEntry(
            destinationHash: destHash,
            filePath: filePath,
            receivedAt: now,
            messageSize: lxmfData.count,
            stampValue: stampValue
        )
        propagationStorageUsedBytes += lxmfData.count

        log(.debug, "Stored propagation message \(transientID.hexString.prefix(8))… for \(destHash.hexString.prefix(8))… (\(lxmfData.count)B)")
        return transientID
    }

    /// Removes expired messages (older than 30 days).
    private func purgePropagationExpiredMessages() {
        let expiry = Date().addingTimeInterval(-30 * 24 * 3600) // 30 days
        let fm = FileManager.default
        var removed = 0
        for (tid, entry) in propagationEntries {
            if entry.receivedAt < expiry {
                try? fm.removeItem(at: entry.filePath)
                propagationStorageUsedBytes -= entry.messageSize
                propagationEntries.removeValue(forKey: tid)
                removed += 1
            }
        }
        if removed > 0 {
            log(.info, "Purged \(removed) expired propagation messages")
        }
    }

    /// Removes oldest messages until at least `targetFreeBytes` are available.
    private func purgeOldestPropagationMessages(targetFreeBytes: Int) {
        let sorted = propagationEntries.sorted { $0.value.receivedAt < $1.value.receivedAt }
        let fm = FileManager.default
        var freed = 0
        for (tid, entry) in sorted {
            guard freed < targetFreeBytes else { break }
            try? fm.removeItem(at: entry.filePath)
            propagationStorageUsedBytes -= entry.messageSize
            freed += entry.messageSize
            propagationEntries.removeValue(forKey: tid)
        }
    }

    /// Announces this device as an LXMF propagation node.
    private func announcePropagationNode() {
        guard let identity else { return }
        let identityHash = identity.hash
        let propDestHash = LXMFAddressing.propagationDestinationHash(identityHash: identityHash)
        let nameHash = Destination.nameHash(appName: "lxmf", aspects: ["propagation"])

        let transferLimit = propagationStorageLimitMB * 1000 // KB
        let syncLimit = transferLimit
        let stampCost = propagationNodeStampCost

        // app_data: [False, timebase, True, transferLimit, syncLimit, [stampCost, 0, 0], {metadata}]
        var appDataArray: [Any] = [
            false,
            Int(Date().timeIntervalSince1970),
            true,
            transferLimit,
            syncLimit,
            [stampCost, 0, 0] as [Any],
        ]

        // Metadata
        var metadata: [Int: Any] = [:]
        if !propagationNodeName.isEmpty {
            metadata[0] = Data(propagationNodeName.utf8)
        }
        if !metadata.isEmpty {
            appDataArray.append(metadata)
        }

        guard let appData = try? MsgPack.encode(appDataArray) else {
            log(.warn, "Failed to encode propagation node announce app_data")
            return
        }

        // Build announce packet (same structure as sendAnnounce)
        var randomHash = Data(count: 10)
        _ = randomHash.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 5, $0.baseAddress!) }
        let ts = UInt64(Date().timeIntervalSince1970)
        randomHash[5] = UInt8((ts >> 32) & 0xff)
        randomHash[6] = UInt8((ts >> 24) & 0xff)
        randomHash[7] = UInt8((ts >> 16) & 0xff)
        randomHash[8] = UInt8((ts >>  8) & 0xff)
        randomHash[9] = UInt8( ts        & 0xff)

        var signedData = propDestHash
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
            destinationHash: propDestHash
        )
        let packet = Packet(header: header, payload: payload)
        let rawPacket = packet.serialize()

        let connectedInterfaces = interfaces
            .filter { serverStatuses[$0.key] == true }
            .map { ($0.key, $0.value) }
        let capturedAI = autoInterface

        Task {
            var sentCount = 0
            for (serverID, iface) in connectedInterfaces {
                do {
                    try await iface.send(rawPacket)
                    sentCount += 1
                    log(.debug, "Propagation announce TX via server \(serverID.uuidString.prefix(8))…")
                } catch {
                    log(.warn, "Propagation announce TX failed via \(serverID.uuidString.prefix(8))…: \(error)")
                }
            }
            if let aiface = capturedAI, await aiface.isOnline {
                do {
                    try await aiface.send(rawPacket)
                    sentCount += 1
                    log(.debug, "Propagation announce TX via AutoInterface")
                } catch {
                    log(.warn, "Propagation announce TX failed via AutoInterface: \(error)")
                }
            }
            if sentCount > 0 {
                appendLog("Announced lxmf.propagation: \(propDestHash.hexString.prefix(8))… (\(sentCount) interface(s))")
            }
        }
    }

    /// Handles an incoming REQUEST (0x09) on a propagation host link.
    private func handlePropagationRequest(linkID: Data, payload: Data) {
        guard let _ = propagationHostLinkStates[linkID] else {
            log(.warn, "Propagation request on unknown link \(linkID.hexString.prefix(8))…")
            return
        }

        // The interface prepends a 16-byte on-wire request_id for REQUEST context.
        guard payload.count > 16 else {
            log(.warn, "Propagation request: payload too short on link=\(linkID.hexString.prefix(8))…")
            return
        }
        let requestID = Data(payload.prefix(16))
        let requestPayload = Data(payload.dropFirst(16))

        // Parse the request: [timestamp, path_hash, data]
        guard let unpacked = MsgPack.decodeAny(requestPayload) as? [Any?],
              unpacked.count >= 3 else {
            log(.warn, "Propagation request: invalid msgpack on link=\(linkID.hexString.prefix(8))…")
            return
        }

        guard let pathHash = unpacked[1] as? Data else {
            log(.warn, "Propagation request: missing path_hash")
            return
        }

        let getPathHash = MsgPack.propagationGetPathHash()
        let offerPathHash = Hashing.truncatedHash(Data("/offer".utf8), length: 16)

        if pathHash == getPathHash {
            handlePropagationGetRequest(linkID: linkID, requestID: requestID, requestData: unpacked[2])
        } else if pathHash == offerPathHash {
            handlePropagationOfferRequest(linkID: linkID, requestID: requestID, requestData: unpacked[2])
        } else {
            log(.debug, "Propagation request: unknown path \(pathHash.hexString.prefix(8))… on link=\(linkID.hexString.prefix(8))…")
        }
    }

    /// Handles a /get request from a client on our propagation node.
    private func handlePropagationGetRequest(linkID: Data, requestID: Data, requestData: Any?) {
        guard let remoteIdentityHash = propagationHostLinkIdentities[linkID] else {
            log(.warn, "Propagation /get rejected: client not identified on link=\(linkID.hexString.prefix(8))…")
            sendPropagationErrorResponse(linkID: linkID, requestID: requestID, errorCode: 0xFD)
            return
        }

        // Derive the client's LXMF delivery destination hash from their identity hash.
        let clientDestHash = LXMFAddressing.deliveryDestinationHash(identityHash: remoteIdentityHash)

        guard let data = requestData as? [Any?], data.count >= 2 else {
            log(.warn, "Propagation /get: invalid data format")
            sendPropagationErrorResponse(linkID: linkID, requestID: requestID, errorCode: 0xFF)
            return
        }

        let wants = data[0] as? [Data]
        let haves = data[1] as? [Data]
        let limitKB: Double? = data.count >= 3 ? (data[2] as? Double) ?? (data[2] as? Int).map(Double.init) : nil

        // Process "haves" — remove messages the client already has (scoped to their destination)
        if let haves, !haves.isEmpty {
            let fm = FileManager.default
            for tid in haves {
                if let entry = propagationEntries[tid], entry.destinationHash == clientDestHash {
                    try? fm.removeItem(at: entry.filePath)
                    propagationStorageUsedBytes -= entry.messageSize
                    propagationEntries.removeValue(forKey: tid)
                }
            }
        }

        // If no wants specified, return list of available transient IDs for this client
        if wants == nil, haves == nil {
            var available: [(Data, Int)] = []
            for (tid, entry) in propagationEntries {
                if entry.destinationHash == clientDestHash {
                    available.append((tid, entry.messageSize))
                }
            }
            // Sort by size ascending
            available.sort { $0.1 < $1.1 }
            let transientIDs = available.map { $0.0 }

            log(.info, "Propagation /get: returning \(transientIDs.count) message IDs for \(clientDestHash.hexString.prefix(8))…")
            sendPropagationResponse(linkID: linkID, requestID: requestID, responseData: transientIDs)
            return
        }

        // Process "wants" — return requested messages
        if let wants, !wants.isEmpty {
            let limitBytes = (limitKB ?? Double(propagationStorageLimitMB * 1000)) * 1000
            var responseMessages: [Data] = []
            var cumulativeSize = 24 // overhead

            for tid in wants {
                guard let entry = propagationEntries[tid],
                      entry.destinationHash == clientDestHash else { continue }
                guard let lxmfData = try? Data(contentsOf: entry.filePath) else { continue }

                let nextSize = cumulativeSize + lxmfData.count + 16
                if Double(nextSize) > limitBytes { break }

                responseMessages.append(lxmfData)
                cumulativeSize = nextSize
            }

            log(.info, "Propagation /get: serving \(responseMessages.count) messages for \(clientDestHash.hexString.prefix(8))…")
            sendPropagationResponse(linkID: linkID, requestID: requestID, responseData: responseMessages)
            return
        }

        sendPropagationResponse(linkID: linkID, requestID: requestID, responseData: [Data]())
    }

    /// Handles a /offer request from a peering propagation node.
    private func handlePropagationOfferRequest(linkID: Data, requestID: Data, requestData: Any?) {
        guard let data = requestData as? [Any], data.count >= 2 else {
            sendPropagationErrorResponse(linkID: linkID, requestID: requestID, errorCode: 0xFF)
            return
        }

        guard let transientIDs = data[1] as? [Data] else {
            sendPropagationErrorResponse(linkID: linkID, requestID: requestID, errorCode: 0xFF)
            return
        }

        // Check which messages we want (don't already have)
        var wantedIDs: [Data] = []
        for tid in transientIDs {
            if propagationEntries[tid] == nil {
                wantedIDs.append(tid)
            }
        }

        if wantedIDs.isEmpty {
            sendPropagationResponse(linkID: linkID, requestID: requestID, responseData: false)
        } else if wantedIDs.count == transientIDs.count {
            sendPropagationResponse(linkID: linkID, requestID: requestID, responseData: true)
        } else {
            sendPropagationResponse(linkID: linkID, requestID: requestID, responseData: wantedIDs)
        }
    }

    /// Sends a propagation response on a hosted link.
    private func sendPropagationResponse(linkID: Data, requestID: Data, responseData: Any) {
        guard let linkState = propagationHostLinkStates[linkID] else { return }
        guard let responsePayload = try? MsgPack.encode([requestID, responseData] as [Any]) else { return }
        guard let iface = findInterfaceForLink(linkID) ?? findAnyOnlineInterface() else {
            log(.warn, "Propagation response: no interface available")
            return
        }

        Task {
            do {
                _ = try await sendLinkRequestPayload(
                    responsePayload,
                    context: 0x0A, // RESPONSE
                    linkState: linkState,
                    via: iface
                )
            } catch {
                log(.warn, "Failed to send propagation response: \(error)")
            }
        }
    }

    /// Sends an error response on a hosted propagation link.
    private func sendPropagationErrorResponse(linkID: Data, requestID: Data, errorCode: Int) {
        sendPropagationResponse(linkID: linkID, requestID: requestID, responseData: errorCode)
    }

    /// Finds any online interface for sending.
    private func findAnyOnlineInterface() -> (any MessageTransportInterface)? {
        for (serverId, iface) in interfaces {
            if serverStatuses[serverId] == true { return iface }
        }
        return nil
    }

    /// Finds the interface associated with a particular link (best-effort).
    private func findInterfaceForLink(_ linkID: Data) -> (any MessageTransportInterface)? {
        // If we know which server received the original LINKREQUEST, use that.
        // For now, use any online interface as fallback.
        return nil
    }
}

// MARK: - Notification Delegate Proxy

/// Separate NSObject subclass so AppModel doesn't need to inherit NSObject.
/// UNUserNotificationCenterDelegate callbacks are always called on the main thread.
private final class NotificationDelegateProxy: NSObject, UNUserNotificationCenterDelegate {

    /// Mirrors AppModel.activeConversationHash. Written on main actor; read on main thread.
    nonisolated(unsafe) var activeConversationHash: Data?
    /// `true` while the app's scene is `.active`. Written on main actor; read on main thread.
    nonisolated(unsafe) var isAppActive: Bool = false
    /// Written on main actor; read on main thread.
    nonisolated(unsafe) weak var model: AppModel?

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // Suppress all banners when the app is in the foreground — the message
        // is already visible in the conversation list or thread view.
        guard !isAppActive else {
            completionHandler([])
            return
        }
        completionHandler([.banner, .sound, .badge])
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let sourceHashStr = response.notification.request.content.userInfo["sourceHash"] as? String
        let pendingModel = model
        if let str = sourceHashStr, let hash = Data(hexString: str) {
            MainActor.assumeIsolated { pendingModel?.pendingOpenConversation = hash }
        }
        completionHandler()
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
