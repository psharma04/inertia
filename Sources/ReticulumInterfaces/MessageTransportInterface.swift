import Foundation

public protocol MessageTransportInterface: Actor {
    var name: String { get }
    var isOnline: Bool { get }

    func start() async throws
    func stop() async
    func send(_ data: Data) async throws

    /// Registers the packet receive callback.
    func setOnReceive(_ handler: @escaping @Sendable (Data) async -> Void)

    /// Returns the cached identity public key (64 bytes) for `destinationHash`, if known.
    func identityPublicKey(for destinationHash: Data) -> Data?

    /// Waits up to `timeout` seconds for a public key to appear in the cache.
    func waitForIdentityPublicKey(destinationHash: Data, timeout: TimeInterval) async -> Data?

    /// Pre-populates the identity cache with a known mapping.
    func seedIdentityCache(destinationHash: Data, publicKey: Data)

    /// Registers an active Reticulum link so incoming link DATA packets can be decrypted.
    func establishLink(linkId: Data, derivedKey: Data)

    /// Removes a previously established link (e.g. after LINKCLOSE).
    func removeLink(linkId: Data)

    /// Registers the Ed25519 signing function used for link packet proofs.
    func setLinkSigner(_ signer: @escaping @Sendable (Data) async -> Data?)

    /// Constructs and sends a SINGLE-type delivery proof for the given raw packet.
    func sendSingleProof(rawPacket: Data, isHeader2: Bool, signer: @escaping @Sendable (Data) async -> Data?)
}
