import Foundation
import ReticulumCrypto

// AnnouncePayload

/// The payload bytes of a Reticulum ANNOUNCE packet, parsed into named fields.
///
/// ## Wire layout (bytes after the 19-byte ``PacketHeader``)
///
/// ```
/// Bytes   0– 63 : identity public key  (64 B = X25519 pub 32 B ‖ Ed25519 pub 32 B)
/// Bytes  64– 73 : name hash            (10 B = SHA-256(destination_full_name)[0:10])
/// Bytes  74– 83 : random hash          (10 B, random nonce chosen by the sender)
/// Bytes  84–147 : Ed25519 signature    (64 B, see ``signedData(destinationHash:)``)
/// Bytes 148+    : app data             (variable, may be empty)
/// ```
///
/// ## Signed data
///
/// The signature covers:
/// ```
/// destination_hash (16 B) ‖ identity_public_key (64 B) ‖
/// name_hash (10 B) ‖ random_hash (10 B) [‖ app_data if non-empty]
/// ```
///
/// This matches `RNS.Identity.sign()` as called from `RNS.Packet` in the
/// Python reference implementation.
public struct AnnouncePayload: Sendable {

    // Constants

    /// Length of the identity public key field.
    public static let publicKeyLength    = 64
    /// Length of the name-hash field.
    public static let nameHashLength     = 10
    /// Length of the random-hash field.
    public static let randomHashLength   = 10
    /// Length of the Ed25519 signature field.
    public static let signatureLength    = 64
    /// Minimum payload size when app data is absent.
    public static let minimumLength      = publicKeyLength + nameHashLength + randomHashLength + signatureLength  // 148

    // Fields

    /// Full 64-byte Reticulum public key: `[X25519 pub (32) | Ed25519 pub (32)]`.
    public var identityPublicKey: Data

    /// 10-byte name hash: `SHA-256(destination_full_name)[0:10]`.
    public var nameHash: Data

    /// 10-byte random nonce chosen by the announcing node.
    public var randomHash: Data

    /// Optional 32-byte ratchet public key.  Present when the announce was
    /// created with ratchets enabled (bit 5 / context_flag set in the packet
    /// header).  `nil` when no ratchet key was included.
    public var ratchetKey: Data?

    /// 64-byte detached Ed25519 signature.
    public var signature: Data

    /// Application-defined data appended after the signature (may be empty).
    public var appData: Data

    // Initialiser

    public init(
        identityPublicKey: Data,
        nameHash:          Data,
        randomHash:        Data,
        signature:         Data,
        appData:           Data  = Data(),
        ratchetKey:        Data? = nil
    ) {
        self.identityPublicKey = identityPublicKey
        self.nameHash          = nameHash
        self.randomHash        = randomHash
        self.signature         = signature
        self.appData           = appData
        self.ratchetKey        = ratchetKey
    }

    // Parsing

    /// Parses an ``AnnouncePayload`` from the raw payload bytes of an announce
    /// ``Packet`` (i.e. everything after the 19-byte ``PacketHeader``).
    ///
    /// - Parameter hasRatchet: When `true` the payload contains a 32-byte
    ///   ratchet public key between the random hash and the signature.  Set
    ///   this to `packet.header.contextFlag` when the source packet is
    ///   available.  Defaults to `false` (no ratchet key).
    /// - Throws: ``AnnouncePayloadError/tooShort(_:)`` when the data is too
    ///   short for the requested layout.
    public static func parse(from data: Data, hasRatchet: Bool = false) throws -> AnnouncePayload {
        let ratchetLength  = hasRatchet ? 32 : 0
        let requiredLength = minimumLength + ratchetLength
        guard data.count >= requiredLength else {
            throw AnnouncePayloadError.tooShort(data.count)
        }

        let base = data.startIndex

        let identityPublicKey = Data(data[base ..< base + publicKeyLength])
        let nameHash          = Data(data[base + publicKeyLength ..< base + publicKeyLength + nameHashLength])
        let randomHashStart   = publicKeyLength + nameHashLength
        let randomHash        = Data(data[base + randomHashStart ..< base + randomHashStart + randomHashLength])

        var offset            = randomHashStart + randomHashLength
        var ratchetKey: Data? = nil
        if hasRatchet {
            ratchetKey = Data(data[base + offset ..< base + offset + 32])
            offset    += 32
        }

        let signature = Data(data[base + offset ..< base + offset + signatureLength])
        offset       += signatureLength

        let appData = (base + offset) < data.endIndex
 ? Data(data[(base + offset)...])
 : Data()
        return AnnouncePayload(
            identityPublicKey: identityPublicKey,
            nameHash:          nameHash,
            randomHash:        randomHash,
            signature:         signature,
            appData:           appData,
            ratchetKey:        ratchetKey
        )
    }

    // Signed data

    /// Constructs the byte sequence that the announcing node signed.
    ///
    /// Layout:
    /// ```
    /// destination_hash (16 B) ‖ identity_public_key (64 B) ‖
    /// name_hash (10 B) ‖ random_hash (10 B) [‖ ratchet_key (32 B)] [‖ app_data]
    /// ```
    ///
    /// The ratchet key is included only when ``ratchetKey`` is non-nil (matching
    /// Python's `signed_data = hash + pub_key + name_hash + random_hash + ratchet
    /// + app_data`).
    public func signedData(destinationHash: Data) -> Data {
        var data = destinationHash
        data.append(identityPublicKey)
        data.append(nameHash)
        data.append(randomHash)
        if let rk = ratchetKey { data.append(rk) }
        if !appData.isEmpty {
            data.append(appData)
        }
        return data
    }

    // Signature verification

    /// Verifies the Ed25519 ``signature`` against the reconstructed signed data.
    ///
    /// Uses the Ed25519 public key embedded in the last 32 bytes of
    /// ``identityPublicKey`` (the Reticulum wire format is
    /// `[X25519 pub 32 B | Ed25519 pub 32 B]`).
    ///
    /// - Returns: `true` if the signature is valid; `false` otherwise (including
    ///   when the public key or signature have unexpected lengths).
    public func verifySignature(destinationHash: Data) -> Bool {
        guard identityPublicKey.count == Self.publicKeyLength else { return false }
        let ed25519Pub = Data(identityPublicKey.suffix(32))
        let message    = signedData(destinationHash: destinationHash)
        return Signature.verify(message, signature: signature, publicKeyBytes: ed25519Pub)
    }
}

// Errors

/// Errors thrown by ``AnnouncePayload/parse(from:)``.
public enum AnnouncePayloadError: Error, Equatable {
    /// The payload contained fewer than 148 bytes.
    case tooShort(Int)
}
