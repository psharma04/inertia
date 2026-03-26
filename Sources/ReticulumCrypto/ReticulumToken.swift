import Foundation
import CryptoKit
import CommonCrypto
import Security

// Errors

public enum ReticulumTokenError: Error, Sendable {
    case invalidPublicKeyLength(Int)
    case encryptionFailed(Int32)
    case decryptionFailed(Int32)
    case invalidTokenLength(Int)
    case hmacMismatch
    case randomGenerationFailed(Int32)
}

// ReticulumToken

/// Reticulum's "Fernet-like" symmetric token, used to encrypt packet payloads
/// destined for SINGLE destinations.
///
/// ## Token wire format (byte layout)
///
/// ```
/// [ephemeral_x25519_pub :  32 bytes]
/// [iv                   :  16 bytes]
/// [ciphertext           : variable  (PKCS7-padded AES-256-CBC)]
/// [hmac                 :  32 bytes]
/// ```
///
/// ## Key derivation
///
/// 1. X25519 ECDH between an ephemeral key and the recipient's public key
///    → 32-byte raw shared secret.
/// 2. HKDF-SHA256 (RFC 5869):
///    - IKM    = shared secret
///    - salt   = `identity.hash` (16 bytes)
///    - info   = `b""` (empty)
///    - length = 64 bytes
///    → `signing_key(32) || encryption_key(32)`
/// 3. AES-256-CBC(PKCS7(plaintext), key=encryption_key, iv=random_16)
/// 4. HMAC-SHA256(signing_key, iv || ciphertext)
///
/// This matches `RNS.Cryptography.Token.encrypt()` in the Python reference.
public enum ReticulumToken {

    /// Minimum token overhead (32 + 16 + 32 = 80 bytes, before any ciphertext).
    public static let minimumOverhead = 80

    // Encryption

    /// Encrypts `plaintext` for a recipient identity.
    ///
    /// - Parameters:
    ///   - plaintext:              Raw bytes to encrypt.
    ///   - recipientX25519PublicKey: 32-byte X25519 public key of the recipient
    ///     (first 32 bytes of the 64-byte Reticulum public key).
    ///   - identityHash:           16-byte SHA-256 truncated hash of the
    ///     recipient's 64-byte public key — used as the HKDF salt.
    ///
    /// - Returns: Token bytes: `ephemeral_pub(32) + iv(16) + ciphertext + hmac(32)`.
    /// - Throws: `ReticulumTokenError` on any cryptographic failure.
    public static func encrypt(
        _ plaintext: Data,
        recipientX25519PublicKey: Data,
        identityHash: Data
    ) throws -> Data {
        guard recipientX25519PublicKey.count == 32 else {
            throw ReticulumTokenError.invalidPublicKeyLength(recipientX25519PublicKey.count)
        }

        // 1. Ephemeral X25519 key pair.
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPub = ephemeralKey.publicKey.rawRepresentation

        // 2. ECDH → raw shared secret.
        let recipientPub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: recipientX25519PublicKey)
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipientPub)

        // 3. HKDF-SHA256 (RFC 5869): IKM=sharedSecret, salt=identityHash, info="", length=64.
        //    CryptoKit's hkdfDerivedSymmetricKey uses RFC 5869 matching Python's custom HKDF.
        let derived = sharedSecret.hkdfDerivedSymmetricKey(
            using:        SHA256.self,
            salt:         identityHash,
            sharedInfo:   Data(),       // context = b"" → info = b""
            outputByteCount: 64
        )
        let derivedBytes  = derived.withUnsafeBytes { Data($0) }
        let signingKey    = Data(derivedBytes[0..<32])
        let encryptionKey = Data(derivedBytes[32..<64])

        // 4. AES-256-CBC encrypt (PKCS7 padding applied manually for exact byte control).
        let iv         = try randomBytes(count: 16)
        let padded     = pkcs7Pad(plaintext, blockSize: 16)
        let ciphertext = try aesCBCEncrypt(padded, key: encryptionKey, iv: iv)

        // 5. HMAC-SHA256(signing_key, iv || ciphertext).
        let signedPart = iv + ciphertext
        let mac        = Data(HMAC<SHA256>.authenticationCode(
            for: signedPart,
            using: SymmetricKey(data: signingKey)))

        // 6. Final token.
        return ephemeralPub + iv + ciphertext + mac
    }

    // Decryption

    /// Decrypts a token produced by ``encrypt(_:recipientX25519PublicKey:identityHash:)``.
    ///
    /// - Parameters:
    ///   - token:   Token bytes: ephemeral pubkey + IV + ciphertext + HMAC.
    ///   - recipientX25519PrivateKey:  32-byte X25519 private key of the recipient
    ///     (first 32 bytes of the 64-byte private key).
    ///   - identityHash:               16-byte identity hash used as HKDF salt.
    ///
    /// - Returns: Decrypted plaintext bytes.
    /// - Throws: `ReticulumTokenError` on cryptographic failure, including HMAC mismatch.
    public static func decrypt(
        _ token: Data,
        recipientX25519PrivateKey: Data,
        identityHash: Data
    ) throws -> Data {
        guard token.count > minimumOverhead else {
            throw ReticulumTokenError.invalidTokenLength(token.count)
        }

        let ephemeralPub = Data(token[0..<32])
        let iv           = Data(token[32..<48])
        let hmac         = Data(token[(token.count - 32)...])
        let ciphertext   = Data(token[48..<(token.count - 32)])

        // ECDH: our X25519 private × their ephemeral public → shared secret.
        let ourPrivKey   = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipientX25519PrivateKey)
        let theirPub     = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPub)
        let sharedSecret = try ourPrivKey.sharedSecretFromKeyAgreement(with: theirPub)

        // HKDF-SHA256: same derivation as encryption.
        let derived = sharedSecret.hkdfDerivedSymmetricKey(
            using:           SHA256.self,
            salt:            identityHash,
            sharedInfo:      Data(),
            outputByteCount: 64
        )
        let derivedBytes  = derived.withUnsafeBytes { Data($0) }
        let signingKey    = Data(derivedBytes[0..<32])
        let encryptionKey = Data(derivedBytes[32..<64])

        // Verify HMAC-SHA256(signing_key, iv || ciphertext) before decrypting.
        let signedPart  = iv + ciphertext
        let expectedMac = Data(HMAC<SHA256>.authenticationCode(
            for: signedPart,
            using: SymmetricKey(data: signingKey)))
        guard hmac == expectedMac else {
            throw ReticulumTokenError.hmacMismatch
        }

        // AES-256-CBC decrypt then strip PKCS7 padding.
        let padded    = try aesCBCDecrypt(ciphertext, key: encryptionKey, iv: iv)
        return try pkcs7Unpad(padded)
    }

    // Link data encrypt/decrypt (pre-shared key, no ECDH)

    /// Encrypts link payload using a pre-derived 64-byte key.
    ///
    /// Wire format: `iv(16) + ciphertext + hmac(32)`
    ///
    /// This matches Python's `Token(derived_key).encrypt(plaintext)` used for
    /// Reticulum link (DIRECT) data packets where ECDH has already been done
    /// during link establishment.
    public static func encryptLinkData(_ plaintext: Data, key: Data) throws -> Data {
        guard key.count == 64 else {
            throw ReticulumTokenError.invalidPublicKeyLength(key.count)
        }
        let signingKey    = Data(key[0..<32])
        let encryptionKey = Data(key[32..<64])

        let iv         = try randomBytes(count: 16)
        let padded     = pkcs7Pad(plaintext, blockSize: 16)
        let ciphertext = try aesCBCEncrypt(padded, key: encryptionKey, iv: iv)

        let signedPart = iv + ciphertext
        let mac        = Data(HMAC<SHA256>.authenticationCode(
            for: signedPart,
            using: SymmetricKey(data: signingKey)))

        return signedPart + mac
    }

    /// Decrypts a link data token produced by ``encryptLinkData(_:key:)``.
    ///
    /// Wire format: `iv(16) + ciphertext + hmac(32)`
    public static func decryptLinkData(_ token: Data, key: Data) throws -> Data {
        // Minimum: iv(16) + at least one block(16) + hmac(32) = 64 bytes
        guard token.count >= 64 else {
            throw ReticulumTokenError.invalidTokenLength(token.count)
        }
        guard key.count == 64 else {
            throw ReticulumTokenError.invalidPublicKeyLength(key.count)
        }

        let signingKey    = Data(key[0..<32])
        let encryptionKey = Data(key[32..<64])

        let iv         = Data(token[0..<16])
        let hmac       = Data(token[(token.count - 32)...])
        let ciphertext = Data(token[16..<(token.count - 32)])

        let signedPart  = iv + ciphertext
        let expectedMac = Data(HMAC<SHA256>.authenticationCode(
            for: signedPart,
            using: SymmetricKey(data: signingKey)))
        guard hmac == expectedMac else {
            throw ReticulumTokenError.hmacMismatch
        }

        let padded = try aesCBCDecrypt(ciphertext, key: encryptionKey, iv: iv)
        return try pkcs7Unpad(padded)
    }

    // Helpers

    /// AES-256-CBC encryption (no padding — caller must already PKCS7-pad).
    private static func aesCBCEncrypt(_ plaintext: Data, key: Data, iv: Data) throws -> Data {
        let bufferSize = plaintext.count + kCCBlockSizeAES128
        var ciphertext = Data(count: bufferSize)
        var numBytesEncrypted = 0

        let status: CCCryptorStatus = plaintext.withUnsafeBytes { pt in
            key.withUnsafeBytes { k in
                iv.withUnsafeBytes { ivBytes in
 // Capture the buffer size before entering the mutation closure to
 // avoid simultaneous access to `ciphertext`.
 let capturedSize = bufferSize
 return ciphertext.withUnsafeMutableBytes { ct in
     CCCrypt(
         CCOperation(kCCEncrypt),
         CCAlgorithm(kCCAlgorithmAES),
         CCOptions(0),           // no padding (already padded)
         k.baseAddress,  key.count,
         ivBytes.baseAddress,
         pt.baseAddress, plaintext.count,
         ct.baseAddress, capturedSize,
         &numBytesEncrypted
     )
 }
                }
            }
        }

        guard status == kCCSuccess else {
            throw ReticulumTokenError.encryptionFailed(status)
        }
        return Data(ciphertext.prefix(numBytesEncrypted))
    }

    /// AES-256-CBC decryption (no padding removal — caller calls `pkcs7Unpad`).
    private static func aesCBCDecrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        let bufferSize = ciphertext.count + kCCBlockSizeAES128
        var plaintext  = Data(count: bufferSize)
        var numBytesDecrypted = 0

        let status: CCCryptorStatus = ciphertext.withUnsafeBytes { ct in
            key.withUnsafeBytes { k in
                iv.withUnsafeBytes { ivBytes in
 let capturedSize = bufferSize
 return plaintext.withUnsafeMutableBytes { pt in
     CCCrypt(
         CCOperation(kCCDecrypt),
         CCAlgorithm(kCCAlgorithmAES),
         CCOptions(0),
         k.baseAddress,  key.count,
         ivBytes.baseAddress,
         ct.baseAddress, ciphertext.count,
         pt.baseAddress, capturedSize,
         &numBytesDecrypted
     )
 }
                }
            }
        }

        guard status == kCCSuccess else {
            throw ReticulumTokenError.decryptionFailed(status)
        }
        return Data(plaintext.prefix(numBytesDecrypted))
    }

    /// PKCS7-pads `data` to the next multiple of `blockSize`.
    private static func pkcs7Pad(_ data: Data, blockSize: Int) -> Data {
        let padLen = blockSize - (data.count % blockSize)
        var out    = data
        out.append(contentsOf: repeatElement(UInt8(padLen), count: padLen))
        return out
    }

    /// Strips PKCS7 padding from `data`.
    private static func pkcs7Unpad(_ data: Data) throws -> Data {
        guard !data.isEmpty,
              let padLen = data.last.map(Int.init),
              padLen >= 1, padLen <= 16,
              data.count >= padLen else {
            throw ReticulumTokenError.decryptionFailed(-2)
        }
        return Data(data.dropLast(padLen))
    }

    /// Returns `count` cryptographically random bytes.
    private static func randomBytes(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else {
            throw ReticulumTokenError.randomGenerationFailed(status)
        }
        return data
    }
}
