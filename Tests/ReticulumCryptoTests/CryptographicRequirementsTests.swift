import Testing
import Foundation
import CryptoKit
@testable import ReticulumCrypto

@Suite("Cryptographic Requirements")
struct CryptographicRequirementsTests {
    @Test("Identity is a 512-bit Curve25519 keyset")
    func identityKeysetLayout() throws {
        let identity = try Identity.generate()
        #expect(identity.publicKey.count == 64)

        let x25519Public = Data(identity.publicKey.prefix(32))
        let ed25519Public = Data(identity.publicKey.suffix(32))
        #expect(x25519Public.count == 32)
        #expect(ed25519Public.count == 32)

        guard let privateKey = identity.privateKeyData else {
            Issue.record("Generated identity has no private key data")
            return
        }
        #expect(privateKey.count == 64)
        #expect(Data(privateKey.prefix(32)).count == 32) // X25519 private
        #expect(Data(privateKey.suffix(32)).count == 32) // Ed25519 seed
    }

    @Test("Ed25519 signatures are 64 bytes and verify correctly")
    func ed25519SignVerify() throws {
        let identity = try Identity.generate()
        let message = Data("reticulum-signature-check".utf8)
        let signature = try identity.sign(message)

        #expect(signature.count == 64)

        let verifier = try Identity(publicKey: identity.publicKey)
        #expect(verifier.verify(message, signature: signature))
    }

    @Test("X25519 ECDH shared secret is symmetric and 32 bytes")
    func x25519ECDHProperties() throws {
        let initiator = Curve25519.KeyAgreement.PrivateKey()
        let responder = Curve25519.KeyAgreement.PrivateKey()

        let sharedA = try initiator.sharedSecretFromKeyAgreement(with: responder.publicKey)
            .withUnsafeBytes { Data($0) }
        let sharedB = try responder.sharedSecretFromKeyAgreement(with: initiator.publicKey)
            .withUnsafeBytes { Data($0) }

        #expect(sharedA.count == 32)
        #expect(sharedA == sharedB)
    }

    @Test("HKDF-SHA256 derives 64-byte key material")
    func hkdfDerivationProperties() throws {
        let initiator = Curve25519.KeyAgreement.PrivateKey()
        let responder = Curve25519.KeyAgreement.PrivateKey()
        let shared = try initiator.sharedSecretFromKeyAgreement(with: responder.publicKey)

        let derived = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(repeating: 0x42, count: 16),
            sharedInfo: Data(),
            outputByteCount: 64
        ).withUnsafeBytes { Data($0) }

        #expect(derived.count == 64)
    }

    @Test("Reticulum token is Fernet-like without version/timestamp metadata fields")
    func tokenWireFormatNoMetadataFields() throws {
        let recipient = try Identity.generate()
        let recipientX25519Public = Data(recipient.publicKey.prefix(32))

        // Empty plaintext forces a single PKCS7 block, making the fixed layout explicit.
        let token = try ReticulumToken.encrypt(
            Data(),
            recipientX25519PublicKey: recipientX25519Public,
            identityHash: recipient.hash
        )

        // Overhead is exactly ephemeral(32) + iv(16) + hmac(32).
        #expect(ReticulumToken.minimumOverhead == 80)
        #expect(token.count == 96) // +16-byte padded ciphertext block

        let ephemeralPublic = Data(token.prefix(32))
        let iv = Data(token[32..<48])
        let ciphertext = Data(token[48..<(token.count - 32)])
        let mac = Data(token.suffix(32))

        #expect(ephemeralPublic.count == 32)
        #expect(iv.count == 16)
        #expect(ciphertext.count == 16)
        #expect(mac.count == 32)
    }

    @Test("Token authentication detects tampering (HMAC-SHA256)")
    func tokenTamperDetection() throws {
        let recipient = try Identity.generate()
        let recipientX25519Public = Data(recipient.publicKey.prefix(32))
        let token = try ReticulumToken.encrypt(
            Data("integrity-check".utf8),
            recipientX25519PublicKey: recipientX25519Public,
            identityHash: recipient.hash
        )

        var tampered = token
        tampered[tampered.startIndex + 45] ^= 0x01

        guard let privateKey = recipient.privateKeyData else {
            Issue.record("Generated identity has no private key data")
            return
        }

        #expect(throws: ReticulumTokenError.self) {
            _ = try ReticulumToken.decrypt(
                tampered,
                recipientX25519PrivateKey: Data(privateKey.prefix(32)),
                identityHash: recipient.hash
            )
        }
    }

    @Test("Token IV is randomized across encryptions")
    func tokenIVRandomization() throws {
        let recipient = try Identity.generate()
        let recipientX25519Public = Data(recipient.publicKey.prefix(32))
        let message = Data("same-plaintext".utf8)

        let tokenA = try ReticulumToken.encrypt(
            message,
            recipientX25519PublicKey: recipientX25519Public,
            identityHash: recipient.hash
        )
        let tokenB = try ReticulumToken.encrypt(
            message,
            recipientX25519PublicKey: recipientX25519Public,
            identityHash: recipient.hash
        )

        let ivA = Data(tokenA[32..<48])
        let ivB = Data(tokenB[32..<48])
        #expect(ivA != ivB)
    }

    @Test("AES-256-CBC with PKCS7 produces block-aligned ciphertext")
    func aesCbcPkcs7Properties() throws {
        let recipient = try Identity.generate()
        let recipientX25519Public = Data(recipient.publicKey.prefix(32))

        let token = try ReticulumToken.encrypt(
            Data("cbc-padding-check".utf8),
            recipientX25519PublicKey: recipientX25519Public,
            identityHash: recipient.hash
        )
        let ciphertext = Data(token[48..<(token.count - 32)])
        #expect(ciphertext.count.isMultiple(of: 16))

        guard let privateKey = recipient.privateKeyData else {
            Issue.record("Generated identity has no private key data")
            return
        }

        let decrypted = try ReticulumToken.decrypt(
            token,
            recipientX25519PrivateKey: Data(privateKey.prefix(32)),
            identityHash: recipient.hash
        )
        #expect(decrypted == Data("cbc-padding-check".utf8))
    }

    @Test("SHA-256 and SHA-512 primitives are available with correct lengths")
    func hashPrimitiveLengths() {
        #expect(Hashing.sha256(Data("reticulum".utf8)).count == 32)
        #expect(Hashing.sha512(Data("reticulum".utf8)).count == 64)
    }
}
