import Testing
import Foundation
import CryptoKit
@testable import ReticulumCrypto

@Suite("Reticulum Claims — Crypto & Addressing")
struct ReticulumCryptoClaimsTests {

    @Test("Identity keys are 512-bit keysets (64 bytes)")
    func identityKeysetWidth() throws {
        let identity = try Identity.generate()
        #expect(identity.publicKey.count == 64)
        #expect(Identity.publicKeyLength == 64)
        #expect(Identity.privateKeyLength == 64)
    }

    @Test("Global unique addressing via name hash + identity hash")
    func globalUniqueAddressing() throws {
        let idA = try Identity.generate()
        let idB = try Identity.generate()

        let hashA = Destination.hash(appName: "lxmf", aspects: ["delivery"], identityHash: idA.hash)
        let hashB = Destination.hash(appName: "lxmf", aspects: ["delivery"], identityHash: idB.hash)

        #expect(hashA.count == 16)
        #expect(hashB.count == 16)
        #expect(hashA != hashB)
    }

    @Test("Identity hash is 16-byte truncated SHA-256(publicKey)")
    func identityHashDerivation() throws {
        let identity = try Identity.generate()
        let full = Hashing.sha256(identity.publicKey)
        #expect(identity.hash.count == 16)
        #expect(identity.hash == Data(full.prefix(16)))
    }

    @Test("SHA-512 primitive is available")
    func sha512PrimitiveAvailable() {
        let digest = Hashing.sha512(Data("reticulum".utf8))
        #expect(digest.count == 64)
    }

    @Test("Token layout carries ephemeral pubkey, IV, ciphertext, HMAC")
    func tokenLayoutAndPrimitives() throws {
        let recipient = try Identity.generate()
        let x25519Pub = Data(recipient.publicKey.prefix(32))
        let payload = Data("capability-claims".utf8)

        let token = try ReticulumToken.encrypt(
            payload,
            recipientX25519PublicKey: x25519Pub,
            identityHash: recipient.hash
        )

        #expect(token.count >= 96)

        let ephemeralPub = Data(token.prefix(32))
        let iv = Data(token[32..<48])
        let hmac = Data(token.suffix(32))

        #expect(ephemeralPub.count == 32)
        #expect(iv.count == 16)
        #expect(hmac.count == 32)

        guard let privateKeyData = recipient.privateKeyData else {
            Issue.record("Recipient private key missing")
            return
        }
        let decrypted = try ReticulumToken.decrypt(
            token,
            recipientX25519PrivateKey: Data(privateKeyData.prefix(32)),
            identityHash: recipient.hash
        )
        #expect(decrypted == payload)
    }

    @Test("Reticulum tokens reject tampering via HMAC")
    func tokenTamperDetection() throws {
        let recipient = try Identity.generate()
        let token = try ReticulumToken.encrypt(
            Data("integrity".utf8),
            recipientX25519PublicKey: Data(recipient.publicKey.prefix(32)),
            identityHash: recipient.hash
        )

        var tampered = token
        tampered[tampered.startIndex + 40] ^= 0x01

        guard let privateKeyData = recipient.privateKeyData else {
            Issue.record("Recipient private key missing")
            return
        }

        #expect(throws: ReticulumTokenError.self) {
            _ = try ReticulumToken.decrypt(
                tampered,
                recipientX25519PrivateKey: Data(privateKeyData.prefix(32)),
                identityHash: recipient.hash
            )
        }
    }

    @Test("Direct link key derivation uses X25519 ECDH + HKDF(link_id)")
    func directKeyDerivationShape() throws {
        let requester = Curve25519.KeyAgreement.PrivateKey()
        let responder = Curve25519.KeyAgreement.PrivateKey()
        let linkID = Data((0..<16).map(UInt8.init))

        let shared1 = try requester.sharedSecretFromKeyAgreement(with: responder.publicKey)
        let shared2 = try responder.sharedSecretFromKeyAgreement(with: requester.publicKey)

        let k1 = shared1.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: linkID,
            sharedInfo: Data(),
            outputByteCount: 64
        ).withUnsafeBytes { Data($0) }

        let k2 = shared2.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: linkID,
            sharedInfo: Data(),
            outputByteCount: 64
        ).withUnsafeBytes { Data($0) }

        #expect(k1.count == 64)
        #expect(k1 == k2)
    }
}
