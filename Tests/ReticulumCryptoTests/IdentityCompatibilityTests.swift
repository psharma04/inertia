import Testing
import Foundation
@testable import ReticulumCrypto


// Helpers

/// Loads and caches a single identity fixture dictionary.
private func loadIdentityFixture(name: String) throws -> [String: Any] {
    try FixtureLoader.load(subdir: "identities", name: "\(name).json")
}

// Keypair Loading

@Suite("Identity — Keypair Loading")
struct IdentityKeypairLoadingTests {

    @Test("identity_a: loads from private key without throwing")
    func loadIdentityAFromPrivateKey() throws {
        let fixture = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        // Must not throw; Identity must accept a 64-byte RNS private key
        _ = try Identity(privateKey: privateKey)
    }

    @Test("identity_b: loads from private key without throwing")
    func loadIdentityBFromPrivateKey() throws {
        let fixture = try loadIdentityFixture(name: "identity_b")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        _ = try Identity(privateKey: privateKey)
    }

    @Test("identity_a: publicKey matches Python reference (full 64 bytes)")
    func identityAPublicKeyMatchesReference() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let expected   = try fixture.hexData(at: "expected.public_key_hex")

        let identity = try Identity(privateKey: privateKey)
        #expect(identity.publicKey == expected,
                "publicKey mismatch — expected \(expected.hexString), got \(identity.publicKey.hexString)")
    }

    @Test("identity_b: publicKey matches Python reference (full 64 bytes)")
    func identityBPublicKeyMatchesReference() throws {
        let fixture    = try loadIdentityFixture(name: "identity_b")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let expected   = try fixture.hexData(at: "expected.public_key_hex")

        let identity = try Identity(privateKey: privateKey)
        #expect(identity.publicKey == expected)
    }

    @Test("identity_a: X25519 public key sub-field (bytes 0–31) matches reference")
    func identityAX25519PublicKeySubfield() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let expected   = try fixture.hexData(at: "expected.x25519_public_key_hex")

        let identity = try Identity(privateKey: privateKey)
        // Public key layout: [0:32] = X25519 pub, [32:64] = Ed25519 pub
        let x25519Pub = identity.publicKey.prefix(32)
        #expect(Data(x25519Pub) == expected)
    }

    @Test("identity_a: Ed25519 public key sub-field (bytes 32–63) matches reference")
    func identityAEd25519PublicKeySubfield() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let expected   = try fixture.hexData(at: "expected.ed25519_public_key_hex")

        let identity = try Identity(privateKey: privateKey)
        let ed25519Pub = identity.publicKey.dropFirst(32)
        #expect(Data(ed25519Pub) == expected)
    }

    @Test("publicKey has exactly 64 bytes")
    func publicKeyLength() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let identity = try Identity(privateKey: privateKey)
        #expect(identity.publicKey.count == 64)
    }
}

// Identity Hash

@Suite("Identity — Hash Derivation")
struct IdentityHashTests {

    @Test("identity_a: hash is SHA-256(publicKey)[0:16]")
    func identityAHashMatchesReference() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let expected   = try fixture.hexData(at: "expected.identity_hash_hex")

        let identity = try Identity(privateKey: privateKey)
        #expect(identity.hash == expected,
                "hash mismatch — expected \(expected.hexString), got \(identity.hash.hexString)")
    }

    @Test("identity_b: hash matches Python reference")
    func identityBHashMatchesReference() throws {
        let fixture    = try loadIdentityFixture(name: "identity_b")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let expected   = try fixture.hexData(at: "expected.identity_hash_hex")

        let identity = try Identity(privateKey: privateKey)
        #expect(identity.hash == expected)
    }

    @Test("hash is exactly 16 bytes (truncated SHA-256)")
    func hashLength() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let identity   = try Identity(privateKey: privateKey)
        #expect(identity.hash.count == 16)
    }

    @Test("full SHA-256 of publicKey matches reference (32 bytes)")
    func fullHashMatchesReference() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let expected   = try fixture.hexData(at: "expected.full_hash_hex")

        let identity  = try Identity(privateKey: privateKey)
        // full_hash is SHA-256(publicKey) — identity.hash == full_hash.prefix(16)
        #expect(identity.fullHash == expected,
                "fullHash mismatch — expected \(expected.hexString), got \(identity.fullHash.hexString)")
    }

    @Test("hash equals first 16 bytes of fullHash")
    func hashIsFirstSixteenBytesOfFullHash() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let identity   = try Identity(privateKey: privateKey)
        #expect(identity.hash == identity.fullHash.prefix(16))
    }

    @Test("two identities loaded from same private key produce the same hash")
    func sameSeedProducesSameHash() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let id1 = try Identity(privateKey: privateKey)
        let id2 = try Identity(privateKey: privateKey)
        #expect(id1.hash == id2.hash)
    }

    @Test("identity_a and identity_b have different hashes")
    func differentKeysProduceDifferentHashes() throws {
        let fa  = try loadIdentityFixture(name: "identity_a")
        let fb  = try loadIdentityFixture(name: "identity_b")
        let idA = try Identity(privateKey: try DeterministicIdentityKeyMaterial.privateKey(for: fa))
        let idB = try Identity(privateKey: try DeterministicIdentityKeyMaterial.privateKey(for: fb))
        #expect(idA.hash != idB.hash)
    }
}

// Signing

@Suite("Identity — Signing")
struct IdentitySigningTests {

    @Test("identity_a: sign() produces Python-reference signature bytes")
    func identityASignatureMatchesReference() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let message    = try fixture.hexData(at: "expected.signature_test_vector.message_hex")
        let expected   = try fixture.hexData(at: "expected.signature_test_vector.signature_hex")

        let identity  = try Identity(privateKey: privateKey)
        let signature = try identity.sign(message)

        #expect(signature == expected,
                "signature mismatch — Ed25519 output must be byte-identical to Python RNS reference")
    }

    @Test("identity_b: sign() produces Python-reference signature bytes")
    func identityBSignatureMatchesReference() throws {
        let fixture    = try loadIdentityFixture(name: "identity_b")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let message    = try fixture.hexData(at: "expected.signature_test_vector.message_hex")
        let expected   = try fixture.hexData(at: "expected.signature_test_vector.signature_hex")

        let identity  = try Identity(privateKey: privateKey)
        let signature = try identity.sign(message)
        #expect(signature == expected)
    }

    @Test("signature is exactly 64 bytes (Ed25519)")
    func signatureLength() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let message    = try fixture.hexData(at: "expected.signature_test_vector.message_hex")

        let identity  = try Identity(privateKey: privateKey)
        let signature = try identity.sign(message)
        #expect(signature.count == 64)
    }

    @Test("sign() is deterministic: same key and message always produce same signature")
    func signingIsDeterministic() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let message    = try fixture.hexData(at: "expected.signature_test_vector.message_hex")

        let identity = try Identity(privateKey: privateKey)
        let sig1 = try identity.sign(message)
        let sig2 = try identity.sign(message)
        #expect(sig1 == sig2, "Ed25519 signing must be deterministic (RFC 8032)")
    }

    @Test("signing an empty message does not throw")
    func signEmptyMessage() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let identity   = try Identity(privateKey: privateKey)
        let sig = try identity.sign(Data())
        #expect(sig.count == 64)
    }
}

// Verification

@Suite("Identity — Verification")
struct IdentityVerificationTests {

    @Test("verify() returns true for Python-generated signature over known message")
    func verifyPythonSignaturePassesWithCorrectMessage() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let publicKey  = try fixture.hexData(at: "expected.public_key_hex")
        let message    = try fixture.hexData(at: "expected.signature_test_vector.message_hex")
        let signature  = try fixture.hexData(at: "expected.signature_test_vector.signature_hex")

        // Load identity with public key only (verify path — no private key needed)
        let identity = try Identity(publicKey: publicKey)
        #expect(identity.verify(message, signature: signature),
                "verify() must accept signatures produced by Python RNS")
    }

    @Test("verify() returns true for identity_b Python signature")
    func verifyPythonSignatureIdentityB() throws {
        let fixture   = try loadIdentityFixture(name: "identity_b")
        let publicKey = try fixture.hexData(at: "expected.public_key_hex")
        let message   = try fixture.hexData(at: "expected.signature_test_vector.message_hex")
        let signature = try fixture.hexData(at: "expected.signature_test_vector.signature_hex")

        let identity = try Identity(publicKey: publicKey)
        #expect(identity.verify(message, signature: signature))
    }

    @Test("sign-then-verify round-trip passes")
    func signThenVerifyRoundTrip() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let identity   = try Identity(privateKey: privateKey)
        let message    = Data("round-trip test".utf8)

        let signature = try identity.sign(message)
        let verifier  = try Identity(publicKey: identity.publicKey)
        #expect(verifier.verify(message, signature: signature))
    }

    @Test("verify() returns false for signature over wrong message")
    func verifyReturnsFalseForWrongMessage() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let identity   = try Identity(privateKey: privateKey)
        let message    = Data("correct message".utf8)
        let wrong      = Data("wrong message".utf8)

        let signature = try identity.sign(message)
        let verifier  = try Identity(publicKey: identity.publicKey)
        #expect(!verifier.verify(wrong, signature: signature))
    }

    @Test("verify() returns false for signature from a different identity")
    func verifyReturnsFalseForWrongKey() throws {
        let fa  = try loadIdentityFixture(name: "identity_a")
        let fb  = try loadIdentityFixture(name: "identity_b")
        let idA = try Identity(privateKey: try DeterministicIdentityKeyMaterial.privateKey(for: fa))
        let idB = try Identity(publicKey:  try fb.hexData(at: "expected.public_key_hex"))

        let message   = Data("test".utf8)
        let signature = try idA.sign(message)

        // Signature made by A should not verify against B's public key
        #expect(!idB.verify(message, signature: signature))
    }

    @Test("verify() returns false for tampered signature (single bit flip)")
    func verifyReturnsFalseForTamperedSignature() throws {
        let fixture    = try loadIdentityFixture(name: "identity_a")
        let privateKey = try DeterministicIdentityKeyMaterial.privateKey(for: fixture)
        let identity   = try Identity(privateKey: privateKey)
        let message    = Data("tamper test".utf8)

        var signature = try identity.sign(message)
        // Flip the first byte
        signature[0] ^= 0xFF

        let verifier = try Identity(publicKey: identity.publicKey)
        #expect(!verifier.verify(message, signature: signature))
    }
}
