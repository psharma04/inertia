import Testing
import Foundation
import CryptoKit
@testable import ReticulumCrypto

/// Cross-platform crypto verification tests using Python-generated test vectors.
/// These vectors were generated with Python's cryptography library and RNS HKDF.
struct LinkCryptoInteropTests {

    private static let privAHex = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
    private static let pubAHex  = "f0b4fd8be480349293ab61f0505ebb5bafccdf8a4127de221e6ef3db20e03d29"
    private static let privBHex = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
    private static let pubBHex  = "80e1a53d3eee82b62b3048578cf38c980ddd1131243a1047fe48482942d6b648"
    private static let sharedSecretHex = "9bdde39c59e1f898e5ab7edd3c3b82c94fe3b9a636c8fdd02e62add9c0e2267f"
    private static let linkIDHex = "0102030405060708090a0b0c0d0e0f10"
    private static let derivedKeyHex = "598f50373ce184410e021781e1936ba031f85b80c07bcf2d11cedefa5f36542ba834ab6ecfbdd914d7b986fc9da54b259e6bbecb44b5eacb5bb3dd338f4af690"

    private static let ivHex = "11223344556677889900aabbccddeeff"
    private static let plaintextHex = "48656c6c6f204e6f6d61644e657421"
    private static let tokenBytesHex = "11223344556677889900aabbccddeeff4ea35c7aa471925ea10c35a1cc8064cad58122d77f83fa6be9946244c8b54ead44d94b4a3ce457571ce73e5a3395886e"

    @Test("X25519 public key derivation matches Python")
    func testX25519PublicKeyDerivation() throws {
        let privA = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(hexString: Self.privAHex)!)
        #expect(privA.publicKey.rawRepresentation == Data(hexString: Self.pubAHex)!)

        let privB = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(hexString: Self.privBHex)!)
        #expect(privB.publicKey.rawRepresentation == Data(hexString: Self.pubBHex)!)
    }

    @Test("X25519 shared secret matches Python")
    func testSharedSecret() throws {
        let privA = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(hexString: Self.privAHex)!)
        let pubB = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(hexString: Self.pubBHex)!)
        let shared = try privA.sharedSecretFromKeyAgreement(with: pubB)

        let sharedBytes = shared.withUnsafeBytes { Data($0) }
        #expect(sharedBytes == Data(hexString: Self.sharedSecretHex)!)
    }

    @Test("HKDF-SHA256 derived key matches Python RNS HKDF")
    func testHKDFDerivedKey() throws {
        let privA = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(hexString: Self.privAHex)!)
        let pubB = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(hexString: Self.pubBHex)!)
        let shared = try privA.sharedSecretFromKeyAgreement(with: pubB)
        let linkID = Data(hexString: Self.linkIDHex)!

        let derived = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: linkID,
            sharedInfo: Data(),
            outputByteCount: 64
        )
        let derivedBytes = derived.withUnsafeBytes { Data($0) }
        #expect(derivedBytes == Data(hexString: Self.derivedKeyHex)!)
    }

    @Test("encryptLinkData matches Python token format")
    func testEncryptLinkData() throws {
        let derivedKey = Data(hexString: Self.derivedKeyHex)!
        let plaintext = Data(hexString: Self.plaintextHex)!

        let encrypted = try ReticulumToken.encryptLinkData(plaintext, key: derivedKey)
        #expect(encrypted.count == 64) // iv(16) + ct(16) + hmac(32)

        let decrypted = try ReticulumToken.decryptLinkData(encrypted, key: derivedKey)
        #expect(decrypted == plaintext)
    }

    @Test("decryptLinkData can decrypt Python-generated token")
    func testDecryptPythonToken() throws {
        let derivedKey = Data(hexString: Self.derivedKeyHex)!
        let tokenBytes = Data(hexString: Self.tokenBytesHex)!
        let expectedPlaintext = Data(hexString: Self.plaintextHex)!

        let decrypted = try ReticulumToken.decryptLinkData(tokenBytes, key: derivedKey)
        #expect(decrypted == expectedPlaintext)
    }

    @Test("NomadNet path hash matches Python SHA256 truncation")
    func testPathHash() throws {
        let path = "/page/index.mu"
        let expectedHex = "fb40abf359b3f25fa0086107c5eee516"
        let hash = Hashing.truncatedHash(Data(path.utf8), length: 16)
        #expect(hash == Data(hexString: expectedHex)!)
    }

    @Test("NomadNet request payload matches Python msgpack")
    func testRequestPayload() throws {
        let expectedHex = "93cb41d954fc40000000c410fb40abf359b3f25fa0086107c5eee516c0"

        var out = Data()
        out.append(0x93) // fixarray(3)
        out.append(0xcb) // float64
        let ts: Double = 1700000000.0
        let bits = ts.bitPattern.bigEndian
        withUnsafeBytes(of: bits) { out.append(contentsOf: $0) }
        out.append(0xc4) // bin8
        let pathHash = Hashing.truncatedHash(Data("/page/index.mu".utf8), length: 16)
        out.append(UInt8(pathHash.count))
        out.append(contentsOf: pathHash)
        out.append(0xc0) // nil

        #expect(out == Data(hexString: expectedHex)!)
    }
}
