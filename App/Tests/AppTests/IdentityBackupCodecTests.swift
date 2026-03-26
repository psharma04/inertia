import Testing
import Foundation
@testable import Inertia
import ReticulumCrypto

@Suite("Identity Backup Codec")
struct IdentityBackupCodecTests {

    @Test("Round-trip backup without password")
    func backupRoundTripUnprotected() throws {
        let identity = try Identity.generate()
        let backup = try IdentityBackupCodec.encode(identity: identity, password: nil)
        let restored = try IdentityBackupCodec.decode(backup, password: nil)
        #expect(restored.identity.hash == identity.hash)
        #expect(restored.privateKeyData == identity.privateKeyData)
    }

    @Test("Round-trip backup with password")
    func backupRoundTripProtected() throws {
        let identity = try Identity.generate()
        let backup = try IdentityBackupCodec.encode(identity: identity, password: "correct horse battery staple")
        let restored = try IdentityBackupCodec.decode(backup, password: "correct horse battery staple")
        #expect(restored.identity.hash == identity.hash)
    }

    @Test("Protected backup requires password")
    func protectedBackupRequiresPassword() throws {
        let identity = try Identity.generate()
        let backup = try IdentityBackupCodec.encode(identity: identity, password: "secret")
        do {
            _ = try IdentityBackupCodec.decode(backup, password: nil)
            #expect(Bool(false), "Decoding should fail without password")
        } catch let error as IdentityBackupCodecError {
            #expect(error == .passwordRequired)
        }
    }

    @Test("Protected backup rejects wrong password")
    func protectedBackupRejectsWrongPassword() throws {
        let identity = try Identity.generate()
        let backup = try IdentityBackupCodec.encode(identity: identity, password: "secret")
        do {
            _ = try IdentityBackupCodec.decode(backup, password: "wrong")
            #expect(Bool(false), "Decoding should fail with wrong password")
        } catch let error as IdentityBackupCodecError {
            #expect(error == .decryptionFailed)
        }
    }
}
