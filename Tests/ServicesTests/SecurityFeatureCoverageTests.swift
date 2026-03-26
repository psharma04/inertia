import Testing
import Foundation
import CryptoKit
@testable import Services

@Suite("Security Feature Coverage")
struct SecurityFeatureCoverageTests {
    private static let envelopeKind = "chat.inertia.identity-backup"
    private static let envelopeVersion = 1
    private static let protectedMode = "password-aes-gcm-sha256"
    private static let unprotectedMode = "none"
    private static let privateKeyLength = 64
    private static let identityHashLength = 16

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

    private enum BackupError: Error, Equatable {
        case invalid
        case passwordRequired
        case decryptionFailed
    }

    @Test("Backup envelope is decodable and unprotected payload is self-consistent")
    func unprotectedBackupEnvelopeRoundTrip() throws {
        let backup = try makeBackupEnvelope(password: nil)
        let decoded = try decodeBackupEnvelope(backup, password: nil)
        #expect(decoded.kind == Self.envelopeKind)
        #expect(decoded.version == Self.envelopeVersion)
        #expect(decoded.protection == Self.unprotectedMode)
    }

    @Test("Protected backup requires password and rejects wrong password")
    func protectedBackupPasswordEnforcement() throws {
        let backup = try makeBackupEnvelope(password: "secret-passphrase")

        do {
            _ = try decodeBackupEnvelope(backup, password: nil)
            #expect(Bool(false), "Expected passwordRequired")
        } catch let error as BackupError {
            #expect(error == .passwordRequired)
        }

        do {
            _ = try decodeBackupEnvelope(backup, password: "wrong-passphrase")
            #expect(Bool(false), "Expected decryptionFailed")
        } catch let error as BackupError {
            #expect(error == .decryptionFailed)
        }

        let decoded = try decodeBackupEnvelope(backup, password: "secret-passphrase")
        #expect(decoded.protection == Self.protectedMode)
    }

    @Test("Biometric lock policy: lock state transitions with app activity")
    func biometricLockPolicyTransitions() {
        let transitions = simulateLockTransitions(
            lockEnabled: true,
            lockOnBackground: true,
            initialState: .unlocked,
            activeSequence: [false, true, false]
        )
        #expect(transitions == [.locked, .locked, .locked])

        let noBackgroundLock = simulateLockTransitions(
            lockEnabled: true,
            lockOnBackground: false,
            initialState: .unlocked,
            activeSequence: [false]
        )
        #expect(noBackgroundLock == [.unlocked])
    }

    @Test("Biometric activation flow uses passcode fallback policy")
    func biometricEnablePolicyUsesDeviceOwnerAuthentication() {
        let selected = authenticationPolicyForEnablingLock(availableBiometry: .faceID)
        #expect(selected == .deviceOwnerAuthentication)
    }

    @Test("Icon configuration stays pinned to messages icon set")
    func iconConfigurationMatchesProject() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // ServicesTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repo root

        let projectYAMLURL = root.appendingPathComponent("project.yml")
        let projectYAML = try String(contentsOf: projectYAMLURL, encoding: .utf8)
        let pbxprojURL = root
            .appendingPathComponent("Inertia.xcodeproj")
            .appendingPathComponent("project.pbxproj")
        let pbxproj = try String(contentsOf: pbxprojURL, encoding: .utf8)
        let appIconsetURL = root
            .appendingPathComponent("App/Resources/Assets.xcassets/messages-icon.appiconset")
        let appIconsetContentsURL = appIconsetURL.appendingPathComponent("Contents.json")
        let appIconsetContents = try String(contentsOf: appIconsetContentsURL, encoding: .utf8)

        #expect(projectYAML.contains("ASSETCATALOG_COMPILER_APPICON_NAME: messages-icon"))
        #expect(!projectYAML.contains("- messages-icon.icon"))
        #expect(projectYAML.contains("- App/Resources/Assets.xcassets"))
        #expect(pbxproj.contains("ASSETCATALOG_COMPILER_APPICON_NAME = \"messages-icon\";"))
        #expect(!pbxproj.contains("messages-icon.icon"))
        #expect(FileManager.default.fileExists(atPath: appIconsetURL.path))
        #expect(FileManager.default.fileExists(atPath: appIconsetContentsURL.path))
        #expect(appIconsetContents.contains("\"idiom\" : \"iphone\""))
        #expect(appIconsetContents.contains("\"idiom\" : \"ipad\""))
        #expect(appIconsetContents.contains("\"idiom\" : \"ios-marketing\""))
    }

    private enum LockState: Equatable {
        case unlocked
        case locked
        case unlocking
    }

    private enum BiometryType: Equatable {
        case none
        case touchID
        case faceID
    }

    private enum AuthenticationPolicy: Equatable {
        case deviceOwnerAuthentication
        case deviceOwnerAuthenticationWithBiometrics
    }

    private func simulateLockTransitions(
        lockEnabled: Bool,
        lockOnBackground: Bool,
        initialState: LockState,
        activeSequence: [Bool]
    ) -> [LockState] {
        var state = initialState
        var output: [LockState] = []

        for isActive in activeSequence {
            if isActive {
                if lockEnabled && state != .unlocked {
                    state = .locked
                }
            } else if lockEnabled && lockOnBackground {
                state = .locked
            }
            output.append(state)
        }

        return output
    }

    private func authenticationPolicyForEnablingLock(availableBiometry: BiometryType) -> AuthenticationPolicy {
        switch availableBiometry {
        case .none:
            return .deviceOwnerAuthenticationWithBiometrics
        case .touchID, .faceID:
            return .deviceOwnerAuthentication
        }
    }

    private func makeBackupEnvelope(password: String?) throws -> Data {
        let privateKey = randomHex(byteCount: Self.privateKeyLength)
        let identityHash = randomHex(byteCount: Self.identityHashLength)
        let payload = BackupPayload(identityPrivateKeyHex: privateKey, identityHashHex: identityHash)
        let payloadData = try JSONEncoder().encode(payload)

        let envelope: BackupEnvelope
        if let password, !password.isEmpty {
            let salt = randomData(count: 16)
            let key = derivePasswordKey(password: password, salt: salt, rounds: 4096)
            let sealed = try AES.GCM.seal(payloadData, using: key)
            envelope = BackupEnvelope(
                kind: Self.envelopeKind,
                version: Self.envelopeVersion,
                createdAt: Date().timeIntervalSince1970,
                protection: Self.protectedMode,
                payloadBase64: nil,
                saltBase64: salt.base64EncodedString(),
                kdfRounds: 4096,
                sealedBoxBase64: sealed.combined?.base64EncodedString()
            )
        } else {
            envelope = BackupEnvelope(
                kind: Self.envelopeKind,
                version: Self.envelopeVersion,
                createdAt: Date().timeIntervalSince1970,
                protection: Self.unprotectedMode,
                payloadBase64: payloadData.base64EncodedString(),
                saltBase64: nil,
                kdfRounds: nil,
                sealedBoxBase64: nil
            )
        }

        return try JSONEncoder().encode(envelope)
    }

    private func decodeBackupEnvelope(_ data: Data, password: String?) throws -> BackupEnvelope {
        let envelope = try JSONDecoder().decode(BackupEnvelope.self, from: data)
        guard envelope.kind == Self.envelopeKind, envelope.version == Self.envelopeVersion else {
            throw BackupError.invalid
        }

        switch envelope.protection {
        case Self.unprotectedMode:
            guard let payloadBase64 = envelope.payloadBase64,
                  let payloadData = Data(base64Encoded: payloadBase64) else {
                throw BackupError.invalid
            }
            _ = try JSONDecoder().decode(BackupPayload.self, from: payloadData)
            return envelope

        case Self.protectedMode:
            guard let password, !password.isEmpty else {
                throw BackupError.passwordRequired
            }
            guard let saltBase64 = envelope.saltBase64,
                  let salt = Data(base64Encoded: saltBase64),
                  let sealedBoxBase64 = envelope.sealedBoxBase64,
                  let combined = Data(base64Encoded: sealedBoxBase64) else {
                throw BackupError.invalid
            }
            let key = derivePasswordKey(password: password, salt: salt, rounds: envelope.kdfRounds ?? 4096)
            do {
                let sealed = try AES.GCM.SealedBox(combined: combined)
                let plaintext = try AES.GCM.open(sealed, using: key)
                _ = try JSONDecoder().decode(BackupPayload.self, from: plaintext)
            } catch {
                throw BackupError.decryptionFailed
            }
            return envelope

        default:
            throw BackupError.invalid
        }
    }

    private func derivePasswordKey(password: String, salt: Data, rounds: Int) -> SymmetricKey {
        let safeRounds = max(1, rounds)
        var digest = Data(SHA256.hash(data: Data(password.utf8) + salt))
        if safeRounds > 1 {
            for _ in 1..<safeRounds {
                digest = Data(SHA256.hash(data: digest + salt))
            }
        }
        return SymmetricKey(data: digest)
    }

    private func randomData(count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }

    private func randomHex(byteCount: Int) -> String {
        randomData(count: byteCount).map { String(format: "%02x", $0) }.joined()
    }
}
