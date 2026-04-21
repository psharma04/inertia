import Foundation
@testable import ReticulumCrypto

// Fixture Loading

enum FixtureLoader {
    static var fixturesRoot: URL {
        URL(fileURLWithPath: #filePath)       // .../Tests/ReticulumCryptoTests/TestHelpers.swift
        .deletingLastPathComponent()       // .../Tests/ReticulumCryptoTests/
        .deletingLastPathComponent()       // .../Tests/
            .appendingPathComponent("ProtocolFixtures")
    }

    static func load(subdir: String, name: String) throws -> [String: Any] {
        let url = fixturesRoot
            .appendingPathComponent(subdir)
            .appendingPathComponent(name)
        let data = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: data)
        guard let dict = json as? [String: Any] else {
            throw FixtureError.invalidFormat(url.lastPathComponent)
        }
        return dict
    }

    enum FixtureError: Error {
        case invalidFormat(String)
        case missingField(String)
    }
}

// JSON helpers

extension Dictionary where Key == String, Value == Any {
    /// Drill into a nested key path of the form "expected.signature_test_vector.message_hex".
    func value(at keyPath: String) throws -> Any {
        let keys = keyPath.split(separator: ".").map(String.init)
        var current: Any = self
        for key in keys {
            guard let dict = current as? [String: Any], let next = dict[key] else {
                throw FixtureLoader.FixtureError.missingField(keyPath)
            }
            current = next
        }
        return current
    }

    func hexData(at keyPath: String) throws -> Data {
        let hex = try value(at: keyPath)
        guard let string = hex as? String, let data = Data(hexString: string) else {
            throw FixtureLoader.FixtureError.missingField(keyPath)
        }
        return data
    }

    func string(at keyPath: String) throws -> String {
        guard let s = try value(at: keyPath) as? String else {
            throw FixtureLoader.FixtureError.missingField(keyPath)
        }
        return s
    }
}

// Data hex decoding

extension Data {
    /// Initialise `Data` from a lowercase or uppercase hex string.
    /// Returns `nil` when the string has an odd length or invalid characters.
    init?(hexString: String) {
        let clean = hexString.replacingOccurrences(of: " ", with: "")
        guard clean.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(clean.count / 2)
        var index = clean.startIndex
        while index < clean.endIndex {
            let next = clean.index(index, offsetBy: 2)
            guard let byte = UInt8(clean[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

enum DeterministicIdentityKeyMaterial {
    static let identityAPrivateKey = Data((0x00...0x3F).map(UInt8.init))
    static let identityBPrivateKey = Data((0x40...0x7F).map(UInt8.init))

    static func privateKey(for fixture: [String: Any]) throws -> Data {
        let expectedPublicKey = try fixture.hexData(at: "expected.public_key_hex")
        let identityA = try Identity(privateKey: identityAPrivateKey)
        if identityA.publicKey == expectedPublicKey {
            return identityAPrivateKey
        }

        let identityB = try Identity(privateKey: identityBPrivateKey)
        if identityB.publicKey == expectedPublicKey {
            return identityBPrivateKey
        }

        throw FixtureLoader.FixtureError.missingField("deterministic_private_key_for_expected_public_key")
    }
}
