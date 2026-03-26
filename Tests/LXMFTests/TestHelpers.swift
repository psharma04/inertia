import Foundation

// Fixture Loading

/// Locates the ProtocolFixtures directory relative to this source file.
enum FixtureLoader {
    static var fixturesRoot: URL {
        URL(fileURLWithPath: #filePath)         // .../Tests/LXMFTests/TestHelpers.swift
            .deletingLastPathComponent()         // .../Tests/LXMFTests/
            .deletingLastPathComponent()         // .../Tests/
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

// Dictionary helpers

extension Dictionary where Key == String, Value == Any {
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

    func double(at keyPath: String) throws -> Double {
        guard let d = try value(at: keyPath) as? Double else {
            throw FixtureLoader.FixtureError.missingField(keyPath)
        }
        return d
    }

    func int(at keyPath: String) throws -> Int {
        guard let i = try value(at: keyPath) as? Int else {
            throw FixtureLoader.FixtureError.missingField(keyPath)
        }
        return i
    }
}

// Data hex helpers

extension Data {
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
