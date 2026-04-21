import Foundation

public struct Destination: Sendable {

    public static let hashLength = 16
    public static let nameHashLength = 10

    /// 16-byte destination hash for packet-header addressing.
    public let hash: Data
    public let name: String
    public let nameHash: Data

    public init(appName: String, aspects: [String], identityHash: Data?) {
        self.nameHash = Self.nameHash(appName: appName, aspects: aspects)
        self.name = Self.fullName(appName: appName, aspects: aspects, identityHash: identityHash)
        self.hash = Self.hash(appName: appName, aspects: aspects, identityHash: identityHash)
    }

    public init(appName: String, aspects: [String], identity: Identity) {
        self.init(appName: appName, aspects: aspects, identityHash: identity.hash)
    }

    public static func hash(appName: String, aspects: [String], identityHash: Data?) -> Data {
        let nh = nameHash(appName: appName, aspects: aspects)
        let material: Data = identityHash.map { nh + $0 } ?? nh
        return Hashing.truncatedHash(material, length: hashLength)
    }

    public static func fullName(appName: String, aspects: [String], identityHash: Data?) -> String {
        var parts = [appName] + aspects
        if let ih = identityHash {
            parts.append(ih.map { String(format: "%02x", $0) }.joined())
        }
        return parts.joined(separator: ".")
    }

    public static func nameHash(appName: String, aspects: [String]) -> Data {
        let baseName = ([appName] + aspects).joined(separator: ".")
        return Hashing.truncatedHash(Data(baseName.utf8), length: nameHashLength)
    }
}
