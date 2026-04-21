import Foundation
import ReticulumCrypto

public struct NomadNode: Sendable {

    public let destinationHash: Data
    public let name: String

    public init(destinationHash: Data, appData: Data) throws {
        self.destinationHash = destinationHash
        self.name = String(data: appData, encoding: .utf8) ?? ""
    }

    public static func destinationHash(for identityHash: Data) -> Data {
        let nameHash10 = announceNameHash()
        return Hashing.truncatedHash(nameHash10 + identityHash, length: 16)
    }

    public static func announceNameHash() -> Data {
        Data(Hashing.sha256(Data("nomadnetwork.node".utf8)).prefix(10))
    }

    public static func buildAnnounceData(nodeName: String) -> Data {
        Data(nodeName.utf8)
    }

    public static func parseAnnounceName(from appData: Data) -> String {
        String(data: appData, encoding: .utf8) ?? ""
    }
}
