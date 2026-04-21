import Foundation

// AutoInterfaceConfig

struct AutoInterfaceConfig: Codable, Sendable, Equatable {
    var enabled:              Bool   = true
    var groupID:              String = ""
    var discoveryPort:        Int    = 29716
    var dataPort:             Int    = 42671
    var discoveryScope:       String = "link"
    var multicastAddressType: String = "temporary"
    /// Comma-separated interface names. If non-empty, only these are used.
    var allowedInterfaces:    String = ""
    /// Comma-separated interface names to skip.
    var ignoredInterfaces:    String = ""

    var allowedInterfaceList:  [String] { splitCSV(allowedInterfaces) }
    var ignoredInterfaceList:  [String] { splitCSV(ignoredInterfaces) }

    private func splitCSV(_ s: String) -> [String] {
        s.split(separator: ",")
         .map { $0.trimmingCharacters(in: .whitespaces) }
         .filter { !$0.isEmpty }
    }
}
