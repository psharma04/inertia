import Foundation

// ServerConfig

struct ServerConfig: Identifiable, Codable, Sendable {
    var id: UUID = UUID()
    var name: String
    var host: String
    var port: Int

    init(id: UUID = UUID(), name: String = "", host: String, port: Int) {
        self.id   = id
        self.name = name.isEmpty ? "\(host):\(String(port))" : name
        self.host = host
        self.port = port
    }

    var displayName: String { name.isEmpty ? "\(host):\(String(port))" : name }

    /// Validates the port is within the legal TCP range.
    var isValidPort: Bool { (1...65535).contains(port) }
}
