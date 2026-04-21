import Foundation

public struct Packet: Sendable {

    public var header: PacketHeader
    public var payload: Data

    public init(header: PacketHeader, payload: Data = Data()) {
        self.header = header
        self.payload = payload
    }

    public func serialize() -> Data {
        var out = header.serialize()
        out.append(payload)
        return out
    }

    public static func deserialize(from data: Data) throws -> Packet {
        let header = try PacketHeader.deserialize(from: data)
        let payload = data.count > PacketHeader.serializedLength
            ? Data(data.dropFirst(PacketHeader.serializedLength))
            : Data()
        return Packet(header: header, payload: payload)
    }
}
