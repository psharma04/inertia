import Foundation

public struct PacketHeader: Sendable {

    public enum HeaderType: UInt8, Sendable {
        case header1 = 0
        case header2 = 1
    }

    public enum PropagationType: UInt8, Sendable {
        case broadcast = 0
        case transport = 1
    }

    /// Destination type occupies bits [3:2] of the flags byte.
    public enum DestinationType: UInt8, Sendable {
        case single = 0
        case group = 1
        case plain = 2
        case link = 3
    }

    public static let serializedLength = 19
    public static let destinationHashLength = 16

    public var headerType: HeaderType
    public var propagationType: PropagationType
    public var destinationType: DestinationType
    public var packetType: PacketType
    public var hops: UInt8
    public var destinationHash: Data
    public var context: UInt8
    /// Bit 5 of the flags byte. When `true` the announce payload contains a
    /// 32-byte ratchet public key between the random hash and the signature.
    public var contextFlag:     Bool

    public var flagsByte: UInt8 {
        (headerType.rawValue          << 6) |
        (contextFlag ? 0x20 : 0x00)        |
        (propagationType.rawValue     << 4) |
        (destinationType.rawValue     << 2) |
         packetType.rawValue
    }

    public init(
        packetType: PacketType,
        destinationType: DestinationType,
        destinationHash: Data,
        hops: UInt8 = 0,
        context: UInt8 = 0,
        headerType: HeaderType = .header1,
        propagationType: PropagationType = .broadcast,
        contextFlag: Bool = false
    ) {
        self.packetType = packetType
        self.destinationType = destinationType
        self.destinationHash = destinationHash
        self.hops = hops
        self.context = context
        self.headerType = headerType
        self.propagationType = propagationType
        self.contextFlag = contextFlag
    }

    public func serialize() -> Data {
        var writer = BinaryWriter()
        writer.writeUInt8(flagsByte)
        writer.writeUInt8(hops)
        writer.writeBytes(destinationHash)
        writer.writeUInt8(context)
        return writer.data
    }

    public static func deserialize(from data: Data) throws -> PacketHeader {
        guard data.count >= Self.serializedLength else {
            throw PacketHeaderError.tooShort(data.count)
        }

        var reader = BinaryReader(data: data)

        let flagsByte = try reader.readUInt8()
        let hops = try reader.readUInt8()
        let destHash = try reader.readBytes(Self.destinationHashLength)
        let context = try reader.readUInt8()

        guard let headerType = HeaderType(rawValue: (flagsByte >> 6) & 0x01) else {
            throw PacketHeaderError.unknownHeaderType((flagsByte >> 6) & 0x01)
        }
        let contextFlag = (flagsByte & 0x20) != 0
        guard let propagationType = PropagationType(rawValue: (flagsByte >> 4) & 0x01) else {
            throw PacketHeaderError.unknownPropagationType((flagsByte >> 4) & 0x01)
        }
        guard let destinationType = DestinationType(rawValue: (flagsByte >> 2) & 0x03) else {
            throw PacketHeaderError.unknownDestinationType((flagsByte >> 2) & 0x03)
        }
        guard let packetType = PacketType(rawValue: flagsByte & 0x03) else {
            throw PacketHeaderError.unknownPacketType(flagsByte & 0x03)
        }

        return PacketHeader(
            packetType: packetType,
            destinationType: destinationType,
            destinationHash: destHash,
            hops: hops,
            context: context,
            headerType: headerType,
            propagationType: propagationType,
            contextFlag: contextFlag
        )
    }
}

/// Errors thrown during `PacketHeader.deserialize(from:)`.
public enum PacketHeaderError: Error, Equatable {
    case tooShort(Int)
    case unknownHeaderType(UInt8)
    case unknownPropagationType(UInt8)
    case unknownDestinationType(UInt8)
    case unknownPacketType(UInt8)
}
