import Foundation

// PacketHeader

/// Binary header of a Reticulum packet (HEADER_1, no IFAC).
///
/// ## Wire layout
///
/// ```
/// Byte  0      : flags byte
///                bit  6    = header_type      (0=HEADER_1, 1=HEADER_2)
///                bit  5    = context_flag     (0=no ratchet, 1=ratchet key present)
///                bit  4    = transport_type   (0=BROADCAST, 1=TRANSPORT)
///                bits [3:2] = destination_type (0=SINGLE, 1=GROUP, 2=PLAIN, 3=LINK)
///                bits [1:0] = packet_type      (0=DATA, 1=ANNOUNCE, 2=LINKREQUEST, 3=PROOF)
/// Byte  1      : hops
/// Bytes 2–17   : destination hash (16 bytes)
/// Byte  18     : context byte
/// ```
///
/// `serialize()` therefore produces exactly 19 bytes for a HEADER_1 packet,
/// matching `RNS.Packet.pack()` in the Python reference implementation.
public struct PacketHeader: Sendable {

    // Nested enums

    /// Header type occupies bits [7:6] of the flags byte.
    ///
    /// - `header1`: No transport ID field (most common).
    /// - `header2`: Transport ID field follows the context byte.
    public enum HeaderType: UInt8, Sendable {
        case header1 = 0
        case header2 = 1
    }

    /// Transport type occupies **bit 4** of the flags byte (1-bit field).
    ///
    /// Matches `RNS.Transport.BROADCAST (0)` and `RNS.Transport.TRANSPORT (1)`.
    /// Note: bit 5 is a separate `contextFlag` field (ratchet-key indicator),
    /// not an additional propagation-type bit.
    public enum PropagationType: UInt8, Sendable {
        case broadcast = 0
        case transport = 1
    }

    /// Destination type occupies bits [3:2] of the flags byte.
    public enum DestinationType: UInt8, Sendable {
        case single = 0
        case group  = 1
        case plain  = 2
        case link   = 3
    }

    // Constants

    /// Byte length of the serialised header (HEADER_1, no IFAC).
    public static let serializedLength = 19

    /// Byte length of the destination hash in the header.
    public static let destinationHashLength = 16

    // Fields

    public var headerType:      HeaderType
    public var propagationType: PropagationType
    public var destinationType: DestinationType
    public var packetType:      PacketType
    public var hops:            UInt8
    /// 16-byte destination hash embedded in the header.
    public var destinationHash: Data
    public var context:         UInt8
    /// Bit 5 of the flags byte. When `true` the announce payload contains a
    /// 32-byte ratchet public key between the random hash and the signature.
    public var contextFlag:     Bool

    // Computed: flags byte

    /// The single-byte flags field encoding all header bit-fields.
    ///
    /// ```
    /// bit  6    = headerType
    /// bit  5    = contextFlag (ratchet present)
    /// bit  4    = propagationType (0=broadcast, 1=transport)
    /// bits [3:2] = destinationType
    /// bits [1:0] = packetType
    /// ```
    public var flagsByte: UInt8 {
        (headerType.rawValue          << 6) |
        (contextFlag ? 0x20 : 0x00)        |
        (propagationType.rawValue     << 4) |
        (destinationType.rawValue     << 2) |
         packetType.rawValue
    }

    // Initialisers

    /// Creates a `PacketHeader` with all fields explicit.
    ///
    /// Defaults model the most common Reticulum packet:
    /// - `headerType` = `.header1` (no transport ID)
    /// - `propagationType` = `.broadcast`
    /// - `context` = `0`
    public init(
        packetType:      PacketType,
        destinationType: DestinationType,
        destinationHash: Data,
        hops:            UInt8 = 0,
        context:         UInt8 = 0,
        headerType:      HeaderType      = .header1,
        propagationType: PropagationType = .broadcast,
        contextFlag:     Bool            = false
    ) {
        self.packetType      = packetType
        self.destinationType = destinationType
        self.destinationHash = destinationHash
        self.hops            = hops
        self.context         = context
        self.headerType      = headerType
        self.propagationType = propagationType
        self.contextFlag     = contextFlag
    }

    // Serialisation

    /// Serialises the header to exactly 19 bytes.
    ///
    /// Layout: `[flagsByte][hops][destinationHash (16 bytes)][context]`
    ///
    /// This matches the byte prefix produced by `RNS.Packet.pack()` in the
    /// Python reference implementation for HEADER_1 packets without IFAC.
    public func serialize() -> Data {
        var writer = BinaryWriter()
        writer.writeUInt8(flagsByte)
        writer.writeUInt8(hops)
        writer.writeBytes(destinationHash)
        writer.writeUInt8(context)
        return writer.data
    }

    // Deserialisation

    /// Parses a `PacketHeader` from the leading bytes of `data`.
    ///
    /// Reads exactly the first 19 bytes; any trailing payload bytes are ignored.
    ///
    /// - Throws: `PacketHeaderError.tooShort` if `data.count < 19`.
    /// - Throws: `PacketHeaderError.unknownHeaderType` / `unknownPropagationType` /
    ///   `unknownDestinationType` / `unknownPacketType` if a bit-field contains
    ///   an unrecognised value.
    public static func deserialize(from data: Data) throws -> PacketHeader {
        guard data.count >= Self.serializedLength else {
            throw PacketHeaderError.tooShort(data.count)
        }

        var reader = BinaryReader(data: data)

        let flagsByte = try reader.readUInt8()
        let hops      = try reader.readUInt8()
        let destHash  = try reader.readBytes(Self.destinationHashLength)
        let context   = try reader.readUInt8()

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
            packetType:      packetType,
            destinationType: destinationType,
            destinationHash: destHash,
            hops:            hops,
            context:         context,
            headerType:      headerType,
            propagationType: propagationType,
            contextFlag:     contextFlag
        )
    }
}

// Errors

/// Errors thrown during `PacketHeader.deserialize(from:)`.
public enum PacketHeaderError: Error, Equatable {
    /// The input buffer contained fewer than 19 bytes.
    case tooShort(Int)
    /// Bits [7:6] of the flags byte do not map to a known `HeaderType`.
    case unknownHeaderType(UInt8)
    /// Bits [5:4] of the flags byte do not map to a known `PropagationType`.
    case unknownPropagationType(UInt8)
    /// Bits [3:2] of the flags byte do not map to a known `DestinationType`.
    case unknownDestinationType(UInt8)
    /// Bits [1:0] of the flags byte do not map to a known `PacketType`.
    case unknownPacketType(UInt8)
}
