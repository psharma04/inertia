import Foundation

/// A Reticulum network packet.
///
/// ## Wire layout (HEADER_1, no IFAC)
///
/// ```
/// Bytes 0–18  : PacketHeader (19 bytes — see PacketHeader.swift)
/// Bytes 19+   : payload (arbitrary length)
/// ```
///
/// Binary format is wire-compatible with `RNS.Packet.pack()` in the Python
/// reference implementation.
public struct Packet: Sendable {

    /// The 19-byte header describing packet and destination metadata.
    public var header: PacketHeader

    /// The raw payload bytes that follow the header on the wire.
    public var payload: Data

    // Initialisers

    public init(header: PacketHeader, payload: Data = Data()) {
        self.header  = header
        self.payload = payload
    }

    // Serialisation

    /// Encodes the packet to its wire representation.
    ///
    /// Layout: `[header (19 bytes)][payload]`
    public func serialize() -> Data {
        var out = header.serialize()
        out.append(payload)
        return out
    }

    // Deserialisation

    /// Parses a `Packet` from raw wire bytes.
    ///
    /// The first 19 bytes are decoded as a `PacketHeader`; everything after
    /// byte 18 is stored verbatim as `payload`.
    ///
    /// - Throws: `PacketHeaderError.tooShort` if `data.count < 19`.
    /// - Throws: `PacketHeaderError.unknown*` for unrecognised header bit-fields.
    public static func deserialize(from data: Data) throws -> Packet {
        let header  = try PacketHeader.deserialize(from: data)
        let payload = data.count > PacketHeader.serializedLength
            ? Data(data.dropFirst(PacketHeader.serializedLength))
            : Data()
        return Packet(header: header, payload: payload)
    }
}
