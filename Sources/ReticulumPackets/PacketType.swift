import Foundation

/// Reticulum packet type constants.
///
/// Values match `RNS.Packet.DATA`, `ANNOUNCE`, `LINKREQUEST`, and `PROOF`
/// in the Python reference implementation and are encoded in bits [1:0] of
/// the header flags byte.
public enum PacketType: UInt8, Sendable {
    case data        = 0x00
    case announce    = 0x01
    case linkRequest = 0x02
    case proof       = 0x03
}
