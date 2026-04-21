import Foundation

public enum PacketType: UInt8, Sendable {
    case data        = 0x00
    case announce    = 0x01
    case linkRequest = 0x02
    case proof       = 0x03
}
