import Foundation

public struct BinaryWriter: Sendable {
    public private(set) var data: Data

    public init() {
        data = Data()
    }

    public mutating func writeUInt8(_ value: UInt8) {
        data.append(value)
    }

    public mutating func writeUInt16(_ value: UInt16) {
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    public mutating func writeUInt32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    public mutating func writeBytes(_ bytes: Data) {
        data.append(bytes)
    }
}
