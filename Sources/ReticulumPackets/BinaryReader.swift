import Foundation

/// Reads primitive values sequentially from a `Data` buffer using big-endian byte order.
///
/// Maintains a cursor that advances with each read. Throws
/// `BinaryReaderError.outOfBounds` if a read would exceed the buffer length.
public struct BinaryReader: Sendable {
    private let data: Data
    private var cursor: Int

    public init(data: Data) {
        self.data = data
        self.cursor = 0
    }

    public mutating func readUInt8() throws -> UInt8 {
        guard cursor < data.count else { throw BinaryReaderError.outOfBounds }
        defer { cursor += 1 }
        return data[cursor]
    }

    public mutating func readUInt16() throws -> UInt16 {
        guard cursor + 2 <= data.count else { throw BinaryReaderError.outOfBounds }
        let hi = data[cursor]
        let lo = data[cursor + 1]
        cursor += 2
        return (UInt16(hi) << 8) | UInt16(lo)
    }

    public mutating func readUInt32() throws -> UInt32 {
        guard cursor + 4 <= data.count else { throw BinaryReaderError.outOfBounds }
        let b0 = data[cursor]
        let b1 = data[cursor + 1]
        let b2 = data[cursor + 2]
        let b3 = data[cursor + 3]
        cursor += 4
        return (UInt32(b0) << 24)
             | (UInt32(b1) << 16)
             | (UInt32(b2) << 8)
             |  UInt32(b3)
    }

    public mutating func readBytes(_ count: Int) throws -> Data {
        guard count >= 0 else { throw BinaryReaderError.outOfBounds }
        guard cursor + count <= data.count else { throw BinaryReaderError.outOfBounds }
        defer { cursor += count }
        return Data(data[cursor ..< cursor + count])
    }
}
