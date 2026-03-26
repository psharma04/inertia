import Foundation

/// Errors thrown by `BinaryReader` when a read cannot be satisfied.
public enum BinaryReaderError: Error, Equatable {
    /// The read would extend beyond the end of the available data.
    case outOfBounds
}
