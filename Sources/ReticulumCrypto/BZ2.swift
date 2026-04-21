import Foundation
import CBzip2

/// bz2 decompression utility for Reticulum Resource transfers.
public enum BZ2 {

    public enum BZ2Error: Error {
        case decompressionFailed(Int32)
        case outputTooLarge
    }

    /// Maximum decompressed output size (64 MB, matching Python
    /// ``Resource.AUTO_COMPRESS_MAX_SIZE``).
    private static let maxOutputSize = 64 * 1024 * 1024

    public static func decompress(_ data: Data) throws -> Data {
        // Start with 4× the compressed size, grow if needed.
        var outputCapacity = max(data.count * 4, 4096)
        var output = Data(count: outputCapacity)

        while true {
            var destLen = UInt32(outputCapacity)
            let result: Int32 = data.withUnsafeBytes { srcPtr in
                output.withUnsafeMutableBytes { dstPtr in
                    BZ2_bzBuffToBuffDecompress(
                        dstPtr.baseAddress?.assumingMemoryBound(to: CChar.self),
                        &destLen,
                        UnsafeMutablePointer(
                            mutating: srcPtr.baseAddress?.assumingMemoryBound(to: CChar.self)
                        ),
                        UInt32(data.count),
                        0,  // small: 0 = use default algorithm
                        0   // verbosity
                    )
                }
            }

            if result == BZ_OK {
                output.count = Int(destLen)
                return output
            } else if result == BZ_OUTBUFF_FULL {
                outputCapacity *= 2
                guard outputCapacity <= maxOutputSize else {
                    throw BZ2Error.outputTooLarge
                }
                output = Data(count: outputCapacity)
                continue
            } else {
                throw BZ2Error.decompressionFailed(result)
            }
        }
    }
}
