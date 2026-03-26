import Foundation
import ReticulumCrypto

/// LXMF proof-of-work stamp generation and validation.
///
/// This follows Python `LXStamper.py` semantics:
/// - workblock = concat(HKDF(material, salt=SHA256(material+msgpack(n)), len=256), rounds)
/// - stamp valid if SHA256(workblock||stamp) <= (1 << (256-cost))
/// - stamp value = number of leading zero bits in SHA256(workblock||stamp)
public enum LXMFStamper {
    public static let workblockExpandRounds = 3000
    public static let propagationWorkblockExpandRounds = 1000
    public static let peeringWorkblockExpandRounds = 25
    public static let stampSize = 32

    public static func stampWorkblock(
        material: Data,
        expandRounds: Int = workblockExpandRounds
    ) -> Data {
        guard expandRounds > 0 else { return Data() }

        var workblock = Data()
        workblock.reserveCapacity(expandRounds * 256)
        for n in 0..<expandRounds {
            let saltMaterial = material + msgpackPackInt(n)
            let salt = Hashing.sha256(saltMaterial)
            let block = hkdfSHA256(
                deriveFrom: material,
                salt: salt,
                context: nil,
                length: 256
            )
            workblock.append(block)
        }
        return workblock
    }

    public static func stampValue(workblock: Data, stamp: Data) -> Int {
        let digest = Hashing.sha256(workblock + stamp)
        return leadingZeroBitCount(digest)
    }

    public static func stampValid(stamp: Data, targetCost: Int, workblock: Data) -> Bool {
        guard stamp.count == stampSize else { return false }
        guard targetCost > 0 && targetCost <= 255 else { return false }

        let digest = Hashing.sha256(workblock + stamp)
        let target = targetThreshold(for: targetCost)
        return lessThanOrEqualBigEndian(digest, target)
    }

    /// Generates a valid stamp for `messageID` and returns `(stamp, value)`.
    ///
    /// `value` can exceed `targetCost` and represents effective PoW quality.
    public static func generateStamp(
        messageID: Data,
        stampCost: Int,
        expandRounds: Int = workblockExpandRounds
    ) -> (stamp: Data, value: Int)? {
        guard stampCost > 0 && stampCost <= 255 else { return nil }
        let workblock = stampWorkblock(material: messageID, expandRounds: expandRounds)
        if workblock.isEmpty { return nil }

        while true {
            var candidate = Data(count: stampSize)
            let status = candidate.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, stampSize, $0.baseAddress!)
            }
            if status != errSecSuccess {
                return nil
            }
            if stampValid(stamp: candidate, targetCost: stampCost, workblock: workblock) {
                return (candidate, stampValue(workblock: workblock, stamp: candidate))
            }
        }
    }

    private static func hkdfSHA256(
        deriveFrom ikm: Data,
        salt: Data,
        context: Data?,
        length: Int
    ) -> Data {
        let info = context ?? Data()
        let hashLen = 32

        let prk = hmacSHA256(key: salt, data: ikm)
        let blocks = Int(ceil(Double(length) / Double(hashLen)))

        var okm = Data()
        okm.reserveCapacity(blocks * hashLen)
        var previous = Data()

        for counter in 1...blocks {
            var input = Data()
            input.append(previous)
            input.append(info)
            input.append(UInt8(counter))
            previous = hmacSHA256(key: prk, data: input)
            okm.append(previous)
        }

        return Data(okm.prefix(length))
    }

    private static func hmacSHA256(key: Data, data: Data) -> Data {
        let blockSize = 64
        var normalizedKey = key
        if normalizedKey.count > blockSize {
            normalizedKey = Hashing.sha256(normalizedKey)
        }
        if normalizedKey.count < blockSize {
            normalizedKey.append(contentsOf: repeatElement(0x00, count: blockSize - normalizedKey.count))
        }

        var oKeyPad = Data(repeating: 0x5c, count: blockSize)
        var iKeyPad = Data(repeating: 0x36, count: blockSize)
        for i in 0..<blockSize {
            oKeyPad[i] ^= normalizedKey[i]
            iKeyPad[i] ^= normalizedKey[i]
        }

        return Hashing.sha256(oKeyPad + Hashing.sha256(iKeyPad + data))
    }

    private static func leadingZeroBitCount(_ data: Data) -> Int {
        var count = 0
        for byte in data {
            if byte == 0 {
                count += 8
                continue
            }
            var mask: UInt8 = 0x80
            while mask != 0 && (byte & mask) == 0 {
                count += 1
                mask >>= 1
            }
            break
        }
        return count
    }

    /// Python-compatible threshold:
    /// `target = 1 << (256-target_cost)` and valid when `digest <= target`.
    private static func targetThreshold(for targetCost: Int) -> Data {
        let exponent = 256 - targetCost
        var threshold = Data(repeating: 0x00, count: 32)
        let byteIndexFromRight = exponent / 8
        let bitIndex = exponent % 8
        let idx = threshold.count - 1 - byteIndexFromRight
        if idx >= 0 && idx < threshold.count {
            threshold[idx] = UInt8(1 << bitIndex)
        }
        return threshold
    }

    private static func lessThanOrEqualBigEndian(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        for i in 0..<lhs.count {
            if lhs[i] < rhs[i] { return true }
            if lhs[i] > rhs[i] { return false }
        }
        return true
    }

    private static func msgpackPackInt(_ value: Int) -> Data {
        if value >= 0 {
            if value <= 0x7F {
                return Data([UInt8(value)])
            } else if value <= 0xFF {
                return Data([0xCC, UInt8(value)])
            } else if value <= 0xFFFF {
                return Data([0xCD, UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)])
            } else {
                return Data([
 0xCE,
 UInt8((value >> 24) & 0xFF),
 UInt8((value >> 16) & 0xFF),
 UInt8((value >> 8) & 0xFF),
 UInt8(value & 0xFF),
                ])
            }
        }

        let signed = Int32(value)
        if signed >= -32 {
            return Data([UInt8(bitPattern: Int8(signed))])
        } else if signed >= Int32(Int8.min) {
            return Data([0xD0, UInt8(bitPattern: Int8(signed))])
        } else if signed >= Int32(Int16.min) {
            return Data([0xD1, UInt8((Int(signed) >> 8) & 0xFF), UInt8(Int(signed) & 0xFF)])
        } else {
            return Data([
                0xD2,
                UInt8((Int(signed) >> 24) & 0xFF),
                UInt8((Int(signed) >> 16) & 0xFF),
                UInt8((Int(signed) >> 8) & 0xFF),
                UInt8(Int(signed) & 0xFF),
            ])
        }
    }
}
