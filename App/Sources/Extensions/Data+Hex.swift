import Foundation

extension Data {
    /// Hex string representation, e.g. "deadbeef".
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Initialise from a hex string (case-insensitive, must have even length).
    init?(hexString: String) {
        let clean = hexString.trimmingCharacters(in: .whitespaces)
        guard clean.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(clean.count / 2)
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            guard let b = UInt8(clean[idx ..< next], radix: 16) else { return nil }
            bytes.append(b)
            idx = next
        }
        self.init(bytes)
    }
}
