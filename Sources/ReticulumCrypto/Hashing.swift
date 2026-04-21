import Foundation
import CryptoKit

public enum Hashing {

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public static func sha512(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    public static func truncatedHash(_ data: Data, length: Int) -> Data {
        Data(sha256(data).prefix(length))
    }
}
