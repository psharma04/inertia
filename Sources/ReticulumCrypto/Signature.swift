import Foundation
import Sodium

public enum Signature {

    public enum SignatureError: Error {
        case invalidSeedLength(Int)
        case signingFailed
    }

    public static func sign(_ message: Data, seed: Data) throws -> Data {
        guard seed.count == 32 else {
            throw SignatureError.invalidSeedLength(seed.count)
        }
        let sodium = Sodium()
        guard let kp = sodium.sign.keyPair(seed: Bytes(seed)),
              let sig = sodium.sign.signature(message: Bytes(message), secretKey: kp.secretKey)
        else {
            throw SignatureError.signingFailed
        }
        return Data(sig)
    }

    public static func verify(
        _ message: Data,
        signature: Data,
        publicKeyBytes: Data
    ) -> Bool {
        let sodium = Sodium()
        return sodium.sign.verify(
            message: Bytes(message),
            publicKey: Bytes(publicKeyBytes),
            signature: Bytes(signature)
        )
    }
}

