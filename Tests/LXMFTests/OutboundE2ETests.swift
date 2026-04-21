import Testing
import Foundation
@testable import ReticulumCrypto
@testable import ReticulumPackets
@testable import LXMF

@Suite("Outbound E2E")
struct OutboundE2ETests {

    @Test("Full LXMF OPPORTUNISTIC round-trip")
    func fullRoundTrip() throws {
        // 1. Generate sender and recipient identities
        let sender    = try Identity.generate()
        let recipient = try Identity.generate()

        let content     = "Hello from Inertia!"
        let title       = ""
        let timestamp   = Date().timeIntervalSince1970

        // Recipient's LXMF delivery destination hash
        let recipientDestHash = Destination.hash(
            appName: "lxmf", aspects: ["delivery"],
            identityHash: recipient.hash
        )
        #expect(recipientDestHash.count == 16)

        // Sender's LXMF delivery destination hash (sourceHash)
        let senderDestHash = Destination.hash(
            appName: "lxmf", aspects: ["delivery"],
            identityHash: sender.hash
        )
        #expect(senderDestHash.count == 16)

        // 2. Create LXMF packed message (as AppModel.send does)
        let packed = try LXMFMessage.create(
            destinationHash: recipientDestHash,
            sourceIdentity:  sender,
            content:         content,
            title:           title,
            timestamp:       timestamp
        )
        #expect(packed.count >= 96) // dest(16) + src(16) + sig(64) + msgpack(>=0)

        // Verify packed starts with recipient dest hash
        #expect(Data(packed.prefix(16)) == recipientDestHash)
        // Verify packed[16:32] is sender's dest hash
        #expect(Data(packed[16..<32]) == senderDestHash)

        // 3. Build Reticulum packet (as AppModel.send does)
        let header = PacketHeader(
            packetType:      .data,
            destinationType: .single,
            destinationHash: recipientDestHash,
            hops:            0,
            context:         0x00
        )
        let packet     = Packet(header: header, payload: packed)
        let serialized = packet.serialize()
        #expect(serialized.count == 19 + packed.count)
        #expect(serialized[0] == 0x00)  // flags = 0x00
        #expect(serialized[1] == 0x00)  // hops = 0
        #expect(serialized[18] == 0x00) // context = 0x00

        // 4. Simulate TCPClientInterface.send() encryption
        let parsedPacket = try Packet.deserialize(from: serialized)
        let destHash     = Data(parsedPacket.header.destinationHash)
        #expect(destHash == recipientDestHash)

        // Strip destination hash prefix (as TCPClientInterface does)
        var plaintext = parsedPacket.payload
        #expect(Data(plaintext.prefix(16)) == destHash)
        plaintext = Data(plaintext.dropFirst(16))

        // plaintext should now be: src(16) + sig(64) + msgpack
        #expect(Data(plaintext.prefix(16)) == senderDestHash)

        // Encrypt with recipient's public key
        let x25519Pub    = Data(recipient.publicKey.prefix(32))
        let identityHash = Hashing.truncatedHash(recipient.publicKey, length: Identity.hashLength)
        #expect(identityHash == recipient.hash)

        let encrypted = try ReticulumToken.encrypt(
            plaintext,
            recipientX25519PublicKey: x25519Pub,
            identityHash: identityHash
        )
        #expect(encrypted.count >= 80 + 16) // ephPub(32) + iv(16) + ct(>=16) + hmac(32)

        // Build encrypted packet
        var encPacket    = parsedPacket
        encPacket.payload = encrypted
        let encSerialized = encPacket.serialize()
        #expect(encSerialized.count == 19 + encrypted.count)

        // 5. Simulate recipient's decryption
        guard let recipientPrivKeyData = recipient.privateKeyData else {
            Issue.record("Recipient has no private key")
            return
        }
        let recipientX25519Priv = Data(recipientPrivKeyData.prefix(32))

        let decrypted = try ReticulumToken.decrypt(
            encrypted,
            recipientX25519PrivateKey: recipientX25519Priv,
            identityHash: recipient.hash
        )
        #expect(decrypted == plaintext)

        // 6. Reconstruct full LXMF packed bytes (prepend dest hash as Python does)
        var fullPacked = recipientDestHash
        fullPacked.append(decrypted)

        let msg = try LXMFMessage(packed: fullPacked)

        // 7. Verify all fields match
        #expect(msg.destinationHash == recipientDestHash)
        #expect(msg.sourceHash      == senderDestHash)
        #expect(msg.content         == content)
        #expect(msg.title           == title)
        #expect(msg.signature.count == 64)

        // Verify signature
        let senderEd25519Pub = Data(sender.publicKey[32..<64])
        let verified = msg.verifySignature(ed25519PublicKey: senderEd25519Pub)
        #expect(verified == true)
    }

    @Test("Encrypted packet fits within Reticulum MTU")
    func packetSizeWithinMTU() throws {
        let sender    = try Identity.generate()
        let recipient = try Identity.generate()

        let recipientDestHash = Destination.hash(
            appName: "lxmf", aspects: ["delivery"],
            identityHash: recipient.hash
        )

        // Short message (typical chat message)
        let packed = try LXMFMessage.create(
            destinationHash: recipientDestHash,
            sourceIdentity:  sender,
            content:         "Hi!",
            title:           "",
            timestamp:       Date().timeIntervalSince1970
        )

        // Simulate stripping dest hash and encrypting
        let plaintext = Data(packed.dropFirst(16))
        let encrypted = try ReticulumToken.encrypt(
            plaintext,
            recipientX25519PublicKey: Data(recipient.publicKey.prefix(32)),
            identityHash: recipient.hash
        )

        // Total packet: header(19) + encrypted token
        let totalPacketSize = 19 + encrypted.count
        #expect(totalPacketSize <= 500, "Packet exceeds Reticulum MTU of 500 bytes")
    }

    @Test("Max content for OPPORTUNISTIC delivery")
    func maxContentOpportunistic() throws {
        let sender    = try Identity.generate()
        let recipient = try Identity.generate()

        let recipientDestHash = Destination.hash(
            appName: "lxmf", aspects: ["delivery"],
            identityHash: recipient.hash
        )


        // Try with 200 bytes of content (should fit easily)
        let content = String(repeating: "X", count: 200)
        let packed = try LXMFMessage.create(
            destinationHash: recipientDestHash,
            sourceIdentity:  sender,
            content:         content,
            title:           "",
            timestamp:       Date().timeIntervalSince1970
        )
        let plaintext = Data(packed.dropFirst(16))
        let encrypted = try ReticulumToken.encrypt(
            plaintext,
            recipientX25519PublicKey: Data(recipient.publicKey.prefix(32)),
            identityHash: recipient.hash
        )
        let totalPacketSize = 19 + encrypted.count
        #expect(totalPacketSize <= 500, "200-char message exceeds MTU: \(totalPacketSize) bytes")
    }

    @Test("Paper message round-trip: create URI → import → verify")
    func paperMessageRoundTrip() throws {
        let sender    = try Identity.generate()
        let recipient = try Identity.generate()
        let content   = "Paper message test"
        let title     = "Test Title"
        let timestamp = Date().timeIntervalSince1970

        let recipientDestHash = Destination.hash(
            appName: "lxmf", aspects: ["delivery"],
            identityHash: recipient.hash
        )

        guard let recipientPrivKeyData = recipient.privateKeyData else {
            Issue.record("Recipient has no private key")
            return
        }
        let recipientX25519Pub = Data(recipient.publicKey.prefix(32))

        let paperPacked = try LXMFMessage.packPaper(
            destinationHash: recipientDestHash,
            sourceIdentity: sender,
            recipientX25519PublicKey: recipientX25519Pub,
            recipientIdentityHash: recipient.hash,
            content: content,
            title: title,
            timestamp: timestamp
        )

        // Verify it starts with dest hash
        #expect(Data(paperPacked.prefix(16)) == recipientDestHash)
        #expect(paperPacked.count > 16)

        // Generate URI
        let uri = LXMFMessage.paperURI(paperPacked: paperPacked)
        #expect(uri.hasPrefix("lxm://"))
        #expect(!uri.contains("="))
        #expect(!uri.contains("+"))

        // Import: strip scheme, base64url decode
        let encoded = String(uri.dropFirst("lxm://".count))
        let padded = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddedLen = padded + String(repeating: "=", count: (4 - padded.count % 4) % 4)
        guard let decoded = Data(base64Encoded: paddedLen) else {
            Issue.record("Could not base64-decode paper URI")
            return
        }
        #expect(decoded == paperPacked)

        // Decrypt
        let destHash = Data(decoded.prefix(16))
        #expect(destHash == recipientDestHash)

        let encrypted = Data(decoded[16...])
        let recipientX25519Priv = Data(recipientPrivKeyData.prefix(32))
        let decrypted = try ReticulumToken.decrypt(
            encrypted,
            recipientX25519PrivateKey: recipientX25519Priv,
            identityHash: recipient.hash
        )

        // Reconstruct full packed and parse
        var fullPacked = destHash
        fullPacked.append(decrypted)
        let msg = try LXMFMessage(packed: fullPacked)

        #expect(msg.destinationHash == recipientDestHash)
        #expect(msg.content == content)
        #expect(msg.title == title)
        #expect(abs(msg.timestamp - timestamp) < 0.001)

        let senderEd25519Pub = Data(sender.publicKey[32..<64])
        #expect(msg.verifySignature(ed25519PublicKey: senderEd25519Pub))
    }

    @Test("LXMF field constants match Python reference values")
    func fieldConstantsMatch() {
        #expect(LXMFField.embeddedLXMs.rawValue == 0x01)
        #expect(LXMFField.telemetry.rawValue == 0x02)
        #expect(LXMFField.fileAttachments.rawValue == 0x05)
        #expect(LXMFField.image.rawValue == 0x06)
        #expect(LXMFField.audio.rawValue == 0x07)
        #expect(LXMFField.ticket.rawValue == 0x0C)
        #expect(LXMFField.renderer.rawValue == 0x0F)
        #expect(LXMFField.customType.rawValue == 0xFB)
        #expect(LXMFField.customData.rawValue == 0xFC)
        #expect(LXMFField.debug.rawValue == 0xFF)
        #expect(LXMFRenderer.plain.rawValue == 0x00)
        #expect(LXMFRenderer.micron.rawValue == 0x01)
        #expect(LXMFRenderer.markdown.rawValue == 0x02)
        #expect(LXMFRenderer.bbcode.rawValue == 0x03)
    }
}
