import Testing
import Foundation
import CryptoKit
@testable import LXMF
@testable import ReticulumCrypto

@Suite("LXMF Delivery Methods")
struct LXMFDeliveryMethodsTests {

    @Test("OPPORTUNISTIC: create, encrypt, decrypt, parse")
    func opportunisticRoundTrip() async throws {
        let sender = try Identity.generate()
        let recipient = try Identity.generate()
        let destinationHash = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: recipient.hash
        )

        let router = LXMFRouter()
        let outbound = try await router.createOpportunisticOutbound(
            destinationHash: destinationHash,
            sourceIdentity: sender,
            recipientIdentityPublicKey: recipient.publicKey,
            content: "Hello opportunistic",
            title: "op",
            timestamp: 1_700_000_000.0
        )

        let recipientX25519Priv = try #require(recipient.privateKeyData).prefix(32)
        let decrypted = try ReticulumToken.decrypt(
            outbound.encryptedPayload,
            recipientX25519PrivateKey: Data(recipientX25519Priv),
            identityHash: recipient.hash
        )

        #expect(decrypted == Data(outbound.packedMessage.dropFirst(16)))

        var fullPacked = destinationHash
        fullPacked.append(decrypted)
        let message = try LXMFMessage(packed: fullPacked)
        #expect(message.title == "op")
        #expect(message.content == "Hello opportunistic")
    }

    @Test("OPPORTUNISTIC: stamp is appended but signature/hash remain valid")
    func opportunisticWithStamp() async throws {
        let sender = try Identity.generate()
        let recipient = try Identity.generate()
        let destinationHash = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: recipient.hash
        )

        let router = LXMFRouter()
        let outbound = try await router.createOpportunisticOutbound(
            destinationHash: destinationHash,
            sourceIdentity: sender,
            recipientIdentityPublicKey: recipient.publicKey,
            messageStampCost: 8,
            content: "Stamped opportunistic",
            title: "stamp",
            timestamp: 1_700_000_020.0
        )

        let recipientX25519Priv = try #require(recipient.privateKeyData).prefix(32)
        let decrypted = try ReticulumToken.decrypt(
            outbound.encryptedPayload,
            recipientX25519PrivateKey: Data(recipientX25519Priv),
            identityHash: recipient.hash
        )

        var fullPacked = destinationHash
        fullPacked.append(decrypted)
        let message = try LXMFMessage(packed: fullPacked)
        #expect(message.stamp != nil)
        #expect(message.stamp?.count == LXMFStamper.stampSize)
        let senderEd25519Pub = Data(sender.publicKey[32..<64])
        #expect(message.verifySignature(ed25519PublicKey: senderEd25519Pub))
    }

    @Test("OPPORTUNISTIC: outbound ticket stamp yields 16-byte stamp")
    func opportunisticWithOutboundTicketStamp() async throws {
        let sender = try Identity.generate()
        let recipient = try Identity.generate()
        let destinationHash = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: recipient.hash
        )
        let ticket = Data(repeating: 0x11, count: 16)

        let router = LXMFRouter()
        let outbound = try await router.createOpportunisticOutbound(
            destinationHash: destinationHash,
            sourceIdentity: sender,
            recipientIdentityPublicKey: recipient.publicKey,
            outboundTicket: ticket,
            content: "Ticket stamped opportunistic",
            title: "ticket",
            timestamp: 1_700_000_021.0
        )

        let recipientX25519Priv = try #require(recipient.privateKeyData).prefix(32)
        let decrypted = try ReticulumToken.decrypt(
            outbound.encryptedPayload,
            recipientX25519PrivateKey: Data(recipientX25519Priv),
            identityHash: recipient.hash
        )

        var fullPacked = destinationHash
        fullPacked.append(decrypted)
        let message = try LXMFMessage(packed: fullPacked)
        #expect(message.stamp?.count == 16)
        let validation = message.validateStamp(targetCost: 6, tickets: [ticket])
        #expect(validation.valid)
        #expect(validation.value == LXMFMessage.ticketStampValue)
    }

    @Test("OPPORTUNISTIC: uses announced ratchet key while keeping identity-hash salt")
    func opportunisticUsesRatchetKey() async throws {
        let sender = try Identity.generate()
        let recipient = try Identity.generate()
        let destinationHash = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: recipient.hash
        )

        let ratchetPrivate = Curve25519.KeyAgreement.PrivateKey()
        let ratchetPublic = ratchetPrivate.publicKey.rawRepresentation

        let router = LXMFRouter()
        let outbound = try await router.createOpportunisticOutbound(
            destinationHash: destinationHash,
            sourceIdentity: sender,
            recipientIdentityPublicKey: recipient.publicKey,
            recipientRatchetPublicKey: ratchetPublic,
            content: "Hello ratchet",
            title: "rt",
            timestamp: 1_700_000_010.0
        )

        // Decrypt with ratchet private key but identity hash salt.
        let decrypted = try ReticulumToken.decrypt(
            outbound.encryptedPayload,
            recipientX25519PrivateKey: ratchetPrivate.rawRepresentation,
            identityHash: recipient.hash
        )

        #expect(decrypted == Data(outbound.packedMessage.dropFirst(16)))

        var fullPacked = destinationHash
        fullPacked.append(decrypted)
        let message = try LXMFMessage(packed: fullPacked)
        #expect(message.title == "rt")
        #expect(message.content == "Hello ratchet")
    }

    @Test("DIRECT: link request/proof and encrypted payload round-trip")
    func directRoundTrip() async throws {
        let sender = try Identity.generate()
        let recipient = try Identity.generate()
        let destinationHash = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: recipient.hash
        )

        let router = LXMFRouter()
        let request = try await router.createDirectLinkRequest(destinationHash: destinationHash)

        // Simulate recipient-side LRPROOF generation.
        let responderEphemeral = Curve25519.KeyAgreement.PrivateKey()
        let responderX25519Pub = responderEphemeral.publicKey.rawRepresentation
        let requesterPub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: request.requesterX25519PublicKey
        )
        let shared = try responderEphemeral.sharedSecretFromKeyAgreement(with: requesterPub)
        let expectedDerivedSymmetric = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: request.linkID,
            sharedInfo: Data(),
            outputByteCount: 64
        )
        let expectedDerivedKey = expectedDerivedSymmetric.withUnsafeBytes { Data($0) }

        var signedData = Data()
        signedData.append(request.linkID)
        signedData.append(responderX25519Pub)
        signedData.append(Data(recipient.publicKey[32..<64]))
        signedData.append(request.signalling)
        let signature = try recipient.sign(signedData)

        var proofPayload = Data()
        proofPayload.append(signature)
        proofPayload.append(responderX25519Pub)
        proofPayload.append(request.signalling)

        let linkState = try await router.completeDirectLink(
            linkID: request.linkID,
            proofPayload: proofPayload,
            recipientIdentityPublicKey: recipient.publicKey
        )
        #expect(linkState.destinationHash == destinationHash)
        #expect(linkState.linkID == request.linkID)
        #expect(linkState.derivedKey == expectedDerivedKey)

        let packed = try LXMFMessage.create(
            destinationHash: destinationHash,
            sourceIdentity: sender,
            content: "Hello direct",
            title: "",
            timestamp: 1_700_000_001.0
        )

        let encrypted = try await router.encryptDirectPayload(
            destinationHash: destinationHash,
            lxmfPackedMessage: packed
        )
        let decrypted = try ReticulumToken.decryptLinkData(encrypted, key: expectedDerivedKey)
        #expect(decrypted == packed)
        let parsed = try LXMFMessage(packed: decrypted)
        #expect(parsed.content == "Hello direct")
    }

    @Test("DIRECT: removing cached link forces re-establishment path")
    func directLinkRemoval() async throws {
        let sender = try Identity.generate()
        let recipient = try Identity.generate()
        let destinationHash = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: recipient.hash
        )

        let router = LXMFRouter()
        let request = try await router.createDirectLinkRequest(destinationHash: destinationHash)

        let responderEphemeral = Curve25519.KeyAgreement.PrivateKey()
        let responderX25519Pub = responderEphemeral.publicKey.rawRepresentation
        var signedData = Data()
        signedData.append(request.linkID)
        signedData.append(responderX25519Pub)
        signedData.append(Data(recipient.publicKey[32..<64]))
        signedData.append(request.signalling)
        let signature = try recipient.sign(signedData)

        var proofPayload = Data()
        proofPayload.append(signature)
        proofPayload.append(responderX25519Pub)
        proofPayload.append(request.signalling)
        _ = try await router.completeDirectLink(
            linkID: request.linkID,
            proofPayload: proofPayload,
            recipientIdentityPublicKey: recipient.publicKey
        )

        #expect(await router.directLink(for: destinationHash) != nil)
        await router.removeDirectLink(for: destinationHash)
        #expect(await router.directLink(for: destinationHash) == nil)

        let packed = try LXMFMessage.create(
            destinationHash: destinationHash,
            sourceIdentity: sender,
            content: "Should fail without link",
            title: "",
            timestamp: 1_700_000_050.0
        )

        do {
            _ = try await router.encryptDirectPayload(
                destinationHash: destinationHash,
                lxmfPackedMessage: packed
            )
            #expect(Bool(false), "Expected missingDirectLink error after removing direct link")
        } catch let err as LXMFRouter.RouterError {
            if case .missingDirectLink = err {
                #expect(Bool(true))
            } else {
                #expect(Bool(false), "Unexpected router error: \(err)")
            }
        } catch {
            #expect(Bool(false), "Unexpected error type: \(error)")
        }
    }

    @Test("DIRECT: invalid proof signature is rejected")
    func directInvalidProofRejected() async throws {
        let recipient = try Identity.generate()
        let destinationHash = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: recipient.hash
        )

        let router = LXMFRouter()
        let request = try await router.createDirectLinkRequest(destinationHash: destinationHash)

        let responderEphemeral = Curve25519.KeyAgreement.PrivateKey()
        let responderX25519Pub = responderEphemeral.publicKey.rawRepresentation
        var signedData = Data()
        signedData.append(request.linkID)
        signedData.append(responderX25519Pub)
        signedData.append(Data(recipient.publicKey[32..<64]))
        signedData.append(request.signalling)
        var signature = try recipient.sign(signedData)
        signature[0] ^= 0x01

        var proofPayload = Data()
        proofPayload.append(signature)
        proofPayload.append(responderX25519Pub)
        proofPayload.append(request.signalling)

        do {
            _ = try await router.completeDirectLink(
                linkID: request.linkID,
                proofPayload: proofPayload,
                recipientIdentityPublicKey: recipient.publicKey
            )
            #expect(Bool(false), "Expected invalidLinkProofSignature")
        } catch let err as LXMFRouter.RouterError {
            if case .invalidLinkProofSignature = err {
                #expect(Bool(true))
            } else {
                #expect(Bool(false), "Unexpected router error: \(err)")
            }
        }
    }

    @Test("PROPAGATED: nested encryption and transient-id correctness")
    func propagatedRoundTrip() async throws {
        let sender = try Identity.generate()
        let recipient = try Identity.generate()
        let propagationNode = try Identity.generate()

        let recipientDest = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: recipient.hash
        )

        let router = LXMFRouter()
        let outbound = try await router.createPropagatedOutbound(
            destinationHash: recipientDest,
            sourceIdentity: sender,
            recipientIdentityPublicKey: recipient.publicKey,
            propagationNodeIdentityPublicKey: propagationNode.publicKey,
            content: "Hello propagated",
            title: "pg",
            messageTimestamp: 1_700_000_002.0,
            propagationTimestamp: 1_700_000_003.0
        )

        #expect(outbound.transientID == Hashing.sha256(outbound.lxmData))

        let nodeX25519Priv = try #require(propagationNode.privateKeyData).prefix(32)
        let decryptedContainer = try ReticulumToken.decrypt(
            outbound.encryptedContainer,
            recipientX25519PrivateKey: Data(nodeX25519Priv),
            identityHash: propagationNode.hash
        )

        let decoded = try LXMFRouter.decodePropagationContainer(decryptedContainer)
        #expect(decoded.timestamp == 1_700_000_003.0)
        #expect(decoded.lxmDatas.count == 1)
        #expect(decoded.lxmDatas[0] == outbound.lxmData)

        let inner = decoded.lxmDatas[0]
        let innerDest = Data(inner.prefix(16))
        let innerEncrypted = Data(inner.dropFirst(16))
        #expect(innerDest == recipientDest)

        let recipientX25519Priv = try #require(recipient.privateKeyData).prefix(32)
        let innerPlain = try ReticulumToken.decrypt(
            innerEncrypted,
            recipientX25519PrivateKey: Data(recipientX25519Priv),
            identityHash: recipient.hash
        )

        var fullPacked = innerDest
        fullPacked.append(innerPlain)
        #expect(fullPacked == outbound.packedMessage)
        let parsed = try LXMFMessage(packed: fullPacked)
        #expect(parsed.title == "pg")
        #expect(parsed.content == "Hello propagated")
    }

    @Test("PROPAGATED: appends propagation stamp to transient payload")
    func propagatedIncludesPropagationStamp() async throws {
        let sender = try Identity.generate()
        let recipient = try Identity.generate()
        let propagationNode = try Identity.generate()

        let recipientDest = Destination.hash(
            appName: "lxmf",
            aspects: ["delivery"],
            identityHash: recipient.hash
        )

        let router = LXMFRouter()
        let outbound = try await router.createPropagatedOutbound(
            destinationHash: recipientDest,
            sourceIdentity: sender,
            recipientIdentityPublicKey: recipient.publicKey,
            propagationNodeIdentityPublicKey: propagationNode.publicKey,
            messageStampCost: 7,
            propagationStampCost: 6,
            content: "Propagation stamped",
            title: "pstamp",
            messageTimestamp: 1_700_000_200.0,
            propagationTimestamp: 1_700_000_210.0
        )

        // lxmData = destination(16) + encrypted(...) + propagation_stamp(32)
        #expect(outbound.lxmData.count > 16 + LXMFStamper.stampSize)
        let propagationStamp = Data(outbound.lxmData.suffix(LXMFStamper.stampSize))
        let unstampedLxmData = Data(outbound.lxmData.dropLast(LXMFStamper.stampSize))
        let transientID = Hashing.sha256(unstampedLxmData)
        let workblock = LXMFStamper.stampWorkblock(
            material: transientID,
            expandRounds: LXMFStamper.propagationWorkblockExpandRounds
        )
        #expect(LXMFStamper.stampValid(stamp: propagationStamp, targetCost: 6, workblock: workblock))
    }
}
