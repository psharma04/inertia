import Testing
import Foundation
@testable import ReticulumCrypto


// Helpers

private func loadDestinationFixture(name: String) throws -> [String: Any] {
    try FixtureLoader.load(subdir: "destinations", name: "\(name).json")
}

// SINGLE Destination: Hash Derivation

@Suite("Destination — SINGLE Hash Derivation")
struct DestinationSingleHashTests {

    // MARK: Fixture-driven hash equality

    @Test("SINGLE: identity_a destination_hash matches Python reference")
    func singleHashIdentityAMatchesReference() throws {
        let fixture      = try loadDestinationFixture(name: "destination_single_identity_a")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let identityHash = try fixture.hexData(at: "inputs.identity_hash_hex")
        let expected     = try fixture.hexData(at: "expected.destination_hash_hex")

        let hash = Destination.hash(appName: appName, aspects: [aspect], identityHash: identityHash)
        #expect(hash == expected,
                "SINGLE hash mismatch — expected \(expected.hexString), got \(hash.hexString)")
    }

    @Test("SINGLE: identity_b destination_hash matches Python reference")
    func singleHashIdentityBMatchesReference() throws {
        let fixture      = try loadDestinationFixture(name: "destination_single_identity_b")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let identityHash = try fixture.hexData(at: "inputs.identity_hash_hex")
        let expected     = try fixture.hexData(at: "expected.destination_hash_hex")

        let hash = Destination.hash(appName: appName, aspects: [aspect], identityHash: identityHash)
        #expect(hash == expected)
    }

    // MARK: Hash shape

    @Test("SINGLE: destination_hash is exactly 16 bytes")
    func singleHashLengthIs16Bytes() throws {
        let fixture      = try loadDestinationFixture(name: "destination_single_identity_a")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let identityHash = try fixture.hexData(at: "inputs.identity_hash_hex")

        let hash = Destination.hash(appName: appName, aspects: [aspect], identityHash: identityHash)
        #expect(hash.count == 16)
    }

    // MARK: Full name string

    @Test("SINGLE: destination_name is '<app>.<aspect>.<identity_hash_hex>'")
    func singleDestinationNameFormat() throws {
        let fixture      = try loadDestinationFixture(name: "destination_single_identity_a")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let identityHash = try fixture.hexData(at: "inputs.identity_hash_hex")
        let expected     = try fixture.string(at: "expected.destination_name")

        let name = Destination.fullName(appName: appName, aspects: [aspect], identityHash: identityHash)
        #expect(name == expected,
                "destination_name mismatch — expected '\(expected)', got '\(name)'")
    }

    // MARK: Name hash (identity-independent)

    @Test("SINGLE: name_hash matches Python reference (10 bytes, no identity in input)")
    func singleNameHashMatchesReference() throws {
        let fixture  = try loadDestinationFixture(name: "destination_single_identity_a")
        let appName  = try fixture.string(at: "inputs.app_name")
        let aspect   = try fixture.string(at: "inputs.aspect")
        let expected = try fixture.hexData(at: "expected.name_hash_hex")

        let nameHash = Destination.nameHash(appName: appName, aspects: [aspect])
        #expect(nameHash == expected,
                "name_hash mismatch — expected \(expected.hexString), got \(nameHash.hexString)")
    }

    @Test("SINGLE: name_hash is exactly 10 bytes")
    func singleNameHashLengthIs10Bytes() throws {
        let fixture = try loadDestinationFixture(name: "destination_single_identity_a")
        let appName = try fixture.string(at: "inputs.app_name")
        let aspect  = try fixture.string(at: "inputs.aspect")

        let nameHash = Destination.nameHash(appName: appName, aspects: [aspect])
        #expect(nameHash.count == 10)
    }

    @Test("SINGLE: identity_a and identity_b share the same name_hash (app+aspect identical)")
    func singleNameHashIsIdentityIndependent() throws {
        let fa = try loadDestinationFixture(name: "destination_single_identity_a")
        let fb = try loadDestinationFixture(name: "destination_single_identity_b")

        let nameHashA = Destination.nameHash(
            appName: try fa.string(at: "inputs.app_name"),
            aspects: [try fa.string(at: "inputs.aspect")]
        )
        let nameHashB = Destination.nameHash(
            appName: try fb.string(at: "inputs.app_name"),
            aspects: [try fb.string(at: "inputs.aspect")]
        )
        #expect(nameHashA == nameHashB,
                "name_hash must be identical when app_name and aspect are the same")
    }

    @Test("SINGLE: identity_a and identity_b have different destination hashes")
    func singleDifferentIdentitiesProduceDifferentHashes() throws {
        let fa = try loadDestinationFixture(name: "destination_single_identity_a")
        let fb = try loadDestinationFixture(name: "destination_single_identity_b")

        let hashA = Destination.hash(
            appName: try fa.string(at: "inputs.app_name"),
            aspects: [try fa.string(at: "inputs.aspect")],
            identityHash: try fa.hexData(at: "inputs.identity_hash_hex")
        )
        let hashB = Destination.hash(
            appName: try fb.string(at: "inputs.app_name"),
            aspects: [try fb.string(at: "inputs.aspect")],
            identityHash: try fb.hexData(at: "inputs.identity_hash_hex")
        )
        #expect(hashA != hashB)
    }

    // MARK: Derived from Identity struct

    @Test("SINGLE: hash derived from Identity struct matches Python reference")
    func singleHashFromIdentityStruct() throws {
        let idFixture   = try FixtureLoader.load(subdir: "identities", name: "identity_a.json")
        let destFixture = try loadDestinationFixture(name: "destination_single_identity_a")

        let identity = try Identity(privateKey: try DeterministicIdentityKeyMaterial.privateKey(for: idFixture))
        let appName  = try destFixture.string(at: "inputs.app_name")
        let aspect   = try destFixture.string(at: "inputs.aspect")
        let expected = try destFixture.hexData(at: "expected.destination_hash_hex")

        let dest = Destination(appName: appName, aspects: [aspect], identity: identity)
        #expect(dest.hash == expected,
                "hash from Identity struct must match Python reference")
    }
}

// PLAIN Destination: Hash Derivation

@Suite("Destination — PLAIN Hash Derivation")
struct DestinationPlainHashTests {

    @Test("PLAIN: destination_hash matches Python reference")
    func plainHashMatchesReference() throws {
        let fixture  = try loadDestinationFixture(name: "destination_plain")
        let appName  = try fixture.string(at: "inputs.app_name")
        let aspect   = try fixture.string(at: "inputs.aspect")
        let expected = try fixture.hexData(at: "expected.destination_hash_hex")

        let hash = Destination.hash(appName: appName, aspects: [aspect], identityHash: nil)
        #expect(hash == expected,
                "PLAIN hash mismatch — expected \(expected.hexString), got \(hash.hexString)")
    }

    @Test("PLAIN: destination_hash is exactly 16 bytes")
    func plainHashLengthIs16Bytes() throws {
        let fixture = try loadDestinationFixture(name: "destination_plain")
        let appName = try fixture.string(at: "inputs.app_name")
        let aspect  = try fixture.string(at: "inputs.aspect")

        let hash = Destination.hash(appName: appName, aspects: [aspect], identityHash: nil)
        #expect(hash.count == 16)
    }

    @Test("PLAIN: destination_name is '<app>.<aspect>' with no identity suffix")
    func plainDestinationNameFormat() throws {
        let fixture      = try loadDestinationFixture(name: "destination_plain")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let expectedName = try fixture.string(at: "expected.destination_name")

        let name = Destination.fullName(appName: appName, aspects: [aspect], identityHash: nil)
        #expect(name == expectedName,
                "PLAIN destination_name mismatch — expected '\(expectedName)', got '\(name)'")
    }

    @Test("PLAIN: name_hash matches Python reference (10 bytes)")
    func plainNameHashMatchesReference() throws {
        let fixture  = try loadDestinationFixture(name: "destination_plain")
        let appName  = try fixture.string(at: "inputs.app_name")
        let aspect   = try fixture.string(at: "inputs.aspect")
        let expected = try fixture.hexData(at: "expected.name_hash_hex")

        let nameHash = Destination.nameHash(appName: appName, aspects: [aspect])
        #expect(nameHash == expected,
                "PLAIN name_hash mismatch — expected \(expected.hexString), got \(nameHash.hexString)")
    }

    @Test("PLAIN: name_hash is exactly 10 bytes")
    func plainNameHashLengthIs10Bytes() throws {
        let fixture = try loadDestinationFixture(name: "destination_plain")
        let appName = try fixture.string(at: "inputs.app_name")
        let aspect  = try fixture.string(at: "inputs.aspect")

        let nameHash = Destination.nameHash(appName: appName, aspects: [aspect])
        #expect(nameHash.count == 10)
    }
}

// Destination Serialisation

@Suite("Destination — Serialisation")
struct DestinationSerialisationTests {

    // MARK: SINGLE

    @Test("SINGLE: Destination instance hash equals expected 16-byte value (identity_a)")
    func singleDestinationInstanceHashIdentityA() throws {
        let fixture      = try loadDestinationFixture(name: "destination_single_identity_a")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let identityHash = try fixture.hexData(at: "inputs.identity_hash_hex")
        let expected     = try fixture.hexData(at: "expected.destination_hash_hex")

        let dest = Destination(appName: appName, aspects: [aspect], identityHash: identityHash)
        #expect(dest.hash == expected)
        #expect(dest.hash.count == 16)
    }

    @Test("SINGLE: Destination instance hash equals expected 16-byte value (identity_b)")
    func singleDestinationInstanceHashIdentityB() throws {
        let fixture      = try loadDestinationFixture(name: "destination_single_identity_b")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let identityHash = try fixture.hexData(at: "inputs.identity_hash_hex")
        let expected     = try fixture.hexData(at: "expected.destination_hash_hex")

        let dest = Destination(appName: appName, aspects: [aspect], identityHash: identityHash)
        #expect(dest.hash == expected)
    }

    @Test("SINGLE: Destination instance name property matches Python reference")
    func singleDestinationInstanceName() throws {
        let fixture      = try loadDestinationFixture(name: "destination_single_identity_a")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let identityHash = try fixture.hexData(at: "inputs.identity_hash_hex")
        let expected     = try fixture.string(at: "expected.destination_name")

        let dest = Destination(appName: appName, aspects: [aspect], identityHash: identityHash)
        #expect(dest.name == expected)
    }

    @Test("SINGLE: Destination instance nameHash property matches Python reference")
    func singleDestinationInstanceNameHash() throws {
        let fixture      = try loadDestinationFixture(name: "destination_single_identity_a")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let identityHash = try fixture.hexData(at: "inputs.identity_hash_hex")
        let expected     = try fixture.hexData(at: "expected.name_hash_hex")

        let dest = Destination(appName: appName, aspects: [aspect], identityHash: identityHash)
        #expect(dest.nameHash == expected)
        #expect(dest.nameHash.count == 10)
    }

    // MARK: PLAIN

    @Test("PLAIN: Destination instance hash equals expected 16-byte value")
    func plainDestinationInstanceHash() throws {
        let fixture  = try loadDestinationFixture(name: "destination_plain")
        let appName  = try fixture.string(at: "inputs.app_name")
        let aspect   = try fixture.string(at: "inputs.aspect")
        let expected = try fixture.hexData(at: "expected.destination_hash_hex")

        let dest = Destination(appName: appName, aspects: [aspect], identityHash: nil)
        #expect(dest.hash == expected)
        #expect(dest.hash.count == 16)
    }

    @Test("PLAIN: Destination instance name property matches Python reference")
    func plainDestinationInstanceName() throws {
        let fixture  = try loadDestinationFixture(name: "destination_plain")
        let appName  = try fixture.string(at: "inputs.app_name")
        let aspect   = try fixture.string(at: "inputs.aspect")
        let expected = try fixture.string(at: "expected.destination_name")

        let dest = Destination(appName: appName, aspects: [aspect], identityHash: nil)
        #expect(dest.name == expected)
    }

    @Test("PLAIN: Destination instance nameHash property matches Python reference")
    func plainDestinationInstanceNameHash() throws {
        let fixture  = try loadDestinationFixture(name: "destination_plain")
        let appName  = try fixture.string(at: "inputs.app_name")
        let aspect   = try fixture.string(at: "inputs.aspect")
        let expected = try fixture.hexData(at: "expected.name_hash_hex")

        let dest = Destination(appName: appName, aspects: [aspect], identityHash: nil)
        #expect(dest.nameHash == expected)
        #expect(dest.nameHash.count == 10)
    }

    // MARK: Cross-type invariants

    @Test("SINGLE destinations with different identities produce different hashes")
    func singleDifferentIdentitiesHaveDifferentHashes() throws {
        let fa = try loadDestinationFixture(name: "destination_single_identity_a")
        let fb = try loadDestinationFixture(name: "destination_single_identity_b")

        let destA = Destination(
            appName: try fa.string(at: "inputs.app_name"),
            aspects: [try fa.string(at: "inputs.aspect")],
            identityHash: try fa.hexData(at: "inputs.identity_hash_hex")
        )
        let destB = Destination(
            appName: try fb.string(at: "inputs.app_name"),
            aspects: [try fb.string(at: "inputs.aspect")],
            identityHash: try fb.hexData(at: "inputs.identity_hash_hex")
        )
        #expect(destA.hash != destB.hash)
    }

    @Test("SINGLE and PLAIN destinations with different aspects have different hashes")
    func singleAndPlainHaveDifferentHashes() throws {
        let fs = try loadDestinationFixture(name: "destination_single_identity_a")
        let fp = try loadDestinationFixture(name: "destination_plain")

        let destSingle = Destination(
            appName: try fs.string(at: "inputs.app_name"),
            aspects: [try fs.string(at: "inputs.aspect")],
            identityHash: try fs.hexData(at: "inputs.identity_hash_hex")
        )
        let destPlain = Destination(
            appName: try fp.string(at: "inputs.app_name"),
            aspects: [try fp.string(at: "inputs.aspect")],
            identityHash: nil
        )
        #expect(destSingle.hash != destPlain.hash)
    }

    @Test("Same inputs always produce the same hash (determinism)")
    func destinationHashIsDeterministic() throws {
        let fixture      = try loadDestinationFixture(name: "destination_single_identity_a")
        let appName      = try fixture.string(at: "inputs.app_name")
        let aspect       = try fixture.string(at: "inputs.aspect")
        let identityHash = try fixture.hexData(at: "inputs.identity_hash_hex")

        let dest1 = Destination(appName: appName, aspects: [aspect], identityHash: identityHash)
        let dest2 = Destination(appName: appName, aspects: [aspect], identityHash: identityHash)
        #expect(dest1.hash == dest2.hash)
    }
}
