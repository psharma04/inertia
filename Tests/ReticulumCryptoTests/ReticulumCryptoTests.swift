import Testing
@testable import ReticulumCrypto

// ReticulumCrypto Module Tests
//
// All tests in this module follow TDD:
//   1. Write a failing test
//   2. Implement minimal code to pass
//   3. Refactor
//
// Binary/cryptographic tests must use deterministic test vectors
// verified against the Python RNS reference implementation.

@Suite("ReticulumCrypto")
struct ReticulumCryptoTests {
    // Tests will be added here as features are implemented.
    // First features to test:
    //   - Identity key generation (Ed25519 + X25519)
    //   - Identity hash derivation (SHA-256 truncated to 16 bytes)
    //   - Signature round-trip (sign then verify)
    //   - X25519 shared secret derivation
    //   - HKDF key derivation with known test vectors
}
