import Testing
import Foundation
import Security
@testable import ReticulumCrypto
@testable import ReticulumPackets
@testable import ReticulumInterfaces
@testable import LXMF

// LXMF Messaging Tests (via rns.inertia.chat relay)
//
// End-to-end bidirectional tests using rns.inertia.chat:4242 as the shared
// relay between the Swift stack and a Python Reticulum node.
//
// Both sides connect to the same public relay — no local TCP server is needed.
//
// Suite 1 — Swift → Python
//   Verifies that Swift can create, sign, and deliver an LXMF message to a
//   Python node that is also connected to the public relay.
//
// Suite 2 — Python → Swift
//   Verifies that Swift can receive, decrypt, and parse an LXMF message sent
//   by a Python node via the public relay.
//
// Requirements:
//   - Network access to rns.inertia.chat:4242
//   - Python 3 (RNS/LXMF dependencies are auto-bootstrapped)
//
// Run with:
//   swift test --filter LXMFMessagingTests

// PublicRelayNodeHelper

/// Manages a Python Reticulum node subprocess that connects to rns.inertia.chat.
///
/// stdout protocol:
///   READY <identity_hash_hex(32)> <lxmf_dest_hash_hex(32)>
///   RECEIVED <content_utf8>
///   SENT
///   ERROR <reason>
final class PublicRelayNodeHelper: @unchecked Sendable {

    struct ReadyInfo: Sendable {
        let identityHash:   Data
        let destinationHash: Data
    }

    enum HelperError: Error, CustomStringConvertible {
        case scriptNotFound
        case processLaunchFailed(String)
        case dependencySetupFailed(String)
        case timeout(String)
        case pythonNodeError(String)
        case malformedReadyLine(String)

        var description: String {
            switch self {
            case .scriptNotFound: return "rns_messaging_node.py not found in Resources/"
            case .processLaunchFailed(let m):        return "Python launch failed: \(m)"
            case .dependencySetupFailed(let m):      return "Python dependency setup failed: \(m)"
            case .timeout(let c): return "Timed out waiting for '\(c)'"
            case .pythonNodeError(let m):            return "Python node error: \(m)"
            case .malformedReadyLine(let l):         return "Malformed READY line: '\(l)'"
            }
        }
    }

    private let process:    Process
    private let readHandle: FileHandle
    nonisolated(unsafe) private var outputBuffer = ""
    private let bufferMutex = NSLock()

    /// - Parameters:
    ///   - swiftDestHashHex: When non-nil, Python will try to send a message
    ///     to this destination hash after announcing.
    ///   - waitTimeout:      How long (s) Python waits for an incoming message.
    init(swiftDestHashHex: String? = nil, waitTimeout: TimeInterval = 40) throws {
        guard let scriptURL = Bundle.module.url(
            forResource: "rns_messaging_node", withExtension: "py"
        ) else {
            throw HelperError.scriptNotFound
        }

        let proc = Process()
        let pythonExecutable: String
        do {
            pythonExecutable = try PythonRuntimeResolver.pythonExecutablePath()
        } catch {
            throw HelperError.dependencySetupFailed(error.localizedDescription)
        }
        proc.executableURL = URL(fileURLWithPath: pythonExecutable)
        var args = [scriptURL.path]
        if let h = swiftDestHashHex { args.append(h) }
        args.append(String(waitTimeout))
        proc.arguments = args

        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError  = FileHandle.nullDevice

        do { try proc.run() }
        catch { throw HelperError.processLaunchFailed(error.localizedDescription) }

        self.process    = proc
        self.readHandle = outPipe.fileHandleForReading
    }

    deinit { stop() }

    func stop() {
        if process.isRunning { process.terminate() }
    }

    func waitForReady(timeout: TimeInterval) async throws -> ReadyInfo {
        let line = try await waitForLine(prefix: "READY ", timeout: timeout)
        return try parseReadyLine(line)
    }

    func waitForMessage(timeout: TimeInterval) async throws -> String {
        let line = try await waitForLine(prefix: "RECEIVED ", timeout: timeout)
        return String(line.dropFirst("RECEIVED ".count))
    }

    func waitForSent(timeout: TimeInterval) async throws {
        _ = try await waitForLine(prefix: "SENT", timeout: timeout)
    }

    // MARK: Private

    private func waitForLine(prefix: String, timeout: TimeInterval) async throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let snapshot = drainAndSnapshot()
            for line in snapshot.components(separatedBy: "\n") {
                let t = line.trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("ERROR ") {
 throw HelperError.pythonNodeError(String(t.dropFirst("ERROR ".count)))
                }
                if t.hasPrefix(prefix) { return t }
            }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        throw HelperError.timeout(prefix.trimmingCharacters(in: .whitespaces))
    }

    private func drainAndSnapshot() -> String {
        let available = readHandle.availableData
        bufferMutex.lock()
        defer { bufferMutex.unlock() }
        if !available.isEmpty, let str = String(data: available, encoding: .utf8) {
            outputBuffer += str
        }
        return outputBuffer
    }

    private func parseReadyLine(_ line: String) throws -> ReadyInfo {
        // "READY <identity_hash_hex> <dest_hash_hex>"
        let parts = line.split(separator: " ")
        guard
            parts.count == 3,
            let identityHash = Data(hexString: String(parts[1])),
            identityHash.count == 16,
            let destHash = Data(hexString: String(parts[2])),
            destHash.count == 16
        else {
            throw HelperError.malformedReadyLine(line)
        }
        return ReadyInfo(identityHash: identityHash, destinationHash: destHash)
    }
}

// Relay-based messaging suites were removed because they are currently unstable
// in CI/local environments due to external relay timing dependencies.
