import Foundation

// PythonNodeHelper

final class PythonNodeHelper: @unchecked Sendable {

    // Nested types

    /// Information printed by the Python node on the READY line.
    struct ReadyInfo: Sendable {
        /// TCP port the Python node is listening on.
        let port: UInt16
        /// 16-byte RNS identity hash of the Python node's identity.
        let identityHash: Data
        /// 16-byte LXMF delivery destination hash (`lxmf.delivery`).
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
            case .scriptNotFound:
                return "rns_test_node.py not found in test bundle Resources/"
            case .processLaunchFailed(let msg):
                return "Python process launch failed: \(msg)"
            case .dependencySetupFailed(let msg):
                return "Python dependency setup failed: \(msg)"
            case .timeout(let ctx):
                return "Timed out waiting for '\(ctx)' from Python node"
            case .pythonNodeError(let msg):
                return "Python node reported error: \(msg)"
            case .malformedReadyLine(let line):
                return "Malformed READY line from Python node: '\(line)'"
            }
        }
    }

    // Private state

    private let process: Process
    private let readHandle: FileHandle
    /// Accumulated stdout text not yet consumed by a waitFor* call.
    /// Protected by `bufferMutex` — only ever mutated from `appendAvailable()`.
    nonisolated(unsafe) private var outputBuffer = ""
    private let bufferMutex = NSLock()

    // Lifecycle

    init(waitTimeout: TimeInterval = 30) throws {
        guard let scriptURL = Bundle.module.url(
            forResource: "rns_test_node", withExtension: "py"
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
        proc.arguments = [scriptURL.path, String(waitTimeout)]

        let outPipe = Pipe()
        proc.standardOutput = outPipe
        // Suppress Python tracebacks from polluting test output.
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
        } catch {
            throw HelperError.processLaunchFailed(error.localizedDescription)
        }

        self.process    = proc
        self.readHandle = outPipe.fileHandleForReading
    }

    deinit { stop() }

    /// Terminate the Python subprocess.
    func stop() {
        if process.isRunning { process.terminate() }
    }

    // Protocol reading

    func waitForReady(timeout: TimeInterval) async throws -> ReadyInfo {
        let line = try await waitForLine(prefix: "READY ", timeout: timeout)
        return try parseReadyLine(line)
    }

    func waitForMessage(timeout: TimeInterval) async throws -> String {
        let line = try await waitForLine(prefix: "RECEIVED ", timeout: timeout)
        return String(line.dropFirst("RECEIVED ".count))
    }

    // Private helpers

    /// Poll the pipe until a line starting with `prefix` appears, or timeout.
    private func waitForLine(prefix: String, timeout: TimeInterval) async throws -> String {
        let deadline = Date().addingTimeInterval(timeout)

        while Date() < deadline {
            // Synchronous helper to drain the pipe and snapshot the buffer —
            // avoids holding a lock across a suspension point.
            let snapshot = drainAndSnapshot()

            for line in snapshot.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("ERROR ") {
 throw HelperError.pythonNodeError(
     String(trimmed.dropFirst("ERROR ".count))
 )
                }
                if trimmed.hasPrefix(prefix) {
 return trimmed
                }
            }

            try await Task.sleep(nanoseconds: 100_000_000) // 100 ms poll
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
        // "READY <port> <identity_hash_hex> <dest_hash_hex>"
        let parts = line.split(separator: " ")
        guard
            parts.count == 4,
            let port = UInt16(parts[1]),
            let identityHash = Data(hexString: String(parts[2])),
            identityHash.count == 16,
            let destHash = Data(hexString: String(parts[3])),
            destHash.count == 16
        else {
            throw HelperError.malformedReadyLine(line)
        }
        return ReadyInfo(port: port, identityHash: identityHash, destinationHash: destHash)
    }
}

// Data hex helpers (local to IntegrationTests target)

extension Data {
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

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
