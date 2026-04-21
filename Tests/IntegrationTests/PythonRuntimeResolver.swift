import Foundation

enum PythonRuntimeResolver {
    enum ResolverError: Error, LocalizedError {
        case noPythonInterpreter(candidates: [String])
        case commandLaunchFailed(command: String, message: String)
        case commandFailed(command: String, status: Int32, output: String)
        case dependencyBootstrapFailed(details: String)

        var errorDescription: String? {
            switch self {
            case .noPythonInterpreter(let candidates):
                let listed = candidates.isEmpty ? "(none)" : candidates.joined(separator: ", ")
                return """
                No usable Python 3 interpreter found.
                Checked: \(listed)
                Set INERTIA_PYTHON to a valid Python 3 path.
                """
            case .commandLaunchFailed(let command, let message):
                return "Failed to launch command '\(command)': \(message)"
            case .commandFailed(let command, let status, let output):
                let suffix = output.isEmpty ? "" : "\n\(output)"
                return "Command failed (\(status)): \(command)\(suffix)"
            case .dependencyBootstrapFailed(let details):
                return """
                Could not prepare Python dependencies for integration tests.
                \(details)
                Install manually with: python3 -m pip install rns lxmf
                """
            }
        }
    }

    private struct CommandResult {
        let status: Int32
        let output: String
    }

    private static let cacheLock = NSLock()
    nonisolated(unsafe) private static var cachedInterpreterPath: String?

    static func pythonExecutablePath() throws -> String {
        cacheLock.lock()
        defer { cacheLock.unlock() }

        if let cachedInterpreterPath, canImportDependencies(using: cachedInterpreterPath) {
            return cachedInterpreterPath
        }

        let candidates = interpreterCandidates()
        for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate) {
            if canImportDependencies(using: candidate) {
                cachedInterpreterPath = candidate
                return candidate
            }
        }

        guard let bootstrapPython = candidates.first(where: {
            FileManager.default.isExecutableFile(atPath: $0)
        }) else {
            throw ResolverError.noPythonInterpreter(candidates: candidates)
        }

        let venvPython = try provisionVirtualEnvironment(using: bootstrapPython)
        guard canImportDependencies(using: venvPython) else {
            throw ResolverError.dependencyBootstrapFailed(
                details: """
                Automatic bootstrap completed, but `import RNS, LXMF` still fails for:
                  \(venvPython)
                """
            )
        }

        cachedInterpreterPath = venvPython
        return venvPython
    }

    private static func interpreterCandidates() -> [String] {
        var candidates: [String] = []

        if let fromEnv = ProcessInfo.processInfo.environment["INERTIA_PYTHON"],
           !fromEnv.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            candidates.append((fromEnv as NSString).expandingTildeInPath)
        }

        if let fromPath = resolvePython3FromPath() {
            candidates.append(fromPath)
        }

        candidates.append(contentsOf: [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
            "/Applications/Xcode.app/Contents/Developer/usr/bin/python3",
        ])

        var unique: [String] = []
        var seen = Set<String>()
        for candidate in candidates {
            let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            if seen.insert(trimmed).inserted {
                unique.append(trimmed)
            }
        }
        return unique
    }

    private static func resolvePython3FromPath() -> String? {
        guard let result = try? runCommand(
            executable: "/usr/bin/env",
            arguments: ["which", "python3"],
            allowFailure: true
        ), result.status == 0 else {
            return nil
        }

        return result.output
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .first
    }

    private static func canImportDependencies(using pythonPath: String) -> Bool {
        guard FileManager.default.isExecutableFile(atPath: pythonPath) else {
            return false
        }
        guard let result = try? runCommand(
            executable: pythonPath,
            arguments: ["-c", "import RNS, LXMF"],
            allowFailure: true
        ) else {
            return false
        }
        return result.status == 0
    }

    private static func provisionVirtualEnvironment(using bootstrapPython: String) throws -> String {
        let fileManager = FileManager.default
        let venvURL = repositoryRootURL
            .appendingPathComponent(".build", isDirectory: true)
            .appendingPathComponent("integration-python-venv", isDirectory: true)
        let venvPythonURL = venvURL.appendingPathComponent("bin/python3")
        let venvPythonPath = venvPythonURL.path

        if !fileManager.isExecutableFile(atPath: venvPythonPath) {
            try fileManager.createDirectory(
                at: venvURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )

            try runCommand(
                executable: bootstrapPython,
                arguments: ["-m", "venv", venvURL.path]
            )
        }

        if !canImportDependencies(using: venvPythonPath) {
            _ = try? runCommand(
                executable: venvPythonPath,
                arguments: ["-m", "ensurepip", "--upgrade"],
                allowFailure: true
            )

            try runCommand(
                executable: venvPythonPath,
                arguments: [
                    "-m", "pip", "install",
                    "--disable-pip-version-check",
                    "--quiet",
                    "rns",
                    "lxmf",
                ]
            )
        }

        return venvPythonPath
    }

    @discardableResult
    private static func runCommand(
        executable: String,
        arguments: [String],
        allowFailure: Bool = false
    ) throws -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        let displayCommand = ([executable] + arguments).joined(separator: " ")
        do {
            try process.run()
        } catch {
            throw ResolverError.commandLaunchFailed(
                command: displayCommand,
                message: error.localizedDescription
            )
        }

        let outputData = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let output = String(data: outputData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let result = CommandResult(status: process.terminationStatus, output: output)

        if !allowFailure, result.status != 0 {
            throw ResolverError.commandFailed(
                command: displayCommand,
                status: result.status,
                output: result.output
            )
        }

        return result
    }

    private static var repositoryRootURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // Tests/IntegrationTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repo root
    }
}
