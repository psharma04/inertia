import SwiftUI
import UniformTypeIdentifiers

private struct IdentityBackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    var data: Data

    init(data: Data) {
        self.data = data
    }

    init(configuration: ReadConfiguration) throws {
        guard let loaded = configuration.file.regularFileContents else {
            throw IdentityBackupCodecError.invalidBackupFile
        }
        self.data = loaded
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

/// Displays the local identity hash and LXMF destination address,
/// with copy and share actions for each.
struct IdentityView: View {
    @Environment(AppModel.self) private var model
    @State private var showRegenerateConfirm = false
    @State private var copiedField: CopiedField?
    @State private var showExportPasswordPrompt = false
    @State private var showImportPasswordPrompt = false
    @State private var exportPassword = ""
    @State private var importPassword = ""
    @State private var pendingImportedData: Data?
    @State private var backupDocument: IdentityBackupDocument?
    @State private var showingFileExporter = false
    @State private var showingFileImporter = false
    @State private var exportResultMessage: String?
    @State private var restoreResultMessage: String?
    @State private var importErrorMessage: String?
    @State private var operationErrorMessage: String?
    @State private var restoreSummaryMessage: String?

    enum CopiedField { case identity, lxmf }

    var body: some View {
        List {
            identitySection
            lxmfSection
            backupSection
            dangerSection
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Identity")
        .navigationBarTitleDisplayMode(.large)
        .confirmationDialog(
            "Regenerate Identity?",
            isPresented: $showRegenerateConfirm,
            titleVisibility: .visible
        ) {
            Button("Regenerate", role: .destructive) {
                model.regenerateIdentity()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will replace your cryptographic identity. Your current identity hash will no longer be associated with this device.")
        }
        .alert("Export Backup", isPresented: Binding(
            get: { exportResultMessage != nil },
            set: { if !$0 { exportResultMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(exportResultMessage ?? "")
        }
        .alert("Restore Backup", isPresented: Binding(
            get: { restoreResultMessage != nil },
            set: { if !$0 { restoreResultMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(restoreResultMessage ?? "")
        }
        .alert("Identity Error", isPresented: Binding(
            get: { operationErrorMessage != nil },
            set: { if !$0 { operationErrorMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(operationErrorMessage ?? "")
        }
        .alert("Password for Backup", isPresented: $showExportPasswordPrompt) {
            SecureField("Optional password", text: $exportPassword)
            Button("Export") { performExport() }
            Button("Cancel", role: .cancel) {
                exportPassword = ""
            }
        } message: {
            Text("Leave empty to export without password protection.")
        }
        .alert("Backup Password Required", isPresented: $showImportPasswordPrompt) {
            SecureField("Backup password", text: $importPassword)
            Button("Restore") { performRestoreFromPendingData() }
            Button("Cancel", role: .cancel) {
                pendingImportedData = nil
                importPassword = ""
            }
        } message: {
            Text("This backup is encrypted. Enter its password to restore your identity.")
        }
        .fileExporter(
            isPresented: $showingFileExporter,
            document: backupDocument,
            contentType: .json,
            defaultFilename: backupFilename
        ) { result in
            switch result {
            case .success:
                exportResultMessage = "Identity backup exported successfully."
            case .failure(let error):
                operationErrorMessage = error.localizedDescription
            }
            backupDocument = nil
        }
        .fileImporter(
            isPresented: $showingFileImporter,
            allowedContentTypes: [.json],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                loadSelectedBackupFile(url)
            case .failure(let error):
                operationErrorMessage = error.localizedDescription
            }
        }
    }

    // Identity hash section

    private var identitySection: some View {
        Section {
            hashRow(
                label: "Identity Hash",
                value: model.identityHashHex,
                icon: "key",
                isCopied: copiedField == .identity
            ) {
                copy(model.identityHashHex)
                copiedField = .identity
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
 if copiedField == .identity { copiedField = nil }
                }
            }
        } header: {
            Text("Reticulum Identity")
        } footer: {
            Text("Your 16-byte (32 hex character) identity hash, derived from your X25519/Ed25519 public key pair. Share this so others can look up your public key.")
        }
    }

    // LXMF address section

    private var lxmfSection: some View {
        Section {
            hashRow(
                label: "LXMF Address",
                value: model.lxmfAddressHex,
                icon: "envelope",
                isCopied: copiedField == .lxmf
            ) {
                copy(model.lxmfAddressHex)
                copiedField = .lxmf
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
 if copiedField == .lxmf { copiedField = nil }
                }
            }
        } header: {
            Text("LXMF Delivery Address")
        } footer: {
            Text("Your lxmf.delivery destination hash — this is your messaging address. Share this with contacts so they can send you messages.")
        }
    }

    private var backupSection: some View {
        Section {
            Button {
                showExportPasswordPrompt = true
            } label: {
                Label("Export Identity Backup…", systemImage: "square.and.arrow.up")
            }

            Button {
                showingFileImporter = true
            } label: {
                Label("Restore Identity from Backup…", systemImage: "square.and.arrow.down")
            }

            if let restoreSummaryMessage, !restoreSummaryMessage.isEmpty {
                Label(restoreSummaryMessage, systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                    .font(.footnote)
            }
        } header: {
            Text("Backup & Restore")
        } footer: {
            Text("Backups include your private Reticulum identity key. Export with an optional password for encrypted backup data.")
        }
    }

    // Danger zone

    private var dangerSection: some View {
        Section {
            Button("Regenerate Identity…", role: .destructive) {
                showRegenerateConfirm = true
            }
        } header: {
            Text("Danger Zone")
        } footer: {
            Text("Generating a new identity creates a new key pair. Your old address will no longer receive messages on this device.")
        }
    }

    // Shared hash row

    @ViewBuilder
    private func hashRow(
        label: String,
        value: String,
        icon: String,
        isCopied: Bool,
        onCopy: @escaping () -> Void
    ) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(label, systemImage: icon)
                .font(.subheadline.bold())
                .foregroundStyle(.secondary)

            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 12) {
                Button {
 onCopy()
                } label: {
 Label(
     isCopied ? "Copied!" : "Copy",
     systemImage: isCopied ? "checkmark" : "doc.on.doc"
 )
 .font(.callout)
 .animation(.default, value: isCopied)
                }
                .buttonStyle(.bordered)
                .tint(isCopied ? .green : .accentColor)

                ShareLink(item: value) {
 Label("Share", systemImage: "square.and.arrow.up")
     .font(.callout)
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(.vertical, 4)
    }

    private func copy(_ string: String) {
        UIPasteboard.general.string = string
    }

    private var backupFilename: String {
        let prefix = String(model.identityHashHex.prefix(8))
        return "inertia-identity-\(prefix).json"
    }

    private func performExport() {
        do {
            let normalized = exportPassword.trimmingCharacters(in: .whitespacesAndNewlines)
            let data = try model.exportIdentityBackup(password: normalized.isEmpty ? nil : normalized)
            backupDocument = IdentityBackupDocument(data: data)
            showingFileExporter = true
            exportPassword = ""
        } catch {
            operationErrorMessage = error.localizedDescription
        }
    }

    private func loadSelectedBackupFile(_ url: URL) {
        do {
            let didAccess = url.startAccessingSecurityScopedResource()
            defer {
                if didAccess {
                    url.stopAccessingSecurityScopedResource()
                }
            }
            let data = try Data(contentsOf: url)
            pendingImportedData = data
            importPassword = ""
            do {
                try model.restoreIdentityBackup(from: data, password: nil)
                restoreSummaryMessage = "Identity restored successfully."
                restoreResultMessage = "Backup restored. Your new identity hash is \(model.identityHashHex)."
                pendingImportedData = nil
            } catch IdentityBackupCodecError.passwordRequired {
                showImportPasswordPrompt = true
            } catch {
                operationErrorMessage = error.localizedDescription
                pendingImportedData = nil
            }
        } catch {
            operationErrorMessage = error.localizedDescription
            pendingImportedData = nil
        }
    }

    private func performRestoreFromPendingData() {
        guard let data = pendingImportedData else { return }
        do {
            let normalized = importPassword.trimmingCharacters(in: .whitespacesAndNewlines)
            try model.restoreIdentityBackup(from: data, password: normalized.isEmpty ? nil : normalized)
            restoreSummaryMessage = "Identity restored successfully."
            restoreResultMessage = "Backup restored. Your new identity hash is \(model.identityHashHex)."
            pendingImportedData = nil
            importPassword = ""
        } catch {
            operationErrorMessage = error.localizedDescription
        }
    }
}
