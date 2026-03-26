import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var biometricErrorMessage: String?

    private let intervalOptions: [(label: String, seconds: TimeInterval)] = [
        ("5 minutes",   300),
        ("15 minutes",  900),
        ("30 minutes",  1800),
        ("1 hour", 3600),
        ("3 hours", 10800)
    ]

    var body: some View {
        NavigationStack {
            Form {
                // MARK: Servers
                Section {
 NavigationLink(destination: ServersView()) {
     HStack {
         Label("Servers", systemImage: "server.rack")
         Spacer()
         serverSummary
     }
 }
                } header: {
 Text("Reticulum Network")
                }

                // MARK: Announce
                Section {
 @Bindable var m = model

 HStack {
     Label("Display Name", systemImage: "person.text.rectangle")
     Spacer()
     TextField("Anonymous Inertia User", text: $m.displayName)
         .multilineTextAlignment(.trailing)
         .foregroundStyle(.secondary)
         .submitLabel(.done)
 }

 Toggle("Auto-Announce", isOn: $m.autoAnnounce)

 if model.autoAnnounce {
     Picker("Interval", selection: $m.announceInterval) {
         ForEach(intervalOptions, id: \.seconds) { opt in
             Text(opt.label).tag(opt.seconds)
         }
     }
 }

 Button {
     model.sendAnnounce()
 } label: {
     Label("Announce Now", systemImage: "megaphone")
 }
 .disabled(!model.isAnyConnected)
                } header: {
 Text("Announce")
                } footer: {
 Text("Broadcasting your identity lets other nodes discover and message you.")
                }

                // MARK: LXMF stamps
                Section {
                    @Bindable var m = model

                    Toggle("Inbound message notifications", isOn: $m.inboundNotificationsEnabled)
                } header: {
 Text("Notifications")
                } footer: {
 Text("Local notifications are shown when messages arrive while Inertia is not active.")
                }

                // MARK: Identity
                Section {
 NavigationLink(destination: IdentityView()) {
      Label("Identity & Address", systemImage: "key.horizontal")
  }
                } header: {
  Text("Cryptographic Identity")
                } footer: {
  Text("Your identity hash: \(model.identityHashHex.prefix(8))…")
      .font(.system(.footnote, design: .monospaced))
                }

                Section {
                    NavigationLink(destination: MessagingDeliverySettingsView()) {
                        Label("Messaging & Propagation", systemImage: "tray.and.arrow.up")
                    }
                } header: {
                    Text("Messaging")
                } footer: {
                    Text("Configure inbound stamp cost and active propagation node.")
                }

                Section {
                    Toggle(
                        "Biometric Lock",
                        isOn: Binding(
                            get: { model.biometricLockEnabled },
                            set: { enabled in
                                Task {
                                    do {
                                        try await model.setBiometricLockEnabled(enabled)
                                        biometricErrorMessage = nil
                                    } catch {
                                        biometricErrorMessage = error.localizedDescription
                                    }
                                }
                            }
                        )
                    )

                    if model.biometricLockEnabled {
                        Toggle("Lock when app backgrounds", isOn: Binding(
                            get: { model.biometricLockOnBackground },
                            set: { model.biometricLockOnBackground = $0 }
                        ))
                    }
                } header: {
                    Text("App Security")
                } footer: {
                    if let biometricErrorMessage, !biometricErrorMessage.isEmpty {
                        Text(biometricErrorMessage)
                    } else if model.availableBiometry == .none {
                        Text("Biometric authentication is unavailable on this device.")
                    } else {
                        Text("Use \(model.biometricTypeLabel) to unlock Inertia.")
                    }
                }

                // MARK: Network status
                Section {
 NavigationLink(destination: NetworkStatusView()) {
     Label("Network Status", systemImage: "network")
 }
                } header: {
 Text("Diagnostics")
                }

                // MARK: About
                Section("About") {
                    LabeledContent("Version", value: "1.0")
                    LabeledContent("Protocol", value: "Reticulum 1.1+")
                    LabeledContent("LXMF", value: "0.9.4+")
                }

                Section {
                    Button {
                        model.restartOnboarding()
                    } label: {
                        Label("Run onboarding again", systemImage: "sparkles")
                    }
                } header: {
                    Text("Onboarding")
                } footer: {
                    Text("Reopens the first-run guide to update nickname, interfaces, and setup help.")
                }

                Section("Community") {
                    Link(destination: URL(string: "https://matrix.to/#/#inertia:inyourair.space")!) {
                        Label("Matrix Chat", systemImage: "message")
                    }

                    Link(destination: URL(string: "https://github.com/psharma04/inertia")!) {
                        Label("GitHub", systemImage: "link")
                    }
                }
            }
            .navigationTitle("Settings")
        }
    }

    @ViewBuilder
    private var serverSummary: some View {
        let connected = model.connectedCount
        let total     = model.servers.count
        if connected > 0 {
            Text("\(connected)/\(total) online")
                .font(.callout)
                .foregroundStyle(.green)
        } else {
            Text(total == 0 ? "None configured" : "Offline")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

}

private struct MessagingDeliverySettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var inboundStampCostText = ""
    @State private var newPropagationNodeHex = ""
    @State private var newPropagationNodeName = ""
    @State private var propagationNodeError: String?

    var body: some View {
        Form {
            Section {
                TextField("None", text: $inboundStampCostText)
                    .keyboardType(.numberPad)
                    .multilineTextAlignment(.trailing)
                    .onChange(of: inboundStampCostText) { _, newValue in
                        applyInboundStampCostInput(newValue)
                    }
            } header: {
                Text("LXMF Stamps")
            } footer: {
                Text("Optional inbound stamp cost for messages sent to your lxmf.delivery destination (1-254). Leave empty to disable.")
            }

            Section {
                @Bindable var m = model

                Toggle("Auto-select best node", isOn: $m.autoSelectBestPropagationNode)

                if model.configuredPropagationNodes.isEmpty {
                    Text("No propagation nodes configured")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.configuredPropagationNodes) { peer in
                        HStack {
                            Button {
                                model.selectPropagationNode(hash: peer.destinationHash)
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(peer.effectiveName)
                                    Text(peer.shortHash + "…")
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                    if peer.announcedPropagationEnabled == false {
                                        Text("Announced: disabled")
                                            .font(.caption2)
                                            .foregroundStyle(.orange)
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            Spacer()
                            if let hops = peer.pathHops {
                                Text("\(hops) hop\(hops == 1 ? "" : "s")")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            Image(systemName: peer.destinationHash == model.selectedPropagationNodeHash ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(peer.destinationHash == model.selectedPropagationNodeHash ? Color.accentColor : Color.secondary)
                        }
                    }
                }

                LabeledContent("Active Node") {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(model.selectedPropagationNode?.effectiveName ?? "Custom Propagation Node")
                        Text(model.selectedPropagationNodeHashHex + "…")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                        if model.autoSelectBestPropagationNode {
                            Text("Automatically selected")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                TextField("Node hash (32 hex chars)", text: $newPropagationNodeHex)
                    .font(.system(.body, design: .monospaced))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                TextField("Optional name", text: $newPropagationNodeName)
                    .autocorrectionDisabled()

                if let propagationNodeError {
                    Label(propagationNodeError, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                        .font(.footnote)
                }

                Button {
                    addPropagationNode()
                } label: {
                    Label("Add Propagation Node", systemImage: "plus.circle")
                }
            } header: {
                Text("Propagation Nodes")
            } footer: {
                Text("Only one propagation node is active at a time. With auto-select enabled, Inertia periodically picks the best announced and reachable node (preferring fewer hops).")
            }
        }
        .navigationTitle("Messaging & Propagation")
        .onAppear {
            inboundStampCostText = model.inboundStampCost.map(String.init) ?? ""
        }
    }

    private func addPropagationNode() {
        propagationNodeError = nil
        guard let hash = Data(hexString: newPropagationNodeHex),
              hash.count == 16 else {
            propagationNodeError = "Propagation node hash must be 32 hex characters."
            return
        }

        model.addPropagationNode(
            hash: hash,
            displayName: newPropagationNodeName
        )
        newPropagationNodeHex = ""
        newPropagationNodeName = ""
    }

    private func applyInboundStampCostInput(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            model.inboundStampCost = nil
            if inboundStampCostText != "" { inboundStampCostText = "" }
            return
        }

        let digitsOnly = trimmed.filter { $0.isNumber }
        if digitsOnly != raw {
            inboundStampCostText = digitsOnly
        }

        guard let parsed = Int(digitsOnly), parsed > 0, parsed < 255 else {
            return
        }
        model.inboundStampCost = parsed
    }
}
