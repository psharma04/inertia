import SwiftUI

struct ContentView: View {
    @Environment(AppModel.self) private var model
    @State private var unlockErrorMessage: String?

    var body: some View {
        ZStack {
            if model.shouldShowOnboarding {
                OnboardingView()
            } else {
                TabView(selection: Bindable(model).selectedTab) {
                    Tab("Messages", systemImage: "bubble.left.and.bubble.right", value: .messages) {
                        ConversationsView()
                    }
                    .accessibilityIdentifier("tab-messages")
                    Tab("Peers", systemImage: "person.wave.2", value: .peers) {
                        PeersView()
                    }
                    .accessibilityIdentifier("tab-peers")
                    Tab("Nomad", systemImage: "safari", value: .nomad) {
                        NomadBrowserView()
                    }
                    .accessibilityIdentifier("tab-nomad")
                    Tab("Settings", systemImage: "gear", value: .settings) {
                        SettingsView()
                    }
                    .accessibilityIdentifier("tab-settings")
                }
                .alert("Deep Link Error", isPresented: Binding(
                    get: { model.deepLinkError != nil },
                    set: { if !$0 { model.deepLinkError = nil } }
                )) {
                    Button("OK") { model.deepLinkError = nil }
                } message: {
                    Text(model.deepLinkError ?? "")
                }
            }

            if !model.shouldShowOnboarding && model.isAppLocked {
                AppLockOverlay(
                    biometricLabel: model.biometricTypeLabel,
                    biometricSystemImageName: model.biometricSystemImageName,
                    errorMessage: unlockErrorMessage
                ) {
                    Task {
                        let unlocked = await model.unlockWithBiometricsIfNeeded(reason: "Unlock Inertia")
                        if unlocked {
                            unlockErrorMessage = nil
                        } else {
                            unlockErrorMessage = "Authentication failed. Try \(model.biometricTypeLabel) again or use your device passcode."
                        }
                    }
                }
            }
        }
        .task {
            if model.biometricLockEnabled && !model.shouldShowOnboarding {
                let unlocked = await model.unlockWithBiometricsIfNeeded(reason: "Unlock Inertia")
                if unlocked {
                    unlockErrorMessage = nil
                } else {
                    unlockErrorMessage = "Authentication failed. Try \(model.biometricTypeLabel) again or use your device passcode."
                }
            }
        }
    }
}

private struct AppLockOverlay: View {
    let biometricLabel: String
    let biometricSystemImageName: String
    let errorMessage: String?
    let unlockAction: () -> Void

    var body: some View {
        Rectangle()
            .fill(.ultraThinMaterial)
            .ignoresSafeArea()
            .overlay {
                VStack(spacing: 12) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 28, weight: .semibold))
                    Text("Inertia Locked")
                        .font(.headline)
                    Text("Authenticate with \(biometricLabel) to continue.")
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    if let errorMessage, !errorMessage.isEmpty {
                        Text(errorMessage)
                            .font(.footnote)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                    }
                    Button {
                        unlockAction()
                    } label: {
                        Label("Unlock with \(biometricLabel)", systemImage: biometricSystemImageName)
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(24)
                .frame(maxWidth: 360)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .padding()
            }
    }
}

struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    @State private var step = 0
    @State private var nickname = ""
    @State private var addingServer = false
    @State private var editingServer: ServerConfig?

    private let totalSteps = 4

    var body: some View {
        NavigationStack {
            VStack(spacing: 18) {
                ProgressView(value: Double(step + 1), total: Double(totalSteps))
                    .padding(.top, 8)

                Group {
                    switch step {
                    case 0:
                        welcomeStep
                    case 1:
                        nicknameStep
                    case 2:
                        interfacesStep
                    default:
                        guideStep
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .animation(.easeInOut(duration: 0.2), value: step)

                controls
            }
            .padding(.horizontal)
            .padding(.bottom)
            .navigationTitle("Welcome to Inertia")
            .navigationBarTitleDisplayMode(.inline)
            .interactiveDismissDisabled(true)
            .sheet(isPresented: $addingServer) {
                AddEditServerView(existing: nil)
            }
            .sheet(item: $editingServer) { server in
                AddEditServerView(existing: server)
            }
            .onAppear {
                nickname = suggestedNickname()
            }
        }
    }

    @ViewBuilder
    private var welcomeStep: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Label("Let's get you set up.", systemImage: "network")
                    .font(.title3.bold())

                Text("This onboarding helps you set your nickname, configure TCP interfaces, and quickly understand what works in the app.")
                    .foregroundStyle(.secondary)

                Text("Inertia is still alpha software, and not all features are working, even if they're in the UI. Known broken functions can be found on GitHub.")
                    .foregroundStyle(.secondary)

                Text("You can rerun onboarding anytime from Settings.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 8)
        }
    }

    @ViewBuilder
    private var nicknameStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Set your nickname", systemImage: "person.text.rectangle")
                .font(.title3.bold())

            Text("Your nickname is included in announce data so other people can identify you.")
                .foregroundStyle(.secondary)

            TextField("Anonymous Inertia User", text: $nickname)
                .textInputAutocapitalization(.words)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)

            Text("If you leave this blank, Inertia will use an anonymous default name.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder
    private var interfacesStep: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Label("Configure TCP Servers", systemImage: "server.rack")
                    .font(.title3.bold())

                Text("Add one or more Reticulum TCP servers. Inertia will connect to all configured servers.")
                    .foregroundStyle(.secondary)

                if model.servers.isEmpty {
                    Text("No interfaces configured yet.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.servers) { server in
                        HStack {
                            Circle()
                                .fill(serverStatusColor(for: server.id))
                                .frame(width: 10, height: 10)

                            VStack(alignment: .leading, spacing: 2) {
                                Text(server.displayName).font(.headline)
                                Text("\(server.host):\(server.port, format: .number.grouping(.never))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Edit") { editingServer = server }
                                .buttonStyle(.bordered)
                        }
                    }
                }

                HStack {
                    Button {
                        addingServer = true
                    } label: {
                        Label("Add Interface", systemImage: "plus")
                    }
                    .buttonStyle(.borderedProminent)

                    Button {
                        runConnectionTest()
                    } label: {
                        Label("Test Connections", systemImage: "bolt.horizontal")
                    }
                    .buttonStyle(.bordered)
                    .disabled(model.servers.isEmpty)
                }

                Text("Default server: rns.inertia.chat:4242. This is a public server hosted by the Inertia devs.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 8)
        }
    }

    @ViewBuilder
    private var guideStep: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Label("Where things are", systemImage: "map")
                    .font(.title3.bold())

                Text("Messages: send and receive LXMF")
                Text("Peers: discovered destinations and metadata")
                Text("Nomad: browse pages, files, and interact with nodes")
                Text("Settings: interfaces, announce, propagation, identity, diagnostics")

                Divider().padding(.vertical, 4)

                Label("Current status", systemImage: "wrench.and.screwdriver")
                    .font(.headline)

                Text("Working now:")
                    .font(.subheadline.bold())
                Text("• Opportunistic, direct, and propagated delivery")
                Text("• Announce handling and route/path refresh")
                Text("• Sent/delivered outbound markers")
                Text("• AutoInterface (multicast peer discovery)")
                Text("• Stamps and propagation node sync")
                Text("• NomadNet page browsing and Micron rendering")
                Text("• Image and file attachments")

                Text("Not complete yet:")
                    .font(.subheadline.bold())
                    .padding(.top, 4)
                Text("• RNode/serial interface support")
                Text("• Reticulum Resource transfers (large NomadNet pages)")
                Text("You can find the current status and known issues at")
                    .font(.subheadline.bold())
                    .padding(.top, 4)
                Link("https://github.com/psharma04/Inertia", destination: URL(string: "https://github.com/psharma04/Inertia")!)
                    .font(.subheadline.bold())
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 8)
        }
    }

    @ViewBuilder
    private var controls: some View {
        HStack {
            if step > 0 {
                Button("Back") { step = max(0, step - 1) }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("onboarding-back")
            }

            Spacer()

            if step < totalSteps - 1 {
                Button("Next") { step = min(totalSteps - 1, step + 1) }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("onboarding-next")
            } else {
                Button("Finish") {
                    model.completeOnboarding(nickname: nickname)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("onboarding-finish")
            }
        }
    }

    private func suggestedNickname() -> String {
        let trimmed = model.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed == "Anonymous Inertia User" {
            return ""
        }
        return trimmed
    }

    private func runConnectionTest() {
        for server in model.servers {
            model.disconnect(serverId: server.id)
        }
        for server in model.servers {
            model.connect(serverId: server.id)
        }
    }

    private func serverStatusColor(for serverID: UUID) -> Color {
        if model.serverStatuses[serverID] == true { return .green }
        if model.serverStatuses[serverID] == false { return .red }
        return Color(.systemGray4)
    }
}
