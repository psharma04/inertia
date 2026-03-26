import SwiftUI

struct ContactsDirectoryView: View {
    @Environment(AppModel.self) private var model
    @State private var searchText = ""

    private var filteredPeers: [DiscoveredPeer] {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return model.peers }
        return model.peers.filter { peer in
            peer.effectiveName.lowercased().contains(q)
                || peer.hashHex.lowercased().contains(q)
                || peer.shortHash.lowercased().contains(q)
                || (peer.displayName?.lowercased().contains(q) ?? false)
                || (peer.alias?.lowercased().contains(q) ?? false)
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if filteredPeers.isEmpty {
                    emptyState
                } else {
                    List(filteredPeers) { peer in
                        NavigationLink(destination: ContactDetailsView(destinationHash: peer.destinationHash)) {
                            ContactRow(peer: peer)
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Contacts")
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $searchText, prompt: "Search name or hash")
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "person.crop.circle.badge.questionmark")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)
            Text("No Contacts Yet")
                .font(.title2.bold())
            Text("Connect to a Reticulum node and wait for announces to discover peers.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(40)
    }
}

private struct ContactRow: View {
    let peer: DiscoveredPeer

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(.tint.opacity(0.15))
                .frame(width: 38, height: 38)
                .overlay {
                    Text(peer.shortHash.prefix(2).uppercased())
                        .font(.system(.subheadline, design: .monospaced).bold())
                        .foregroundStyle(.tint)
                }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(peer.effectiveName)
                        .font(.headline)
                    if peer.isPropagationNode {
                        Image(systemName: "antenna.radiowaves.left.and.right")
                            .font(.caption2)
                            .foregroundStyle(.teal)
                    }
                    if peer.isNomadNode {
                        Image(systemName: "safari")
                            .font(.caption2)
                            .foregroundStyle(.blue)
                    }
                }
                Text(peer.shortHash + "…")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
    }
}

struct ContactDetailsView: View {
    @Environment(AppModel.self) private var model

    let destinationHash: Data

    @State private var nicknameText = ""
    @State private var nicknameSeededForHash: String?
    @State private var messageText = ""
    @State private var isSending = false
    @State private var sendError: String?
    @State private var sentFeedback = false

    private var peer: DiscoveredPeer? {
        model.peers.first(where: { $0.destinationHash == destinationHash })
    }

    private var conversationHasMessages: Bool {
        model.conversations.contains(where: { $0.destinationHash == destinationHash })
    }

    private var pageTitle: String {
        peer?.effectiveName ?? "\(destinationHash.hexString.prefix(8))…"
    }

    var body: some View {
        List {
            if let peer {
                identitySection(peer)
                messageActionSection(peer)
                routingSection(peer)
                capabilitiesSection(peer)
                technicalSection(peer)
            } else {
                Section {
                    Text("This contact is no longer in the peer list.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .onAppear {
            seedNicknameIfNeeded()
        }
        .navigationTitle(pageTitle)
        .navigationBarTitleDisplayMode(.inline)
        .alert("Send Failed", isPresented: .constant(sendError != nil)) {
            Button("OK") { sendError = nil }
        } message: {
            Text(sendError ?? "")
        }
    }

    @ViewBuilder
    private func identitySection(_ peer: DiscoveredPeer) -> some View {
        Section("Identity") {
            HStack {
                Text("Nickname")
                Spacer()
                TextField(peer.effectiveName, text: $nicknameText)
                    .multilineTextAlignment(.trailing)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .onSubmit {
                        saveNickname(for: peer)
                    }
            }
            labeledValue("LXMF hash", value: peer.hashHex)
            labeledValue(
                "Identity hash",
                value: peer.hasValidPublicKey ? peer.identityHashHex : "Unknown (no announce key)"
            )
            if let displayName = peer.displayName, !displayName.isEmpty {
                labeledValue("Announced name", value: displayName)
                if peer.aliasSet {
                    Button("Revert to announced name", role: .destructive) {
                        model.clearPeerAlias(for: peer.destinationHash)
                        nicknameText = ""
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func routingSection(_ peer: DiscoveredPeer) -> some View {
        Section("Routing") {
            if let hops = peer.pathHops {
                labeledValue("Current path", value: "\(hops) hop\(hops == 1 ? "" : "s")")
            } else {
                labeledValue("Current path", value: "Unknown")
            }
            if let announce = peer.lastAnnounceAt {
                HStack {
                    Text("Last seen online")
                    Spacer()
                    Text(announce, style: .relative)
                        .foregroundStyle(.secondary)
                }
            } else {
                labeledValue("Last seen online", value: "Never")
            }
            if let serverID = peer.lastAnnounceServerID {
                labeledValue("Last announce server", value: serverID.uuidString)
            }
            if let transportID = peer.lastAnnounceTransportID {
                labeledValue("Last transport ID", value: transportID.hexString)
            }
        }
    }

    @ViewBuilder
    private func capabilitiesSection(_ peer: DiscoveredPeer) -> some View {
        Section("Capabilities") {
            labeledValue("LXMF delivery announce", value: peer.isLXMFPeer ? "Yes" : "No")
            labeledValue("Nomad node announce", value: peer.isNomadNode ? "Yes" : "No")
            labeledValue("Propagation node", value: peer.isPropagationNode ? "Yes" : "No")
            if let cost = peer.announcedStampCost {
                labeledValue("Announced stamp cost", value: "\(cost)")
            } else {
                labeledValue("Announced stamp cost", value: "Not announced")
            }
            if peer.isPropagationNode {
                if let propagationCost = peer.announcedPropagationStampCost {
                    labeledValue("Propagation stamp cost", value: "\(propagationCost)")
                } else {
                    labeledValue("Propagation stamp cost", value: "Not announced")
                }
                if let enabled = peer.announcedPropagationEnabled {
                    labeledValue("Propagation enabled", value: enabled ? "Yes" : "No")
                } else {
                    labeledValue("Propagation enabled", value: "Unknown")
                }
            }
            if model.selectedPropagationNodeHash == peer.destinationHash {
                labeledValue("Selected as propagation node", value: "Yes")
            }
            if let activePropagation = model.selectedPropagationNode {
                labeledValue(
                    "Active propagation node",
                    value: "\(activePropagation.effectiveName) (\(activePropagation.shortHash)...)"
                )
            }
        }
    }

    @ViewBuilder
    private func technicalSection(_ peer: DiscoveredPeer) -> some View {
        Section("Technical") {
            labeledValue("Discovered", value: peer.discoveredAt.formatted(date: .abbreviated, time: .shortened))
            labeledValue("Public key bytes", value: "\(peer.publicKey.count)")
        }
    }

    @ViewBuilder
    private func messageActionSection(_ peer: DiscoveredPeer) -> some View {
        Section {
            TextField("Message", text: $messageText, axis: .vertical)
                .lineLimit(2...5)
            Button {
                sendMessage()
            } label: {
                HStack {
                    if isSending {
                        ProgressView()
                    } else {
                        Image(systemName: "paperplane.fill")
                    }
                    Text(isSending ? "Sending…" : "Send message")
                }
            }
            .disabled(messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isSending)

            if sentFeedback {
                Label("Message sent", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }

            NavigationLink {
                ThreadView(destinationHash: peer.destinationHash)
            } label: {
                Label(
                    conversationHasMessages ? "Open conversation" : "Open empty conversation",
                    systemImage: "bubble.left.and.bubble.right"
                )
            }
        } header: {
            Text("Send this user a message")
        } footer: {
            Text("Delivery method is selected automatically (direct, opportunistic, or propagated) based on current route availability.")
        }
    }

    private func labeledValue(_ label: String, value: String) -> some View {
        HStack(alignment: .top) {
            Text(label)
            Spacer()
            Text(value)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }

    private func sendMessage() {
        let trimmed = messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        isSending = true
        sentFeedback = false
        sendError = nil

        Task {
            do {
                try await model.send(to: destinationHash, content: trimmed)
                messageText = ""
                sentFeedback = true
            } catch {
                sendError = error.localizedDescription
            }
            isSending = false
        }
    }

    private func seedNicknameIfNeeded() {
        guard let peer else { return }
        let currentHash = peer.destinationHash.hexString
        guard nicknameSeededForHash != currentHash else { return }
        nicknameSeededForHash = currentHash
        nicknameText = peer.alias ?? ""
    }

    private func saveNickname(for peer: DiscoveredPeer) {
        let trimmed = nicknameText.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            model.clearPeerAlias(for: peer.destinationHash)
        } else {
            model.setPeerAlias(trimmed, for: peer.destinationHash)
        }
        nicknameText = trimmed
    }
}
