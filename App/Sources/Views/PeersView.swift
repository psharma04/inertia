import SwiftUI

struct PeersView: View {
    @Environment(AppModel.self) private var model
    @State private var aliasPeer: DiscoveredPeer?
    @State private var aliasText: String = ""
    @State private var searchText: String = ""

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
         PeerRow(peer: peer)
     }
          .swipeActions(edge: .leading, allowsFullSwipe: false) {
              Button {
                  aliasText = peer.aliasSet ? (peer.alias ?? "") : ""
                 aliasPeer = peer
             } label: {
                 Label(peer.aliasSet ? "Edit Alias" : "Set Alias",
    systemImage: "tag")
             }
             .tint(.indigo)

             if peer.aliasSet {
                 Button(role: .destructive) {
  model.clearPeerAlias(for: peer.destinationHash)
                 } label: {
  Label("Clear Alias", systemImage: "tag.slash")
                 }
             }
         }
 }
 .listStyle(.plain)
                }
            }
            .navigationTitle("Peers")
            .searchable(text: $searchText, prompt: "Search name or hash")
            .alert("Set Alias", isPresented: Binding(
                get: { aliasPeer != nil },
                set: { if !$0 { aliasPeer = nil } }
            )) {
                TextField("Alias", text: $aliasText)
 .autocorrectionDisabled()
                Button("Save") {
 if let peer = aliasPeer {
     model.setPeerAlias(aliasText, for: peer.destinationHash)
 }
 aliasPeer = nil
                }
                Button("Cancel", role: .cancel) { aliasPeer = nil }
            } message: {
                if let peer = aliasPeer {
 let name = peer.displayName.map { "\"\($0)\"" } ?? "\(peer.shortHash)…"
 Text("Enter a custom alias for \(name). Leave blank to remove the alias.")
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "person.wave.2")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)
            Text("No Peers Yet")
                .font(.title2.bold())
                .accessibilityIdentifier("peers-empty-title")
            Text("Connect to a Reticulum node to start\ndiscovering peers via announce packets.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(40)
    }
}

// Peer row

private struct PeerRow: View {
    let peer: DiscoveredPeer

    var body: some View {
        HStack(spacing: 14) {
            Circle()
                .fill(.tint.opacity(0.15))
                .frame(width: 44, height: 44)
                .overlay {
 Text(peer.shortHash.prefix(2).uppercased())
     .font(.system(.subheadline, design: .monospaced).bold())
     .foregroundStyle(.tint)
                }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
 Text(peer.effectiveName)
     .font(.headline)
 if peer.aliasSet {
     Image(systemName: "tag.fill")
         .font(.caption2)
         .foregroundStyle(.indigo)
 }
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
                Text("\(peer.shortHash)…")
 .font(.system(.caption, design: .monospaced))
 .foregroundStyle(.secondary)
                if let hops = peer.pathHops {
 Text("Path: \(hops) hop\(hops == 1 ? "" : "s")")
     .font(.caption2)
     .foregroundStyle(.secondary)
                }
                if let stampCost = peer.announcedStampCost {
 Text("Stamp cost: \(stampCost)")
     .font(.caption2)
     .foregroundStyle(.secondary)
                }
                if peer.isPropagationNode, let pnStampCost = peer.announcedPropagationStampCost {
 Text("Propagation stamp: \(pnStampCost)")
     .font(.caption2)
     .foregroundStyle(.secondary)
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 2) {
                Text(peer.lastAnnounceAt ?? peer.discoveredAt, style: .relative)
 .font(.caption2)
 .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 6)
    }
}
