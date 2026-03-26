import SwiftUI

struct NetworkStatusView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        List {
            serversSection
            discoverySection
            activitySection
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Network Status")
        .navigationBarTitleDisplayMode(.large)
    }

    // Servers

    private var serversSection: some View {
        Section("Servers") {
            ForEach(model.servers) { server in
                let connected = model.serverStatuses[server.id] == true
                LabeledContent(server.displayName) {
 HStack(spacing: 6) {
     Circle()
         .fill(connected ? Color.green : Color(.systemGray4))
         .frame(width: 8, height: 8)
     Text(connected ? "Online" : "Offline")
         .foregroundStyle(connected ? .primary : .secondary)
         .font(.callout)
 }
                }
            }
            if model.servers.isEmpty {
                Text("No servers configured")
 .foregroundStyle(.secondary)
            }
        }
    }

    // Discovery

    private var discoverySection: some View {
        Section("Discovery") {
            LabeledContent("Peers discovered", value: "\(model.peers.count)")
            LabeledContent("Active connections", value: "\(model.connectedCount)")
        }
    }

    // Activity log

    private var activitySection: some View {
        Section("Activity Log") {
            if model.activityLog.isEmpty {
                Text("No activity yet")
 .foregroundStyle(.secondary)
 .font(.callout)
            } else {
                ForEach(model.activityLog.prefix(100)) { entry in
 HStack(alignment: .top, spacing: 10) {
     Text(entry.timestamp, style: .time)
         .font(.system(.caption2, design: .monospaced))
         .foregroundStyle(.secondary)
         .frame(width: 60, alignment: .trailing)
     Text(entry.message)
         .font(.system(.caption, design: .monospaced))
 }
                }
            }
        }
    }
}

