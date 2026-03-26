import SwiftUI

/// Manage the list of Reticulum TCP server connections.
struct ServersView: View {
    @Environment(AppModel.self) private var model
    @State private var addingServer = false
    @State private var editingServer: ServerConfig?

    var body: some View {
        List {
            ForEach(model.servers) { server in
                ServerRow(server: server)
 .contentShape(Rectangle())
 .onTapGesture { editingServer = server }
            }
            .onDelete { indexSet in
                indexSet.map { model.servers[$0].id }.forEach { model.removeServer(id: $0) }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Servers")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { addingServer = true } label: {
 Image(systemName: "plus")
                }
            }
        }
        .sheet(isPresented: $addingServer) {
            AddEditServerView(existing: nil)
        }
        .sheet(item: $editingServer) { server in
            AddEditServerView(existing: server)
        }
    }
}

// Server row

private struct ServerRow: View {
    @Environment(AppModel.self) private var model
    let server: ServerConfig

    private var isConnected: Bool { model.serverStatuses[server.id] == true }
    private var statusColor: Color {
        if model.serverStatuses[server.id] == true { return .green }
        if model.serverStatuses[server.id] == false { return .red }
        return Color(.systemGray4)
    }

    var body: some View {
        HStack(spacing: 14) {
            Circle()
                .fill(statusColor)
                .frame(width: 10, height: 10)

            VStack(alignment: .leading, spacing: 2) {
                Text(server.displayName)
 .font(.headline)
                Text("\(server.host):\(server.port, format: .number.grouping(.never))")
 .font(.caption)
 .foregroundStyle(.secondary)
            }

            Spacer()

            Toggle("", isOn: Binding(
                get: { isConnected },
                set: { on in
 if on { model.connect(serverId: server.id) }
 else  { model.disconnect(serverId: server.id) }
                }
            ))
            .labelsHidden()
        }
        .padding(.vertical, 4)
    }
}

// Add / edit server form

struct AddEditServerView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    let existing: ServerConfig?

    @State private var name = ""
    @State private var host = ""
    @State private var portText = "4242"

    private var isEditing: Bool { existing != nil }

    private var portValue: Int { Int(portText) ?? 0 }
    private var isValidPort: Bool { (1...65535).contains(portValue) }
    private var isValidHost: Bool { !host.trimmingCharacters(in: .whitespaces).isEmpty }
    private var canSave: Bool { isValidHost && isValidPort }

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
 LabeledContent("Name") {
     TextField("Optional label", text: $name)
         .multilineTextAlignment(.trailing)
         .autocorrectionDisabled()
 }
 LabeledContent("Host") {
     TextField("rns.inertia.chat", text: $host)
         .multilineTextAlignment(.trailing)
         .autocorrectionDisabled()
         .textInputAutocapitalization(.never)
 }
 LabeledContent("Port") {
     TextField("4242", text: $portText)
         .multilineTextAlignment(.trailing)
         .keyboardType(.numberPad)
         .onChange(of: portText) { _, new in
             // Strip non-digits and enforce 1-65535
             let digits = new.filter(\.isNumber)
             if let value = Int(digits), value > 65535 {
                 portText = "65535"
             } else {
                 portText = digits
             }
         }
 }
                }

                if !isValidPort && !portText.isEmpty {
 Section {
     Label("Port must be between 1 and 65535", systemImage: "exclamationmark.triangle")
         .foregroundStyle(.orange)
         .font(.callout)
 }
                }
            }
            .navigationTitle(isEditing ? "Edit Server" : "Add Server")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
 Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
 Button("Save") { save() }
     .disabled(!canSave)
                }
            }
            .onAppear {
                if let s = existing {
 name     = s.name
 host     = s.host
 portText = "\(s.port)"
                }
            }
        }
    }

    private func save() {
        var config = existing ?? ServerConfig(host: host, port: portValue)
        config.name = name
        config.host = host.trimmingCharacters(in: .whitespaces)
        config.port = portValue
        if isEditing {
            model.updateServer(config)
        } else {
            model.addServer(config)
        }
        dismiss()
    }
}
