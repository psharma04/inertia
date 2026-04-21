import SwiftUI

struct AutoInterfaceSettingsView: View {
    @Environment(AppModel.self) private var model

    private let scopeOptions: [(label: String, value: String)] = [
        ("Link-local (default)", "link"),
        ("Admin", "admin"),
        ("Site", "site"),
        ("Organisation", "organisation"),
        ("Global", "global"),
    ]

    private let mcastTypeOptions: [(label: String, value: String)] = [
        ("Temporary (default)", "temporary"),
        ("Permanent", "permanent"),
    ]

    var body: some View {
        @Bindable var m = model

        Form {
            Section {
                Toggle("Enable AutoInterface", isOn: $m.autoInterfaceConfig.enabled)
            } header: {
                Text("AutoInterface")
            } footer: {
                Text("Discovers and connects to nearby Reticulum nodes over Wi-Fi. AutoInterface only operates when a Wi-Fi network is available.")
            }

            if model.autoInterfaceConfig.enabled {
                Section {
                    HStack {
                        Label("Status", systemImage: statusIcon)
                            .foregroundStyle(statusColor)
                        Spacer()
                        Text(statusLabel)
                            .foregroundStyle(statusColor)
                    }
                    if model.autoInterfaceOnline == true {
                        HStack {
                            Label("Discovered Peers", systemImage: "person.2.wave.2")
                            Spacer()
                            Text("\(model.autoInterfacePeerCount)")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            Section {
                LabeledContent("Group ID") {
                    TextField("reticulum", text: $m.autoInterfaceConfig.groupID)
                        .multilineTextAlignment(.trailing)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }

                Picker("Discovery Scope", selection: $m.autoInterfaceConfig.discoveryScope) {
                    ForEach(scopeOptions, id: \.value) { opt in
                        Text(opt.label).tag(opt.value)
                    }
                }

                Picker("Multicast Address", selection: $m.autoInterfaceConfig.multicastAddressType) {
                    ForEach(mcastTypeOptions, id: \.value) { opt in
                        Text(opt.label).tag(opt.value)
                    }
                }
            } header: {
                Text("Network")
            } footer: {
                Text("Devices with different Group IDs cannot discover each other, letting you run isolated Reticulum networks on the same physical LAN.")
            }

            Section {
                PortField(label: "Discovery Port", value: $m.autoInterfaceConfig.discoveryPort, placeholder: "29716")
                PortField(label: "Data Port", value: $m.autoInterfaceConfig.dataPort, placeholder: "42671")
            } header: {
                Text("Ports")
            } footer: {
                Text("Only change these if the defaults (29716 / 42671) conflict with another application. All peers on a network must use the same ports.")
            }

            Section {
                LabeledContent("Allowed") {
                    TextField("e.g. en0,en1", text: $m.autoInterfaceConfig.allowedInterfaces)
                        .multilineTextAlignment(.trailing)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
                LabeledContent("Ignored") {
                    TextField("e.g. utun0", text: $m.autoInterfaceConfig.ignoredInterfaces)
                        .multilineTextAlignment(.trailing)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
            } header: {
                Text("Interface Filtering")
            } footer: {
                Text("Comma-separated interface names. If Allowed is non-empty only those interfaces are used. Leave both blank to use all suitable interfaces.")
            }
        }
        .navigationTitle("AutoInterface")
    }

    private var statusIcon: String {
        switch model.autoInterfaceOnline {
        case true:  "wifi"
        case false: "wifi.exclamationmark"
        default:    "wifi.slash"
        }
    }

    private var statusColor: Color {
        switch model.autoInterfaceOnline {
        case true:  .green
        case false: .red
        default:    .secondary
        }
    }

    private var statusLabel: String {
        switch model.autoInterfaceOnline {
        case true:  "Online"
        case false: "Error"
        default:
            if !model.isWiFiAvailable {
                "Waiting for Wi-Fi"
            } else {
                "Starting…"
            }
        }
    }
}

private struct PortField: View {
    let label: String
    @Binding var value: Int
    let placeholder: String

    @State private var text: String = ""

    var body: some View {
        LabeledContent(label) {
            TextField(placeholder, text: $text)
                .multilineTextAlignment(.trailing)
                .keyboardType(.numberPad)
                .onChange(of: text) { _, new in
                    let digits = new.filter(\.isNumber)
                    if digits != new { text = digits }
                    if let parsed = Int(digits), (1...65535).contains(parsed) {
                        value = parsed
                    }
                }
        }
        .onAppear {
            text = value > 0 ? "\(value)" : ""
        }
    }
}
