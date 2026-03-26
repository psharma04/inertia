import SwiftUI
import NomadNet

/// Nomad Network page browser.
///
/// Sends requests over Reticulum to NomadNet nodes and renders their
/// Micron-formatted pages as plain text.  Full rendering requires an
/// established Reticulum link layer; until then the browser operates
/// in a degraded-connectivity state.
struct NomadBrowserView: View {
    @Environment(AppModel.self) private var model
    @State private var addressText = ""
    @State private var currentAddress: NomadAddress?
    @State private var pageDocument: MicronDocument?
    @State private var isLoading = false
    @State private var errorMessage: String?
    @State private var history: [NomadAddress] = []
    @State private var historyIndex = -1
    @FocusState private var addressFieldFocused: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                addressBar
                Divider()
                contentArea
            }
            .ignoresSafeArea(.keyboard, edges: .bottom)
            .navigationTitle("Nomad Network")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .topBarLeading) {
 Button {
     navigateBack()
 } label: {
     Image(systemName: "chevron.left")
 }
 .disabled(historyIndex <= 0)

 Button {
     navigateForward()
 } label: {
     Image(systemName: "chevron.right")
 }
 .disabled(historyIndex >= history.count - 1)
                }
            }
        }
    }

    // Address bar

    private var addressBar: some View {
        HStack(spacing: 10) {
            Image(systemName: "safari")
                .foregroundStyle(.secondary)
                .frame(width: 20)

            TextField("Destination hash, hash:/path, or nn:// address", text: $addressText)
                .font(.system(.callout, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .onSubmit { loadAddress() }
                .submitLabel(.go)
                .focused($addressFieldFocused)

            if isLoading {
                ProgressView()
 .scaleEffect(0.8)
            } else {
                Button {
 loadAddress()
                } label: {
 Image(systemName: "arrow.right.circle.fill")
     .foregroundStyle(addressText.isEmpty ? AnyShapeStyle(.secondary) : AnyShapeStyle(Color.accentColor))
                }
                .disabled(addressText.isEmpty)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color(.secondarySystemBackground))
    }

    // Content area

    @ViewBuilder
    private var contentArea: some View {
        if let error = errorMessage {
            errorView(error)
        } else if let document = pageDocument {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    MicronDocumentView(document: document)
                    if !documentLinks.isEmpty {
                        Divider()
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Links")
                                .font(.footnote.bold())
                                .foregroundStyle(.secondary)
                            ForEach(Array(documentLinks.enumerated()), id: \.offset) { _, link in
                                Button {
                                    openMicronLink(link)
                                } label: {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(link.label.isEmpty ? link.destination : link.label)
                                            .font(.callout)
                                            .foregroundStyle(.blue)
                                        Text(link.destination)
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                    }
                }
                .padding(16)
            }
            .scrollDismissesKeyboard(.interactively)
            .onTapGesture { addressFieldFocused = false }
        } else if currentAddress != nil {
            loadingView
        } else {
            welcomeView
        }
    }

    private var welcomeView: some View {
        VStack(spacing: 20) {
            Image(systemName: "safari")
                .font(.system(size: 60))
                .foregroundStyle(.secondary)

            Text("Nomad Network Browser")
                .font(.title2.bold())

            Text("Enter a destination hash, or an address like\n<hash>:/page/index.mu to browse a Nomad node.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if !model.isAnyConnected {
                Label("Connect to a Reticulum node in Settings first.", systemImage: "exclamationmark.triangle")
 .font(.callout)
 .foregroundStyle(.orange)
 .padding(.top, 8)
            }

            if !model.peers.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
 Text("Discovered peers")
     .font(.footnote.bold())
     .foregroundStyle(.secondary)
 ForEach(model.peers.prefix(5)) { peer in
     Button(peer.hashHex) {
         addressText = peer.hashHex
         loadAddress()
     }
     .font(.system(.caption, design: .monospaced))
     .buttonStyle(.bordered)
 }
                }
                .padding(.top, 8)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
            Text("Loading page…")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorView(_ message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 48))
                .foregroundStyle(.orange)
            Text("Could not load page")
                .font(.headline)
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Try Again") { loadAddress() }
                .buttonStyle(.bordered)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // Navigation

    private func loadAddress() {
        guard !addressText.isEmpty else { return }
        let address = NomadAddress(
            raw: addressText,
            defaultDestinationHashHex: currentAddress?.destinationHashHex
        )
        guard address.destinationHashHex != nil else {
            errorMessage = "Invalid Nomad address. Use <hash>:/page/index.mu, <hash>, or nn://<hash>/<path>."
            return
        }
        navigate(to: address)
    }

    private func navigate(to address: NomadAddress) {
        currentAddress = address
        addressText    = address.canonical ?? address.raw
        pageDocument   = nil
        errorMessage   = nil

        // Trim forward history when navigating to a new address
        if historyIndex < history.count - 1 {
            history = Array(history.prefix(historyIndex + 1))
        }
        history.append(address)
        historyIndex = history.count - 1

        fetchPage(address: address)
    }

    private func navigateBack() {
        guard historyIndex > 0 else { return }
        historyIndex -= 1
        let address = history[historyIndex]
        currentAddress = address
        addressText    = address.canonical ?? address.raw
        pageDocument   = nil
        errorMessage   = nil
        fetchPage(address: address)
    }

    private func navigateForward() {
        guard historyIndex < history.count - 1 else { return }
        historyIndex += 1
        let address = history[historyIndex]
        currentAddress = address
        addressText    = address.canonical ?? address.raw
        pageDocument   = nil
        errorMessage   = nil
        fetchPage(address: address)
    }

    private func fetchPage(address: NomadAddress) {
        isLoading    = true
        errorMessage = nil
        Task {
            defer { isLoading = false }
            guard let destinationHex = address.destinationHashHex,
                  let destinationHash = Data(hexString: destinationHex) else {
                errorMessage = "Invalid Nomad address. Use <hash>:/page/index.mu, <hash>, or nn://<hash>/<path>."
                return
            }

            do {
                let page = try await model.fetchNomadPage(
 destinationHash: destinationHash,
 path: address.path
                )
                pageDocument = page.micronDocument
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private var documentLinks: [MicronLink] {
        guard let document = pageDocument else { return [] }
        return document.blocks.flatMap { block -> [MicronLink] in
            let line: MicronLine
            switch block {
            case let .heading(_, headingLine):
                line = headingLine
            case let .line(blockLine):
                line = blockLine
            case .divider:
                return []
            }
            return line.inlines.compactMap { inline in
                guard case let .link(link, _) = inline else { return nil }
                return link
            }
        }
    }

    private func openMicronLink(_ link: MicronLink) {
        let resolved = NomadAddress(
            raw: link.destination,
            defaultDestinationHashHex: currentAddress?.destinationHashHex
        )
        guard resolved.destinationHashHex != nil else {
            errorMessage = "Unsupported link destination: \(link.destination)"
            return
        }
        navigate(to: resolved)
    }
}

private struct MicronDocumentView: View {
    let document: MicronDocument

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(Array(document.blocks.enumerated()), id: \.offset) { _, block in
                switch block {
                case let .heading(level, line):
 rendered(line)
     .font(headingFont(level))
     .frame(maxWidth: .infinity, alignment: frameAlignment(for: line.alignment))
                case let .line(line):
 rendered(line)
     .frame(maxWidth: .infinity, alignment: frameAlignment(for: line.alignment))
                case let .divider(character):
 Text(String(repeating: String(character), count: 32))
     .foregroundStyle(.secondary)
     .font(.system(.callout, design: .monospaced))
     .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .textSelection(.enabled)
    }

    private func rendered(_ line: MicronLine) -> some View {
        if line.inlines.isEmpty {
            return Text("")
                .font(.system(.callout, design: .monospaced))
        } else {
            let prefix = String(repeating: "  ", count: max(0, line.sectionDepth - 1))
            var composed = Text("\(prefix)")
            for inline in line.inlines {
                composed = Text("\(composed)\(inlineText(inline))")
            }
            return composed.font(.system(.callout, design: .monospaced))
        }
    }

    private func inlineText(_ inline: MicronInline) -> Text {
        switch inline {
        case let .text(value, style):
            return styled(Text(value), style: style)
        case let .link(link, style):
            let label = link.label.isEmpty ? link.destination : link.label
            return styled(Text(label).underline().foregroundStyle(.blue), style: style)
        case let .field(field, style):
            let rendered: String
            switch field.kind {
            case .text:
                rendered = "[\(field.name)=\(field.value)]"
            case .password:
                rendered = "[\(field.name)=••••]"
            case .checkbox:
                rendered = "[\(field.value.isEmpty ? " " : "x")] \(field.name)"
            case .radio:
                rendered = "(•) \(field.name)=\(field.value)"
            }
            return styled(Text(rendered), style: style)
        }
    }

    private func styled(_ text: Text, style: MicronTextStyle) -> Text {
        var out = text
        if style.bold { out = out.bold() }
        if style.italic { out = out.italic() }
        if style.underline { out = out.underline() }
        return out
    }

    private func headingFont(_ level: Int) -> Font {
        switch level {
        case 1:
            return .title3.bold()
        case 2:
            return .headline
        default:
            return .subheadline.bold()
        }
    }

    private func frameAlignment(for alignment: MicronAlignment) -> Alignment {
        switch alignment {
        case .left, .default:
            return .leading
        case .center:
            return .center
        case .right:
            return .trailing
        }
    }
}
