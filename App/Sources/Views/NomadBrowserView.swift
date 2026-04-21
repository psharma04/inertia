import SwiftUI
import NomadNet
import Persistence
import os.log

private let nomadLog = OSLog(subsystem: "chat.inertia.app", category: "nomad-browser")

/// Nomad Network page browser with node sidebar.
struct NomadBrowserView: View {
    @Environment(AppModel.self) private var model
    @State private var addressText = ""
    @State private var currentAddress: NomadAddress?
    @State private var pageDocument: MicronDocument?
    @State private var rawContent: String?
    @State private var isLoading = false
    @State private var loadingStatus: String?
    @State private var errorMessage: String?
    @State private var history: [NomadAddress] = []
    @State private var historyIndex = -1
    @State private var showSource = false
    @Environment(\.openURL) private var openURL
    @State private var showNodeList = false
    @State private var isFavorited = false
    @State private var downloadedFileURL: URL?
    @State private var showShareSheet = false
    @FocusState private var addressFieldFocused: Bool

    // Form field state
    @State private var formFieldValues: [String: String] = [:]
    @State private var formCheckboxValues: [String: Bool] = [:]
    @State private var formRadioValues: [String: String] = [:]

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
                    Button { navigateBack() } label: {
                        Image(systemName: "chevron.left")
                    }
                    .disabled(historyIndex <= 0)

                    Button { navigateForward() } label: {
                        Image(systemName: "chevron.right")
                    }
                    .disabled(historyIndex >= history.count - 1)
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    if currentAddress != nil {
                        Button { showSource.toggle() } label: {
                            Image(systemName: showSource ? "doc.richtext" : "doc.plaintext")
                        }
                    }
                    Button { showNodeList = true } label: {
                        Image(systemName: "list.bullet")
                    }
                }
            }
            .sheet(isPresented: $showNodeList) {
                NomadNodeListView { address in
                    showNodeList = false
                    addressText = address
                    loadAddress()
                }
            }
            .sheet(isPresented: $showShareSheet) {
                if let url = downloadedFileURL {
                    ShareSheet(items: [url])
                }
            }
            .onChange(of: model.pendingNomadAddress) { _, address in
                os_log("onChange pendingNomadAddress: %{public}@", log: nomadLog, type: .default, address ?? "(nil)")
                guard let address else { return }
                addressText = address
                model.pendingNomadAddress = nil
                loadAddress()
            }
            .onAppear {
                os_log("onAppear pendingNomadAddress: %{public}@", log: nomadLog, type: .default, model.pendingNomadAddress ?? "(nil)")
                // Pick up any pendingNomadAddress set before this view appeared
                if let address = model.pendingNomadAddress {
                    addressText = address
                    model.pendingNomadAddress = nil
                    loadAddress()
                }
            }
        }
    }

    // MARK: - Address Bar

    private var addressBar: some View {
        HStack(spacing: 8) {
            // Home button
            if currentAddress != nil {
                Button {
                    if let hash = currentAddress?.destinationHashHex {
                        addressText = "\(hash):/page/index.mu"
                        loadAddress()
                    }
                } label: {
                    Image(systemName: "house")
                        .font(.callout)
                }
            }

            Image(systemName: "safari")
                .foregroundStyle(.secondary)
                .frame(width: 16)

            TextField("hash:/page/index.mu", text: $addressText)
                .font(.system(.callout, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .onSubmit { loadAddress() }
                .submitLabel(.go)
                .focused($addressFieldFocused)
                .accessibilityIdentifier("nomad-address-field")

            if isLoading {
                ProgressView()
                    .scaleEffect(0.8)
            } else {
                // Reload
                if currentAddress != nil {
                    Button {
                        reloadPage()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                            .font(.callout)
                    }
                }

                // Favorite
                if currentAddress?.destinationHashHex != nil {
                    Button {
                        toggleFavorite()
                    } label: {
                        Image(systemName: isFavorited ? "star.fill" : "star")
                            .foregroundStyle(isFavorited ? .yellow : .secondary)
                            .font(.callout)
                    }
                }

                // Go
                Button {
                    loadAddress()
                } label: {
                    Image(systemName: "arrow.right.circle.fill")
                        .foregroundStyle(addressText.isEmpty ? AnyShapeStyle(.secondary) : AnyShapeStyle(Color.accentColor))
                }
                .disabled(addressText.isEmpty)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(.secondarySystemBackground))
    }

    // MARK: - Content Area

    @ViewBuilder
    private var contentArea: some View {
        if let error = errorMessage {
            errorView(error)
        } else if showSource, let raw = rawContent {
            sourceView(raw)
        } else if let document = pageDocument {
            pageView(document)
        } else if isLoading {
            loadingView
        } else {
            welcomeView
        }
    }

    private func pageView(_ document: MicronDocument) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                MicronDocumentView(
                    document: document,
                    formFieldValues: $formFieldValues,
                    formCheckboxValues: $formCheckboxValues,
                    formRadioValues: $formRadioValues,
                    onLinkTap: { link in openMicronLink(link) },
                    currentDestinationHashHex: currentAddress?.destinationHashHex
                )

                // Submit button if form fields are present
                if hasFormFields(in: document) {
                    Divider().padding(.vertical, 4)
                    Button {
                        submitForm()
                    } label: {
                        Label("Submit", systemImage: "paperplane")
                    }
                    .buttonStyle(.borderedProminent)
                    .frame(maxWidth: .infinity, alignment: .center)
                }
            }
            .padding(16)
        }
        .background(Color.black)
        .foregroundStyle(Color.white)
        .environment(\.openURL, OpenURLAction { url in
            os_log("openURL tapped: %{public}@", log: nomadLog, type: .default, url.absoluteString)
            if let scheme = url.scheme?.lowercased() {
                // NomadNet links: navigate directly within the browser.
                if scheme == "nomadnet" || scheme == "nn" {
                    let prefix = "\(scheme)://"
                    let raw = url.absoluteString
                    guard raw.count > prefix.count else { return .handled }
                    let addressStr = String(raw.dropFirst(prefix.count))
                    os_log("NomadNet link navigate: %{public}@", log: nomadLog, type: .default, addressStr)
                    let resolved = NomadAddress(
                        raw: addressStr,
                        defaultDestinationHashHex: currentAddress?.destinationHashHex
                    )
                    if resolved.destinationHashHex != nil {
                        navigate(to: resolved)
                    }
                    return .handled
                }
                // LXMF links route through deep link handler.
                if scheme == "lxm" || scheme == "lxmf" {
                    model.handleDeepLink(url)
                    return .handled
                }
            }
            // HTTP/HTTPS links open in the system browser.
            return .systemAction
        })
        .scrollDismissesKeyboard(.immediately)
    }

    private func sourceView(_ raw: String) -> some View {
        ScrollView {
            Text(raw)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
        }
        .background(Color.black)
        .foregroundStyle(Color.green)
    }

    private var welcomeView: some View {
        VStack(spacing: 20) {
            Image(systemName: "safari")
                .font(.system(size: 60))
                .foregroundStyle(.secondary)

            Text("Nomad Network Browser")
                .font(.title2.bold())

            Text("Enter a destination hash or tap the list icon to browse discovered nodes.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if !model.isAnyConnected {
                Label("Connect to a Reticulum node in Settings first.", systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .padding(.top, 8)
            }

            // Show discovered Nomad nodes
            let nomadPeers = model.peers.filter(\.isNomadNode)
            if !nomadPeers.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Nomad Nodes")
                        .font(.footnote.bold())
                        .foregroundStyle(.secondary)
                    ForEach(nomadPeers.prefix(8)) { peer in
                        Button {
                            addressText = peer.hashHex
                            loadAddress()
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(peer.displayName ?? peer.shortHash)
                                        .font(.callout)
                                    Text(peer.hashHex)
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if let hops = peer.pathHops {
                                    Text("\(hops) hop\(hops == 1 ? "" : "s")")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 8)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
            Text(model.resourceTransferStatus ?? loadingStatus ?? "Loading page…")
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
            Button("Try Again") { reloadPage() }
                .buttonStyle(.bordered)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Navigation

    private func loadAddress() {
        os_log("loadAddress: '%{public}@'", log: nomadLog, type: .default, addressText)
        guard !addressText.isEmpty else { return }
        let address = NomadAddress(
            raw: addressText,
            defaultDestinationHashHex: currentAddress?.destinationHashHex
        )
        os_log("loadAddress parsed hash=%{public}@ path=%{public}@", log: nomadLog, type: .default, address.destinationHashHex ?? "(nil)", address.path)
        guard address.destinationHashHex != nil else {
            errorMessage = "Invalid address. Use <hash>:/page/index.mu or nn://<hash>/<path>."
            return
        }
        navigate(to: address)
    }

    private func navigate(to address: NomadAddress) {
        currentAddress = address
        addressText    = address.canonical ?? address.raw
        pageDocument   = nil
        rawContent     = nil
        errorMessage   = nil
        showSource     = false
        formFieldValues.removeAll()
        formCheckboxValues.removeAll()
        formRadioValues.removeAll()

        if historyIndex < history.count - 1 {
            history = Array(history.prefix(historyIndex + 1))
        }
        history.append(address)
        historyIndex = history.count - 1

        fetchPage(address: address, bypassCache: false)
        checkFavoriteStatus()
    }

    private func navigateBack() {
        guard historyIndex > 0 else { return }
        historyIndex -= 1
        restoreHistoryEntry()
    }

    private func navigateForward() {
        guard historyIndex < history.count - 1 else { return }
        historyIndex += 1
        restoreHistoryEntry()
    }

    private func restoreHistoryEntry() {
        let address = history[historyIndex]
        currentAddress = address
        addressText    = address.canonical ?? address.raw
        pageDocument   = nil
        rawContent     = nil
        errorMessage   = nil
        showSource     = false
        fetchPage(address: address, bypassCache: false)
        checkFavoriteStatus()
    }

    private func reloadPage() {
        guard let address = currentAddress else { return }
        pageDocument = nil
        rawContent   = nil
        errorMessage = nil
        fetchPage(address: address, bypassCache: true)
    }

    private func fetchPage(address: NomadAddress, bypassCache: Bool) {
        os_log("fetchPage: hash=%{public}@ path=%{public}@", log: nomadLog, type: .default, address.destinationHashHex ?? "(nil)", address.path)
        isLoading     = true
        errorMessage  = nil
        loadingStatus = "Resolving node…"
        Task {
            defer {
                isLoading = false
                loadingStatus = nil
            }
            guard let destinationHex = address.destinationHashHex,
                  let destinationHash = Data(hexString: destinationHex) else {
                errorMessage = "Invalid address."
                return
            }

            let isFileDownload = address.path.hasPrefix("/file/")

            do {
                loadingStatus = isFileDownload ? "Downloading file…" : "Establishing link…"
                os_log("fetchPage calling model.fetchNomadPage dest=%{public}@ path=%{public}@", log: nomadLog, type: .default, destinationHex, address.path)
                let page = try await model.fetchNomadPage(
                    destinationHash: destinationHash,
                    path: address.path
                )

                if isFileDownload {
                    // Save to temp and offer share sheet
                    let filename = String(address.path.dropFirst("/file/".count))
                        .replacingOccurrences(of: "/", with: "_")
                    let safeName = filename.isEmpty ? "download" : filename
                    let tempDir = FileManager.default.temporaryDirectory
                    let fileURL = tempDir.appendingPathComponent(safeName)
                    try page.content.write(to: fileURL)
                    downloadedFileURL = fileURL
                    showShareSheet = true
                } else {
                    rawContent   = page.contentString
                    pageDocument = page.micronDocument
                }
            } catch {
                os_log("fetchPage ERROR: %{public}@", log: nomadLog, type: .error, String(describing: error))
                errorMessage = error.localizedDescription
            }
        }
    }

    // MARK: - Form Submission

    private func hasFormFields(in document: MicronDocument) -> Bool {
        document.blocks.contains { block in
            let line: MicronLine
            switch block {
            case let .heading(_, l): line = l
            case let .line(l): line = l
            case .divider: return false
            }
            return line.inlines.contains { inline in
                if case .field = inline { return true }
                return false
            }
        }
    }

    private func submitForm() {
        guard let address = currentAddress else { return }
        // Collect all field values into a single dict
        var allFields = formFieldValues
        for (key, checked) in formCheckboxValues where checked {
            allFields["field_\(key)"] = "on"
        }
        for (key, value) in formRadioValues {
            allFields["field_\(key)"] = value
        }

        isLoading     = true
        errorMessage  = nil
        loadingStatus = "Submitting form…"
        Task {
            defer {
                isLoading = false
                loadingStatus = nil
            }
            guard let destinationHex = address.destinationHashHex,
                  let destinationHash = Data(hexString: destinationHex) else {
                errorMessage = "Invalid address."
                return
            }
            do {
                let page = try await model.fetchNomadPage(
                    destinationHash: destinationHash,
                    path: address.path,
                    formData: allFields
                )
                rawContent   = page.contentString
                pageDocument = page.micronDocument
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    // MARK: - Links

    private func openMicronLink(_ link: MicronLink) {
        let dest = link.destination.trimmingCharacters(in: .whitespacesAndNewlines)

        // External HTTP/HTTPS links open in the system browser.
        if let url = URL(string: dest), ["http", "https"].contains(url.scheme?.lowercased()) {
            openURL(url)
            return
        }

        // LXMF paper message links route through deep link handler.
        if let url = URL(string: dest), ["lxm", "lxmf"].contains(url.scheme?.lowercased()) {
            model.handleDeepLink(url)
            return
        }

        // NomadNet page links — resolve relative to current destination.
        let resolved = NomadAddress(
            raw: dest,
            defaultDestinationHashHex: currentAddress?.destinationHashHex
        )
        guard resolved.destinationHashHex != nil else {
            errorMessage = "Unsupported link destination: \(link.destination)"
            return
        }
        navigate(to: resolved)
    }

    // MARK: - Favorites

    private func checkFavoriteStatus() {
        guard let hex = currentAddress?.destinationHashHex else {
            isFavorited = false
            return
        }
        Task {
            isFavorited = await model.nomadStore.isFavorite(destinationHashHex: hex)
        }
    }

    private func toggleFavorite() {
        guard let hex = currentAddress?.destinationHashHex else { return }
        Task {
            if isFavorited {
                await model.nomadStore.removeFavorite(destinationHashHex: hex)
            } else {
                let name = model.peers.first(where: { $0.hashHex == hex })?.displayName ?? ""
                await model.nomadStore.addFavorite(
                    NomadStore.NodeFavorite(destinationHashHex: hex, customName: name)
                )
            }
            isFavorited.toggle()
        }
    }
}

// MARK: - Micron Document View

private struct MicronDocumentView: View {
    let document: MicronDocument
    @Binding var formFieldValues: [String: String]
    @Binding var formCheckboxValues: [String: Bool]
    @Binding var formRadioValues: [String: String]
    let onLinkTap: (MicronLink) -> Void
    /// Current page's destination hash hex, used to resolve relative NomadNet links.
    var currentDestinationHashHex: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(document.blocks.enumerated()), id: \.offset) { _, block in
                switch block {
                case let .heading(level, line):
                    renderLine(line, font: headingFont(level))
                case let .line(line):
                    renderLine(line, font: .system(.callout, design: .monospaced))
                case let .divider(character):
                    Text(String(repeating: String(character), count: 40))
                        .foregroundStyle(.secondary)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }

    @ViewBuilder
    private func renderLine(_ line: MicronLine, font: Font) -> some View {
        let alignment = frameAlignment(for: line.alignment)

        // Only use HStack for lines with form fields (they need real SwiftUI controls).
        // Links use AttributedString .link attribute for proper text wrapping.
        let hasFields = line.inlines.contains {
            if case .field = $0 { return true }
            return false
        }

        if hasFields {
            HStack(spacing: 0) {
                let prefix = String(repeating: "  ", count: max(0, line.sectionDepth - 1))
                if !prefix.isEmpty { Text(prefix).font(font) }
                ForEach(Array(line.inlines.enumerated()), id: \.offset) { _, inline in
                    inlineView(inline, font: font)
                }
            }
            .frame(maxWidth: .infinity, alignment: alignment)
        } else {
            // AttributedString for all text/link lines — supports natural wrapping + backgrounds.
            Text(buildLineAttributedString(line))
                .font(font)
                .frame(maxWidth: .infinity, alignment: alignment)
        }
    }

    /// Build an AttributedString for an entire non-interactive line.
    private func buildLineAttributedString(_ line: MicronLine) -> AttributedString {
        let prefix = String(repeating: "  ", count: max(0, line.sectionDepth - 1))
        var result = AttributedString(prefix)
        for inline in line.inlines {
            result.append(styledAttributedString(inline))
        }
        return result
    }

    // Interactive inline → View
    @ViewBuilder
    private func inlineView(_ inline: MicronInline, font: Font) -> some View {
        switch inline {
        case let .text(value, style):
            styledView(Text(value), style: style, font: font)
        case let .link(link, style):
            Button {
                onLinkTap(link)
            } label: {
                let label = link.label.isEmpty ? link.destination : link.label
                styledView(Text(label).underline(), style: style, font: font)
                    .foregroundStyle(.blue)
            }
            .buttonStyle(.plain)
        case let .field(field, _):
            fieldView(field).font(font)
        }
    }

    @ViewBuilder
    private func fieldView(_ field: MicronField) -> some View {
        switch field.kind {
        case .text:
            TextField(field.name, text: fieldBinding(field.name, default: field.value))
                .textFieldStyle(.roundedBorder)
                .frame(width: CGFloat(max(field.width ?? 20, 8)) * 9)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
        case .password:
            SecureField(field.name, text: fieldBinding(field.name, default: field.value))
                .textFieldStyle(.roundedBorder)
                .frame(width: CGFloat(max(field.width ?? 20, 8)) * 9)
        case .checkbox:
            Toggle(field.name, isOn: checkboxBinding(field.name, default: !field.value.isEmpty))
                .toggleStyle(.switch)
                .fixedSize()
        case .radio:
            Button {
                formRadioValues[field.name] = field.value
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: formRadioValues[field.name] == field.value ? "circle.inset.filled" : "circle")
                    Text(field.value)
                }
            }
            .buttonStyle(.plain)
        }
    }

    private func fieldBinding(_ name: String, default defaultValue: String) -> Binding<String> {
        Binding(
            get: { formFieldValues[name] ?? defaultValue },
            set: { formFieldValues[name] = $0 }
        )
    }

    private func checkboxBinding(_ name: String, default defaultValue: Bool) -> Binding<Bool> {
        Binding(
            get: { formCheckboxValues[name] ?? defaultValue },
            set: { formCheckboxValues[name] = $0 }
        )
    }

    private func styled(_ text: Text, style: MicronTextStyle) -> Text {
        var out = text
        if style.bold { out = out.bold() }
        if style.italic { out = out.italic() }
        if style.underline { out = out.underline() }
        if style.strikethrough { out = out.strikethrough() }
        if let fg = style.foreground {
            out = out.foregroundColor(micronColor(fg))
        }
        return out
    }

    /// Create an AttributedString for a single inline element, supporting background colors and links.
    private func styledAttributedString(_ inline: MicronInline) -> AttributedString {
        let value: String
        let style: MicronTextStyle
        let isLink: Bool
        var linkURL: URL?

        switch inline {
        case let .text(v, s):
            value = v; style = s; isLink = false
        case let .link(link, s):
            value = link.label.isEmpty ? link.destination : link.label
            style = s; isLink = true
            // Resolve the link destination to a URL.
            let dest = link.destination.trimmingCharacters(in: .whitespacesAndNewlines)
            if let url = URL(string: dest),
               let scheme = url.scheme?.lowercased(),
               ["http", "https", "lxm", "lxmf"].contains(scheme) {
                linkURL = url
            } else {
                // NomadNet page link — resolve relative to current destination.
                let resolved = NomadAddress(
                    raw: dest,
                    defaultDestinationHashHex: currentDestinationHashHex
                )
                if let hash = resolved.destinationHashHex {
                    linkURL = URL(string: "nomadnet://\(hash)\(resolved.path)")
                }
            }
        case let .field(field, _):
            value = "[\(field.name)]"
            style = MicronTextStyle(); isLink = false
        }

        var attr = AttributedString(value)
        if style.bold { attr.font = .body.bold() }
        if style.italic {
            attr.font = (attr.font ?? .body).italic()
        }
        if style.underline || isLink {
            attr.underlineStyle = .single
        }
        if style.strikethrough {
            attr.strikethroughStyle = .single
        }
        if isLink {
            attr.foregroundColor = .blue
        } else if let fg = style.foreground {
            attr.foregroundColor = uiMicronColor(fg)
        }
        if let bg = style.background {
            attr.backgroundColor = uiMicronColor(bg)
        }
        if let url = linkURL {
            attr.link = url
        }
        return attr
    }

    /// Styled text with background color support (returns View, not Text).
    @ViewBuilder
    private func styledView(_ text: Text, style: MicronTextStyle, font: Font) -> some View {
        let styledText = styled(text, style: style).font(font)
        if let bg = style.background {
            styledText.background(micronColor(bg))
        } else {
            styledText
        }
    }

    private func micronColor(_ mc: MicronColor) -> Color {
        switch mc {
        case let .rgb(hex):
            return Color(hex: hex)
        case let .extendedRgb(hex6):
            return Color(hex: hex6)
        case let .grayscale(level):
            let v = Double(min(level, 99)) / 99.0
            return Color(white: v)
        }
    }

    /// Platform color for use with AttributedString (which requires UIColor/NSColor).
    private func uiMicronColor(_ mc: MicronColor) -> Color {
        micronColor(mc)
    }

    private func headingFont(_ level: Int) -> Font {
        switch level {
        case 1:  return .title3.bold()
        case 2:  return .headline
        default: return .subheadline.bold()
        }
    }

    private func frameAlignment(for alignment: MicronAlignment) -> Alignment {
        switch alignment {
        case .left, .default: return .leading
        case .center:         return .center
        case .right:          return .trailing
        }
    }
}

// MARK: - Color Extension

private extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)

        let r, g, b: Double
        switch hex.count {
        case 3:
            r = Double((int >> 8) & 0xF) / 15.0
            g = Double((int >> 4) & 0xF) / 15.0
            b = Double(int & 0xF) / 15.0
        case 6:
            r = Double((int >> 16) & 0xFF) / 255.0
            g = Double((int >> 8) & 0xFF) / 255.0
            b = Double(int & 0xFF) / 255.0
        default:
            r = 1; g = 1; b = 1
        }
        self.init(red: r, green: g, blue: b)
    }
}

// MARK: - Node List View

struct NomadNodeListView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let onSelectNode: (String) -> Void

    @State private var favorites: [NomadStore.NodeFavorite] = []
    @State private var searchText = ""
    @State private var renamingNode: String?
    @State private var renameText = ""

    private var nomadPeers: [DiscoveredPeer] {
        model.peers.filter(\.isNomadNode)
    }

    private var filteredFavorites: [NomadStore.NodeFavorite] {
        guard !searchText.isEmpty else { return favorites }
        let q = searchText.lowercased()
        return favorites.filter {
            $0.customName.lowercased().contains(q) || $0.destinationHashHex.contains(q)
        }
    }

    private var filteredPeers: [DiscoveredPeer] {
        guard !searchText.isEmpty else { return nomadPeers }
        let q = searchText.lowercased()
        return nomadPeers.filter {
            ($0.displayName?.lowercased().contains(q) ?? false) || $0.hashHex.contains(q)
        }
    }

    var body: some View {
        NavigationStack {
            List {
                if !filteredFavorites.isEmpty {
                    Section("Favorites") {
                        ForEach(filteredFavorites) { fav in
                            Button {
                                onSelectNode(fav.destinationHashHex)
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(fav.customName.isEmpty ? "Unnamed Node" : fav.customName)
                                        .font(.callout)
                                        .foregroundStyle(.primary)
                                    Text(fav.destinationHashHex)
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .contextMenu {
                                Button("Rename") {
                                    renamingNode = fav.destinationHashHex
                                    renameText = fav.customName
                                }
                                Button("Remove from Favorites", role: .destructive) {
                                    Task {
                                        await model.nomadStore.removeFavorite(destinationHashHex: fav.destinationHashHex)
                                        await loadFavorites()
                                    }
                                }
                            }
                        }
                    }
                }

                Section("Discovered Nodes") {
                    if filteredPeers.isEmpty {
                        Text("No Nomad nodes discovered yet.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(filteredPeers) { peer in
                            Button {
                                onSelectNode(peer.hashHex)
                            } label: {
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(peer.displayName ?? peer.shortHash)
                                            .font(.callout)
                                            .foregroundStyle(.primary)
                                        Text(peer.hashHex)
                                            .font(.system(.caption2, design: .monospaced))
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    VStack(alignment: .trailing, spacing: 2) {
                                        if let hops = peer.pathHops {
                                            Text("\(hops) hop\(hops == 1 ? "" : "s")")
                                                .font(.caption2)
                                                .foregroundStyle(.secondary)
                                        }
                                        if let lastSeen = peer.lastAnnounceAt {
                                            Text(lastSeen, style: .relative)
                                                .font(.caption2)
                                                .foregroundStyle(.secondary)
                                        }
                                    }
                                }
                            }
                            .contextMenu {
                                let isFav = favorites.contains { $0.destinationHashHex == peer.hashHex }
                                if isFav {
                                    Button("Remove from Favorites", role: .destructive) {
                                        Task {
                                            await model.nomadStore.removeFavorite(destinationHashHex: peer.hashHex)
                                            await loadFavorites()
                                        }
                                    }
                                } else {
                                    Button("Add to Favorites") {
                                        Task {
                                            await model.nomadStore.addFavorite(
                                                NomadStore.NodeFavorite(
                                                    destinationHashHex: peer.hashHex,
                                                    customName: peer.displayName ?? ""
                                                )
                                            )
                                            await loadFavorites()
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .searchable(text: $searchText, prompt: "Search by name or hash")
            .navigationTitle("Nomad Nodes")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
            .alert("Rename Node", isPresented: .init(
                get: { renamingNode != nil },
                set: { if !$0 { renamingNode = nil } }
            )) {
                TextField("Node name", text: $renameText)
                Button("Save") {
                    if let hash = renamingNode {
                        Task {
                            await model.nomadStore.renameFavorite(destinationHashHex: hash, newName: renameText)
                            await loadFavorites()
                        }
                    }
                    renamingNode = nil
                }
                Button("Cancel", role: .cancel) { renamingNode = nil }
            }
            .task { await loadFavorites() }
        }
    }

    private func loadFavorites() async {
        favorites = await model.nomadStore.allFavorites()
    }
}

// MARK: - Share Sheet

private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
