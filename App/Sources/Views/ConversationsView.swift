import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

struct ConversationsView: View {
    @Environment(AppModel.self) private var model
    @State private var showContacts = false
    @State private var showQRScanner = false
    @State private var navPath = NavigationPath()

    var body: some View {
        NavigationStack(path: $navPath) {
            Group {
                if model.conversations.isEmpty {
                    emptyState
                } else {
                    List(model.sortedConversations) { conversation in
                        NavigationLink(destination: ThreadView(destinationHash: conversation.destinationHash)) {
                            ConversationRow(conversation: conversation)
                        }
                        .swipeActions(edge: .leading) {
                            Button {
                                if model.isPinned(conversation.destinationHash) {
                                    model.unpinConversation(hash: conversation.destinationHash)
                                } else {
                                    model.pinConversation(hash: conversation.destinationHash)
                                }
                            } label: {
                                Label(
                                    model.isPinned(conversation.destinationHash) ? "Unpin" : "Pin",
                                    systemImage: model.isPinned(conversation.destinationHash) ? "pin.slash" : "pin"
                                )
                            }
                            .tint(.orange)
                        }
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                if model.isBlocked(conversation.destinationHash) {
                                    model.unblockContact(hash: conversation.destinationHash)
                                } else {
                                    model.blockContact(hash: conversation.destinationHash)
                                }
                            } label: {
                                Label(
                                    model.isBlocked(conversation.destinationHash) ? "Unblock" : "Block",
                                    systemImage: model.isBlocked(conversation.destinationHash) ? "hand.raised.slash" : "hand.raised"
                                )
                            }
                            .tint(model.isBlocked(conversation.destinationHash) ? .green : .red)
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Messages")
            .accessibilityIdentifier("conversations-list")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showContacts = true
                    } label: {
                        Image(systemName: "person.crop.circle.badge.plus")
                    }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showQRScanner = true
                    } label: {
                        Image(systemName: "qrcode.viewfinder")
                    }
                }
            }
            .sheet(isPresented: $showContacts) {
                ContactsDirectoryView()
            }
            .sheet(isPresented: $showQRScanner) {
                QRScannerView()
            }
            .navigationDestination(for: Data.self) { hash in
                ThreadView(destinationHash: hash)
            }
        }
        .onChange(of: model.pendingOpenConversation) { _, hash in
            guard let hash else { return }
            navPath.append(hash)
            model.pendingOpenConversation = nil
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "bubble.left.and.bubble.right")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)
            Text("No Messages")
                .font(.title2.bold())
            Text("Connect to a Reticulum node, then tap\nthe contacts button to open node details and message peers.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(40)
    }
}

// Conversation row

private struct ConversationRow: View {
    @Environment(AppModel.self) private var model
    let conversation: Conversation

    private var peerName: String {
        model.peerName(for: conversation.destinationHash) ?? "\(conversation.shortHash)…"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                if model.isPinned(conversation.destinationHash) {
                    Image(systemName: "pin.fill")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
                Text(peerName)
 .font(.headline)
                if model.isBlocked(conversation.destinationHash) {
                    Image(systemName: "hand.raised.fill")
                        .font(.caption2)
                        .foregroundStyle(.red)
                }
                Spacer()
                if let last = conversation.lastMessage {
 HStack(spacing: 4) {
     Text(last.timestamp, style: .relative)
         .font(.caption)
         .foregroundStyle(.secondary)
     if last.isOutbound {
         OutboundStatusIndicator(status: last.deliveryStatus)
     }
 }
                }
            }
            if let last = conversation.lastMessage {
                HStack(spacing: 4) {
                    if last.hasMedia {
                        Image(systemName: last.image != nil ? "photo" : "paperclip")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
 Text(last.content)
     .font(.subheadline)
     .foregroundStyle(.secondary)
     .lineLimit(1)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

// Thread view

struct ThreadView: View {
    @Environment(AppModel.self) private var model
    let destinationHash: Data

    @State private var inputText  = ""
    @State private var isSending  = false
    @State private var sendError: String?
    @State private var showContactDetails = false
    @State private var showQRShare = false

    // Attachment state
    @State private var selectedPhotoItem: PhotosPickerItem?
    @State private var pendingImageData: Data?
    @State private var pendingImageName: String?
    @State private var showDocumentPicker = false
    @State private var showPhotoPicker = false
    @State private var pendingFileData: Data?
    @State private var pendingFileName: String?
    @State private var showAttachmentOptions = false
    @State private var isNearBottom = true

    private var conversation: Conversation? {
        model.conversations.first { $0.destinationHash == destinationHash }
    }

    private var hasPendingAttachment: Bool {
        pendingImageData != nil || pendingFileData != nil
    }

    var body: some View {
        VStack(spacing: 0) {
            messageList
            if hasPendingAttachment {
                attachmentPreview
            } else {
                Divider()
            }
            inputBar
        }
        .navigationTitle("")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Button {
                    showContactDetails = true
                } label: {
                    Text(model.peerName(for: destinationHash) ?? "\(destinationHash.hexString.prefix(8))…")
                        .font(.headline)
                        .lineLimit(1)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Open contact details")
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showQRShare = true
                } label: {
                    Image(systemName: "qrcode")
                }
            }
        }
        .navigationDestination(isPresented: $showContactDetails) {
            ContactDetailsView(destinationHash: destinationHash)
        }
        .sheet(isPresented: $showQRShare) {
            QRShareView(destinationHash: destinationHash)
        }
        .sheet(isPresented: $showDocumentPicker) {
            DocumentPickerView { url in
                loadFileFromURL(url)
            }
        }
        .onAppear { model.activeConversationHash = destinationHash }
        .onDisappear { model.activeConversationHash = nil }
        .alert("Send Failed", isPresented: .constant(sendError != nil)) {
            Button("OK") { sendError = nil }
        } message: {
            Text(sendError ?? "")
        }
        .onChange(of: selectedPhotoItem) { _, item in
            guard let item else { return }
            Task {
                if let imageData = await loadPhotoData(from: item) {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        pendingImageData = imageData
                        pendingImageName = "image.jpg"
                        pendingFileData = nil
                        pendingFileName = nil
                    }
                }
                selectedPhotoItem = nil
            }
        }
        .photosPicker(isPresented: $showPhotoPicker, selection: $selectedPhotoItem, matching: .images)
    }

    // MARK: Attachment preview

    private var attachmentPreview: some View {
        VStack(spacing: 0) {
            Divider()
            if let imageData = pendingImageData, let uiImage = UIImage(data: imageData) {
                ZStack(alignment: .topTrailing) {
                    Image(uiImage: uiImage)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: .infinity, maxHeight: 240)
                        .clipShape(RoundedRectangle(cornerRadius: 12))

                    Button {
                        withAnimation(.easeOut(duration: 0.15)) {
                            clearPendingAttachment()
                        }
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.title2)
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, Color.black.opacity(0.55))
                            .shadow(radius: 2)
                    }
                    .padding(6)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            } else if let fileName = pendingFileName {
                HStack(spacing: 10) {
                    Image(systemName: "doc.fill")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(fileName)
                            .font(.subheadline.weight(.medium))
                            .lineLimit(1)
                        if let size = pendingFileData?.count {
                            Text(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    Button {
                        withAnimation(.easeOut(duration: 0.15)) {
                            clearPendingAttachment()
                        }
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.title3)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
            }
        }
        .background(Color(.systemBackground))
        .transition(.move(edge: .bottom).combined(with: .opacity))
    }

    // MARK: Message list

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 2) {
 ForEach(conversation?.messages ?? []) { message in
     MessageBubble(message: message)
         .id(message.id)
 }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            .onScrollGeometryChange(for: Bool.self) { geometry in
                let maxOffset = geometry.contentSize.height - geometry.containerSize.height
                // Consider "near bottom" if within ~60pt of the end
                return maxOffset <= 0 || geometry.contentOffset.y >= maxOffset - 60
            } action: { _, newValue in
                isNearBottom = newValue
            }
            .onChange(of: conversation?.messages.count) { _, _ in
                if isNearBottom, let last = conversation?.messages.last {
 withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
            .onAppear {
                if let last = conversation?.messages.last {
 proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
        }
    }

    // MARK: Input bar

    private var inputBar: some View {
        HStack(alignment: .bottom, spacing: 8) {
            // Attachment button
            Menu {
                Button {
                    showPhotoPicker = true
                } label: {
                    Label("Photo", systemImage: "photo")
                }
                Button {
                    showDocumentPicker = true
                } label: {
                    Label("File", systemImage: "doc")
                }
            } label: {
                Image(systemName: "plus.circle.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(.secondary)
            }

            TextField("Message", text: $inputText, axis: .vertical)
                .textFieldStyle(.plain)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 20))
                .lineLimit(1...5)
                .accessibilityIdentifier("message-input")

            Button {
                sendMessage()
            } label: {
                Image(systemName: "arrow.up.circle.fill")
 .font(.system(size: 32))
 .foregroundStyle(canSend
     ? AnyShapeStyle(Color.accentColor)
     : AnyShapeStyle(.secondary))
            }
            .disabled(!canSend || isSending)
            .accessibilityIdentifier("send-button")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
    }

    private var canSend: Bool {
        !inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || hasPendingAttachment
    }

    // MARK: Send action

    private func sendMessage() {
        let content = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !content.isEmpty || hasPendingAttachment else { return }
        let capturedImageData = pendingImageData
        let capturedImageName = pendingImageName
        let capturedFileData = pendingFileData
        let capturedFileName = pendingFileName
        let savedText = inputText
        inputText  = ""
        clearPendingAttachment()
        isSending  = true
        isNearBottom = true
        Task {
            do {
                var fields: [Int: Data] = [:]
                var outAttachments: [MessageAttachment]?
                var outImage: MessageImage?
                let msgID = UUID()

                if let imgData = capturedImageData {
                    // Compress and encode as FIELD_IMAGE
                    let compressed: Data
                    if let uiImage = UIImage(data: imgData),
                       let comp = model.compressImageForTransport(uiImage) {
                        compressed = comp
                    } else {
                        compressed = imgData
                    }
                    fields[LXMFFieldKey.image] = model.encodeImageField(type: "jpg", data: compressed)
                    let path = model.saveAttachmentData(compressed, messageID: msgID.uuidString, filename: capturedImageName ?? "image.jpg")
                    outImage = MessageImage(type: "jpg", size: compressed.count, storagePath: path)
                } else if let fileData = capturedFileData, let fileName = capturedFileName {
                    // Encode as FIELD_FILE_ATTACHMENTS
                    fields[LXMFFieldKey.fileAttachments] = model.encodeFileAttachmentsField(files: [(name: fileName, data: fileData)])
                    let path = model.saveAttachmentData(fileData, messageID: msgID.uuidString, filename: fileName)
                    outAttachments = [MessageAttachment(name: fileName, size: fileData.count, storagePath: path)]
                }

                try await model.send(
                    to: destinationHash,
                    content: content.isEmpty ? "📎" : content,
                    fields: fields,
                    attachments: outAttachments,
                    image: outImage,
                    outboundMessageID: msgID
                )
            } catch {
                sendError = error.localizedDescription
                // Restore the message text so the user can retry
                if inputText.isEmpty { inputText = savedText }
            }
            isSending = false
        }
    }

    private func clearPendingAttachment() {
        pendingImageData = nil
        pendingImageName = nil
        pendingFileData = nil
        pendingFileName = nil
    }

    private func loadPhotoData(from item: PhotosPickerItem) async -> Data? {
        // PhotosPicker's loadTransferable(type: Data.self) is unreliable.
        // Use a custom Transferable with .image content type instead.
        if let photo = try? await item.loadTransferable(type: PhotoTransferable.self) {
            return photo.data
        }
        // Last resort: raw Data
        return try? await item.loadTransferable(type: Data.self)
    }

    private func loadFileFromURL(_ url: URL) {
        guard url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }
        guard let data = try? Data(contentsOf: url) else { return }
        pendingFileData = data
        pendingFileName = url.lastPathComponent
        pendingImageData = nil
        pendingImageName = nil
    }
}

// Message bubble

private struct MessageBubble: View {
    @Environment(AppModel.self) private var model
    let message: ConversationMessage
    @State private var showFullImage = false

    var body: some View {
        HStack {
            if message.isOutbound { Spacer(minLength: 60) }
            VStack(alignment: message.isOutbound ? .trailing : .leading, spacing: 2) {
                VStack(alignment: .leading, spacing: 6) {
                    // Inline image
                    if let img = message.image, let path = img.storagePath,
                       let data = model.loadAttachmentData(storagePath: path),
                       let uiImage = UIImage(data: data) {
                        Button { showFullImage = true } label: {
                            Image(uiImage: uiImage)
                                .resizable()
                                .scaledToFit()
                                .frame(maxWidth: 220, maxHeight: 220)
                                .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                    }
                    // File attachments
                    if let attachments = message.attachments {
                        ForEach(attachments.indices, id: \.self) { i in
                            let att = attachments[i]
                            Label {
                                Text(att.name)
                                    .font(.caption)
                                Text(ByteCountFormatter.string(fromByteCount: Int64(att.size), countStyle: .file))
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            } icon: {
                                Image(systemName: "doc")
                            }
                            .padding(.vertical, 2)
                        }
                    }
                    // Text
                    if !message.content.isEmpty && message.content != "📎" {
                        Text(message.content)
                    }
                }
 .padding(.horizontal, 14)
 .padding(.vertical, 10)
 .background(
     message.isOutbound ? Color.accentColor : Color(.secondarySystemBackground),
     in: RoundedRectangle(cornerRadius: 18)
 )
 .foregroundStyle(message.isOutbound ? .white : .primary)
                if message.isOutbound {
                    HStack(spacing: 4) {
                        Text(message.timestamp, style: .time)
                        OutboundStatusIndicator(status: message.deliveryStatus)
                    }
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .padding(.horizontal, 4)
                } else {
                    Text(message.timestamp, style: .time)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .padding(.horizontal, 4)
                }
            }
            if !message.isOutbound { Spacer(minLength: 60) }
        }
        .padding(.vertical, 2)
        .fullScreenCover(isPresented: $showFullImage) {
            if let img = message.image, let path = img.storagePath,
               let data = model.loadAttachmentData(storagePath: path),
               let uiImage = UIImage(data: data) {
                ZStack(alignment: .topTrailing) {
                    Color.black.ignoresSafeArea()
                    Image(uiImage: uiImage)
                        .resizable()
                        .scaledToFit()
                    Button {
                        showFullImage = false
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.title)
                            .foregroundStyle(.white)
                            .padding()
                    }
                }
            }
        }
    }
}

private struct OutboundStatusIndicator: View {
    let status: OutboundDeliveryStatus?

    var body: some View {
        switch status ?? .sent {
        case .sending:
            ProgressView()
                .controlSize(.mini)

        case .sent:
            Image(systemName: "checkmark")
                .font(.caption2)
                .foregroundStyle(.secondary)

        case .delivered:
            HStack(spacing: -5) {
                Image(systemName: "checkmark")
                Image(systemName: "checkmark")
            }
            .font(.caption2)
            .foregroundStyle(.secondary)

        case .failed:
            Image(systemName: "exclamationmark.circle.fill")
                .font(.caption2)
                .foregroundStyle(.red)
        }
    }
}

// MARK: - QR Code Views

struct QRShareView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let destinationHash: Data
    @State private var messageText = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Text("Paper Message")
                    .font(.title2.bold())
                Text("Generate a QR code containing an encrypted paper message.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                TextField("Message (text only)", text: $messageText, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(3...6)
                    .padding(.horizontal)

                if let qrImage = generateQRCode() {
                    Image(uiImage: qrImage)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 250, maxHeight: 250)
                        .padding()
                } else if !messageText.isEmpty {
                    Text("Message too long for QR code")
                        .foregroundStyle(.red)
                        .font(.caption)
                }

                Spacer()
            }
            .padding()
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func generateQRCode() -> UIImage? {
        let trimmed = messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        // For paper messages, we need the recipient's public key to encrypt.
        // Use the cached peer key if available.
        guard let identity = model.identity else { return nil }
        let srcHash = identity.hash
        let content = Data(trimmed.utf8)
        let plaintext = srcHash + content

        // Encrypt to the recipient using our identity
        guard let encrypted = try? identity.encrypt(plaintext) else { return nil }
        let payload = destinationHash + encrypted
        let base64url = payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let uri = "lxm://\(base64url)"

        guard let data = uri.data(using: String.Encoding.utf8) else { return nil }
        // QR v40 at ECC L supports max 2953 bytes
        guard data.count <= 2953 else { return nil }
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("L", forKey: "inputCorrectionLevel")
        guard let ciImage = filter.outputImage else { return nil }
        let scale = CGAffineTransform(scaleX: 8, y: 8)
        let scaledImage = ciImage.transformed(by: scale)
        let context = CIContext()
        guard let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

struct QRScannerView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var scannedCode: String?
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            VStack {
                Text("Scan a paper message QR code")
                    .font(.headline)
                    .padding()
                Text("Point your camera at an lxm:// QR code to import a paper message.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)

                Spacer()

                // Manual paste fallback
                if let error = errorMessage {
                    Text(error)
                        .foregroundStyle(.red)
                        .font(.caption)
                        .padding()
                }

                Button {
                    if let clipboard = UIPasteboard.general.string, clipboard.hasPrefix("lxm://") {
                        handleScanned(clipboard)
                    } else {
                        errorMessage = "No lxm:// URI found in clipboard"
                    }
                } label: {
                    Label("Paste from Clipboard", systemImage: "doc.on.clipboard")
                }
                .padding()
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func handleScanned(_ uri: String) {
        guard let url = URL(string: uri) else {
            errorMessage = "Invalid URI"
            return
        }
        model.handleDeepLink(url)
        dismiss()
    }
}

// MARK: - Document Picker

struct DocumentPickerView: UIViewControllerRepresentable {
    let onPick: (URL) -> Void

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.item])
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onPick: onPick)
    }

    class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onPick: (URL) -> Void
        init(onPick: @escaping (URL) -> Void) { self.onPick = onPick }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else { return }
            onPick(url)
        }
    }
}

private struct PhotoTransferable: Transferable {
    let data: Data

    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(importedContentType: .image) { data in
            PhotoTransferable(data: data)
        }
    }
}
