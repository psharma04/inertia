import SwiftUI

struct ConversationsView: View {
    @Environment(AppModel.self) private var model
    @State private var showContacts = false

    var body: some View {
        NavigationStack {
            Group {
                if model.conversations.isEmpty {
 emptyState
                } else {
 List(model.conversations) { conversation in
     NavigationLink(destination: ThreadView(destinationHash: conversation.destinationHash)) {
         ConversationRow(conversation: conversation)
     }
 }
 .listStyle(.plain)
                }
            }
            .navigationTitle("Messages")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showContacts = true
                    } label: {
                        Image(systemName: "person.crop.circle.badge.plus")
                    }
                }
            }
            .sheet(isPresented: $showContacts) {
                ContactsDirectoryView()
            }
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
        model.peerName(for: conversation.destinationHash) ?? (conversation.shortHash + "…")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(peerName)
 .font(.headline)
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

    private var conversation: Conversation? {
        model.conversations.first { $0.destinationHash == destinationHash }
    }

    var body: some View {
        VStack(spacing: 0) {
            messageList
            Divider()
            inputBar
        }
        .navigationTitle("")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Button {
                    showContactDetails = true
                } label: {
                    Text(model.peerName(for: destinationHash) ?? (destinationHash.hexString.prefix(8) + "…"))
                        .font(.headline)
                        .lineLimit(1)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Open contact details")
            }
        }
        .navigationDestination(isPresented: $showContactDetails) {
            ContactDetailsView(destinationHash: destinationHash)
        }
        .alert("Send Failed", isPresented: .constant(sendError != nil)) {
            Button("OK") { sendError = nil }
        } message: {
            Text(sendError ?? "")
        }
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
            .onChange(of: conversation?.messages.count) { _, _ in
                if let last = conversation?.messages.last {
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
            TextField("Message", text: $inputText, axis: .vertical)
                .textFieldStyle(.plain)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 20))
                .lineLimit(1...5)

            Button {
                sendMessage()
            } label: {
                Image(systemName: "arrow.up.circle.fill")
 .font(.system(size: 32))
 .foregroundStyle(inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
     ? AnyShapeStyle(.secondary)
     : AnyShapeStyle(Color.accentColor))
            }
            .disabled(inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isSending)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
    }

    // MARK: Send action

    private func sendMessage() {
        let content = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !content.isEmpty else { return }
        inputText  = ""
        isSending  = true
        Task {
            do {
                try await model.send(to: destinationHash, content: content)
            } catch {
                sendError = error.localizedDescription
            }
            isSending = false
        }
    }
}

// Message bubble

private struct MessageBubble: View {
    let message: ConversationMessage

    var body: some View {
        HStack {
            if message.isOutbound { Spacer(minLength: 60) }
            VStack(alignment: message.isOutbound ? .trailing : .leading, spacing: 2) {
                Text(message.content)
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
    }
}

private struct OutboundStatusIndicator: View {
    let status: OutboundDeliveryStatus?

    var body: some View {
        switch status ?? .sent {
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
