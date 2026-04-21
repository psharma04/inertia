import Foundation

// Micron model

public enum MicronAlignment: String, Sendable, Equatable {
    case `default`
    case left
    case center
    case right
}

public enum MicronColor: Sendable, Equatable {
    case rgb(String)          // 3-digit hex, e.g. "0af"
    case extendedRgb(String)  // 6-digit hex, e.g. "00aaff"
    case grayscale(UInt8)     // 00...99
}

public struct MicronTextStyle: Sendable, Equatable {
    public var bold: Bool
    public var italic: Bool
    public var underline: Bool
    public var strikethrough: Bool
    public var foreground: MicronColor?
    public var background: MicronColor?

    public init(
        bold: Bool = false,
        italic: Bool = false,
        underline: Bool = false,
        strikethrough: Bool = false,
        foreground: MicronColor? = nil,
        background: MicronColor? = nil
    ) {
        self.bold = bold
        self.italic = italic
        self.underline = underline
        self.strikethrough = strikethrough
        self.foreground = foreground
        self.background = background
    }
}

public struct MicronLink: Sendable, Equatable {
    public let label: String
    public let destination: String
    public let fields: String?

    public init(label: String, destination: String, fields: String?) {
        self.label = label
        self.destination = destination
        self.fields = fields
    }
}

public enum MicronFieldKind: String, Sendable, Equatable {
    case text
    case password
    case checkbox
    case radio
}

public struct MicronField: Sendable, Equatable {
    public let kind: MicronFieldKind
    public let name: String
    public let value: String
    public let width: Int?

    public init(kind: MicronFieldKind, name: String, value: String, width: Int?) {
        self.kind = kind
        self.name = name
        self.value = value
        self.width = width
    }
}

public enum MicronInline: Sendable, Equatable {
    case text(String, style: MicronTextStyle)
    case link(MicronLink, style: MicronTextStyle)
    case field(MicronField, style: MicronTextStyle)

    public var text: String {
        switch self {
        case let .text(value, _): return value
        case let .link(link, _): return link.label.isEmpty ? link.destination : link.label
        case let .field(field, _): return field.name
        }
    }

    public var style: MicronTextStyle {
        switch self {
        case let .text(_, style): return style
        case let .link(_, style): return style
        case let .field(_, style): return style
        }
    }
}

public struct MicronLine: Sendable, Equatable {
    public let alignment: MicronAlignment
    public let sectionDepth: Int
    public let inlines: [MicronInline]

    public init(alignment: MicronAlignment, sectionDepth: Int, inlines: [MicronInline]) {
        self.alignment = alignment
        self.sectionDepth = sectionDepth
        self.inlines = inlines
    }

    public var plainText: String {
        inlines.map { inline in
            switch inline {
            case let .text(value, _):
                value
            case let .link(link, _):
                link.label.isEmpty ? link.destination : link.label
            case let .field(field, _):
                field.value
            }
        }.joined()
    }
}

public enum MicronBlock: Sendable, Equatable {
    case heading(level: Int, line: MicronLine)
    case line(MicronLine)
    case divider(Character)
}

public struct MicronDocument: Sendable, Equatable {
    public let metadata: [String: String]
    public let blocks: [MicronBlock]

    public init(metadata: [String: String], blocks: [MicronBlock]) {
        self.metadata = metadata
        self.blocks = blocks
    }

    public var plainText: String {
        blocks.map { block in
            switch block {
            case let .heading(_, line):
                line.plainText
            case let .line(line):
                line.plainText
            case let .divider(character):
                String(repeating: String(character), count: 32)
            }
        }.joined(separator: "\n")
    }

    /// Cache TTL in seconds from `#!c=N` metadata directive, or nil for default.
    public var cacheTTL: TimeInterval? {
        guard let value = metadata["c"], let seconds = TimeInterval(value), seconds >= 0 else {
            return nil
        }
        return seconds
    }
}

// Micron parser

public enum MicronParser {
    public static func parse(_ source: String) -> MicronDocument {
        var metadata: [String: String] = [:]
        var blocks: [MicronBlock] = []
        var state = ParserState()

        let lines = source.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
        for lineSlice in lines {
            let rawLine = String(lineSlice)

            if !state.literalMode {
                if rawLine.hasPrefix("#!") {
 parseMetadata(rawLine, into: &metadata)
 continue
                }

                if rawLine.hasPrefix("#") {
 continue
                }

                if rawLine == "<" {
 state.sectionDepth = 0
 continue
                }

                if rawLine.hasPrefix("<") {
 state.sectionDepth = 0
 let remainder = String(rawLine.dropFirst())
 if remainder.isEmpty {
     continue
 }
 let line = parseInline(remainder, state: &state)
 blocks.append(.line(line))
 continue
                }

                if rawLine.hasPrefix("-") {
 let chars = Array(rawLine)
 let dividerCharacter: Character = chars.count > 1 ? chars[1] : "─"
 blocks.append(.divider(dividerCharacter))
 continue
                }

                if rawLine.hasPrefix(">") {
 let level = rawLine.prefix(while: { $0 == ">" }).count
 state.sectionDepth = max(0, level)
 var remainder = String(rawLine.dropFirst(level))
 if remainder.hasPrefix(" ") {
     remainder.removeFirst()
 }
 let headingLine = parseInline(remainder, state: &state)
 blocks.append(.heading(level: max(1, level), line: headingLine))
 continue
                }
            }

            let line = parseInline(rawLine, state: &state)
            blocks.append(.line(line))
        }

        return MicronDocument(metadata: metadata, blocks: blocks)
    }

    private struct ParserState {
        var style = MicronTextStyle()
        var alignment: MicronAlignment = .default
        var sectionDepth = 0
        var literalMode = false

        mutating func resetFormatting() {
            style.bold = false
            style.italic = false
            style.underline = false
            style.strikethrough = false
            style.foreground = nil
            style.background = nil
        }
    }

    private static func parseMetadata(_ line: String, into metadata: inout [String: String]) {
        let body = String(line.dropFirst(2))
        guard let separator = body.firstIndex(of: "=") else { return }

        let key = String(body[..<separator]).trimmingCharacters(in: .whitespaces)
        let value = String(body[body.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty else { return }
        metadata[key] = value
    }

    private static func parseInline(_ line: String, state: inout ParserState) -> MicronLine {
        let chars = Array(line)
        var inlines: [MicronInline] = []
        var buffer = ""
        var index = 0
        var lineAlignment = state.alignment
        var emittedVisibleInline = false

        func flushBuffer() {
            guard !buffer.isEmpty else { return }
            inlines.append(.text(buffer, style: state.style))
            buffer.removeAll(keepingCapacity: true)
            emittedVisibleInline = true
        }

        while index < chars.count {
            let current = chars[index]

            if state.literalMode {
                if current == "`", index + 1 < chars.count, chars[index + 1] == "=" {
 flushBuffer()
 state.literalMode.toggle()
 index += 2
 continue
                }

                if current == "\\", index + 1 < chars.count {
 buffer.append(chars[index + 1])
 index += 2
 continue
                }

                buffer.append(current)
                index += 1
                continue
            }

            if current == "\\" {
                if index + 1 < chars.count {
 buffer.append(chars[index + 1])
 index += 2
                } else {
 buffer.append("\\")
 index += 1
                }
                continue
            }

            guard current == "`" else {
                buffer.append(current)
                index += 1
                continue
            }

            // Lone trailing backtick with no command character – drop it.
            guard index + 1 < chars.count else {
                index += 1
                continue
            }

            let command = chars[index + 1]
            switch command {
            case "!":
                flushBuffer()
                state.style.bold.toggle()
                index += 2

            case "*":
                flushBuffer()
                state.style.italic.toggle()
                index += 2

            case "_":
                flushBuffer()
                state.style.underline.toggle()
                index += 2

            case "~":
                flushBuffer()
                state.style.strikethrough.toggle()
                index += 2

            case "`":
                flushBuffer()
                state.resetFormatting()
                index += 2

            case "=":
                flushBuffer()
                state.literalMode.toggle()
                index += 2

            case "c", "l", "r", "a":
                flushBuffer()
                let alignment = alignmentFor(command)
                if !emittedVisibleInline {
 lineAlignment = alignment
                }
                state.alignment = alignment
                index += 2

            case "f":
                flushBuffer()
                state.style.foreground = nil
                index += 2

            case "b":
                flushBuffer()
                state.style.background = nil
                index += 2

            case "F":
                if index + 2 < chars.count, chars[index + 2] == "T",
                   let (hex6, next) = parseExtendedHex(chars: chars, start: index + 3) {
                    flushBuffer()
                    state.style.foreground = .extendedRgb(hex6)
                    index = next
                } else if let (triplet, next) = parseHexTriplet(chars: chars, start: index + 2) {
                    flushBuffer()
                    state.style.foreground = .rgb(triplet)
                    index = next
                } else {
                    buffer.append("`")
                    index += 1
                }

            case "B":
                if index + 2 < chars.count, chars[index + 2] == "T",
                   let (hex6, next) = parseExtendedHex(chars: chars, start: index + 3) {
                    flushBuffer()
                    state.style.background = .extendedRgb(hex6)
                    index = next
                } else if let (triplet, next) = parseHexTriplet(chars: chars, start: index + 2) {
                    flushBuffer()
                    state.style.background = .rgb(triplet)
                    index = next
                } else {
                    buffer.append("`")
                    index += 1
                }

            case "g":
                if let (value, next) = parseGrayscale(chars: chars, start: index + 2) {
 flushBuffer()
 state.style.foreground = .grayscale(value)
 index = next
                } else {
 buffer.append("`")
 index += 1
                }

            case "[":
                if let (raw, next) = parseDelimited(chars: chars, start: index + 2, terminator: "]"),
                   let link = parseLink(raw) {
 flushBuffer()
 inlines.append(.link(link, style: state.style))
 emittedVisibleInline = true
 index = next
                } else {
 buffer.append("`")
 index += 1
                }

            case "<":
                if let (raw, next) = parseDelimited(chars: chars, start: index + 2, terminator: ">"),
                   let field = parseField(raw) {
 flushBuffer()
 inlines.append(.field(field, style: state.style))
 emittedVisibleInline = true
 index = next
                } else {
 buffer.append("`")
 index += 1
                }

            default:
                // Unknown command: treat the backtick literally and keep parsing.
                buffer.append("`")
                index += 1
            }
        }

        flushBuffer()
        return MicronLine(alignment: lineAlignment, sectionDepth: state.sectionDepth, inlines: inlines)
    }

    private static func alignmentFor(_ command: Character) -> MicronAlignment {
        switch command {
        case "c":
            return .center
        case "l":
            return .left
        case "r":
            return .right
        default:
            return .default
        }
    }

    private static func parseHexTriplet(chars: [Character], start: Int) -> (String, Int)? {
        guard start + 2 < chars.count else { return nil }
        let triplet = String(chars[start ... start + 2]).lowercased()
        guard triplet.count == 3, triplet.allSatisfy({ $0.hexDigitValue != nil }) else { return nil }
        return (triplet, start + 3)
    }

    private static func parseExtendedHex(chars: [Character], start: Int) -> (String, Int)? {
        guard start + 5 < chars.count else { return nil }
        let hex6 = String(chars[start ... start + 5]).lowercased()
        guard hex6.count == 6, hex6.allSatisfy({ $0.hexDigitValue != nil }) else { return nil }
        return (hex6, start + 6)
    }

    private static func parseGrayscale(chars: [Character], start: Int) -> (UInt8, Int)? {
        guard start + 1 < chars.count else { return nil }
        let digits = String(chars[start ... start + 1])
        guard let value = UInt8(digits), value <= 99 else { return nil }
        return (value, start + 2)
    }

    private static func parseDelimited(
        chars: [Character],
        start: Int,
        terminator: Character
    ) -> (String, Int)? {
        var index = start
        var value: [Character] = []

        while index < chars.count {
            let current = chars[index]
            if current == "\\", index + 1 < chars.count {
                value.append(chars[index + 1])
                index += 2
                continue
            }

            if current == terminator {
                return (String(value), index + 1)
            }

            value.append(current)
            index += 1
        }

        return nil
    }

    private static func parseLink(_ raw: String) -> MicronLink? {
        let parts = raw.split(separator: "`", omittingEmptySubsequences: false).map(String.init)
        guard !parts.isEmpty else { return nil }

        if parts.count == 1 {
            let destination = parts[0].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !destination.isEmpty else { return nil }
            return MicronLink(label: destination, destination: destination, fields: nil)
        }

        let destination = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
        guard !destination.isEmpty else { return nil }

        let label = parts[0].isEmpty ? destination : parts[0]
        let fieldRaw = parts.count > 2 ? parts.dropFirst(2).joined(separator: "`") : ""
        let fields = fieldRaw.isEmpty ? nil : fieldRaw
        return MicronLink(label: label, destination: destination, fields: fields)
    }

    private static func parseField(_ raw: String) -> MicronField? {
        let parts = raw.split(separator: "`", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        guard let head = parts.first, !head.isEmpty else { return nil }
        let tail = parts.count > 1 ? parts[1] : ""

        if head.hasPrefix("?|") || head.hasPrefix("^|") {
            let kind: MicronFieldKind = head.hasPrefix("?|") ? .checkbox : .radio
            let fieldParts = head.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard fieldParts.count >= 2 else { return nil }
            let name = fieldParts[1]
            guard !name.isEmpty else { return nil }
            let value = fieldParts.count > 2 ? fieldParts[2] : tail
            return MicronField(kind: kind, name: name, value: value, width: nil)
        }

        var kind: MicronFieldKind = .text
        var name = head
        var width: Int?

        if let pipeIndex = head.firstIndex(of: "|") {
            let left = String(head[..<pipeIndex])
            let right = String(head[head.index(after: pipeIndex)...])
            guard !right.isEmpty else { return nil }

            if left.hasPrefix("!") {
                kind = .password
                let widthDigits = String(left.dropFirst())
                if let parsedWidth = Int(widthDigits), parsedWidth > 0 {
 width = parsedWidth
                }
            } else if let parsedWidth = Int(left), parsedWidth > 0 {
                width = parsedWidth
            }

            name = right
        } else if name.hasPrefix("!") {
            kind = .password
            name = String(name.dropFirst())
        }

        guard !name.isEmpty else { return nil }
        return MicronField(kind: kind, name: name, value: tail, width: width)
    }
}
