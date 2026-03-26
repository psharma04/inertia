import Testing
@testable import NomadNet

// NomadNet Module Tests

@Suite("NomadNet")
struct NomadNetTests {

    @Test("MicronParser: plain text passthrough")
    func micronPlainTextPassthrough() {
        let doc = MicronParser.parse("Hello NomadNet")
        #expect(doc.blocks.count == 1)

        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected first block to be plain line")
            return
        }
        #expect(line.plainText == "Hello NomadNet")
    }

    @Test("MicronParser: headings and section reset")
    func micronHeadingAndSectionDepth() {
        let doc = MicronParser.parse("""
        >Title
        Body line
        <
        Root line
        """)

        #expect(doc.blocks.count == 3)

        guard case let .heading(level, headingLine) = doc.blocks[0] else {
            Issue.record("Expected heading as first block")
            return
        }
        #expect(level == 1)
        #expect(headingLine.plainText == "Title")
        #expect(headingLine.sectionDepth == 1)

        guard case let .line(sectionLine) = doc.blocks[1] else {
            Issue.record("Expected line as second block")
            return
        }
        #expect(sectionLine.sectionDepth == 1)
        #expect(sectionLine.plainText == "Body line")

        guard case let .line(rootLine) = doc.blocks[2] else {
            Issue.record("Expected line as third block")
            return
        }
        #expect(rootLine.sectionDepth == 0)
        #expect(rootLine.plainText == "Root line")
    }

    @Test("MicronParser: formatting toggles and reset")
    func micronFormattingToggles() {
        let doc = MicronParser.parse("`!Bold`! normal `*italic`* `__` ``flat")
        #expect(doc.blocks.count == 1)

        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }

        let textInlines = line.inlines.compactMap { inline -> (String, MicronTextStyle)? in
            guard case let .text(value, style) = inline else { return nil }
            return (value, style)
        }

        #expect(textInlines.contains(where: { $0.0 == "Bold" && $0.1.bold }))
        #expect(textInlines.contains(where: { $0.0.contains("italic") && $0.1.italic }))
        #expect(textInlines.contains(where: { $0.0.contains("flat") && !$0.1.bold && !$0.1.italic && !$0.1.underline }))
    }

    @Test("MicronParser: links parse correctly")
    func micronLinks() {
        let doc = MicronParser.parse("`[Home`:/page/index.mu] and `[nn://abcd]")
        #expect(doc.blocks.count == 1)

        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }

        let links = line.inlines.compactMap { inline -> MicronLink? in
            guard case let .link(link, _) = inline else { return nil }
            return link
        }

        #expect(links.count == 2)
        #expect(links[0].label == "Home")
        #expect(links[0].destination == ":/page/index.mu")
        #expect(links[0].fields == nil)
        #expect(links[1].label == "nn://abcd")
        #expect(links[1].destination == "nn://abcd")
    }

    @Test("MicronParser: fields parse text, password and checkbox")
    func micronFields() {
        let doc = MicronParser.parse("`<username`guest> `<!16|password`secret> `<?|remember|yes`>")
        #expect(doc.blocks.count == 1)

        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }

        let fields = line.inlines.compactMap { inline -> MicronField? in
            guard case let .field(field, _) = inline else { return nil }
            return field
        }

        #expect(fields.count == 3)
        #expect(fields[0].kind == .text)
        #expect(fields[0].name == "username")
        #expect(fields[0].value == "guest")

        #expect(fields[1].kind == .password)
        #expect(fields[1].name == "password")
        #expect(fields[1].width == 16)

        #expect(fields[2].kind == .checkbox)
        #expect(fields[2].name == "remember")
        #expect(fields[2].value == "yes")
    }

    @Test("MicronParser: literal mode disables command parsing")
    func micronLiteralMode() {
        let doc = MicronParser.parse("`=literal `!not-bold`! text`= normal")
        #expect(doc.blocks.count == 1)

        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }

        #expect(line.plainText.contains("`!not-bold`!"))
        #expect(line.plainText.hasSuffix(" normal"))
    }

    @Test("MicronParser: metadata and comments")
    func micronMetadataAndComments() {
        let doc = MicronParser.parse("""
        #!c=0
        #!fg=bbb
        # this line should be ignored
        Visible
        -*
        """)

        #expect(doc.metadata["c"] == "0")
        #expect(doc.metadata["fg"] == "bbb")
        #expect(doc.blocks.count == 2)

        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected visible line first")
            return
        }
        #expect(line.plainText == "Visible")

        guard case let .divider(ch) = doc.blocks[1] else {
            Issue.record("Expected divider second")
            return
        }
        #expect(ch == "*")
    }
}
