import Testing
import Foundation
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

    @Test("MicronParser: strikethrough toggle")
    func micronStrikethrough() {
        let doc = MicronParser.parse("`~crossed`~ out")
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        #expect(line.inlines.count == 2)
        #expect(line.inlines[0].text == "crossed")
        #expect(line.inlines[0].style.strikethrough == true)
        #expect(line.inlines[1].text == " out")
        #expect(line.inlines[1].style.strikethrough == false)
    }

    @Test("MicronParser: strikethrough with bold nesting")
    func micronStrikethroughBoldNesting() {
        let doc = MicronParser.parse("`!`~bold-strike`!`~ plain")
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        #expect(line.inlines[0].style.bold == true)
        #expect(line.inlines[0].style.strikethrough == true)
        #expect(line.inlines[0].text == "bold-strike")
    }

    @Test("MicronParser: extended 6-digit foreground color")
    func micronExtendedForegroundColor() {
        let doc = MicronParser.parse("`FTff8800orange`f")
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        #expect(line.inlines[0].style.foreground == .extendedRgb("ff8800"))
        #expect(line.inlines[0].text == "orange")
    }

    @Test("MicronParser: extended 6-digit background color")
    func micronExtendedBackgroundColor() {
        let doc = MicronParser.parse("`BT0000fftxt`b")
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        #expect(line.inlines[0].style.background == .extendedRgb("0000ff"))
        #expect(line.inlines[0].text == "txt")
    }

    @Test("MicronParser: mixed extended and standard colors")
    func micronMixedColorFormats() {
        let doc = MicronParser.parse("`Ff00short`f`FTff0000long`f")
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        #expect(line.inlines[0].style.foreground == .rgb("f00"))
        #expect(line.inlines[0].text == "short")
        #expect(line.inlines[1].style.foreground == .extendedRgb("ff0000"))
        #expect(line.inlines[1].text == "long")
    }

    @Test("MicronParser: invalid extended color falls through")
    func micronInvalidExtendedColor() {
        // FTxyz is not valid hex6 (only 3 chars after T), should fall through
        let doc = MicronParser.parse("`FTxyzHello")
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        // Should not crash; the backtick is treated as literal
        #expect(line.plainText.contains("`"))
    }

    @Test("MicronParser: trailing backtick is silently dropped")
    func micronTrailingBacktick() {
        // `l` → left alignment, trailing backtick should not render
        let doc = MicronParser.parse("`l`")
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        #expect(line.alignment == .left)
        #expect(line.plainText == "")
    }

    @Test("MicronParser: link with HTTP destination")
    func micronHTTPLink() {
        let doc = MicronParser.parse("`[TestFlight`https://testflight.apple.com/join/ABC]")
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        guard case let .link(link, _) = line.inlines.first else {
            Issue.record("Expected link inline")
            return
        }
        #expect(link.label == "TestFlight")
        #expect(link.destination == "https://testflight.apple.com/join/ABC")
    }

    @Test("MicronParser: link with hash fragment in URL")
    func micronLinkWithFragment() {
        let src = "`[#inertia:inyourair.space`https://matrix.to/#/#inertia:inyourair.space]"
        let doc = MicronParser.parse(src)
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        guard case let .link(link, _) = line.inlines.first else {
            Issue.record("Expected link inline")
            return
        }
        #expect(link.label == "#inertia:inyourair.space")
        #expect(link.destination == "https://matrix.to/#/#inertia:inyourair.space")
    }

    @Test("MicronParser: styled link with colors and underline")
    func micronStyledLink() {
        // Pattern from the real index.mu: `F07f`_`[TestFlight`https://example.com]`_`f
        let src = "`F07f`_`[TestFlight`https://example.com]`_`f"
        let doc = MicronParser.parse(src)
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        // Should contain a link inline
        let linkInlines = line.inlines.filter {
            if case .link = $0 { return true }
            return false
        }
        #expect(linkInlines.count == 1)
        if case let .link(link, style) = linkInlines.first {
            #expect(link.label == "TestFlight")
            #expect(link.destination == "https://example.com")
            #expect(style.underline == true)
            #expect(style.foreground != nil)
        }
    }

    @Test("MicronParser: nomadnet page link with local path")
    func micronNomadPageLink() {
        let src = "`[About`:/page/about.mu]"
        let doc = MicronParser.parse(src)
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        guard case let .link(link, _) = line.inlines.first else {
            Issue.record("Expected link inline")
            return
        }
        #expect(link.label == "About")
        #expect(link.destination == ":/page/about.mu")
    }

    @Test("MicronParser: link with text on same line produces link inline")
    func micronLinkMixedWithText() {
        let src = "Visit `[Home`:/page/index.mu] now"
        let doc = MicronParser.parse(src)
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        let links = line.inlines.compactMap { inline -> MicronLink? in
            guard case let .link(link, _) = inline else { return nil }
            return link
        }
        #expect(links.count == 1)
        #expect(links[0].label == "Home")
        #expect(links[0].destination == ":/page/index.mu")
        // Also has text inlines
        let texts = line.inlines.compactMap { inline -> String? in
            guard case let .text(value, _) = inline else { return nil }
            return value
        }
        #expect(texts.count == 2)
    }

    @Test("MicronParser: link to another destination hash")
    func micronCrossNodeLink() {
        let dest = "47850a3b99243cfb1147e8856bab2691"
        let src = "`[Nomad Index`\(dest):/page/index.mu]"
        let doc = MicronParser.parse(src)
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block")
            return
        }
        guard case let .link(link, _) = line.inlines.first else {
            Issue.record("Expected link inline")
            return
        }
        #expect(link.label == "Nomad Index")
        #expect(link.destination == "\(dest):/page/index.mu")
    }

    @Test("MicronParser: mixed text and HTTP link on same line")
    func micronMixedTextAndLink() {
        let src = "Visit `[our site`https://example.com] for details."
        let doc = MicronParser.parse(src)
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block"); return
        }
        // Should have: text "Visit ", link "our site"→https://example.com, text " for details."
        let links = line.inlines.compactMap { inline -> MicronLink? in
            guard case let .link(link, _) = inline else { return nil }
            return link
        }
        #expect(links.count == 1)
        #expect(links[0].label == "our site")
        #expect(links[0].destination == "https://example.com")
    }

    @Test("MicronParser: colored text with link on same line")
    func micronColoredTextWithLink() {
        // Pattern from inertia test page: colored text + HTTP link on same line
        let src = "Contact `F3d3@user:example.com`f on Matrix, or message in `F3d3`_`[#channel`https://matrix.to/#/#channel:example.com]`_`f."
        let doc = MicronParser.parse(src)
        guard case let .line(line) = doc.blocks[0] else {
            Issue.record("Expected line block"); return
        }
        let links = line.inlines.compactMap { inline -> MicronLink? in
            guard case let .link(link, _) = inline else { return nil }
            return link
        }
        #expect(links.count == 1)
        #expect(links[0].destination == "https://matrix.to/#/#channel:example.com")
    }

    // MARK: - Real Page Link Extraction Tests

    @Test("Real page: all links extracted from Inertia test page")
    func realPageLinkExtraction() {
        let src = """
        -
        <
        `c`!Inertia`!
        An Reticulum client for iOS and MacOS
        <
        -

        `l`

        App now available on `F07f`_`[TestFlight`https://testflight.apple.com/join/TNCkZ6KX]`_`f.

        Website and source code at `F07f`_`[https://inertia.chat`https://inertia.chat]`_`f

        Contact `F3d3@pepsi:inyourair.space`f on Matrix for progress updates, or message in `F3d3`_`[#inertia:inyourair.space`https://matrix.to/#/#inertia:inyourair.space]`_`f.

        Via LXMF, contact `F3d33662d822203188617b2e44f2908b0bb3`f.

        > RNS Services

        >> TCP Server Interface

        Try `F07frns.inertia.chat:4242`f as a TCP Client Interface.

        >> Propagation Node

        Try `_4c59456b269469fb44bc62c125e8db36`_ as a propagation node.

        The propagation node has a message size limit of 256 kilobytes.
        """
        let doc = MicronParser.parse(src)
        // Collect all links from the document
        var allLinks: [MicronLink] = []
        for block in doc.blocks {
            let line: MicronLine
            switch block {
            case let .heading(_, l): line = l
            case let .line(l): line = l
            case .divider: continue
            }
            for inline in line.inlines {
                if case let .link(link, _) = inline {
                    allLinks.append(link)
                }
            }
        }
        // Should find exactly 3 links: TestFlight, inertia.chat, Matrix channel
        #expect(allLinks.count == 3)
        #expect(allLinks[0].label == "TestFlight")
        #expect(allLinks[0].destination == "https://testflight.apple.com/join/TNCkZ6KX")
        #expect(allLinks[1].label == "https://inertia.chat")
        #expect(allLinks[1].destination == "https://inertia.chat")
        #expect(allLinks[2].label == "#inertia:inyourair.space")
        #expect(allLinks[2].destination == "https://matrix.to/#/#inertia:inyourair.space")
    }

    @Test("NomadAddress: relative path link resolves to current node")
    func nomadAddressRelativePathLink() {
        let currentHash = "1e12dc236a05c930bd2c9190a2940ce7"
        // A bare path link like "/page/about.mu" should resolve to the current node
        let addr = NomadAddress(raw: "/page/about.mu", defaultDestinationHashHex: currentHash)
        #expect(addr.destinationHashHex == currentHash)
        #expect(addr.path == "/page/about.mu")
    }

    @Test("NomadAddress: cross-node link resolves correctly")
    func nomadAddressCrossNodeLink() {
        let currentHash = "1e12dc236a05c930bd2c9190a2940ce7"
        let otherHash = "47850a3b9e0c1d2f3a4b5c6d7e8f9012"
        let addr = NomadAddress(raw: "\(otherHash):/page/index.mu", defaultDestinationHashHex: currentHash)
        #expect(addr.destinationHashHex == otherHash)
        #expect(addr.path == "/page/index.mu")
    }

    @Test("NomadAddress: nomadnet:// URL parses correctly")
    func nomadAddressNomadnetURL() {
        let hash = "1e12dc236a05c930bd2c9190a2940ce7"
        let addr = NomadAddress(raw: "nomadnet://\(hash)/page/about.mu")
        #expect(addr.destinationHashHex == hash)
        #expect(addr.path == "/page/about.mu")
    }

    @Test("NomadAddress: bare hash defaults to /page/index.mu")
    func nomadAddressBareHash() {
        let hash = "1e12dc236a05c930bd2c9190a2940ce7"
        let addr = NomadAddress(raw: hash)
        #expect(addr.destinationHashHex == hash)
        #expect(addr.path == "/page/index.mu")
    }

    @Test("NomadAddress: page/ prefix resolves with default hash")
    func nomadAddressPagePrefix() {
        let currentHash = "1e12dc236a05c930bd2c9190a2940ce7"
        let addr = NomadAddress(raw: "page/about.mu", defaultDestinationHashHex: currentHash)
        #expect(addr.destinationHashHex == currentHash)
        #expect(addr.path == "/page/about.mu")
    }

    @Test("NomadAddress: colon-slash local path")
    func nomadAddressColonSlashLocal() {
        let currentHash = "1e12dc236a05c930bd2c9190a2940ce7"
        let addr = NomadAddress(raw: ":/page/other.mu", defaultDestinationHashHex: currentHash)
        #expect(addr.destinationHashHex == currentHash)
        #expect(addr.path == "/page/other.mu")
    }

    // MARK: - Link URL Construction Tests
    // These test the same URL construction logic used by MicronDocumentView.styledAttributedString.

    /// Helper: build the URL that MicronDocumentView would assign to attr.link for a given link destination.
    private func buildLinkURL(destination: String, currentDestinationHashHex: String?) -> URL? {
        let dest = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: dest),
           let scheme = url.scheme?.lowercased(),
           ["http", "https", "lxm", "lxmf"].contains(scheme) {
            return url
        } else {
            let resolved = NomadAddress(
                raw: dest,
                defaultDestinationHashHex: currentDestinationHashHex
            )
            if let hash = resolved.destinationHashHex {
                return URL(string: "nomadnet://\(hash)\(resolved.path)")
            }
            return nil
        }
    }

    /// Helper: resolve a nomadnet:// URL back to a NomadAddress (as the openURL handler does).
    private func resolveNomadNetURL(_ url: URL, currentDestinationHashHex: String?) -> NomadAddress? {
        guard let scheme = url.scheme?.lowercased(),
              scheme == "nomadnet" || scheme == "nn" else { return nil }
        let prefix = "\(url.scheme!)://"
        let raw = url.absoluteString
        guard raw.count > prefix.count else { return nil }
        let addressStr = String(raw.dropFirst(prefix.count))
        let resolved = NomadAddress(
            raw: addressStr,
            defaultDestinationHashHex: currentDestinationHashHex
        )
        return resolved.destinationHashHex != nil ? resolved : nil
    }

    @Test("Link URL: HTTPS link passes through directly")
    func linkURLHttps() {
        let url = buildLinkURL(destination: "https://example.com/page", currentDestinationHashHex: nil as String?)
        #expect(url?.absoluteString == "https://example.com/page")
        #expect(url?.scheme == "https")
    }

    @Test("Link URL: HTTP link passes through directly")
    func linkURLHttp() {
        let url = buildLinkURL(destination: "http://example.com", currentDestinationHashHex: nil as String?)
        #expect(url?.absoluteString == "http://example.com")
        #expect(url?.scheme == "http")
    }

    @Test("Link URL: relative path becomes nomadnet:// with current hash")
    func linkURLRelativePath() {
        let current = "1e12dc236a05c930bd2c9190a2940ce7"
        let url = buildLinkURL(destination: "/page/about.mu", currentDestinationHashHex: current)
        #expect(url?.scheme == "nomadnet")
        #expect(url?.absoluteString == "nomadnet://\(current)/page/about.mu")
    }

    @Test("Link URL: bare hash becomes nomadnet:// with default path")
    func linkURLBareHash() {
        let other = "47850a3b99243cfb1147e8856bab2691"
        let url = buildLinkURL(destination: other, currentDestinationHashHex: nil as String?)
        #expect(url?.scheme == "nomadnet")
        #expect(url?.absoluteString == "nomadnet://\(other)/page/index.mu")
    }

    @Test("Link URL: hash:/path format becomes nomadnet://")
    func linkURLHashColonPath() {
        let hash = "47850a3b99243cfb1147e8856bab2691"
        let url = buildLinkURL(destination: "\(hash):/page/info.mu", currentDestinationHashHex: nil as String?)
        #expect(url?.scheme == "nomadnet")
        #expect(url?.absoluteString == "nomadnet://\(hash)/page/info.mu")
    }

    @Test("Link URL: colon-slash path resolves to current hash")
    func linkURLColonSlash() {
        let current = "1e12dc236a05c930bd2c9190a2940ce7"
        let url = buildLinkURL(destination: ":/page/other.mu", currentDestinationHashHex: current)
        #expect(url?.scheme == "nomadnet")
        #expect(url?.absoluteString == "nomadnet://\(current)/page/other.mu")
    }

    @Test("Link URL: page/ prefix resolves to current hash")
    func linkURLPagePrefix() {
        let current = "1e12dc236a05c930bd2c9190a2940ce7"
        let url = buildLinkURL(destination: "page/about.mu", currentDestinationHashHex: current)
        #expect(url?.scheme == "nomadnet")
        #expect(url?.absoluteString == "nomadnet://\(current)/page/about.mu")
    }

    @Test("Link URL: nomadnet:// URL passes through construction unchanged")
    func linkURLNomadnetScheme() {
        let hash = "47850a3b99243cfb1147e8856bab2691"
        let url = buildLinkURL(destination: "nomadnet://\(hash)/page/index.mu", currentDestinationHashHex: nil as String?)
        // nomadnet:// scheme is not in the ["http", "https", "lxm", "lxmf"] list,
        // so it goes through NomadAddress resolution
        #expect(url?.scheme == "nomadnet")
        #expect(url?.absoluteString == "nomadnet://\(hash)/page/index.mu")
    }

    // MARK: - Round-trip: URL construction → openURL resolution

    @Test("Round-trip: relative path link resolves correctly via nomadnet:// URL")
    func roundTripRelativePath() {
        let current = "1e12dc236a05c930bd2c9190a2940ce7"
        let url = buildLinkURL(destination: "/page/about.mu", currentDestinationHashHex: current)!
        let resolved = resolveNomadNetURL(url, currentDestinationHashHex: current)
        #expect(resolved != nil)
        #expect(resolved?.destinationHashHex == current)
        #expect(resolved?.path == "/page/about.mu")
    }

    @Test("Round-trip: cross-node link resolves correctly via nomadnet:// URL")
    func roundTripCrossNode() {
        let current = "1e12dc236a05c930bd2c9190a2940ce7"
        let other = "47850a3b99243cfb1147e8856bab2691"
        let url = buildLinkURL(destination: "\(other):/page/info.mu", currentDestinationHashHex: current)!
        let resolved = resolveNomadNetURL(url, currentDestinationHashHex: current)
        #expect(resolved != nil)
        #expect(resolved?.destinationHashHex == other)
        #expect(resolved?.path == "/page/info.mu")
    }

    @Test("Round-trip: bare hash link resolves with default page path")
    func roundTripBareHash() {
        let hash = "47850a3b99243cfb1147e8856bab2691"
        let url = buildLinkURL(destination: hash, currentDestinationHashHex: nil as String?)!
        let resolved = resolveNomadNetURL(url, currentDestinationHashHex: nil as String?)
        #expect(resolved != nil)
        #expect(resolved?.destinationHashHex == hash)
        #expect(resolved?.path == "/page/index.mu")
    }

    @Test("Round-trip: page/ prefix resolves correctly")
    func roundTripPagePrefix() {
        let current = "1e12dc236a05c930bd2c9190a2940ce7"
        let url = buildLinkURL(destination: "page/custom.mu", currentDestinationHashHex: current)!
        let resolved = resolveNomadNetURL(url, currentDestinationHashHex: current)
        #expect(resolved != nil)
        #expect(resolved?.destinationHashHex == current)
        #expect(resolved?.path == "/page/custom.mu")
    }

    @Test("LXMF link URL passes through with lxmf scheme")
    func linkURLLxmf() {
        let url = buildLinkURL(destination: "lxmf://somedata", currentDestinationHashHex: nil as String?)
        #expect(url?.scheme == "lxmf")
        #expect(url?.absoluteString == "lxmf://somedata")
    }
}
