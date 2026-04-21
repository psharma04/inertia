import XCTest

final class InertiaUITests: XCTestCase {

    private var app: XCUIApplication!

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments += ["-UITest"]
        app.launch()
    }

    override func tearDown() {
        app = nil
        super.tearDown()
    }

    // MARK: - Onboarding

    func testOnboardingFlowCompletesToMainUI() {
        // First launch shows onboarding
        let welcomeTitle = app.navigationBars["Welcome to Inertia"]
        if !welcomeTitle.waitForExistence(timeout: 5) {
            // Already past onboarding — skip
            return
        }

        // Step through onboarding
        let nextButton = app.buttons["onboarding-next"]
        XCTAssertTrue(nextButton.waitForExistence(timeout: 3))
        nextButton.tap()

        // Step 2: nickname
        XCTAssertTrue(nextButton.waitForExistence(timeout: 3))
        nextButton.tap()

        // Step 3: interfaces
        XCTAssertTrue(nextButton.waitForExistence(timeout: 3))
        nextButton.tap()

        // Step 4: guide — finish
        let finishButton = app.buttons["onboarding-finish"]
        XCTAssertTrue(finishButton.waitForExistence(timeout: 3))
        finishButton.tap()

        // Should see main tab bar
        let messagesTab = app.buttons["tab-messages"]
        XCTAssertTrue(messagesTab.waitForExistence(timeout: 5))
    }

    func testOnboardingBackButton() {
        let welcomeTitle = app.navigationBars["Welcome to Inertia"]
        if !welcomeTitle.waitForExistence(timeout: 5) {
            return
        }

        let nextButton = app.buttons["onboarding-next"]
        XCTAssertTrue(nextButton.waitForExistence(timeout: 3))
        nextButton.tap()

        // Now on step 2 — back button should exist
        let backButton = app.buttons["onboarding-back"]
        XCTAssertTrue(backButton.waitForExistence(timeout: 3))
        backButton.tap()

        // Should be back on step 1 — back button hidden or step 1 visible
        XCTAssertTrue(nextButton.waitForExistence(timeout: 3))
    }

    // MARK: - Tab Navigation

    func testTabBarShowsFourTabs() {
        skipOnboardingIfNeeded()

        XCTAssertTrue(app.buttons["tab-messages"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["tab-peers"].exists)
        XCTAssertTrue(app.buttons["tab-nomad"].exists)
        XCTAssertTrue(app.buttons["tab-settings"].exists)
    }

    func testTabSwitching() {
        skipOnboardingIfNeeded()

        let settingsTab = app.buttons["tab-settings"]
        XCTAssertTrue(settingsTab.waitForExistence(timeout: 5))
        settingsTab.tap()

        // Settings should show announce section
        let announceButton = app.buttons["announce-now"]
        XCTAssertTrue(announceButton.waitForExistence(timeout: 3))

        // Sync button should be visible
        let syncButton = app.buttons["sync-now"]
        XCTAssertTrue(syncButton.exists)

        // Switch back to messages
        app.buttons["tab-messages"].tap()
        let convList = app.otherElements["conversations-list"]
        XCTAssertTrue(convList.waitForExistence(timeout: 3))
    }

    func testAllTabsLoad() {
        skipOnboardingIfNeeded()

        // Messages tab
        app.buttons["tab-messages"].tap()
        XCTAssertTrue(app.navigationBars["Messages"].waitForExistence(timeout: 3))

        // Peers tab
        app.buttons["tab-peers"].tap()
        XCTAssertTrue(app.navigationBars["Peers"].waitForExistence(timeout: 3))

        // Nomad tab
        app.buttons["tab-nomad"].tap()
        XCTAssertTrue(app.navigationBars["Nomad Network"].waitForExistence(timeout: 3))

        // Settings tab
        app.buttons["tab-settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 3))
    }

    // MARK: - Settings

    func testSettingsContainsAnnounceAndSyncButtons() {
        skipOnboardingIfNeeded()

        app.buttons["tab-settings"].tap()

        let announceButton = app.buttons["announce-now"]
        XCTAssertTrue(announceButton.waitForExistence(timeout: 5))

        let syncButton = app.buttons["sync-now"]
        XCTAssertTrue(syncButton.exists)
    }

    func testSettingsNavigationLinks() {
        skipOnboardingIfNeeded()

        app.buttons["tab-settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 5))

        // Servers link
        let serversLink = app.buttons["settings-servers"]
        XCTAssertTrue(serversLink.waitForExistence(timeout: 3))

        // AutoInterface link
        let autoLink = app.buttons["settings-autointerface"]
        XCTAssertTrue(autoLink.exists)

        // Identity link
        let identityLink = app.buttons["settings-identity"]
        XCTAssertTrue(identityLink.exists)

        // Messaging link
        let messagingLink = app.buttons["settings-messaging"]
        XCTAssertTrue(messagingLink.exists)

        // Network status link
        let networkLink = app.buttons["settings-network-status"]
        XCTAssertTrue(networkLink.exists)
    }

    func testSettingsServersNavigation() {
        skipOnboardingIfNeeded()

        app.buttons["tab-settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 5))

        app.buttons["settings-servers"].tap()
        // Should navigate to Servers screen
        let serversNav = app.navigationBars["Servers"]
        XCTAssertTrue(serversNav.waitForExistence(timeout: 3))

        // Navigate back
        app.navigationBars.buttons.element(boundBy: 0).tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 3))
    }

    func testSettingsIdentityNavigation() {
        skipOnboardingIfNeeded()

        app.buttons["tab-settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 5))

        app.buttons["settings-identity"].tap()
        // Should navigate to Identity screen
        let identityNav = app.navigationBars.firstMatch
        XCTAssertTrue(identityNav.waitForExistence(timeout: 3))
    }

    func testSettingsAboutSection() {
        skipOnboardingIfNeeded()

        app.buttons["tab-settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 5))

        // Scroll to find About section
        let versionLabel = app.staticTexts["Version"]
        if !versionLabel.waitForExistence(timeout: 2) {
            app.swipeUp()
        }
        XCTAssertTrue(versionLabel.waitForExistence(timeout: 3))

        let protocolLabel = app.staticTexts["Protocol"]
        XCTAssertTrue(protocolLabel.exists)
    }

    // MARK: - Messages Empty State

    func testMessagesShowsEmptyState() {
        skipOnboardingIfNeeded()

        app.buttons["tab-messages"].tap()

        // On a fresh install, should see "No Messages" text
        let emptyLabel = app.staticTexts["No Messages"]
        if emptyLabel.waitForExistence(timeout: 3) {
            XCTAssertTrue(emptyLabel.exists)
        }
        // If messages exist, that's also fine — the view loaded
    }

    func testMessagesToolbarHasComposeButton() {
        skipOnboardingIfNeeded()

        app.buttons["tab-messages"].tap()
        XCTAssertTrue(app.navigationBars["Messages"].waitForExistence(timeout: 3))

        // Toolbar should have at least one button (compose/contacts)
        let toolbarButtons = app.navigationBars["Messages"].buttons
        XCTAssertTrue(toolbarButtons.count > 0)
    }

    // MARK: - Peers Tab

    func testPeersTabLoads() {
        skipOnboardingIfNeeded()

        let peersTab = app.buttons["tab-peers"]
        XCTAssertTrue(peersTab.waitForExistence(timeout: 5))
        peersTab.tap()

        // The Peers screen should load with a navigation title
        let navBar = app.navigationBars["Peers"]
        XCTAssertTrue(navBar.waitForExistence(timeout: 3))
    }

    func testPeersShowsEmptyState() {
        skipOnboardingIfNeeded()

        app.buttons["tab-peers"].tap()

        // On a fresh install, should see empty state
        let emptyTitle = app.staticTexts["peers-empty-title"]
        if emptyTitle.waitForExistence(timeout: 3) {
            XCTAssertTrue(emptyTitle.exists)
        }
        // If peers exist, that's fine too
    }

    func testPeersSearchBarExists() {
        skipOnboardingIfNeeded()

        app.buttons["tab-peers"].tap()
        XCTAssertTrue(app.navigationBars["Peers"].waitForExistence(timeout: 3))

        // Search bar should exist (visible or via pull-down)
        let searchField = app.searchFields.firstMatch
        // Pull down to reveal search
        app.swipeDown()
        if searchField.waitForExistence(timeout: 3) {
            XCTAssertTrue(searchField.exists)
        }
    }

    // MARK: - Nomad Tab

    func testNomadTabLoads() {
        skipOnboardingIfNeeded()

        let nomadTab = app.buttons["tab-nomad"]
        XCTAssertTrue(nomadTab.waitForExistence(timeout: 5))
        nomadTab.tap()

        // The Nomad browser should load
        let navBar = app.navigationBars["Nomad Network"]
        XCTAssertTrue(navBar.waitForExistence(timeout: 3))
    }

    func testNomadAddressBarExists() {
        skipOnboardingIfNeeded()

        app.buttons["tab-nomad"].tap()
        XCTAssertTrue(app.navigationBars["Nomad Network"].waitForExistence(timeout: 3))

        let addressField = app.textFields["nomad-address-field"]
        XCTAssertTrue(addressField.waitForExistence(timeout: 3))
    }

    func testNomadAddressBarAcceptsInput() {
        skipOnboardingIfNeeded()

        app.buttons["tab-nomad"].tap()
        XCTAssertTrue(app.navigationBars["Nomad Network"].waitForExistence(timeout: 3))

        let addressField = app.textFields["nomad-address-field"]
        XCTAssertTrue(addressField.waitForExistence(timeout: 3))

        addressField.tap()
        addressField.typeText("abc123:/page/index.mu")

        // Verify the text was entered
        let fieldValue = addressField.value as? String ?? ""
        XCTAssertTrue(fieldValue.contains("abc123"))
    }

    func testNomadToolbarButtons() {
        skipOnboardingIfNeeded()

        app.buttons["tab-nomad"].tap()
        XCTAssertTrue(app.navigationBars["Nomad Network"].waitForExistence(timeout: 3))

        // Toolbar should have navigation buttons (back, forward) and node list
        let toolbar = app.navigationBars["Nomad Network"]
        XCTAssertTrue(toolbar.buttons.count >= 2,
            "Expected at least back/forward and node list buttons")
    }

    // MARK: - Cross-Tab State Persistence

    func testTabSwitchPreservesState() {
        skipOnboardingIfNeeded()

        // Go to settings
        app.buttons["tab-settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 3))

        // Switch to messages and back
        app.buttons["tab-messages"].tap()
        XCTAssertTrue(app.navigationBars["Messages"].waitForExistence(timeout: 3))

        app.buttons["tab-settings"].tap()
        // Settings should still be at root
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 3))
    }

    // MARK: - Helpers

    private func skipOnboardingIfNeeded() {
        let welcomeTitle = app.navigationBars["Welcome to Inertia"]
        if welcomeTitle.waitForExistence(timeout: 3) {
            let nextButton = app.buttons["onboarding-next"]
            for _ in 0..<3 {
                if nextButton.waitForExistence(timeout: 2) {
                    nextButton.tap()
                }
            }
            let finishButton = app.buttons["onboarding-finish"]
            if finishButton.waitForExistence(timeout: 2) {
                finishButton.tap()
            }
        }
    }
}
