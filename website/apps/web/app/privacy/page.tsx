import * as React from "react"
import { Separator } from "@workspace/ui/components/separator"
import { PolicySection } from "@/components/policy-section"

// To add or remove a section: update tocSections + add/remove a <PolicySection> below.
const tocSections = [
  { id: "section-1",  label: "1. Scope and roles" },
  { id: "section-2",  label: "2. Data we process" },
  { id: "section-3",  label: "3. Why we process data" },
  { id: "section-4",  label: "4. Default Server" },
  { id: "section-5",  label: "5. Third-party servers" },
  { id: "section-6",  label: "6. Sharing and disclosures" },
  { id: "section-7",  label: "7. International data transfers" },
  { id: "section-8",  label: "8. Data retention" },
  { id: "section-9",  label: "9. Security" },
  { id: "section-10", label: "10. Your GDPR rights" },
  { id: "section-11", label: "11. Children's privacy" },
  { id: "section-12", label: "12. Opt-out rights" },
  { id: "section-13", label: "13. Changes to this policy" },
  { id: "section-14", label: "14. Contact" },
] as const

// Reusable inline helpers
function Code({ children }: { children: string }) {
  return <code className="font-mono text-xs bg-muted px-1 py-0.5 rounded">{children}</code>
}

export default function PrivacyPage(): React.JSX.Element {
  return (
    <div>
      <h1 className="text-3xl font-bold tracking-tight">Privacy Policy</h1>
      <p className="mt-2 text-muted-foreground">Effective date: 2026-03-26</p>
      <Separator className="my-6" />

      <div className="lg:grid lg:grid-cols-4 lg:gap-8">

        {/* ---------------------------------------------------------------- */}
        {/* Main content                                                      */}
        {/* ---------------------------------------------------------------- */}
        <div className="lg:col-span-3 space-y-8 text-sm leading-relaxed">

          {/* Intro — not a numbered section */}
          <div className="space-y-3">
            <p>This Privacy Policy applies to:</p>
            <ul className="list-disc pl-6 space-y-1">
              <li>the <strong>Inertia for iOS</strong> application (the &ldquo;App&rdquo;), and</li>
              <li>
                the default public Reticulum server <Code>rns.inertia.chat:4242</Code>{" "}
                (the &ldquo;Default Server&rdquo;),
              </li>
            </ul>
            <p>operated by the Inertia project maintainers (&ldquo;we&rdquo;, &ldquo;us&rdquo;, &ldquo;our&rdquo;).</p>
            <p>Contact: <strong>privacy@inertia.chat</strong></p>
          </div>

          <PolicySection id="section-1" title="1. Scope and roles">
            <p className="mb-3">
              This policy describes how data is processed when you use the App and/or the Default Server.
            </p>
            <ul className="list-disc pl-6 space-y-2 mb-3">
              <li>
                For App-local processing and operation of <Code>rns.inertia.chat</Code>, we act as a
                data controller for applicable processing under GDPR.
              </li>
              <li>
                If you connect to a <strong>third-party server</strong>, that server operator is an
                independent controller for their own processing.
              </li>
            </ul>
            <p>
              <strong>Important:</strong> If you choose to use third-party servers, the Inertia developers
              do not control and are not responsible for how those third parties collect, use, retain, or
              share your data.
            </p>
          </PolicySection>

          <PolicySection id="section-2" title="2. Data we process">
            <h3 className="text-base font-medium mb-2 mt-4">A. Data stored on your device by the App</h3>
            <p className="mb-2">Depending on how you use Inertia, the App may store:</p>
            <ul className="list-disc pl-6 space-y-1 mb-6">
              <li>your Reticulum identity material (private keys stored using platform security features, including Keychain),</li>
              <li>contacts/peer metadata (for example: display name, destination hashes, path/hops, last-seen),</li>
              <li>conversations and messages,</li>
              <li>app settings (for example: server selection, lock preferences, notification settings, stamp/propagation preferences),</li>
              <li>optional identity backup files you explicitly export.</li>
            </ul>

            <h3 className="text-base font-medium mb-2">B. Data processed over the network</h3>
            <p className="mb-2">
              When you connect to the Default Server or any Reticulum server, network operators may process:
            </p>
            <ul className="list-disc pl-6 space-y-1 mb-3">
              <li>your IP address and connection metadata (for example: timestamps, transport-level details),</li>
              <li>protocol metadata required for routing and delivery (for example: destination hashes, announce/routing data, delivery proofs, propagation message identifiers),</li>
              <li>encrypted packet payloads relayed through the network.</li>
            </ul>
            <p className="mb-6">
              Reticulum/LXMF is designed to protect message content cryptographically, but network
              operators may still observe certain metadata required to run the service.
            </p>

            <h3 className="text-base font-medium mb-2">C. Data we do <strong>not</strong> collect for product analytics/advertising</h3>
            <p className="mb-2">
              The App does not require account registration and does not include ad tracking SDKs. We do
              not sell personal data.
            </p>
            <p className="mb-2">The App does not collect precise real-time GPS location.</p>
            <p className="mb-6">
              Biometric authentication (Face ID/Touch ID) is handled by iOS; biometric data is not
              provided to us.
            </p>

            <h3 className="text-base font-medium mb-2">D. Apple App Store / TestFlight / Apple analytics data</h3>
            <p className="mb-2">
              When you download, install, or use Inertia via Apple platforms,{" "}
              <strong>Apple may process data as an independent controller</strong> under Apple&apos;s own
              terms and privacy policy.
            </p>
            <p className="mb-2">This can include, for example:</p>
            <ul className="list-disc pl-6 space-y-1 mb-3">
              <li>App Store and TestFlight distribution data (downloads, updates, storefront/region, and fraud/security signals),</li>
              <li>diagnostic and crash data handled by Apple,</li>
              <li>device and usage analytics shared by Apple.</li>
            </ul>
            <p className="mb-2">
              If you enable Apple&apos;s &ldquo;Share with App Developers&rdquo; or related analytics
              settings, Apple may provide us with analytics and crash information through App Store
              Connect/Xcode tools (typically aggregated and/or pseudonymised, but sometimes including
              technical crash metadata such as device model, OS version, and timestamp).
            </p>
            <p>We do not control Apple&apos;s processing practices.</p>
          </PolicySection>

          <PolicySection id="section-3" title="3. Why we process data (GDPR legal bases)">
            <p className="mb-3">Where GDPR applies, we rely on:</p>
            <ul className="list-disc pl-6 space-y-2 mb-3">
              <li><strong>Contract / service delivery</strong>: to provide messaging, routing, and synchronisation features you request.</li>
              <li><strong>Legitimate interests</strong>: to secure and operate the network/service (for example, abuse prevention, reliability, diagnostics, and integrity).</li>
              <li><strong>Legal obligation</strong>: where required by applicable law.</li>
              <li><strong>Consent</strong>: for optional features where consent is the appropriate basis (for example, optional device-level permissions you enable).</li>
            </ul>
            <p>
              For Apple-provided analytics/crash reporting, legal basis may be applied by Apple
              independently. Where we process analytics Apple shares with us, we rely on legitimate
              interests and/or your consent state in Apple device/platform settings, as applicable.
            </p>
          </PolicySection>

          <PolicySection
            id="section-4"
            title={<>4. Default Server (<Code>rns.inertia.chat</Code>)</>}
          >
            <p className="mb-3">
              The Default Server is a public server and may relay traffic and support store-and-forward
              behavior used by Reticulum/LXMF propagation.
            </p>
            <p className="mb-3">
              To operate safely and reliably, the Default Server may temporarily process routing and
              operational metadata and may keep limited operational logs for security, abuse prevention,
              and troubleshooting.
            </p>
            <p>
              Operational logs are not guaranteed to have a fixed, uniform retention period. Different
              log types and systems may be retained for different durations based on operational,
              security, abuse-response, and legal needs.
            </p>
          </PolicySection>

          <PolicySection id="section-5" title="5. Third-party servers">
            <p className="mb-3">You can configure Inertia to use servers not operated by us. If you do:</p>
            <ul className="list-disc pl-6 space-y-1 mb-3">
              <li>your traffic and metadata will be processed under that third party&apos;s policies and practices,</li>
              <li>you must review that provider&apos;s legal terms/privacy policy yourself.</li>
            </ul>
            <p>Again, we have no control over third-party server processing.</p>
          </PolicySection>

          <PolicySection id="section-6" title="6. Sharing and disclosures">
            <p className="mb-3">We do not sell personal data. We may disclose data only when necessary to:</p>
            <ul className="list-disc pl-6 space-y-1 mb-3">
              <li>comply with legal obligations,</li>
              <li>protect rights, safety, and security,</li>
              <li>investigate abuse or technical attacks.</li>
            </ul>
            <p className="mb-2">
              Because the network is decentralised, packet relay by other network participants may occur
              as part of normal protocol operation.
            </p>
            <p>
              Apple may also disclose certain data to us through App Store Connect and related developer
              tools as described above.
            </p>
          </PolicySection>

          <PolicySection id="section-7" title="7. International data transfers">
            <p>
              Reticulum infrastructure and third-party servers may be located in multiple countries. By
              using decentralised routing or non-local servers, data may be processed outside your
              jurisdiction, including countries that may have different data protection standards.
            </p>
          </PolicySection>

          <PolicySection id="section-8" title="8. Data retention">
            <ul className="list-disc pl-6 space-y-2 mb-4">
              <li>
                <strong>App</strong>: Data is retained until you delete it (for example by deleting
                conversations/settings, restoring/resetting identity, or uninstalling the App), subject
                to iOS behavior and any external backups you created.
              </li>
              <li>
                <strong>Default Server</strong>: Data is retained only as needed for network delivery,
                propagation, security, and operations, then purged according to operational needs.
                Retention periods may vary across data categories and are not always consistent.
              </li>
              <li>
                <strong>Third-party servers</strong>: Determine their own retention policies.
              </li>
            </ul>
            <p className="mb-2"><strong>Data deletion limitations:</strong></p>
            <ul className="list-disc pl-6">
              <li>
                If a message has been delivered to another person&apos;s device or another server,
                deleting it from your device (or from one server) may not remove all other copies.
              </li>
            </ul>
          </PolicySection>

          <PolicySection id="section-9" title="9. Security">
            <p className="mb-3">
              We use reasonable technical and organisational measures to protect data processed by the
              App and Default Server. However, no method of transmission or storage is completely secure.
            </p>
            <p>
              You are responsible for safeguarding your device, passcode, exported backups, and any
              third-party infrastructure you choose to use.
            </p>
          </PolicySection>

          <PolicySection id="section-10" title="10. Your GDPR rights">
            <p className="mb-3">If GDPR applies, you may have rights to:</p>
            <ul className="list-disc pl-6 space-y-1 mb-4">
              <li>access your personal data,</li>
              <li>rectify inaccurate data,</li>
              <li>erase data,</li>
              <li>restrict processing,</li>
              <li>object to processing,</li>
              <li>data portability,</li>
              <li>withdraw consent (where processing is consent-based),</li>
              <li>lodge a complaint with your local supervisory authority.</li>
            </ul>
            <p className="mb-2">
              To exercise rights related to App/Default Server processing, contact{" "}
              <strong>privacy@inertia.chat</strong>.
            </p>
            <p>For third-party servers, contact that server operator directly.</p>
          </PolicySection>

          <PolicySection id="section-11" title="11. Children's privacy">
            <p className="mb-3">
              The App and Default Server are not intended for children under 13, and we do not knowingly
              solicit data from children under 13.
            </p>
            <p>
              Where required by local law, users must meet the applicable age of digital consent (which
              may be higher, such as 16 in some jurisdictions) or use with valid parental/guardian consent.
            </p>
          </PolicySection>

          <PolicySection id="section-12" title="12. Opt-out rights">
            <p className="mb-2">
              You can stop App data processing by uninstalling the App and deleting local app data from
              your device.
            </p>
            <p className="mb-2">
              You can stop Default Server processing by removing/disabling{" "}
              <Code>rns.inertia.chat</Code> in the App server settings and disconnecting.
            </p>
            <p>
              For Apple analytics/crash sharing, you can opt out through Apple settings (for example,
              Analytics &amp; Improvements settings, including &ldquo;Share with App Developers&rdquo;)
              and by not using TestFlight builds.
            </p>
          </PolicySection>

          <PolicySection id="section-13" title="13. Changes to this policy">
            <p>
              We may update this policy from time to time. The &ldquo;Effective date&rdquo; above
              reflects the latest version.
            </p>
          </PolicySection>

          <PolicySection id="section-14" title="14. Contact">
            <p>Privacy questions or requests: <strong>privacy@inertia.chat</strong></p>
          </PolicySection>

        </div>

        {/* ---------------------------------------------------------------- */}
        {/* TOC sidebar — hidden on mobile, sticky on desktop                */}
        {/* ---------------------------------------------------------------- */}
        <nav
          className="hidden lg:block lg:col-span-1 sticky top-24 self-start"
          aria-label="Table of contents"
        >
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
            On this page
          </p>
          <ul className="space-y-1.5 text-xs">
            {tocSections.map(({ id, label }) => (
              <li key={id}>
                <a href={`#${id}`} className="text-muted-foreground hover:text-foreground transition-colors">
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>

      </div>
    </div>
  )
}
