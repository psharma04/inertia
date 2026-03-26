# Privacy Policy

> Effective date: 2026-03-26

This Privacy Policy applies to:

- the **Inertia for iOS** application (the “App”), and
- the default public Reticulum server `rns.inertia.chat:4242` (the “Default Server”),

operated by the Inertia project maintainers (“we”, “us”, “our”).

Contact: `privacy@inertia.chat`

## 1. Scope and roles

This policy describes how data is processed when you use the App and/or the Default Server.

- For App-local processing and operation of `rns.inertia.chat`, we act as a data controller for applicable processing under GDPR.
- If you connect to a **third-party server**, that server operator is an independent controller for their own processing.

**Important:** If you choose to use third-party servers, the Inertia developers do not control and are not responsible for how those third parties collect, use, retain, or share your data.

## 2. Data we process

### A. Data stored on your device by the App

Depending on how you use Inertia, the App may store:

- your Reticulum identity material (private keys stored using platform security features, including Keychain),
- contacts/peer metadata (for example: display name, destination hashes, path/hops, last-seen),
- conversations and messages,
- app settings (for example: server selection, lock preferences, notification settings, stamp/propagation preferences),
- optional identity backup files you explicitly export.

### B. Data processed over the network

When you connect to the Default Server or any Reticulum server, network operators may process:

- your IP address and connection metadata (for example: timestamps, transport-level details),
- protocol metadata required for routing and delivery (for example: destination hashes, announce/routing data, delivery proofs, propagation message identifiers),
- encrypted packet payloads relayed through the network.

Reticulum/LXMF is designed to protect message content cryptographically, but network operators may still observe certain metadata required to run the service.

### C. Data we do not collect for product analytics/advertising

The App does not require account registration and does not include ad tracking SDKs. We do not sell personal data.

The App does not collect precise real-time GPS location.

Biometric authentication (Face ID/Touch ID) is handled by iOS; biometric data is not provided to us.

### D. Apple App Store / TestFlight / Apple analytics data

When you download, install, or use Inertia via Apple platforms, **Apple may process data as an independent controller** under Apple’s own terms and privacy policy.

This can include, for example:

- App Store and TestFlight distribution data (downloads, updates, storefront/region, and fraud/security signals),
- diagnostic and crash data handled by Apple,
- device and usage analytics shared by Apple.

If you enable Apple’s “Share with App Developers” or related analytics settings, Apple may provide us with analytics and crash information through App Store Connect/Xcode tools (typically aggregated and/or pseudonymised, but sometimes including technical crash metadata such as device model, OS version, and timestamp).

We do not control Apple’s processing practices.

## 3. Why we process data (GDPR legal bases)

Where GDPR applies, we rely on:

- Contract/service delivery: to provide messaging, routing, and synchronisation features you request.
- Legitimate interests: to secure and operate the network/service (for example, abuse prevention, reliability, diagnostics, and integrity).
- Legal obligation: where required by applicable law.
- Consent: for optional features where consent is the appropriate basis (for example, optional device-level permissions you enable).

For Apple-provided analytics/crash reporting, legal basis may be applied by Apple independently. Where we process analytics Apple shares with us, we rely on legitimate interests and/or your consent state in Apple device/platform settings, as applicable.

## 4. Default Server (`rns.inertia.chat`)

The Default Server is a public server and may relay traffic and support store-and-forward behavior used by Reticulum/LXMF propagation.

To operate safely and reliably, the Default Server may temporarily process routing and operational metadata and may keep limited operational logs for security, abuse prevention, and troubleshooting.

Operational logs are not guaranteed to have a fixed, uniform retention period. Different log types and systems may be retained for different durations based on operational, security, abuse-response, and legal needs.

## 5. Third-party servers

You can configure Inertia to use servers not operated by us. If you do:

- your traffic and metadata will be processed under that third party’s policies and practices,
- you must review that provider’s legal terms/privacy policy yourself.

Again, we have no control over third-party server processing.

## 6. Sharing and disclosures

We do not sell personal data. We may disclose data only when necessary to:

- comply with legal obligations,
- protect rights, safety, and security,
- investigate abuse or technical attacks.

Because the network is decentralised, packet relay by other network participants may occur as part of normal protocol operation.

Apple may also disclose certain data to us through App Store Connect and related developer tools as described above.

## 7. International data transfers

Reticulum infrastructure and third-party servers may be located in multiple countries. By using decentralised routing or non-local servers, data may be processed outside your jurisdiction, including countries that may have different data protection standards.

## 8. Data retention

- App: Data is retained until you delete it (for example by deleting conversations/settings, restoring/resetting identity, or uninstalling the App), subject to iOS behavior and any external backups you created.
- Default Server: Data is retained only as needed for network delivery, propagation, security, and operations, then purged according to operational needs. Retention periods may vary across data categories and are not always consistent.
- Third-party servers: Determine their own retention policies.

### Data deletion limitations

- If a message has been delivered to another person’s device or another server, deleting it from your device (or from one server) may not remove all other copies.

## 9. Security

We use reasonable technical and organisational measures to protect data processed by the App and Default Server. However, no method of transmission or storage is completely secure.

You are responsible for safeguarding your device, passcode, exported backups, and any third-party infrastructure you choose to use.

## 10. Your GDPR rights

If GDPR applies, you may have rights to:

- access your personal data,
- rectify inaccurate data,
- erase data,
- restrict processing,
- object to processing,
- data portability,
- withdraw consent (where processing is consent-based),
- lodge a complaint with your local supervisory authority.

To exercise rights related to App/Default Server processing, contact `privacy@inertia.chat`.

For third-party servers, contact that server operator directly.

## 11. Children’s privacy

The App and Default Server are not intended for children under 13, and we do not knowingly solicit data from children under 13.

Where required by local law, users must meet the applicable age of digital consent (which may be higher, such as 16 in some jurisdictions) or use with valid parental/guardian consent.

## 12. Opt-out rights

You can stop App data processing by uninstalling the App and deleting local app data from your device.

You can stop Default Server processing by removing/disabling `rns.inertia.chat` in the App server settings and disconnecting.

For Apple analytics/crash sharing, you can opt out through Apple settings (for example, Analytics & Improvements settings, including “Share with App Developers”) and by not using TestFlight builds.

## 13. Changes to this policy

We may update this policy from time to time. The “Effective date” above reflects the latest version.

## 15. Contact

Privacy questions or requests: `privacy@inertia.chat`
