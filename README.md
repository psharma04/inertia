<div align="center">

![GitHub commit activity](https://img.shields.io/github/commit-activity/m/psharma04/inertia)
![GitHub Issues or Pull Requests](https://img.shields.io/github/issues/psharma04/inertia)
![GitHub Release](https://img.shields.io/github/v/release/psharma04/inertia)

</div>

&nbsp;

<div align="center">

![Inertia for iOS](https://inertia.chat/assets/banner/gh-banner.png)

</div>

<h3 align="center">

An decentralised, cross-platform communication client for iOS.
<br />
Built by humans, for humans.

</h3>

<div align="center">

Inertia is a pure Swift client for Reticulum, LXMF, and NomadNet. It's designed to provide a simple entrypoint for privacy-conscious people to try out a truly decentralised network, without needing to buy new gear.

**THIS IS ALPHA SOFTWARE. DO NOT RELY ON THIS FOR CRITICAL COMMUNICATION, AND EXPECT YOUR DATA TO BE LOST EVERY TIME A NEW VERSION IS INSTALLED.**

</div>

## Features

- Send and receive encrypted messages without relying on traditional cloud providers
- Communicate with users on other clients (Sideband, MeshChat, Columba)

## Planned

- [x] First install/setup flow
- [x] Key importing/exporting
- [ ] Accessibility and contrast in UI elements
- [ ] Auto-interface support
- [ ] Access pages on the Nomad Network
- [ ] Use propagation nodes to stop messages from being lost in transit
- [ ] Send/receive images and other files
- [ ] Support for rnsh, RRC, RetiBBS, and other services
- [ ] Calls via LXST
- [ ] Paper messages
- [ ] RNode/LoRa support
- [ ] CI/CD flows
- [ ] Reproducible builds & code-signing
- [ ] Blocking/favouriting contacts
- [ ] Bookmarking Nomad Network pages
- [ ] NomadNet and LXMF URL scheme
- [ ] iOS Shortcuts support
- [ ] Getting a better logo

## Contact

- Matrix space (preferred): [#inertia:inyourair.space](https://matrix.to/#/#inertia:inyourair.space)
- LXMF: 3662d822203188617b2e44f2908b0bb3

## Building & Contributing

Requires iOS >26.0 and XCode >26.0. Dependencies are managed by SPM.

1. Clone the repository
2. `brew install xcodegen`
3. `cd` into the repository
4. `xcodegen generate`
5. Open the generated `Inertia.xcodeproj` in XCode.
5. Set signing team
6. Run build

Pull requests are more than welcome [(please look at the project board if you want to contribute but don't know what's needed)](https://github.com/users/psharma04/projects/5), but AI usage in any manner will result in the PR being ignored and immediately closed.

---

Inertia is powered by [Reticulum](https://github.com/markqvist/Reticulum), [LXMF](https://github.com/markqvist/LXMF), and [NomadNet](https://github.com/markqvist/nomadnet).

---

## FAQ

### Why "Inertia"?

Coming from Meshtastic and MeshCore, the idea of a more powerful decentralised protocol that allows for files and hosted pages was extremely appealing. However, my primary device was an iPhone, and no Reticulum client existed for iOS. Thus, the *inertia* of not having support on my primary device delayed my use of the platform. This project exists so that nobody else has to consider changing their workflow or device to use Reticulum.

### AI?

No thanks. See [AI.md](AI.md) for more information.

### Why isn't [feature] implemented yet?

Unfortunately, writing code by hand still takes longer than getting AI to do it. While AI would probably massively speed up development on this project, it also introduces security and trust issues between the developer and the end user.

Development bounties are something I might consider if the project grows in popularity, but for now I'm mainly focused on getting the basics working correctly.

### Can I give you money?

Many options are available:
- [GitHub Sponsors](https://github.com/sponsors/psharma04)
- [OpenCollective](https://opencollective.com/inertia)
- [Ko-Fi](https://ko-fi.com/hyperbolicpurple)

## Licensing

All contents of the repository are licensed under the MIT license.

Content which are considered artistic works, such as icons, are dual-licensed under MIT and [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). This covers any files in the `assets/` folder, and any copies of those files elsewhere in the project.

### Upstream packages

- [Swift-Sodium](https://github.com/jedisct1/swift-sodium) is licensed under the ISC licence, which is considered compatible with the MIT license.
