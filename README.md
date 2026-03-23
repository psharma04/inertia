# Inertia

A decentralised, cross-platform communication client for iOS.

---

Inertia is a pure Swift client for Reticulum, LXMF, and NomadNet.

## Features

- Send and receive encrypted messages without relying on traditional cloud providers
- Communicate with users on other clients (Sideband, MeshChat, Columba)

## Planned

- [ ] LAN auto-interface support
- [ ] First install/setup flow
- [ ] Key importing/exporting
- [ ] Access pages on the Nomad Network
- [ ] Use propagation nodes to stop messages from being lost in transit
- [ ] Send/receive images and other files
- [ ] Support for rnsh, RRC, RetiBBS, and other services
- [ ] Calls via LXST
- [ ] Paper messages
- [ ] RNode/LoRa support
- [ ] CI/CD flows
- [ ] Reproducible builds & code-signing

## Contact

- Matrix (preferred): [@pepsi:inyourair.space](https://matrix.to/#/@pepsi:inyourair.space)
- LXMF: 3662d822203188617b2e44f2908b0bb3

---

Inertia is powered by [Reticulum](https://github.com/markqvist/Reticulum), [LXMF](https://github.com/markqvist/LXMF), and [NomadNet](https://github.com/markqvist/nomadnet).

---

## Why "Inertia"?

Coming from Meshtastic and MeshCore, the idea of a more powerful decentralised protocol that allows for files and hosted pages was extremely appealing. However, my primary device was an iPhone, and no Reticulum client existed for iOS. Thus, the *inertia* of not having support on my primary device delayed my use of the platform. This project exists so that nobody else has to consider changing their workflow or device to use Reticulum.

---

## AI?

No thanks. See [AI.md](AI.md) for more information.

## Licensing

All contents of the repository are licensed under the MIT license.

Content which are considered artistic works, such as icons, are dual-licensed under MIT and [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). This covers any files in the `assets/` folder, and any copies of those files elsewhere in the project.

### Upstream packages

- [Swift-Sodium](https://github.com/jedisct1/swift-sodium) is licensed under the ISC licence, which is considered compatible with the MIT license.
