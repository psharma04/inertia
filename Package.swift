// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Inertia",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(name: "ReticulumCrypto",    targets: ["ReticulumCrypto"]),
        .library(name: "ReticulumPackets",   targets: ["ReticulumPackets"]),
        .library(name: "ReticulumRouting",   targets: ["ReticulumRouting"]),
        .library(name: "ReticulumInterfaces",targets: ["ReticulumInterfaces"]),
        .library(name: "ReticulumCore",      targets: ["ReticulumCore"]),
        .library(name: "LXMF",              targets: ["LXMF"]),
        .library(name: "NomadNet",          targets: ["NomadNet"]),
        .library(name: "Persistence",       targets: ["Persistence"]),
        .library(name: "Services",          targets: ["Services"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.10.0"),
    ],
    targets: [

        // Core Protocol Modules

        .target(
            name: "ReticulumCrypto",
            dependencies: [
                .product(name: "Sodium", package: "swift-sodium"),
            ]
        ),
        .target(
            name: "ReticulumPackets",
            dependencies: ["ReticulumCrypto"]
        ),
        .target(
            name: "ReticulumInterfaces",
            dependencies: ["ReticulumCrypto", "ReticulumPackets"]
        ),
        .target(
            name: "ReticulumRouting",
            dependencies: ["ReticulumCrypto", "ReticulumPackets"]
        ),
        .target(
            name: "ReticulumCore",
            dependencies: [
                "ReticulumCrypto",
                "ReticulumPackets",
                "ReticulumRouting",
                "ReticulumInterfaces"
            ]
        ),

        // Application Protocol Modules

        .target(
            name: "LXMF",
            dependencies: ["ReticulumCore", "ReticulumCrypto"]
        ),
        .target(
            name: "NomadNet",
            dependencies: ["ReticulumCore", "LXMF", "ReticulumCrypto"]
        ),

        // Persistence & Services

        .target(
            name: "Persistence",
            dependencies: ["ReticulumCore", "LXMF", "NomadNet"]
        ),
        .target(
            name: "Services",
            dependencies: ["ReticulumCore", "LXMF", "NomadNet", "Persistence"]
        ),

        // Test Targets

        .testTarget(
            name: "ReticulumCryptoTests",
            dependencies: ["ReticulumCrypto"]
        ),
        .testTarget(
            name: "ReticulumPacketsTests",
            dependencies: ["ReticulumPackets", "ReticulumCrypto"]
        ),
        .testTarget(
            name: "ReticulumInterfacesTests",
            dependencies: ["ReticulumInterfaces"]
        ),
        .testTarget(
            name: "ReticulumRoutingTests",
            dependencies: ["ReticulumRouting", "ReticulumPackets"]
        ),
        .testTarget(
            name: "ReticulumCoreTests",
            dependencies: ["ReticulumCore"]
        ),
        .testTarget(
            name: "LXMFTests",
            dependencies: ["LXMF"]
        ),
        .testTarget(
            name: "NomadNetTests",
            dependencies: ["NomadNet"]
        ),
        .testTarget(
            name: "PersistenceTests",
            dependencies: ["Persistence"]
        ),
        .testTarget(
            name: "ServicesTests",
            dependencies: ["Services"]
        ),
        .testTarget(
            name: "IntegrationTests",
            dependencies: [
                "ReticulumInterfaces",
                "ReticulumPackets",
                "ReticulumCrypto",
                "LXMF",
            ],
            resources: [
                .copy("Resources"),
            ]
        ),
    ]
)
