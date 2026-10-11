// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "IPAToolKit",
    platforms: [
        .macOS(.v14),
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "IPAToolCore",
            targets: ["IPAToolCore"]
        ),
    ],
    targets: [
        .target(
            name: "CSAP",
            path: "Sources/CSAP",
            publicHeadersPath: "include",
            cSettings: [
                .define("CSAP_BUILD", to: "1"),
            ],
            linkerSettings: [
                .linkedLibrary("dl"),
            ]
        ),
        .target(
            name: "IPAToolCore",
            dependencies: ["CSAP"],
            path: "Sources/IPAToolCore"
        ),
    ]
)
