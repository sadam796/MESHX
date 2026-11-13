// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MESHXKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "MESHXKit", targets: ["MESHXKit"])],
    targets: [
        .target(name: "MESHXKit"),
        .testTarget(name: "MESHXKitTests", dependencies: ["MESHXKit"])
    ]
)
