import Foundation

/// macOS 27 (26A434) arm64 SAP 资产的固定规格。
/// 对应 Go 侧 `internal/sap/assets/{assets,remote,kernel}.go` 的常量。
enum IPSWAssetSpec {
    static let restoreURL = URL(
        string: "https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/UniversalMac_27.0.1_26A434_Restore.ipsw"
    )!

    /// 缓存目录名（与 Go 侧保持一致，便于共用缓存）。
    static let cacheDirectoryName = "ipatool/sap/apple-assets-macos-27-26A434-arm64-v4"

    /// 合成镜像的校验清单，与 7 个文件放在同一目录。
    static let manifestName = "swift-assets.json"

    struct Asset {
        let name: String
        let size: Int
        let digest: String
        /// 是否是从镜像里原样取出的文件（否则为 Swift 合成的 Mach-O）。
        let isSynthesized: Bool
    }

    /// 顺序与 C 侧 `adi_asset_specs` 一致。
    static let assets: [Asset] = [
        Asset(
            name: "AppleMediaServices", size: 14_813_888,
            digest: "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4",
            isSynthesized: true
        ),
        Asset(
            name: "commerce", size: 8_092_640,
            digest: "76de40a4a32f691947cb926ce3b128d2fc446f7cac9755f831c406cf5a316ac9",
            isSynthesized: false
        ),
        Asset(
            name: "adid", size: 9_797_952,
            digest: "1fec225b6917206e3d9b00fe636c04878f82bfd06a87a4b6941711de60efab5b",
            isSynthesized: false
        ),
        Asset(
            name: "CoreFP", size: 94_842_464,
            digest: "2c30fa2b5f695fd66c0360dce72f54757d03ddb7107549715c12cb359a003b46",
            isSynthesized: false
        ),
        Asset(
            name: "CoreFP.icxs", size: 7_365_344,
            digest: "cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b",
            isSynthesized: false
        ),
        Asset(
            name: "fairplayd", size: 37_689_264,
            digest: "28b4c7b2a5a0409c5020da55fc3984713a8e2b0eec8557076c8717f7166d003e",
            isSynthesized: false
        ),
        Asset(
            name: "FairPlayIOKit", size: 2_132_320,
            digest: "47452960ec010d3a80b02cceec73a65f8a9758850fd0fb7b2fdac7a5d1b81025",
            isSynthesized: true
        ),
    ]

    // MARK: - IPSW zip 成员

    static let fileSystemImageName = "043-70867-640.dmg.aea"
    static let fileSystemArchiveSize: Int64 = 11_274_289_152
    static let fileSystemImageSize: Int64 = 14_189_330_432

    static let systemOSImageName = "043-70701-651.dmg.aea"
    static let systemOSArchiveSize: Int64 = 2_415_919_104
    static let systemOSImageSize: Int64 = 2_879_389_696

    static let kernelCacheName = "kernelcache.release.mac13j"
    static let kernelCacheCompressedSize: Int64 = 33_043_908
    static let kernelCacheArchiveSize: Int64 = 33_096_787
    static let kernelCachePayloadSize: Int64 = 33_096_384
    static let kernelCacheImageSize: Int64 = 124_354_560

    static let fairPlayKextIdentifier = "com.apple.driver.FairPlayIOKit"

    // MARK: - 镜像内路径

    static let appleMediaServicesPath =
        "/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices"
    static let dyldCachePath = "/System/Library/dyld/dyld_shared_cache_arm64e"

    static let frameworkFiles: [(name: String, path: String)] = [
        ("adid", "/System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/adid"),
        ("commerce", "/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce"),
        ("CoreFP", "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP"),
        ("CoreFP.icxs", "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/Resources/CoreFP.icxs"),
        ("fairplayd", "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd"),
    ]

    static func asset(named name: String) -> Asset? {
        assets.first { $0.name == name }
    }
}
