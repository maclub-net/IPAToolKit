import Foundation
import Compression
import CryptoKit

/// 内置的 Store emulator profile 资产。
///
/// 三个文件由 Go 侧 `internal/store/profile` 生成，用 zlib 压缩后随包分发。
/// 加载时校验解压长度与 SHA-256，避免资产被替换后产生难以复现的 guest 行为。
enum StoreProfileAssets {
    struct Loaded {
        let metadata: [UInt8]
        let pages: [UInt8]
        let plugin: [UInt8]
    }

    private struct Asset {
        let name: String
        let size: Int
        let sha256: String
    }

    // Go 侧固定值：
    // metadata 4,807,917；pages 20,893,696；plugin 138,088。
    private static let metadataAsset = Asset(
        name: "profile-metadata",
        size: 4_807_917,
        sha256: "5e92717743272aa84343bd25f6bab6401155f88ade51b704ec535d3e6b5bd421"
    )
    private static let pagesAsset = Asset(
        name: "profile-pages",
        size: 20_893_696,
        sha256: "4fd8cf193ca6e71d52a2d6e68d9ca76907332ff33dade332351c97efe5f0caed"
    )
    private static let pluginAsset = Asset(
        name: "profile-plugin",
        size: 138_088,
        sha256: "e33fff05a6e6593dd91e33fd103b5d3068b62a787c680df33b859f19b3acc4ea"
    )

    static func load() throws -> Loaded {
        Loaded(
            metadata: try load(metadataAsset),
            pages: try load(pagesAsset),
            plugin: try load(pluginAsset)
        )
    }

    private static func load(_ asset: Asset) throws -> [UInt8] {
        guard let url = Bundle.module.url(
            forResource: asset.name,
            withExtension: "zlib",
            subdirectory: "Resources"
        ) else {
            throw StoreRuntimeError.failure("missing embedded asset \(asset.name).zlib")
        }

        let compressed = try Data(contentsOf: url)
        let raw = try inflate(compressed, expectedSize: asset.size)

        let digest = SHA256.hash(data: Data(raw))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        guard hex == asset.sha256 else {
            throw StoreRuntimeError.failure("embedded asset \(asset.name) digest mismatch")
        }

        return raw
    }

    private static func inflate(_ data: Data, expectedSize: Int) throws -> [UInt8] {
        guard data.count > 6 else {
            throw StoreRuntimeError.failure("empty embedded asset")
        }

        // compression_decode_buffer 的 COMPRESSION_ZLIB 只接受裸 deflate 数据，
        // 这里去掉 Python zlib 生成的 2 字节头与 4 字节 Adler-32 尾。
        let payload = [UInt8](data[2 ..< data.count - 4])

        var output = [UInt8](repeating: 0, count: expectedSize)
        let written = output.withUnsafeMutableBytes { destination -> Int in
            payload.withUnsafeBytes { source -> Int in
                guard let sourceBase = source.bindMemory(to: UInt8.self).baseAddress,
                      let destinationBase = destination.bindMemory(to: UInt8.self).baseAddress else {
                    return 0
                }

                return compression_decode_buffer(
                    destinationBase,
                    expectedSize,
                    sourceBase,
                    payload.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }

        guard written == expectedSize else {
            throw StoreRuntimeError.failure("embedded asset inflate failed")
        }

        return output
    }
}
