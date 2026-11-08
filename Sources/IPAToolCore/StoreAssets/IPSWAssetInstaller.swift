import CryptoKit
import Foundation

/// 从固定 IPSW 安装 7 个 Store 资产到缓存目录。
/// 对应 Go 侧 `internal/sap/assets/{remote,kernel,assets}.go`。
enum IPSWAssetInstaller {
    /// 补齐缓存目录里缺失或损坏的资产，并写出校验清单。
    static func installIfNeeded(directory: String, session: URLSession = .shared) throws {
        let root = URL(fileURLWithPath: directory, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let missing = IPSWAssetSpec.assets.filter { !isCached($0, in: root) }
        guard !missing.isEmpty else {
            return
        }

        let remote = try RemoteRangeReader(url: IPSWAssetSpec.restoreURL, session: session)
        let archive = try ZipArchive(source: remote)

        let frameworkNames = Set(IPSWAssetSpec.frameworkFiles.map(\.name))
        if missing.contains(where: { frameworkNames.contains($0.name) }) {
            try installFrameworkFiles(archive: archive, remote: remote, session: session,
                                      missing: missing, root: root)
        }

        if missing.contains(where: { $0.name == "AppleMediaServices" }) {
            try installAppleMediaServices(archive: archive, remote: remote, session: session, root: root)
        }

        if missing.contains(where: { $0.name == "FairPlayIOKit" }) {
            try installFairPlayIOKit(archive: archive, remote: remote, root: root)
        }

        try writeManifest(in: root)
    }

    // MARK: - 原始框架文件

    private static func installFrameworkFiles(archive: ZipArchive, remote: RemoteRangeReader,
                                              session: URLSession, missing: [IPSWAssetSpec.Asset],
                                              root: URL) throws {
        let entry = try archive.pinnedEntry(IPSWAssetSpec.fileSystemImageName,
                                            compressedSize: IPSWAssetSpec.fileSystemArchiveSize,
                                            uncompressedSize: IPSWAssetSpec.fileSystemArchiveSize)
        let cryptex = try AEACryptex(source: try subReader(archive, remote, entry), session: session)
        guard cryptex.size == IPSWAssetSpec.fileSystemImageSize else {
            throw StoreAuthError.failure("macOS 文件系统大小为 \(cryptex.size)")
        }

        let filesystem = try openFilesystem(cryptex)
        for spec in missing where IPSWAssetSpec.frameworkFiles.contains(where: { $0.name == spec.name }) {
            guard let path = IPSWAssetSpec.frameworkFiles.first(where: { $0.name == spec.name })?.path else {
                continue
            }

            let temp = temporaryFile(for: spec, in: root)
            try? FileManager.default.removeItem(at: temp)
            try filesystem.extractFile(at: path, to: temp)
            try commit(temp, spec: spec, in: root)
        }
    }

    // MARK: - 合成镜像

    private static func installAppleMediaServices(archive: ZipArchive, remote: RemoteRangeReader,
                                                  session: URLSession, root: URL) throws {
        guard let spec = IPSWAssetSpec.asset(named: "AppleMediaServices") else {
            return
        }

        let entry = try archive.pinnedEntry(IPSWAssetSpec.systemOSImageName,
                                            compressedSize: IPSWAssetSpec.systemOSArchiveSize,
                                            uncompressedSize: IPSWAssetSpec.systemOSArchiveSize)
        let cryptex = try AEACryptex(source: try subReader(archive, remote, entry), session: session)
        guard cryptex.size == IPSWAssetSpec.systemOSImageSize else {
            throw StoreAuthError.failure("SystemOS cryptex 大小为 \(cryptex.size)")
        }

        let systemOS = try openFilesystem(cryptex)
        let cache = try DyldSharedCache { suffix in
            try systemOS.openFile(at: IPSWAssetSpec.dyldCachePath + suffix)
        }
        let data = try MachOBuilder.export(cache: cache,
                                           image: try cache.image(at: IPSWAssetSpec.appleMediaServicesPath))
        try commit(data, spec: spec, in: root)
    }

    private static func installFairPlayIOKit(archive: ZipArchive, remote: RemoteRangeReader,
                                             root: URL) throws {
        guard let spec = IPSWAssetSpec.asset(named: "FairPlayIOKit") else {
            return
        }

        let entry = try archive.pinnedEntry(IPSWAssetSpec.kernelCacheName,
                                            compressedSize: IPSWAssetSpec.kernelCacheCompressedSize,
                                            uncompressedSize: IPSWAssetSpec.kernelCacheArchiveSize)
        let compressed = try remote.readExact(at: try archive.dataOffset(of: entry),
                                              count: Int(entry.compressedSize))
        let payload = try CompressionCodecs.inflateRaw(compressed,
                                                       expectedSize: Int(entry.uncompressedSize))
        try commit(try KernelCollection.fairPlayKext(archive: payload), spec: spec, in: root)
    }

    // MARK: - 镜像打开

    /// APFS 容器可能是裸镜像，也可能包在 UDIF 磁盘映像里。
    private static func openFilesystem(_ source: RangeReadable) throws -> APFSReader {
        guard source.size >= 36 else {
            throw StoreAuthError.failure("磁盘映像过小：\(source.size)")
        }

        let header = try source.readExact(at: 0, count: 36)
        if header.slice(at: 32, count: 4) == Data("NXSB".utf8) {
            return try APFSReader(source: source)
        }

        return try APFSReader(source: try UDIFDiskImage(source: source))
    }

    // MARK: - 缓存校验与落盘

    private static func subReader(_ archive: ZipArchive, _ remote: RemoteRangeReader,
                                  _ entry: ZipArchive.Entry) throws -> SubRangeReader {
        try SubRangeReader(base: remote, offset: try archive.dataOffset(of: entry),
                           length: entry.compressedSize)
    }

    private static func isCached(_ spec: IPSWAssetSpec.Asset, in root: URL) -> Bool {
        let url = root.appendingPathComponent(spec.name)
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = attributes[.size] as? NSNumber,
              size.intValue == spec.size,
              let data = try? Data(contentsOf: url) else {
            return false
        }

        return digest(of: data) == spec.digest
    }

    private static func temporaryFile(for spec: IPSWAssetSpec.Asset, in root: URL) -> URL {
        root.appendingPathComponent(".\(spec.name).\(UUID().uuidString).tmp")
    }

    private static func commit(_ data: Data, spec: IPSWAssetSpec.Asset, in root: URL) throws {
        let temp = temporaryFile(for: spec, in: root)
        defer {
            try? FileManager.default.removeItem(at: temp)
        }

        try data.write(to: temp, options: .atomic)
        try commit(temp, spec: spec, in: root)
    }

    private static func commit(_ temp: URL, spec: IPSWAssetSpec.Asset, in root: URL) throws {
        defer {
            try? FileManager.default.removeItem(at: temp)
        }

        guard let attributes = try? FileManager.default.attributesOfItem(atPath: temp.path),
              let size = attributes[.size] as? NSNumber,
              size.intValue == spec.size,
              let data = try? Data(contentsOf: temp) else {
            throw StoreAuthError.failure("\(spec.name) 的输出文件无效")
        }

        let actual = digest(of: data)
        guard actual == spec.digest else {
            throw StoreAuthError.failure("\(spec.name) 的摘要为 \(actual)")
        }

        let destination = root.appendingPathComponent(spec.name)
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.moveItem(at: temp, to: destination)
    }

    private static func writeManifest(in root: URL) throws {
        var manifest: [String: [String: Any]] = [:]
        for spec in IPSWAssetSpec.assets {
            manifest[spec.name] = ["size": spec.size, "sha256": spec.digest]
        }

        let data = try JSONSerialization.data(withJSONObject: manifest,
                                              options: [.prettyPrinted, .sortedKeys])
        try data.write(to: root.appendingPathComponent(IPSWAssetSpec.manifestName), options: .atomic)
    }

    private static func digest(of data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
