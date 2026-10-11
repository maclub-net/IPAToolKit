import Foundation
import CryptoKit
import CSAP

#if canImport(zlib)
import zlib
#endif

/// 负责下载 unicorn 动态库和 SAP 资产到沙盒缓存目录
public enum SAPAssetDownloader {

    // MARK: - Unicorn

    struct UnicornArtifact {
        let url: URL
        let archiveSHA256: String
        let librarySHA256: String
        let member: String  // ZIP 内的路径
    }

    /// 根据架构选择 unicorn 制品
    static func unicornArtifact() -> UnicornArtifact {
        #if arch(arm64)
        return UnicornArtifact(
            url: URL(string: "https://files.pythonhosted.org/packages/6c/ae/4943c6f8524d729ec7d5e69df6407ea05d710fe77471d91cecf3fc64eb57/unicorn-2.1.4-cp37-abi3-macosx_11_0_arm64.whl")!,
            archiveSHA256: "d6c93e0f60328d8f4a1792af3f834137a28050fcc2305f2ec01efe8558a9844e",
            librarySHA256: "7207c8e3d7a63118fb0bca73e01816797fd51b1d8a39a4cbc7abfd562ee59c85",
            member: "unicorn/lib/libunicorn.2.dylib"
        )
        #else
        return UnicornArtifact(
            url: URL(string: "https://files.pythonhosted.org/packages/c8/a7/92b47771e2107a201632a199cec91e8a81ee8a071ca6b7e7d600d8c61ac9/unicorn-2.1.4-cp37-abi3-macosx_10_9_x86_64.whl")!,
            archiveSHA256: "2a6f738fab5fabffa56af1e7bbf16ea1e91466c342f8dc64f125bd70f36c6b80",
            librarySHA256: "51c4a6f3ce22628ecd3acd1c49b921a818ffb989ca2c473134cc7eb06094f256",
            member: "unicorn/lib/libunicorn.2.dylib"
        )
        #endif
    }

    /// 确保 unicorn dylib 已下载到缓存目录，返回其路径
    public static func ensureUnicornLibrary() async throws -> String {
        let artifact = unicornArtifact()
        let cacheRoot = unicornCacheRoot()
        let directory = cacheRoot.appendingPathComponent(artifact.librarySHA256, isDirectory: true)
        let destination = directory.appendingPathComponent("libunicorn.2.dylib")

        // 检查已缓存
        if FileManager.default.fileExists(atPath: destination.path),
           let hash = sha256(of: destination), hash == artifact.librarySHA256 {
            return destination.path
        }

        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        // 下载 WHL
        print("[unicorn] downloading \(artifact.url.lastPathComponent)...")
        var request = URLRequest(url: artifact.url)
        request.setValue("ipatool Unicorn runtime downloader", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw SAPDownloadError.networkFailed
        }

        // 校验 archive SHA256
        guard sha256(of: data) == artifact.archiveSHA256 else {
            throw SAPDownloadError.checksumMismatch
        }

        // 从 ZIP 中提取 dylib
        guard let dylibData = extractZIPEntry(data: data, member: artifact.member) else {
            throw SAPDownloadError.extractionFailed
        }

        // 校验 dylib SHA256
        guard sha256(of: dylibData) == artifact.librarySHA256 else {
            throw SAPDownloadError.checksumMismatch
        }

        try dylibData.write(to: destination, options: .atomic)
        print("[unicorn] cached at \(destination.path)")
        return destination.path
    }

    private static func unicornCacheRoot() -> URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return caches.appendingPathComponent("ipatool/unicorn/2.1.4", isDirectory: true)
    }

    // MARK: - ZIP Extraction (minimal, deflate only)

    private static func extractZIPEntry(data: Data, member: String) -> Data? {
        let eocdSignature: [UInt8] = [0x50, 0x4b, 0x05, 0x06]
        guard let eocdRange = data.range(of: Data(eocdSignature), options: .backwards) else {
            return nil
        }
        let eocdOffset = eocdRange.lowerBound

        let cdEntries = data.withUnsafeBytes { ptr -> Int in
            Int(ptr.loadUnaligned(fromByteOffset: eocdOffset + 10, as: UInt16.self))
        }
        let cdOffset = data.withUnsafeBytes { ptr -> Int in
            Int(ptr.loadUnaligned(fromByteOffset: eocdOffset + 16, as: UInt32.self))
        }

        var pos = cdOffset
        for _ in 0..<cdEntries {
            let sig = data.withUnsafeBytes { ptr -> UInt32 in
                ptr.loadUnaligned(fromByteOffset: pos, as: UInt32.self)
            }
            if sig != 0x02014b50 { break }

            let compressionMethod = data.withUnsafeBytes { ptr -> UInt16 in
                ptr.loadUnaligned(fromByteOffset: pos + 10, as: UInt16.self)
            }
            let compressedSize = data.withUnsafeBytes { ptr -> UInt32 in
                ptr.loadUnaligned(fromByteOffset: pos + 20, as: UInt32.self)
            }
            let uncompressedSize = data.withUnsafeBytes { ptr -> UInt32 in
                ptr.loadUnaligned(fromByteOffset: pos + 24, as: UInt32.self)
            }
            let nameLen = data.withUnsafeBytes { ptr -> UInt16 in
                ptr.loadUnaligned(fromByteOffset: pos + 28, as: UInt16.self)
            }
            let extraLen = data.withUnsafeBytes { ptr -> UInt16 in
                ptr.loadUnaligned(fromByteOffset: pos + 30, as: UInt16.self)
            }
            let commentLen = data.withUnsafeBytes { ptr -> UInt16 in
                ptr.loadUnaligned(fromByteOffset: pos + 32, as: UInt16.self)
            }
            let localHeaderOffset = data.withUnsafeBytes { ptr -> UInt32 in
                ptr.loadUnaligned(fromByteOffset: pos + 42, as: UInt32.self)
            }

            let nameStart = pos + 46
            let nameData = data.subdata(in: nameStart..<(nameStart + Int(nameLen)))
            let name = String(data: nameData, encoding: .utf8) ?? ""

            if name == member {
                let lhNameLen = data.withUnsafeBytes { ptr -> UInt16 in
                    ptr.loadUnaligned(fromByteOffset: Int(localHeaderOffset) + 26, as: UInt16.self)
                }
                let lhExtraLen = data.withUnsafeBytes { ptr -> UInt16 in
                    ptr.loadUnaligned(fromByteOffset: Int(localHeaderOffset) + 28, as: UInt16.self)
                }
                let dataOffset = Int(localHeaderOffset) + 30 + Int(lhNameLen) + Int(lhExtraLen)
                let compressed = data.subdata(in: dataOffset..<(dataOffset + Int(compressedSize)))

                if compressionMethod == 0 {
                    return compressed
                } else if compressionMethod == 8 {
                    return decompressDeflate(compressed, uncompressedSize: Int(uncompressedSize))
                }
                return nil
            }

            pos += 46 + Int(nameLen) + Int(extraLen) + Int(commentLen)
        }
        return nil
    }

    private static func decompressDeflate(_ data: Data, uncompressedSize: Int) -> Data? {
        #if canImport(zlib)
        var output = Data(count: uncompressedSize)
        var outputLen = 0

        let result = data.withUnsafeBytes { inputPtr in
            output.withUnsafeMutableBytes { outputPtr -> Int32 in
                var stream = z_stream()
                stream.next_in = UnsafeMutablePointer<UInt8>(mutating: inputPtr.bindMemory(to: UInt8.self).baseAddress)
                stream.avail_in = UInt32(data.count)
                stream.next_out = outputPtr.bindMemory(to: UInt8.self).baseAddress
                stream.avail_out = UInt32(uncompressedSize)

                let initRet = inflateInit2_(&stream, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
                if initRet != Z_OK { return initRet }

                let inflateRet = inflate(&stream, Z_FINISH)
                outputLen = uncompressedSize - Int(stream.avail_out)
                inflateEnd(&stream)
                return inflateRet
            }
        }

        if result != Z_STREAM_END && result != Z_OK {
            return nil
        }
        return output.prefix(outputLen)
        #else
        return nil
        #endif
    }

    // MARK: - SHA256

    private static func sha256(of data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func sha256(of url: URL) -> String? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return sha256(of: data)
    }

    // MARK: - SAP Assets (from Apple software update package)

    private static let applePackageURL = URL(string: "https://swcdn.apple.com/content/downloads/27/34/041-98128-A_SYPWICN3KH/5dqkl4rqgbsr18yzy61yeie9g3cmjc5hiv/OSXUpd10.9.pkg")!

    // Payload 中 bzip2 数据起始偏移
    private static let payloadBZOffset: Int64 = 0x352F40D5

    struct SAPFileSpec {
        let name: String
        let path: String  // CPIO 内路径
        let size: Int
        let sha256: String
        let cacheSubdir: String  // 缓存子目录（相对于 SAPAssets.cacheRoot）
    }

    private static let requiredSAPFiles: [SAPFileSpec] = [
        SAPFileSpec(name: "CommerceKit", path: "./System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/CommerceKit", size: 3271840, sha256: "b84ff12c21987856c0a17b78f1ad82b73195a6dec5f3b208a17d245555a2c8a2", cacheSubdir: "apple-assets-v2"),
        SAPFileSpec(name: "CommerceCore", path: "./System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Frameworks/CommerceCore.framework/Versions/A/CommerceCore", size: 207744, sha256: "c5401e57402230f3c876409d295319ddf1e61287bc882683c5d61277be7bc1f2", cacheSubdir: "apple-assets-v2"),
        SAPFileSpec(name: "CoreFP", path: "./System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP", size: 29014912, sha256: "f19141336be4198d0f8991bb00017c915efc7aeaece36c345f7faa1237ea6074", cacheSubdir: "apple-assets-v2"),
        SAPFileSpec(name: "CoreFP.icxs", path: "./System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP.icxs", size: 5288352, sha256: "473e78af86979f5bd4f6269561caf770b3d16c098d918846eeac8cdd2fe6566a", cacheSubdir: "apple-assets-v2"),
        SAPFileSpec(name: "storeagent", path: "./System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/storeagent", size: 2580176, sha256: "70ce036f9dbcbc04db9511ebd08de0dd3cbc35ccc9d44b089c90170cb5453c59", cacheSubdir: "apple-storeagent-v1"),
    ]

    /// 获取指定 spec 的缓存文件 URL
    private static func cacheURL(for spec: SAPFileSpec) -> URL {
        let cacheRoot = SAPAssets.cacheRoot
        return cacheRoot
            .appendingPathComponent(spec.cacheSubdir, isDirectory: true)
            .appendingPathComponent(spec.name)
    }

    /// 确保所有 SAP 资产已下载到缓存目录
    public static func ensureSAPAssets() async throws {
        let fm = FileManager.default

        // 检查是否所有文件都已缓存且校验通过
        var allCached = true
        for spec in requiredSAPFiles {
            let fileURL = cacheURL(for: spec)
            guard fm.fileExists(atPath: fileURL.path),
                  let attrs = try? fm.attributesOfItem(atPath: fileURL.path),
                  let fileSize = attrs[.size] as? Int,
                  fileSize == spec.size,
                  sha256(of: fileURL) == spec.sha256 else {
                allCached = false
                break
            }
        }
        if allCached {
            print("[sap-assets] all assets cached")
            return
        }

        print("[sap-assets] downloading from Apple package...")
        let files = try await downloadSAPAssets()

        for spec in requiredSAPFiles {
            guard let data = files[spec.path] else {
                throw SAPDownloadError.assetNotFound
            }
            guard data.count == spec.size, sha256(of: data) == spec.sha256 else {
                throw SAPDownloadError.checksumMismatch
            }
            let fileURL = cacheURL(for: spec)
            try fm.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: fileURL, options: .atomic)
            print("[sap-assets] cached \(spec.name) (\(data.count) bytes)")
        }
    }

    private static func downloadSAPAssets() async throws -> [String: Data] {
        // 1. 下载 XAR header (28 bytes)
        let headerData = try await downloadRange(from: 0, length: 28)
        guard headerData.count >= 28 else { throw SAPDownloadError.networkFailed }

        let magic = headerData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) }
        guard magic == 0x21726178 else { // "xar!" little-endian
            throw SAPDownloadError.extractionFailed
        }

        let tocCompressedSize = headerData.withUnsafeBytes { Int($0.loadUnaligned(fromByteOffset: 4, as: UInt64.self).bigEndian) }
        let tocUncompressedSize = headerData.withUnsafeBytes { Int($0.loadUnaligned(fromByteOffset: 12, as: UInt64.self).bigEndian) }

        // 2. 下载压缩的 TOC
        let tocCompressed = try await downloadRange(from: 28, length: tocCompressedSize)
        guard tocCompressed.count == tocCompressedSize else { throw SAPDownloadError.networkFailed }

        // 3. 解压 TOC (zlib)
        guard let tocData = decompressZlib(tocCompressed, uncompressedSize: tocUncompressedSize) else {
            throw SAPDownloadError.extractionFailed
        }

        // 4. 解析 TOC XML，查找 Payload 的 offset 和 size
        guard let payload = parseXARToc(tocData) else {
            throw SAPDownloadError.extractionFailed
        }

        let heapOffset = 28 + tocCompressedSize
        let payloadHeapOffset = heapOffset + payload.offset
        let bz2Start = payloadHeapOffset + Int(payloadBZOffset)

        // 5. 从 bz2 偏移开始下载（下载足够大的范围）
        // 4 个文件总共约 38MB，bzip2 压缩后约 10-15MB，下载 50MB 足够
        let downloadSize = min(50 * 1024 * 1024, payload.size - Int(payloadBZOffset))
        let bz2Data = try await downloadRange(from: bz2Start, length: downloadSize)

        // Go 代码在数据前补 "BZh9"
        var bz2Full = Data([0x42, 0x5A, 0x68, 0x39]) // "BZh9"
        bz2Full.append(bz2Data)

        // 6. bzip2 解压
        var outputPtr: UnsafeMutablePointer<UInt8>?
        var outputLen: Int = 0
        let ret = bz2Full.withUnsafeBytes { ptr -> Int32 in
            csap_bz2_decompress(ptr.bindMemory(to: UInt8.self).baseAddress, bz2Full.count, &outputPtr, &outputLen)
        }
        guard ret == 0, let ptr = outputPtr, outputLen > 0 else {
            throw SAPDownloadError.extractionFailed
        }
        let cpioData = Data(bytesNoCopy: ptr, count: outputLen, deallocator: .free)
        print("[sap-assets] CPIO size: \(cpioData.count) bytes")

        // 7. 解析 CPIO，提取 4 个文件
        let files = extractCPIOEntries(cpioData, wantedPaths: Set(requiredSAPFiles.map { $0.path }))
        return files
    }

    struct XARFile {
        let offset: Int
        let size: Int
    }

    private static func parseXARToc(_ data: Data) -> XARFile? {
        let parser = XMLParser(data: data)
        let delegate = XARPayloadParser()
        parser.delegate = delegate
        parser.parse()
        return delegate.payload
    }

    private static func extractCPIOEntries(_ data: Data, wantedPaths: Set<String>) -> [String: Data] {
        var result: [String: Data] = [:]
        var pos = 0
        let magic = "070701" // newc format

        while pos + 110 <= data.count {
            let headerData = data.subdata(in: pos..<(pos + 110))
            guard let headerStr = String(data: headerData, encoding: .ascii) else { break }
            guard headerStr.hasPrefix(magic) else { break }

            // newc format: 6 字符 magic + 13 字段各 8 字符十六进制
            func field(_ idx: Int) -> Int? {
                let start = 6 + idx * 8
                guard start + 8 <= headerStr.count else { return nil }
                let s = headerStr.index(headerStr.startIndex, offsetBy: start)
                let e = headerStr.index(s, offsetBy: 8)
                return Int(headerStr[s..<e], radix: 16)
            }

            guard let namesize = field(9), let filesize = field(6) else { break }

            let nameStart = pos + 110
            guard nameStart + namesize <= data.count else { break }
            let nameData = data.subdata(in: nameStart..<(nameStart + namesize))
            let name = String(data: nameData, encoding: .ascii)?.trimmingCharacters(in: .controlCharacters) ?? ""

            // 计算 data 起始位置（4 字节对齐）
            let headerAndName = 110 + namesize
            let dataStart = pos + ((headerAndName + 3) & ~3)
            let dataEnd = dataStart + filesize

            if wantedPaths.contains(name) {
                if dataEnd <= data.count {
                    result[name] = data.subdata(in: dataStart..<dataEnd)
                }
                if result.count == wantedPaths.count {
                    break
                }
            }

            // 移动到下一个条目（data 也 4 字节对齐）
            let entrySize = ((filesize + 3) & ~3)
            pos = dataStart + entrySize
        }

        return result
    }

    // MARK: - HTTP Range Download

    private static func downloadRange(from offset: Int, length: Int) async throws -> Data {
        var request = URLRequest(url: applePackageURL)
        request.setValue("bytes=\(offset)-\(offset + length - 1)", forHTTPHeaderField: "Range")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse,
              http.statusCode == 206 || http.statusCode == 200 else {
            throw SAPDownloadError.networkFailed
        }
        return data
    }

    // MARK: - Zlib Decompress (for XAR TOC)

    private static func decompressZlib(_ data: Data, uncompressedSize: Int) -> Data? {
        #if canImport(zlib)
        var output = Data(count: uncompressedSize)
        var outputLen = 0

        let result = data.withUnsafeBytes { inputPtr in
            output.withUnsafeMutableBytes { outputPtr -> Int32 in
                var stream = z_stream()
                stream.next_in = UnsafeMutablePointer<UInt8>(mutating: inputPtr.bindMemory(to: UInt8.self).baseAddress)
                stream.avail_in = UInt32(data.count)
                stream.next_out = outputPtr.bindMemory(to: UInt8.self).baseAddress
                stream.avail_out = UInt32(uncompressedSize)

                let initRet = inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
                if initRet != Z_OK { return initRet }

                let inflateRet = inflate(&stream, Z_FINISH)
                outputLen = uncompressedSize - Int(stream.avail_out)
                inflateEnd(&stream)
                return inflateRet
            }
        }

        if result != Z_STREAM_END && result != Z_OK {
            return nil
        }
        return output.prefix(outputLen)
        #else
        return nil
        #endif
    }
}

// MARK: - Errors

public enum SAPDownloadError: Error, LocalizedError {
    case networkFailed
    case checksumMismatch
    case extractionFailed
    case assetNotFound

    public var errorDescription: String? {
        switch self {
        case .networkFailed: return "网络下载失败"
        case .checksumMismatch: return "校验和不匹配"
        case .extractionFailed: return "解压失败"
        case .assetNotFound: return "未找到 SAP 资产"
        }
    }
}

// MARK: - XAR TOC XML Parser

class XARPayloadParser: NSObject, XMLParserDelegate {
    var payload: SAPAssetDownloader.XARFile?
    private var currentFile = ""
    private var currentData: [String: String] = [:]
    private var currentElement = ""
    private var inData = false

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        currentElement = elementName
        if elementName == "data" {
            inData = true
            currentData = [:]
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        if inData {
            currentData[currentElement] = trimmed
        } else if currentElement == "name" {
            currentFile = trimmed
        }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if elementName == "data" {
            inData = false
            if currentFile == "Payload",
               let offsetStr = currentData["offset"], let offset = Int(offsetStr),
               let sizeStr = currentData["size"], let size = Int(sizeStr) {
                payload = SAPAssetDownloader.XARFile(offset: offset, size: size)
            }
            currentFile = ""
        }
        currentElement = ""
    }
}
