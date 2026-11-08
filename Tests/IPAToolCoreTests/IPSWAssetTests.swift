import CryptoKit
import XCTest
@testable import IPAToolCore

final class IPSWAssetTests: XCTestCase {
    // MARK: - HPKE

    /// 向量由 Go 标准库 `crypto/hpke`（DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM）生成。
    func testHPKEOpensGoGeneratedVector() throws {
        let scalar = try XCTUnwrap(Data(base64Encoded: "lCiOaGTRP2RyILwHyfTowvO4cENFyo0TqvIufNkSLUQ="))
        let encapsulation = try XCTUnwrap(Data(base64Encoded:
            "BO3guzZzJKtjychZLT7U8qj0NAvU4MsJx89sD+t1u2CJUsu7dEJhhDRg/Dp/FKwjM3bvNhQFm0P1d1byLgWUemM="
        ))
        let ciphertext = try XCTUnwrap(Data(base64Encoded:
            "EoZxS/+4XgNJpl/mA1gfznxyIacWxfljYtb2/HkFNde8X/04ZKTGXbjPlgod73xy3TXFyqZKVA=="
        ))

        let plaintext = try AssetCrypto.HPKE.openBaseP256(
            recipientPrivateKey: scalar,
            encapsulation: encapsulation,
            ciphertext: ciphertext
        )

        XCTAssertEqual(String(data: plaintext, encoding: .utf8),
                       "ipatoolkit hpke interoperability vector")
    }

    func testPKCS8ExtractsP256Scalar() throws {
        let der = try XCTUnwrap(Data(base64Encoded:
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnliJnkNtKsAEydEKCxWS0Y4ZDiGstdOE6wYS05bm06+hRANCAAS1sVxtHCXHX4aTx2CT3pK484yyjwUjytzI47Z4coA2E7Pf/nQLgz4+wnKhCipKiaBLxynTPE5mbkFy+MmSb7UD"
        ))

        let scalar = try AssetCrypto.p256PrivateScalar(pkcs8: der)
        XCTAssertEqual(scalar.map { String(format: "%02x", $0) }.joined(),
                       "9e58899e436d2ac004c9d10a0b1592d18e190e21acb5d384eb0612d396e6d3af")
    }

    // MARK: - AES-CTR

    /// NIST SP 800-38A F.5.1 CTR-AES128.Encrypt 的第一块。
    func testAESCTRMatchesNISTVector() throws {
        let key = try XCTUnwrap(Data(hex: "2b7e151628aed2a6abf7158809cf4f3c"))
        let counter = try XCTUnwrap(Data(hex: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
        let plaintext = try XCTUnwrap(Data(hex: "6bc1bee22e409f96e93d7e117393172a"))

        let ciphertext = try AssetCrypto.aesCTR(plaintext, key: key, iv: counter)
        XCTAssertEqual(ciphertext.map { String(format: "%02x", $0) }.joined(),
                       "874d6191b620e3261bef6864990db6ce")
    }

    // MARK: - HKDF

    /// RFC 5869 测试用例 1。
    func testHKDFMatchesRFC5869() throws {
        let ikm = Data(repeating: 0x0b, count: 22)
        let salt = try XCTUnwrap(Data(hex: "000102030405060708090a0b0c"))
        let info = try XCTUnwrap(Data(hex: "f0f1f2f3f4f5f6f7f8f9"))

        let prk = AssetCrypto.hkdfExtract(salt: salt, ikm: ikm)
        XCTAssertEqual(prk.map { String(format: "%02x", $0) }.joined(),
                       "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

        let okm = AssetCrypto.hkdfExpand(prk: prk, info: info, count: 42)
        XCTAssertEqual(okm.map { String(format: "%02x", $0) }.joined(),
                       "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    }

    // MARK: - ZIP

    func testZipArchiveParsesStoredEntry() throws {
        let payload = Data("ipatoolkit zip fixture".utf8)
        let archive = try makeStoredArchive(name: "payload.bin", payload: payload)

        let zip = try ZipArchive(source: MemoryRangeReader(archive))
        let entry = try zip.entry("payload.bin")
        XCTAssertEqual(entry.method, ZipArchive.methodStore)
        XCTAssertEqual(entry.compressedSize, Int64(payload.count))
        XCTAssertEqual(entry.uncompressedSize, Int64(payload.count))

        let offset = try zip.dataOffset(of: entry)
        let data = try MemoryRangeReader(archive).readExact(at: offset, count: payload.count)
        XCTAssertEqual(data, payload)
    }

    func testZipArchiveRejectsMissingMember() throws {
        let payload = Data("payload".utf8)
        let archive = try makeStoredArchive(name: "payload.bin", payload: payload)
        let zip = try ZipArchive(source: MemoryRangeReader(archive))

        XCTAssertThrowsError(try zip.entry("missing"))
    }

    // MARK: - 内核集合

    func testIM4PPayloadExtractsOctetString() throws {
        let payload = Data("kernel payload".utf8)
        var inner = Data()
        inner.append(contentsOf: [0x16, 0x04])
        inner.append(Data("IM4P".utf8))
        inner.append(contentsOf: [0x16, 0x04])
        inner.append(Data("krnl".utf8))
        inner.append(contentsOf: [0x16, 0x00])
        inner.append(contentsOf: [0x04, UInt8(payload.count)])
        inner.append(payload)

        var der = Data([0x30, UInt8(inner.count)])
        der.append(inner)

        XCTAssertEqual(try KernelCollection.im4pPayload(der), payload)
        XCTAssertThrowsError(try KernelCollection.im4pPayload(der.dropLast()))
    }

    /// 联网：从固定 IPSW 取内核集合，导出的 FairPlayIOKit 必须与固定摘要一致。
    func testLiveKernelCollectionExportsPinnedFairPlayKext() throws {
        guard ProcessInfo.processInfo.environment["IPATOOL_IPSW_LIVE"] == "1" else {
            throw XCTSkip("设置 IPATOOL_IPSW_LIVE=1 才会访问 IPSW")
        }

        let source = try RemoteRangeReader(url: IPSWAssetSpec.restoreURL)
        let zip = try ZipArchive(source: source)
        let entry = try zip.pinnedEntry(IPSWAssetSpec.kernelCacheName,
                                        compressedSize: IPSWAssetSpec.kernelCacheCompressedSize,
                                        uncompressedSize: IPSWAssetSpec.kernelCacheArchiveSize)
        let compressed = try source.readExact(at: try zip.dataOffset(of: entry),
                                              count: Int(entry.compressedSize))
        let archive = try CompressionCodecs.inflateRaw(compressed,
                                                       expectedSize: Int(entry.uncompressedSize))

        let output = try KernelCollection.fairPlayKext(archive: archive)
        XCTAssertEqual(output.count, 2_132_320)
        XCTAssertEqual(SHA256.hash(data: output).map { String(format: "%02x", $0) }.joined(),
                       "47452960ec010d3a80b02cceec73a65f8a9758850fd0fb7b2fdac7a5d1b81025")
    }

    /// 联网：完整安装流程必须产出与固定摘要一致的 7 个资产。
    func testLiveInstallerProducesPinnedAssets() throws {
        guard ProcessInfo.processInfo.environment["IPATOOL_IPSW_LIVE"] == "1" else {
            throw XCTSkip("设置 IPATOOL_IPSW_LIVE=1 才会访问 IPSW")
        }

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ipsw-assets-\(UUID().uuidString)", isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: directory)
        }

        try IPSWAssetInstaller.installIfNeeded(directory: directory.path)
        for spec in IPSWAssetSpec.assets {
            let data = try Data(contentsOf: directory.appendingPathComponent(spec.name))
            XCTAssertEqual(data.count, spec.size, spec.name)
            XCTAssertEqual(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
                           spec.digest, spec.name)
        }

        XCTAssertNoThrow(try StoreAssets(directory: directory.path))
    }

    // MARK: - 构造最小 ZIP

    private func makeStoredArchive(name: String, payload: Data) throws -> Data {
        let nameBytes = Data(name.utf8)
        var output = Data()

        var local = Data()
        local.append(UInt32(0x0403_4B50).le)
        local.append(UInt16(20).le)
        local.append(UInt16(0).le)
        local.append(UInt16(ZipArchive.methodStore).le)
        local.append(UInt16(0).le)
        local.append(UInt16(0).le)
        local.append(UInt32(0).le)
        local.append(UInt32(payload.count).le)
        local.append(UInt32(payload.count).le)
        local.append(UInt16(nameBytes.count).le)
        local.append(UInt16(0).le)
        local.append(nameBytes)
        local.append(payload)
        output.append(local)

        let centralOffset = output.count
        var central = Data()
        central.append(UInt32(0x0201_4B50).le)
        central.append(UInt16(20).le)
        central.append(UInt16(20).le)
        central.append(UInt16(0).le)
        central.append(UInt16(ZipArchive.methodStore).le)
        central.append(UInt16(0).le)
        central.append(UInt16(0).le)
        central.append(UInt32(0).le)
        central.append(UInt32(payload.count).le)
        central.append(UInt32(payload.count).le)
        central.append(UInt16(nameBytes.count).le)
        central.append(UInt16(0).le)
        central.append(UInt16(0).le)
        central.append(UInt16(0).le)
        central.append(UInt16(0).le)
        central.append(UInt32(0).le)
        central.append(UInt32(0).le)
        central.append(nameBytes)
        output.append(central)

        var end = Data()
        end.append(UInt32(0x0605_4B50).le)
        end.append(UInt16(0).le)
        end.append(UInt16(0).le)
        end.append(UInt16(1).le)
        end.append(UInt16(1).le)
        end.append(UInt32(central.count).le)
        end.append(UInt32(centralOffset).le)
        end.append(UInt16(0).le)
        output.append(end)

        return output
    }
}

// MARK: - 测试辅助

private extension Data {
    init?(hex: String) {
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                return nil
            }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}

private extension FixedWidthInteger {
    var le: Data {
        withUnsafeBytes(of: littleEndian) { Data($0) }
    }
}
