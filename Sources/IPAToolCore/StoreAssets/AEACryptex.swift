import Foundation

/// AEA1 加密镜像的只读解密层，对应 Go 侧 `aeaReader`。
///
/// 结构：header(12) + authData(TLV) + mainSalt(32) + 加密 root(112) + 若干 cluster。
/// 每个 cluster 头部包含本簇所有段的加密头部、下一个 cluster 的 MAC、以及各段 MAC。
final class AEACryptex: RangeReadable {
    private static let magic = "AEA1"
    private static let symmetricProfile: UInt32 = 1
    private static let mainKeyInfo = "AEA_AMK"
    private static let rootKeyInfo = "AEA_RHEK"
    private static let clusterKeyInfo = "AEA_CK"
    private static let clusterHeaderKeyInfo = "AEA_CHEK"
    private static let segmentKeyInfo = "AEA_SK"
    private static let lzfseCompression: UInt8 = UInt8(ascii: "e")
    private static let sha256Checksum: UInt8 = 2
    private static let headerSize = 12
    private static let rootHeaderSize = 112
    private static let segmentHeaderSize = 8 + 32
    private static let headerKeySize = 32 + 32 + 16
    private static let cacheLimit = 64
    private static let maxAuthDataSize = 1 << 20
    private static let maxFCSKeySize = 64 << 10

    private struct Segment {
        var inputOffset: Int64 = 0
        var outputOffset: Int64 = 0
        var compressedSize: UInt32 = 0
        var decompressedSize: UInt32 = 0
        var checksum = Data()
        var mac = Data()
        var cluster: UInt32 = 0
        var index: UInt32 = 0
    }

    private struct HeaderKey {
        let mac: Data
        let key: Data
        let iv: Data
    }

    private let source: RangeReadable
    private let segmentSize: UInt32
    private let mainKey: Data
    private var segments: [Segment]

    private let cacheLock = NSLock()
    private var cache: [Int: Data] = [:]
    private var cacheOrder: [Int] = []

    let size: Int64

    init(source: RangeReadable, session: URLSession = .shared) throws {
        self.source = source

        let header = try source.readExact(at: 0, count: AEACryptex.headerSize)
        guard String(decoding: header.prefix(4), as: UTF8.self) == AEACryptex.magic else {
            throw StoreAuthError.failure("AEA 镜像头标识无效")
        }

        let profileAndStrength = header.uint32LE(at: 4)
        guard profileAndStrength & 0xFF_FFFF == AEACryptex.symmetricProfile else {
            throw StoreAuthError.failure("不支持的 AEA profile \(profileAndStrength & 0xFF_FFFF)")
        }

        let authDataLength = Int(header.uint32LE(at: 8))
        guard authDataLength <= AEACryptex.maxAuthDataSize else {
            throw StoreAuthError.failure("AEA 认证数据过大：\(authDataLength)")
        }

        let authData = try source.readExact(at: Int64(AEACryptex.headerSize), count: authDataLength)
        let metadata = try AEACryptex.parseMetadata(authData)
        let symmetricKey = try AEACryptex.resolveSymmetricKey(metadata: metadata, session: session)

        let mainSaltOffset = Int64(AEACryptex.headerSize + authDataLength)
        let mainSalt = try source.readExact(at: mainSaltOffset, count: 32)

        var mainKeyInfo = Data(AEACryptex.mainKeyInfo.utf8)
        mainKeyInfo.append(contentsOf: AEACryptex.littleEndian32(profileAndStrength))
        let mainKey = try AEACryptex.deriveKey(secret: symmetricKey, salt: mainSalt,
                                              info: mainKeyInfo, count: symmetricKey.count)
        self.mainKey = mainKey

        let rootOffset = mainSaltOffset + 32
        let encryptedRoot = try source.readExact(at: rootOffset, count: AEACryptex.rootHeaderSize)
        let rootMAC = encryptedRoot.slice(at: 0, count: 32)
        let rootData = encryptedRoot.slice(at: 32, count: 48)
        let clusterMAC = encryptedRoot.slice(at: 80, count: 32)

        let rootKey = try AEACryptex.deriveHeaderKey(mainKey, info: Data(AEACryptex.rootKeyInfo.utf8))
        var rootSalt = clusterMAC
        rootSalt.append(authData)
        let computedRootMAC = AEACryptex.calculateMAC(key: rootKey.mac, data: rootData, salt: rootSalt)
        guard computedRootMAC == rootMAC else {
            throw StoreAuthError.failure("AEA root 头部认证失败")
        }

        let decryptedRoot = try AssetCrypto.aesCTR(rootData, key: rootKey.key, iv: rootKey.iv)
        let fileSize = decryptedRoot.uint64LE(at: 0)
        let encryptedSize = decryptedRoot.uint64LE(at: 8)
        let segmentSize = decryptedRoot.uint32LE(at: 16)
        let segmentsPerCluster = decryptedRoot.uint32LE(at: 20)
        let compression = decryptedRoot.byte(at: 24)
        let checksum = decryptedRoot.byte(at: 25)

        guard fileSize > 0, fileSize <= UInt64(Int64.max) else {
            throw StoreAuthError.failure("AEA 输出尺寸无效：\(fileSize)")
        }
        guard encryptedSize == UInt64(source.size) else {
            throw StoreAuthError.failure("AEA 记录的加密尺寸 \(encryptedSize) 与实际 \(source.size) 不一致")
        }
        guard segmentSize > 0, segmentsPerCluster > 0 else {
            throw StoreAuthError.failure("AEA 段布局无效")
        }
        guard compression == AEACryptex.lzfseCompression, checksum == AEACryptex.sha256Checksum else {
            throw StoreAuthError.failure("不支持的 AEA 编码：压缩 \(compression)，校验 \(checksum)")
        }

        self.size = Int64(fileSize)
        self.segmentSize = segmentSize
        self.segments = Array(repeating: Segment(),
                              count: Int((fileSize + UInt64(segmentSize) - 1) / UInt64(segmentSize)))

        try indexClusters(clusterOffset: rootOffset + Int64(AEACryptex.rootHeaderSize),
                          clusterMAC: clusterMAC,
                          fileSize: fileSize,
                          segmentsPerCluster: segmentsPerCluster,
                          sourceSize: source.size)
    }

    // MARK: - RangeReadable

    func read(at offset: Int64, count: Int) throws -> Data {
        guard count > 0 else {
            return Data()
        }
        guard offset >= 0 else {
            throw StoreAuthError.failure("AEA 读取偏移为负：\(offset)")
        }
        guard offset < size else {
            return Data()
        }

        let wanted = Int(min(Int64(count), size - offset))
        var output = Data(capacity: wanted)

        while output.count < wanted {
            let absolute = offset + Int64(output.count)
            let index = Int(absolute / Int64(segmentSize))
            guard index < segments.count else {
                throw StoreAuthError.failure("AEA 段索引不完整")
            }

            let segment = segments[index]
            guard segment.decompressedSize > 0 else {
                throw StoreAuthError.failure("AEA 段 \(index) 缺失")
            }

            let decoded = try decodeSegment(index: index, segment: segment)
            let inside = Int(absolute - segment.outputOffset)
            guard inside >= 0, inside < decoded.count else {
                throw StoreAuthError.failure("AEA 段 \(index) 的输出偏移无效")
            }

            let take = min(wanted - output.count, decoded.count - inside)
            output.append(decoded.subdata(in: inside..<(inside + take)))
        }

        return output
    }

    // MARK: - Cluster 索引

    private func indexClusters(clusterOffset: Int64,
                               clusterMAC: Data,
                               fileSize: UInt64,
                               segmentsPerCluster: UInt32,
                               sourceSize: Int64) throws {
        let headerSize = Int64(AEACryptex.segmentHeaderSize) * Int64(segmentsPerCluster)
            + 32 + 32 * Int64(segmentsPerCluster)
        let encryptedHeadersSize = AEACryptex.segmentHeaderSize * Int(segmentsPerCluster)

        var offset = clusterOffset
        var currentMAC = clusterMAC
        var clusterIndex: UInt32 = 0
        var outputSize: UInt64 = 0

        while outputSize < fileSize {
            guard offset >= 0, headerSize <= sourceSize - offset else {
                throw StoreAuthError.failure("AEA cluster \(clusterIndex) 头部超出镜像范围")
            }

            let headerData = try source.readExact(at: offset, count: Int(headerSize))

            var clusterKeyInfo = Data(AEACryptex.clusterKeyInfo.utf8)
            clusterKeyInfo.append(contentsOf: AEACryptex.littleEndian32(clusterIndex))
            let clusterKey = try AEACryptex.deriveKey(secret: mainKey, salt: Data(),
                                                      info: clusterKeyInfo, count: mainKey.count)
            let clusterHeaderKey = try AEACryptex.deriveHeaderKey(
                clusterKey, info: Data(AEACryptex.clusterHeaderKeyInfo.utf8)
            )

            let encryptedHeaders = headerData.slice(at: 0, count: encryptedHeadersSize)
            let nextClusterMAC = headerData.slice(at: encryptedHeadersSize, count: 32)
            let segmentMACData = headerData.slice(at: encryptedHeadersSize + 32,
                                                  count: headerData.count - encryptedHeadersSize - 32)

            var hmacSalt = nextClusterMAC
            hmacSalt.append(segmentMACData)
            let computedMAC = AEACryptex.calculateMAC(key: clusterHeaderKey.mac,
                                                      data: encryptedHeaders, salt: hmacSalt)
            guard computedMAC == currentMAC else {
                throw StoreAuthError.failure("AEA cluster \(clusterIndex) 认证失败")
            }

            let decryptedHeaders = try AssetCrypto.aesCTR(encryptedHeaders,
                                                          key: clusterHeaderKey.key,
                                                          iv: clusterHeaderKey.iv)
            var dataOffset = offset + headerSize

            for segmentIndex in 0..<Int(segmentsPerCluster) {
                let start = segmentIndex * AEACryptex.segmentHeaderSize
                let decompressedSize = decryptedHeaders.uint32LE(at: start)
                let compressedSize = decryptedHeaders.uint32LE(at: start + 4)
                let segmentChecksum = decryptedHeaders.slice(at: start + 8, count: 32)

                if decompressedSize == 0 {
                    guard compressedSize == 0 else {
                        throw StoreAuthError.failure("AEA cluster \(clusterIndex) 段 \(segmentIndex) 有压缩数据但无输出")
                    }
                    continue
                }
                guard decompressedSize <= segmentSize, compressedSize > 0 else {
                    throw StoreAuthError.failure("AEA cluster \(clusterIndex) 段 \(segmentIndex) 尺寸无效")
                }
                guard Int64(compressedSize) <= sourceSize - dataOffset else {
                    throw StoreAuthError.failure("AEA cluster \(clusterIndex) 段 \(segmentIndex) 超出镜像范围")
                }

                let segmentMAC = segmentMACData.slice(at: segmentIndex * 32, count: 32)
                let globalIndex = UInt64(clusterIndex) * UInt64(segmentsPerCluster) + UInt64(segmentIndex)
                guard globalIndex < UInt64(segments.count) else {
                    throw StoreAuthError.failure("AEA cluster \(clusterIndex) 段 \(segmentIndex) 超出声明的输出")
                }

                let outputOffset = Int64(globalIndex * UInt64(segmentSize))
                guard UInt64(outputOffset) + UInt64(decompressedSize) <= fileSize else {
                    throw StoreAuthError.failure("AEA cluster \(clusterIndex) 段 \(segmentIndex) 超出输出尺寸")
                }

                segments[Int(globalIndex)] = Segment(
                    inputOffset: dataOffset,
                    outputOffset: outputOffset,
                    compressedSize: compressedSize,
                    decompressedSize: decompressedSize,
                    checksum: segmentChecksum,
                    mac: segmentMAC,
                    cluster: clusterIndex,
                    index: UInt32(segmentIndex)
                )

                dataOffset += Int64(compressedSize)
                outputSize += UInt64(decompressedSize)
                guard outputSize <= fileSize else {
                    throw StoreAuthError.failure("AEA 段数据超出声明的输出尺寸")
                }
            }

            offset = dataOffset
            currentMAC = nextClusterMAC
            clusterIndex += 1
        }

        guard outputSize == fileSize else {
            throw StoreAuthError.failure("AEA 段数据为 \(outputSize) 字节，期望 \(fileSize)")
        }
    }

    // MARK: - 段解码

    private func decodeSegment(index: Int, segment: Segment) throws -> Data {
        cacheLock.lock()
        defer { cacheLock.unlock() }

        if let cached = cache[index] {
            return cached
        }

        let encrypted = try source.readExact(at: segment.inputOffset, count: Int(segment.compressedSize))

        var clusterKeyInfo = Data(AEACryptex.clusterKeyInfo.utf8)
        clusterKeyInfo.append(contentsOf: AEACryptex.littleEndian32(segment.cluster))
        let clusterKey = try AEACryptex.deriveKey(secret: mainKey, salt: Data(),
                                                  info: clusterKeyInfo, count: mainKey.count)

        var segmentKeyInfo = Data(AEACryptex.segmentKeyInfo.utf8)
        segmentKeyInfo.append(contentsOf: AEACryptex.littleEndian32(segment.index))
        let segmentKey = try AEACryptex.deriveHeaderKey(clusterKey, info: segmentKeyInfo)

        let computedMAC = AEACryptex.calculateMAC(key: segmentKey.mac, data: encrypted, salt: Data())
        guard computedMAC == segment.mac else {
            throw StoreAuthError.failure("AEA cluster \(segment.cluster) 段 \(segment.index) 认证失败")
        }

        let compressed = try AssetCrypto.aesCTR(encrypted, key: segmentKey.key, iv: segmentKey.iv)

        let decoded: Data
        if segment.compressedSize == segment.decompressedSize {
            decoded = compressed
        } else {
            decoded = try CompressionCodecs.lzfse(compressed, expectedSize: Int(segment.decompressedSize))
            guard decoded.count == Int(segment.decompressedSize) else {
                throw StoreAuthError.failure(
                    "AEA cluster \(segment.cluster) 段 \(segment.index) 解压得到 \(decoded.count) 字节，期望 \(segment.decompressedSize)"
                )
            }
        }

        guard AssetCrypto.sha256(decoded) == segment.checksum else {
            throw StoreAuthError.failure("AEA cluster \(segment.cluster) 段 \(segment.index) 校验和不匹配")
        }

        if cacheOrder.count == AEACryptex.cacheLimit {
            cache.removeValue(forKey: cacheOrder[0])
            cacheOrder.removeFirst()
        }
        cache[index] = decoded
        cacheOrder.append(index)

        return decoded
    }

    // MARK: - 密钥派生

    private static func deriveKey(secret: Data, salt: Data, info: Data, count: Int) throws -> Data {
        let prk = AssetCrypto.hkdfExtract(salt: salt, ikm: secret)
        return try expand(prk: prk, info: info, count: count)
    }

    private static func expand(prk: Data, info: Data, count: Int) throws -> Data {
        guard count > 0, count <= 0xFF * 32 else {
            throw StoreAuthError.failure("AEA 密钥长度无效：\(count)")
        }

        return AssetCrypto.hkdfExpand(prk: prk, info: info, count: count)
    }

    private static func deriveHeaderKey(_ key: Data, info: Data) throws -> HeaderKey {
        let derived = try deriveKey(secret: key, salt: Data(), info: info, count: headerKeySize)
        return HeaderKey(
            mac: derived.slice(at: 0, count: 32),
            key: derived.slice(at: 32, count: 32),
            iv: derived.slice(at: 64, count: 16)
        )
    }

    private static func calculateMAC(key: Data, data: Data, salt: Data) -> Data {
        var input = salt
        input.append(data)
        input.append(contentsOf: littleEndian64(UInt64(salt.count)))
        return AssetCrypto.hmacSHA256(key: key, data: input)
    }

    private static func littleEndian32(_ value: UInt32) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF),
         UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)]
    }

    private static func littleEndian64(_ value: UInt64) -> [UInt8] {
        (0..<8).map { UInt8((value >> (8 * UInt64($0))) & 0xFF) }
    }

    // MARK: - 元数据与 FCS 密钥

    private static func parseMetadata(_ data: Data) throws -> [String: Data] {
        var metadata: [String: Data] = [:]
        var offset = 0

        while offset < data.count {
            let length = Int(data.uint32LE(at: offset))
            guard length >= 5, length - 4 <= data.count - offset - 4 else {
                throw StoreAuthError.failure("AEA 元数据记录长度无效：\(length)")
            }

            let record = data.slice(at: offset + 4, count: length - 4)
            guard let separator = record.firstIndex(of: 0), separator > record.startIndex else {
                throw StoreAuthError.failure("AEA 元数据记录格式无效")
            }

            let key = String(decoding: record[record.startIndex..<separator], as: UTF8.self)
            metadata[key] = Data(record[(separator + 1)...])
            offset += length
        }

        return metadata
    }

    private static func resolveSymmetricKey(metadata: [String: Data], session: URLSession) throws -> Data {
        guard let rawURL = metadata["com.apple.wkms.fcs-key-url"] else {
            throw StoreAuthError.failure("AEA 元数据缺少 FCS 密钥地址")
        }
        guard let keyURL = URL(string: String(decoding: rawURL, as: UTF8.self)),
              keyURL.scheme == "https", keyURL.host == "wkms-public.apple.com" else {
            throw StoreAuthError.failure("AEA FCS 密钥地址无效")
        }

        let pem = try fetch(url: keyURL, session: session)
        guard let scalar = try? AssetCrypto.p256PrivateScalar(pkcs8: decodePEM(pem)) else {
            throw StoreAuthError.failure("Apple FCS 私钥不是 P-256 私钥")
        }

        guard let rawResponse = metadata["com.apple.wkms.fcs-response"] else {
            throw StoreAuthError.failure("AEA 元数据缺少 FCS 响应")
        }
        guard let wrapped = try? JSONSerialization.jsonObject(with: rawResponse) as? [String: String],
              let encRequest = wrapped["enc-request"], let wrappedKey = wrapped["wrapped-key"],
              let encapsulation = Data(base64Encoded: encRequest),
              let ciphertext = Data(base64Encoded: wrappedKey) else {
            throw StoreAuthError.failure("AEA FCS 响应格式无效")
        }

        return try AssetCrypto.HPKE.openBaseP256(recipientPrivateKey: scalar,
                                                 encapsulation: encapsulation,
                                                 ciphertext: ciphertext)
    }

    private static func fetch(url: URL, session: URLSession) throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 120

        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Data, Error> = .failure(StoreAuthError.failure("FCS 密钥请求未完成"))

        let task = session.dataTask(with: request) { data, response, error in
            defer { semaphore.signal() }

            if let error {
                result = .failure(error)
                return
            }
            guard let http = response as? HTTPURLResponse else {
                result = .failure(StoreAuthError.failure("FCS 密钥服务器返回非 HTTP 响应"))
                return
            }
            guard http.statusCode == 200 else {
                result = .failure(StoreAuthError.failure("下载 FCS 密钥失败：HTTP \(http.statusCode)"))
                return
            }
            guard let data else {
                result = .failure(StoreAuthError.failure("FCS 密钥响应为空"))
                return
            }

            result = .success(data)
        }
        task.resume()
        semaphore.wait()

        let data = try result.get()
        guard data.count <= maxFCSKeySize else {
            throw StoreAuthError.failure("FCS 密钥响应过大")
        }

        return data
    }

    private static func decodePEM(_ data: Data) throws -> Data {
        let text = String(decoding: data, as: UTF8.self)
        let body = text
            .split(whereSeparator: \.isNewline)
            .filter { !$0.hasPrefix("-----") }
            .joined()

        guard let der = Data(base64Encoded: body) else {
            throw StoreAuthError.failure("Apple FCS 密钥不是 PEM 编码")
        }

        return der
    }
}
