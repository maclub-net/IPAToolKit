import Foundation

/// 只读 ZIP 目录解析：支持 EOCD、zip64 与中央目录。
/// IPSW 超过 4 GB，必须处理 zip64 字段。
struct ZipArchive {
    struct Entry {
        let name: String
        let method: UInt16
        let compressedSize: Int64
        let uncompressedSize: Int64
        let localHeaderOffset: Int64
    }

    static let methodStore: UInt16 = 0
    static let methodDeflate: UInt16 = 8

    private static let eocdSignature: UInt32 = 0x0605_4B50
    private static let zip64LocatorSignature: UInt32 = 0x0706_4B50
    private static let zip64EndSignature: UInt32 = 0x0606_4B50
    private static let centralSignature: UInt32 = 0x0201_4B50
    private static let localSignature: UInt32 = 0x0403_4B50

    private let source: RangeReadable
    let entries: [String: Entry]

    init(source: RangeReadable) throws {
        self.source = source

        let tailSize = Int(min(source.size, 131_072))
        let tail = try source.readExact(at: source.size - Int64(tailSize), count: tailSize)
        guard let eocd = ZipArchive.findEndOfCentralDirectory(in: tail) else {
            throw StoreAuthError.failure("IPSW 中找不到 ZIP 目录结尾")
        }

        var entryCount = Int(tail.uint16LE(at: eocd + 10))
        var directorySize = Int64(tail.uint32LE(at: eocd + 12))
        var directoryOffset = Int64(tail.uint32LE(at: eocd + 16))

        if eocd >= 20, tail.uint32LE(at: eocd - 20) == ZipArchive.zip64LocatorSignature {
            let zip64Offset = Int64(tail.uint64LE(at: eocd - 20 + 8))
            let header = try source.readExact(at: zip64Offset, count: 56)
            guard header.uint32LE(at: 0) == ZipArchive.zip64EndSignature else {
                throw StoreAuthError.failure("IPSW 的 ZIP64 目录头无效")
            }
            entryCount = Int(header.uint64LE(at: 32))
            directorySize = Int64(header.uint64LE(at: 40))
            directoryOffset = Int64(header.uint64LE(at: 48))
        }

        guard entryCount > 0, entryCount < 1_000_000,
              directorySize > 0, directoryOffset >= 0,
              directoryOffset <= source.size, directorySize <= source.size - directoryOffset else {
            throw StoreAuthError.failure("IPSW 的 ZIP 中央目录范围无效")
        }

        let directory = try ZipArchive.readDirectory(source: source,
                                                    offset: directoryOffset,
                                                    size: directorySize)
        var parsed: [String: Entry] = [:]
        parsed.reserveCapacity(entryCount)

        var position = 0
        for _ in 0..<entryCount {
            guard position + 46 <= directory.count,
                  directory.uint32LE(at: position) == ZipArchive.centralSignature else {
                throw StoreAuthError.failure("IPSW 的 ZIP 中央目录条目无效")
            }

            let method = directory.uint16LE(at: position + 10)
            let compressed = Int64(directory.uint32LE(at: position + 20))
            let uncompressed = Int64(directory.uint32LE(at: position + 24))
            let nameLength = Int(directory.uint16LE(at: position + 28))
            let extraLength = Int(directory.uint16LE(at: position + 30))
            let commentLength = Int(directory.uint16LE(at: position + 32))
            var localOffset = Int64(directory.uint32LE(at: position + 42))
            var compressedSize = compressed
            var uncompressedSize = uncompressed

            guard position + 46 + nameLength + extraLength + commentLength <= directory.count else {
                throw StoreAuthError.failure("IPSW 的 ZIP 中央目录条目被截断")
            }

            let nameData = directory.subdata(in: (position + 46)..<(position + 46 + nameLength))
            let name = String(data: nameData, encoding: .utf8) ?? ""

            if compressed == 0xFFFF_FFFF || uncompressed == 0xFFFF_FFFF || localOffset == 0xFFFF_FFFF {
                let extraStart = position + 46 + nameLength
                let extra = directory.subdata(in: extraStart..<(extraStart + extraLength))
                var cursor = 0
                while cursor + 4 <= extra.count {
                    let identifier = extra.uint16LE(at: cursor)
                    let size = Int(extra.uint16LE(at: cursor + 2))
                    guard cursor + 4 + size <= extra.count else {
                        break
                    }

                    if identifier == 0x0001 {
                        var field = cursor + 4
                        let fieldEnd = field + size
                        if uncompressed == 0xFFFF_FFFF, field + 8 <= fieldEnd {
                            uncompressedSize = Int64(extra.uint64LE(at: field))
                            field += 8
                        }
                        if compressed == 0xFFFF_FFFF, field + 8 <= fieldEnd {
                            compressedSize = Int64(extra.uint64LE(at: field))
                            field += 8
                        }
                        if localOffset == 0xFFFF_FFFF, field + 8 <= fieldEnd {
                            localOffset = Int64(extra.uint64LE(at: field))
                        }
                    }

                    cursor += 4 + size
                }
            }

            parsed[name] = Entry(
                name: name,
                method: method,
                compressedSize: compressedSize,
                uncompressedSize: uncompressedSize,
                localHeaderOffset: localOffset
            )

            position += 46 + nameLength + extraLength + commentLength
        }

        entries = parsed
    }

    func entry(_ name: String) throws -> Entry {
        guard let entry = entries[name] else {
            throw StoreAuthError.failure("IPSW 中缺少成员 \(name)")
        }

        return entry
    }

    /// 校验成员的方法与大小与固定镜像一致。
    func pinnedEntry(_ name: String, compressedSize: Int64, uncompressedSize: Int64) throws -> Entry {
        let entry = try entry(name)
        let expectedMethod = compressedSize == uncompressedSize ? ZipArchive.methodStore : ZipArchive.methodDeflate

        guard entry.method == expectedMethod,
              entry.compressedSize == compressedSize,
              entry.uncompressedSize == uncompressedSize else {
            throw StoreAuthError.failure("IPSW 成员 \(name) 与固定镜像不一致")
        }

        return entry
    }

    /// 成员数据在 ZIP 文件中的起始偏移。
    func dataOffset(of entry: Entry) throws -> Int64 {
        guard entry.localHeaderOffset >= 0, entry.localHeaderOffset + 30 <= source.size else {
            throw StoreAuthError.failure("ZIP 成员 \(entry.name) 的本地头越界")
        }

        let header = try source.readExact(at: entry.localHeaderOffset, count: 30)
        guard header.uint32LE(at: 0) == ZipArchive.localSignature else {
            throw StoreAuthError.failure("ZIP 成员 \(entry.name) 的本地头无效")
        }

        let nameLength = Int64(header.uint16LE(at: 26))
        let extraLength = Int64(header.uint16LE(at: 28))
        let offset = entry.localHeaderOffset + 30 + nameLength + extraLength

        guard offset >= 0, offset <= source.size, entry.compressedSize <= source.size - offset else {
            throw StoreAuthError.failure("ZIP 成员 \(entry.name) 的数据越界")
        }

        return offset
    }

    /// 安装成员数据（仅支持 Store / Deflate）。
    func extract(_ entry: Entry, to destination: URL) throws {
        let offset = try dataOffset(of: entry)

        switch entry.method {
        case ZipArchive.methodStore:
            guard entry.compressedSize == entry.uncompressedSize else {
                throw StoreAuthError.failure("ZIP 成员 \(entry.name) 的 Store 大小不一致")
            }
            let reader = try SubRangeReader(base: source, offset: offset, length: entry.compressedSize)
            let handle = try FileHandle(forWritingTo: destination)
            defer { try? handle.close() }
            try reader.copy(to: handle, offset: 0, length: reader.size)

        case ZipArchive.methodDeflate:
            guard entry.uncompressedSize <= Int64(Int.max) else {
                throw StoreAuthError.failure("ZIP 成员 \(entry.name) 解压后过大")
            }
            let compressed = try source.readExact(at: offset, count: Int(entry.compressedSize))
            let data = try CompressionCodecs.inflateRaw(compressed, expectedSize: Int(entry.uncompressedSize))
            try data.write(to: destination, options: .atomic)

        default:
            throw StoreAuthError.failure("ZIP 成员 \(entry.name) 使用了不支持的压缩方法 \(entry.method)")
        }
    }

    // MARK: - 内部

    private static func findEndOfCentralDirectory(in tail: Data) -> Int? {
        guard tail.count >= 22 else {
            return nil
        }

        var index = tail.count - 22
        while index >= 0 {
            if tail.uint32LE(at: index) == eocdSignature {
                let commentLength = Int(tail.uint16LE(at: index + 20))
                if index + 22 + commentLength <= tail.count {
                    return index
                }
            }
            index -= 1
        }

        return nil
    }

    private static func readDirectory(source: RangeReadable, offset: Int64, size: Int64) throws -> Data {
        let chunkSize: Int64 = 4 << 20
        if size <= chunkSize {
            return try source.readExact(at: offset, count: Int(size))
        }

        var data = Data()
        data.reserveCapacity(Int(size))
        var position: Int64 = 0
        while position < size {
            let count = Int(min(chunkSize, size - position))
            data.append(try source.readExact(at: offset + position, count: count))
            position += Int64(count)
        }

        return data
    }
}
