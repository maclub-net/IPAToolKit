import Foundation

/// UDIF (koly) 磁盘映像的只读解析，对应 Go 侧 `go-apfs/pkg/disk/dmg`。
///
/// IPSW 里的 `*.dmg.aea` 解密后是 UDIF 映像：末尾 512 字节是 koly 尾表，
/// 尾表指向一个 plist 资源分支，其中 `blkx` 项的 `Data` 是 `mish` 块表，
/// 块表之后紧跟每个 chunk 的描述（逻辑扇区范围 + 压缩数据范围）。
final class UDIFDiskImage: RangeReadable {
    private static let footerSize = 512
    private static let blockHeaderSize = 204
    private static let chunkSize = 40
    private static let sectorSize: Int64 = 512
    private static let maximumChunkSize: Int64 = 64 << 20

    private static let zeroFill: UInt32 = 0x0000_0000
    private static let uncompressed: UInt32 = 0x0000_0001
    private static let ignored: UInt32 = 0x0000_0002
    private static let compressedADC: UInt32 = 0x8000_0004
    private static let compressedZlib: UInt32 = 0x8000_0005
    private static let compressedBzip2: UInt32 = 0x8000_0006
    private static let compressedLZFSE: UInt32 = 0x8000_0007
    private static let compressedLZMA: UInt32 = 0x8000_0008
    private static let comment: UInt32 = 0x7FFF_FFFE
    private static let lastBlock: UInt32 = 0xFFFF_FFFF

    private struct Chunk {
        let type: UInt32
        /// 在解码后映像中的绝对字节偏移。
        let diskOffset: Int64
        let diskLength: Int64
        /// 在 UDIF 文件中的绝对字节偏移。
        let compressedOffset: Int64
        let compressedLength: Int64
    }

    private struct Partition {
        let name: String
        let startSector: UInt64
        let sectorCount: UInt64
        let buffersNeeded: Int
        let chunks: [Chunk]
    }

    private let source: RangeReadable
    private let chunks: [Chunk]

    private let cacheLimit: Int
    private let cacheLock = NSLock()
    private var cache: [Int: Data] = [:]
    private var cacheOrder: [Int] = []

    let size: Int64

    init(source: RangeReadable) throws {
        self.source = source

        guard source.size >= Int64(UDIFDiskImage.footerSize) else {
            throw StoreAuthError.failure("磁盘映像过小：\(source.size)")
        }

        let footer = try source.readExact(at: source.size - Int64(UDIFDiskImage.footerSize),
                                          count: UDIFDiskImage.footerSize)
        guard String(decoding: footer.prefix(4), as: UTF8.self) == "koly" else {
            throw StoreAuthError.failure("磁盘映像缺少 UDIF 尾表")
        }
        guard footer.uint32BE(at: 4) == 4 else {
            throw StoreAuthError.failure("不支持的 UDIF 版本 \(footer.uint32BE(at: 4))")
        }

        let dataForkOffset = footer.uint64BE(at: 24)
        let dataForkLength = footer.uint64BE(at: 32)
        let plistOffset = footer.uint64BE(at: 216)
        let plistLength = footer.uint64BE(at: 224)
        let imageSectorCount = footer.uint64BE(at: 492)

        guard dataForkOffset <= UInt64(source.size), dataForkLength <= UInt64(source.size) - dataForkOffset else {
            throw StoreAuthError.failure("UDIF 数据分支范围越界")
        }
        guard plistOffset > 0, plistLength > 0,
              plistOffset <= UInt64(source.size), plistLength <= UInt64(source.size) - plistOffset,
              plistLength <= UInt64(Int.max) else {
            throw StoreAuthError.failure("UDIF plist 范围越界")
        }

        let plistData = try source.readExact(at: Int64(plistOffset), count: Int(plistLength))
        let partitions = try UDIFDiskImage.parsePartitions(
            plistData: plistData,
            dataForkOffset: dataForkOffset,
            dataForkLength: dataForkLength,
            imageSectorCount: imageSectorCount,
            sourceSize: source.size
        )

        guard let partition = UDIFDiskImage.selectPartition(partitions) else {
            throw StoreAuthError.failure("UDIF 中找不到可用的分区")
        }
        guard partition.sectorCount > 0,
              partition.sectorCount <= UInt64(Int64.max) / UInt64(UDIFDiskImage.sectorSize) else {
            throw StoreAuthError.failure("UDIF 分区尺寸无效")
        }

        chunks = partition.chunks
        size = Int64(partition.sectorCount) * UDIFDiskImage.sectorSize
        cacheLimit = max(min(partition.buffersNeeded, 16), 1)
    }

    // MARK: - RangeReadable

    func read(at offset: Int64, count: Int) throws -> Data {
        guard count > 0 else {
            return Data()
        }
        guard offset >= 0 else {
            throw StoreAuthError.failure("磁盘映像读取偏移为负：\(offset)")
        }
        guard offset < size else {
            return Data()
        }

        var output = Data(capacity: min(count, Int(size - offset)))
        var absolute = offset
        var remaining = Int(min(Int64(count), size - offset))
        var index = findChunkIndex(absolute)

        while remaining > 0 {
            guard index >= 0, index < chunks.count else {
                throw StoreAuthError.failure("磁盘映像在 offset \(absolute) 处出现空洞")
            }

            let chunk = chunks[index]
            guard absolute >= chunk.diskOffset, absolute - chunk.diskOffset < chunk.diskLength else {
                throw StoreAuthError.failure("磁盘映像在 offset \(absolute) 处出现空洞")
            }

            let diff = absolute - chunk.diskOffset
            if chunk.type == UDIFDiskImage.zeroFill || chunk.type == UDIFDiskImage.ignored {
                let take = Int(min(chunk.diskLength - diff, Int64(remaining)))
                output.append(Data(count: take))
                absolute += Int64(take)
                remaining -= take
                index += 1
                continue
            }

            let decoded = try chunkData(index: index, chunk: chunk)
            guard diff < Int64(decoded.count) else {
                throw StoreAuthError.failure("磁盘映像块 \(index) 的输出偏移无效")
            }

            let take = Int(min(Int64(remaining), Int64(decoded.count) - diff))
            output.append(decoded.subdata(in: Int(diff)..<(Int(diff) + take)))
            absolute += Int64(take)
            remaining -= take
            index += 1
        }

        return output
    }

    // MARK: - Chunk 解码

    private func chunkData(index: Int, chunk: Chunk) throws -> Data {
        cacheLock.lock()
        defer { cacheLock.unlock() }

        if let cached = cache[index] {
            return cached
        }

        guard chunk.compressedLength <= UDIFDiskImage.maximumChunkSize,
              chunk.diskLength <= UDIFDiskImage.maximumChunkSize,
              chunk.compressedLength <= Int64(Int.max),
              chunk.diskLength <= Int64(Int.max) else {
            throw StoreAuthError.failure("磁盘映像块 \(index) 尺寸过大")
        }

        let compressed = try source.readExact(at: chunk.compressedOffset, count: Int(chunk.compressedLength))
        let expected = Int(chunk.diskLength)
        let decoded: Data

        switch chunk.type {
        case UDIFDiskImage.uncompressed:
            guard chunk.compressedLength == chunk.diskLength else {
                throw StoreAuthError.failure("磁盘映像块 \(index) 的原始长度不一致")
            }
            decoded = compressed

        case UDIFDiskImage.compressedZlib:
            decoded = try CompressionCodecs.inflateZlib(compressed, expectedSize: expected)

        case UDIFDiskImage.compressedBzip2:
            decoded = try CompressionCodecs.bunzip2(compressed)

        case UDIFDiskImage.compressedLZFSE:
            decoded = try CompressionCodecs.lzfse(compressed, expectedSize: expected)

        case UDIFDiskImage.compressedADC, UDIFDiskImage.compressedLZMA:
            throw StoreAuthError.failure("磁盘映像块 \(index) 使用了尚未移植的压缩类型 \(String(format: "%#x", chunk.type))")

        default:
            throw StoreAuthError.failure("磁盘映像块 \(index) 使用了不支持的压缩类型 \(String(format: "%#x", chunk.type))")
        }

        guard decoded.count == expected else {
            throw StoreAuthError.failure("磁盘映像块 \(index) 解压得到 \(decoded.count) 字节，期望 \(expected)")
        }

        if cacheOrder.count == cacheLimit {
            cache.removeValue(forKey: cacheOrder[0])
            cacheOrder.removeFirst()
        }
        cache[index] = decoded
        cacheOrder.append(index)

        return decoded
    }

    private func findChunkIndex(_ offset: Int64) -> Int {
        var low = 0
        var high = chunks.count - 1

        while low <= high {
            let middle = (low + high) / 2
            let chunk = chunks[middle]
            if offset < chunk.diskOffset {
                high = middle - 1
            } else if offset - chunk.diskOffset >= chunk.diskLength {
                low = middle + 1
            } else {
                return middle
            }
        }

        return -1
    }

    // MARK: - 解析

    private static func parsePartitions(plistData: Data,
                                        dataForkOffset: UInt64,
                                        dataForkLength: UInt64,
                                        imageSectorCount: UInt64,
                                        sourceSize: Int64) throws -> [Partition] {
        let propertyList = try PropertyListSerialization.propertyList(
            from: plistData, options: [], format: nil
        )
        guard let root = propertyList as? [String: Any],
              let resourceFork = root["resource-fork"] as? [String: Any],
              let blocks = resourceFork["blkx"] as? [[String: Any]] else {
            throw StoreAuthError.failure("UDIF plist 缺少 resource-fork/blkx")
        }

        var partitions: [Partition] = []
        partitions.reserveCapacity(blocks.count)

        for block in blocks {
            let name = block["Name"] as? String ?? block["CFName"] as? String ?? ""
            guard let data = block["Data"] as? Data, data.count >= blockHeaderSize else {
                continue
            }
            guard String(decoding: data.prefix(4), as: UTF8.self) == "mish" else {
                throw StoreAuthError.failure("UDIF 块 \(name) 的 mish 头无效")
            }

            let startSector = data.uint64BE(at: 8)
            let sectorCount = data.uint64BE(at: 16)
            let blockDataOffset = data.uint64BE(at: 24)
            let buffersNeeded = Int(data.uint32BE(at: 32))
            let chunkCount = Int(data.uint32BE(at: 200))

            guard chunkCount >= 0, chunkCount <= (data.count - blockHeaderSize) / chunkSize,
                  blockDataOffset <= dataForkLength else {
                throw StoreAuthError.failure("UDIF 块 \(name) 的块表被截断")
            }
            guard startSector <= imageSectorCount, sectorCount <= imageSectorCount - startSector else {
                throw StoreAuthError.failure("UDIF 块 \(name) 的分区范围越界")
            }

            let forkRemaining = dataForkLength - blockDataOffset
            var chunks: [Chunk] = []
            chunks.reserveCapacity(chunkCount)
            var previousEnd: Int64 = 0

            for index in 0..<chunkCount {
                let base = blockHeaderSize + index * chunkSize
                let type = data.uint32BE(at: base)
                if type == comment || type == lastBlock {
                    continue
                }

                let diskOffset = data.uint64BE(at: base + 8)
                let diskLength = data.uint64BE(at: base + 16)
                let compressedOffset = data.uint64BE(at: base + 24)
                let compressedLength = data.uint64BE(at: base + 32)

                guard diskOffset <= sectorCount, diskLength <= sectorCount - diskOffset else {
                    throw StoreAuthError.failure("UDIF 块 \(name) 的 chunk 扇区范围越界")
                }

                let absoluteDiskOffset = (startSector + diskOffset) * UInt64(sectorSize)
                let absoluteDiskLength = diskLength * UInt64(sectorSize)
                guard absoluteDiskOffset <= UInt64(Int64.max),
                      absoluteDiskLength <= UInt64(Int64.max) else {
                    throw StoreAuthError.failure("UDIF 块 \(name) 的 chunk 尺寸溢出")
                }
                guard Int64(absoluteDiskOffset) >= previousEnd else {
                    throw StoreAuthError.failure("UDIF 块 \(name) 的 chunk 顺序错乱")
                }
                previousEnd = Int64(absoluteDiskOffset) + Int64(absoluteDiskLength)

                var absoluteCompressedOffset: Int64 = 0
                if type != zeroFill && type != ignored {
                    guard compressedOffset <= forkRemaining,
                          compressedLength <= forkRemaining - compressedOffset else {
                        throw StoreAuthError.failure("UDIF 块 \(name) 的 chunk 压缩范围越界")
                    }

                    let combined = dataForkOffset + blockDataOffset + compressedOffset
                    guard combined <= UInt64(sourceSize),
                          compressedLength <= UInt64(sourceSize) - combined else {
                        throw StoreAuthError.failure("UDIF 块 \(name) 的 chunk 超出映像范围")
                    }
                    absoluteCompressedOffset = Int64(combined)
                }

                chunks.append(Chunk(
                    type: type,
                    diskOffset: Int64(absoluteDiskOffset),
                    diskLength: Int64(absoluteDiskLength),
                    compressedOffset: absoluteCompressedOffset,
                    compressedLength: Int64(compressedLength)
                ))
            }

            partitions.append(Partition(
                name: name,
                startSector: startSector,
                sectorCount: sectorCount,
                buffersNeeded: buffersNeeded,
                chunks: chunks
            ))
        }

        return partitions
    }

    /// 与 Go 侧一致使用第一个分区；若 plist 里明确标出 APFS 分区则优先它。
    private static func selectPartition(_ partitions: [Partition]) -> Partition? {
        if let apfs = partitions.first(where: { $0.name.localizedCaseInsensitiveContains("APFS") }) {
            return apfs
        }

        return partitions.first
    }
}
