import Foundation

/// decmpfs 压缩文件读取器：资源分支前部是块偏移表，之后是 64 KiB 压缩块。
final class DecmpfsReader: RangeReadable {
    private static let blockSize = 64 << 10
    private static let cacheLimit = 128

    private let source: RangeReadable
    private let method: UInt32
    private let blockOffsets: [UInt32]

    private let cacheLock = NSLock()
    private var cache: [Int: Data] = [:]
    private var cacheOrder: [Int] = []

    let size: Int64

    init(source: RangeReadable, outputSize: UInt64, method: UInt32) throws {
        guard outputSize <= UInt64(Int64.max) else {
            throw StoreAuthError.failure("decmpfs 输出尺寸溢出")
        }
        guard source.size >= 0 else {
            throw StoreAuthError.failure("decmpfs 资源分支尺寸无效")
        }

        self.source = source
        self.method = method
        self.size = Int64(outputSize)

        guard outputSize > 0 else {
            self.blockOffsets = []
            return
        }

        let blockCount = (outputSize + UInt64(Self.blockSize) - 1) / UInt64(Self.blockSize)
        let tableSize = (blockCount + 1) * 4
        guard tableSize <= UInt64(Int.max), tableSize <= UInt64(source.size) else {
            throw StoreAuthError.failure("decmpfs 块表超出资源分支")
        }

        let table = try source.readExact(at: 0, count: Int(tableSize))
        var offsets: [UInt32] = []
        offsets.reserveCapacity(Int(blockCount) + 1)

        for index in 0...Int(blockCount) {
            offsets.append(table.uint32LE(at: index * 4))
        }

        for index in 0..<Int(blockCount) {
            guard UInt64(offsets[index]) >= tableSize,
                  UInt64(offsets[index]) <= UInt64(source.size),
                  offsets[index + 1] > offsets[index],
                  Int(offsets[index + 1] - offsets[index]) <= Self.blockSize + 1 else {
                throw StoreAuthError.failure("decmpfs 块表中第 \(index) 项无效")
            }
        }

        guard UInt64(offsets[Int(blockCount)]) == UInt64(source.size) else {
            throw StoreAuthError.failure("decmpfs 块表未覆盖整个资源分支")
        }

        self.blockOffsets = offsets
    }

    func read(at offset: Int64, count: Int) throws -> Data {
        guard count > 0 else {
            return Data()
        }
        guard offset >= 0 else {
            throw StoreAuthError.failure("decmpfs 读取偏移为负：\(offset)")
        }
        guard offset < size else {
            return Data()
        }

        var output = Data(capacity: min(count, Int(size - offset)))
        var absolute = offset
        var remaining = Int(min(Int64(count), size - offset))

        while remaining > 0 {
            let index = Int(absolute / Int64(Self.blockSize))
            guard index + 1 < blockOffsets.count else {
                throw StoreAuthError.failure("decmpfs 块索引缺失")
            }

            let decoded = try blockData(index: index)
            let blockStart = Int64(index) * Int64(Self.blockSize)
            let inside = Int(absolute - blockStart)
            guard inside >= 0, inside < decoded.count else {
                throw StoreAuthError.failure("decmpfs 块 \(index) 的输出偏移无效")
            }

            let take = min(remaining, decoded.count - inside)
            output.append(decoded.subdata(in: inside..<(inside + take)))
            absolute += Int64(take)
            remaining -= take
        }

        return output
    }

    private func blockData(index: Int) throws -> Data {
        cacheLock.lock()
        defer { cacheLock.unlock() }

        if let cached = cache[index] {
            return cached
        }

        let start = Int64(blockOffsets[index])
        let end = Int64(blockOffsets[index + 1])
        let block = try source.readExact(at: start, count: Int(end - start))
        let expected = Int(min(Int64(Self.blockSize), size - Int64(index) * Int64(Self.blockSize)))

        let decoded = try CompressionCodecs.decmpfsBlock(block, method: method, maximumSize: expected)
        guard decoded.count == expected else {
            throw StoreAuthError.failure(
                "decmpfs 块 \(index) 解压得到 \(decoded.count) 字节，期望 \(expected)"
            )
        }

        if cacheOrder.count == Self.cacheLimit {
            cache.removeValue(forKey: cacheOrder[0])
            cacheOrder.removeFirst()
        }
        cache[index] = decoded
        cacheOrder.append(index)

        return decoded
    }
}
