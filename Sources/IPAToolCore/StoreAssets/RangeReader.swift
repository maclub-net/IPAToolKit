import Foundation

/// 随机读取接口，对应 Go 侧的 `io.ReaderAt`。
protocol RangeReadable: AnyObject {
    var size: Int64 { get }

    /// 读取 `count` 字节；越过末尾时返回较短的数据。
    func read(at offset: Int64, count: Int) throws -> Data
}

extension RangeReadable {
    /// 严格读取，长度不足即报错（格式解析默认使用这个）。
    func readExact(at offset: Int64, count: Int) throws -> Data {
        let data = try read(at: offset, count: count)
        guard data.count == count else {
            throw StoreAuthError.failure("读取数据不完整：offset \(offset) 需要 \(count) 字节，实际 \(data.count)")
        }
        return data
    }

    /// 分块顺序读取整个区间，避免一次性申请过大内存。
    func copy(to handle: FileHandle, offset: Int64, length: Int64, chunkSize: Int = 1 << 20) throws {
        guard length >= 0, offset >= 0, offset <= size, length <= size - offset else {
            throw StoreAuthError.failure("读取区间越界：offset \(offset) length \(length)")
        }

        var position: Int64 = 0
        while position < length {
            let count = Int(min(Int64(chunkSize), length - position))
            let data = try readExact(at: offset + position, count: count)
            try handle.write(contentsOf: data)
            position += Int64(count)
        }
    }
}

// MARK: - 内存

final class MemoryRangeReader: RangeReadable {
    private let data: Data

    var size: Int64 { Int64(data.count) }

    init(_ data: Data) {
        self.data = data
    }

    func read(at offset: Int64, count: Int) throws -> Data {
        guard count > 0 else {
            return Data()
        }
        guard offset >= 0, offset < size else {
            return Data()
        }

        let start = Int(offset)
        let length = Int(min(Int64(count), size - offset))
        return data.subdata(in: start..<(start + length))
    }
}

// MARK: - 区间切片

final class SubRangeReader: RangeReadable {
    private let base: RangeReadable
    private let offset: Int64
    let size: Int64

    init(base: RangeReadable, offset: Int64, length: Int64) throws {
        guard offset >= 0, length >= 0, offset <= base.size, length <= base.size - offset else {
            throw StoreAuthError.failure("区间超出底层数据：offset \(offset) length \(length)")
        }

        self.base = base
        self.offset = offset
        self.size = length
    }

    func read(at offset: Int64, count: Int) throws -> Data {
        guard offset >= 0, offset < size else {
            return Data()
        }

        let length = Int(min(Int64(count), size - offset))
        return try base.read(at: self.offset + offset, count: length)
    }
}

// MARK: - 本地文件

final class FileRangeReader: RangeReadable {
    private let handle: FileHandle
    private let lock = NSLock()
    let size: Int64

    init(url: URL) throws {
        handle = try FileHandle(forReadingFrom: url)
        size = Int64(try handle.seekToEnd())
        try handle.seek(toOffset: 0)
    }

    deinit {
        try? handle.close()
    }

    func read(at offset: Int64, count: Int) throws -> Data {
        guard count > 0 else {
            return Data()
        }
        guard offset >= 0, offset < size else {
            return Data()
        }

        let length = Int(min(Int64(count), size - offset))
        lock.lock()
        defer { lock.unlock() }
        try handle.seek(toOffset: UInt64(offset))
        return try handle.read(upToCount: length) ?? Data()
    }
}

// MARK: - HTTP Range

/// 通过 HTTP Range 读取远端文件，行为对齐 Go 侧 `remoteFile`：
/// 固定 3 次尝试、校验 `Content-Range`、禁止服务器忽略 Range 返回整包。
final class RemoteRangeReader: RangeReadable {
    private static let attempts = 3

    private let url: URL
    private let session: URLSession
    private let timeout: TimeInterval
    let size: Int64

    init(url: URL, session: URLSession = .shared, timeout: TimeInterval = 120) throws {
        self.url = url
        self.session = session
        self.timeout = timeout

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("bytes=0-0", forHTTPHeaderField: "Range")
        request.timeoutInterval = timeout

        let (_, response) = try RemoteRangeReader.perform(session: session, request: request)
        guard let http = response as? HTTPURLResponse else {
            throw StoreAuthError.failure("IPSW 服务器返回非 HTTP 响应")
        }
        guard http.statusCode == 206 else {
            throw StoreAuthError.failure("IPSW 服务器不支持 Range：HTTP \(http.statusCode)")
        }
        guard let raw = http.value(forHTTPHeaderField: "Content-Range"),
              let range = ContentRange(raw), range.start == 0, range.end == 0 else {
            throw StoreAuthError.failure("IPSW 服务器返回了无法识别的 Content-Range")
        }

        size = range.total
    }

    func read(at offset: Int64, count: Int) throws -> Data {
        guard count > 0 else {
            return Data()
        }
        guard offset >= 0 else {
            throw StoreAuthError.failure("IPSW 读取偏移为负：\(offset)")
        }
        guard offset < size else {
            return Data()
        }

        let wanted = Int(min(Int64(count), size - offset))
        var output = Data(capacity: wanted)
        var lastError: Error?

        for _ in 0..<Self.attempts where output.count < wanted {
            let start = offset + Int64(output.count)
            let end = offset + Int64(wanted) - 1

            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            request.setValue("bytes=\(start)-\(end)", forHTTPHeaderField: "Range")
            request.timeoutInterval = timeout

            do {
                let (data, response) = try Self.perform(session: session, request: request)
                guard let http = response as? HTTPURLResponse else {
                    throw StoreAuthError.failure("IPSW 服务器返回非 HTTP 响应")
                }
                guard http.statusCode == 206 else {
                    throw StoreAuthError.failure("IPSW 区间请求返回 HTTP \(http.statusCode)")
                }
                guard let raw = http.value(forHTTPHeaderField: "Content-Range"),
                      let range = ContentRange(raw),
                      range.start == start, range.end == end, range.total == size else {
                    throw StoreAuthError.failure("IPSW 服务器返回了不匹配的区间")
                }

                let remaining = wanted - output.count
                output.append(data.prefix(remaining))
            } catch {
                lastError = error
            }
        }

        guard output.count == wanted else {
            let reason = lastError.map { "：\($0.localizedDescription)" } ?? ""
            throw StoreAuthError.failure("IPSW 读取中断于 offset \(offset + Int64(output.count))\(reason)")
        }

        return output
    }

    private static func perform(session: URLSession, request: URLRequest) throws -> (Data, URLResponse) {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<(Data, URLResponse), Error> =
            .failure(StoreAuthError.failure("IPSW 请求未完成"))

        let task = session.dataTask(with: request) { data, response, error in
            if let error {
                result = .failure(error)
            } else if let data, let response {
                result = .success((data, response))
            } else {
                result = .failure(StoreAuthError.failure("IPSW 响应为空"))
            }
            semaphore.signal()
        }
        task.resume()
        semaphore.wait()

        return try result.get()
    }
}

// MARK: - Content-Range

struct ContentRange {
    let start: Int64
    let end: Int64
    let total: Int64

    init?(_ value: String) {
        guard value.hasPrefix("bytes ") else {
            return nil
        }

        let parts = value.dropFirst(6).split(separator: "/")
        guard parts.count == 2,
              let total = Int64(parts[1]), total > 0 else {
            return nil
        }

        let bounds = parts[0].split(separator: "-")
        guard bounds.count == 2,
              let start = Int64(bounds[0]),
              let end = Int64(bounds[1]),
              start >= 0, end >= start, end < total else {
            return nil
        }

        self.start = start
        self.end = end
        self.total = total
    }
}

// MARK: - 二进制读取辅助

/// 越界读取返回 0，由调用方通过 magic / size 校验发现异常。
extension Data {
    func byte(at offset: Int) -> UInt8 {
        guard offset >= 0, offset < count else {
            return 0
        }

        return withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt8.self) }
    }

    func uint16LE(at offset: Int) -> UInt16 {
        guard offset >= 0, offset + 2 <= count else {
            return 0
        }

        return withUnsafeBytes { UInt16(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt16.self)) }
    }

    func uint32LE(at offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= count else {
            return 0
        }

        return withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)) }
    }

    func uint64LE(at offset: Int) -> UInt64 {
        guard offset >= 0, offset + 8 <= count else {
            return 0
        }

        return withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self)) }
    }

    func uint32BE(at offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= count else {
            return 0
        }

        return withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)) }
    }

    func uint64BE(at offset: Int) -> UInt64 {
        guard offset >= 0, offset + 8 <= count else {
            return 0
        }

        return withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self)) }
    }

    func slice(at offset: Int, count length: Int) -> Data {
        guard offset >= 0, length >= 0, offset <= count else {
            return Data()
        }

        let end = Swift.min(self.count, offset + length)
        return subdata(in: offset..<end)
    }

    func nullTerminatedString(at offset: Int, maxLength: Int) -> String? {
        guard offset >= 0, offset < count else {
            return nil
        }

        let end = Swift.min(count, offset + maxLength)
        var index = offset
        while index < end {
            if self[index] == 0 {
                return String(data: subdata(in: offset..<index), encoding: .utf8)
            }
            index += 1
        }

        return nil
    }
}
