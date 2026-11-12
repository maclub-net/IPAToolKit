import Foundation

/// 多连接 Range 下载器。
///
/// Apple 的 IPA 下载 URL 支持 HTTP Range，而 CDN 会按单连接限速；把文件切成固定大小
/// 的块、用多条连接并发拉取可以显著提升吞吐（实测单连接约 15 MB/s，6 连接约 80 MB/s）。
///
/// 服务器不支持 Range、文件过小或探测失败时抛出 `DownloadError.rangeUnsupported`，
/// 调用方应回退到单连接下载。
final class SegmentedDownloader {
    enum DownloadError: Error, LocalizedError {
        case rangeUnsupported
        case invalidResponse(String)
        case httpStatus(Int)
        case incomplete(expected: Int64, received: Int64)

        var errorDescription: String? {
            switch self {
            case .rangeUnsupported:
                return "服务器不支持分段下载"
            case .invalidResponse(let detail):
                return "分段下载响应异常：\(detail)"
            case .httpStatus(let status):
                return "分段下载失败：HTTP \(status)"
            case .incomplete(let expected, let received):
                return "分段下载不完整：期望 \(expected) 字节，实际 \(received) 字节"
            }
        }
    }

    private let session: URLSession
    private let chunkSize: Int64
    private let minimumSize: Int64
    private let maxAttempts = 3

    /// - Parameters:
    ///   - chunkSize: 单个请求的块大小，默认 8 MiB。
    ///   - minimumSize: 小于该大小直接回退单连接，默认 16 MiB。
    ///   - session: 仅测试时注入；正式使用内部创建。
    init(chunkSize: Int64 = 8 << 20, minimumSize: Int64 = 16 << 20, session: URLSession? = nil) {
        self.chunkSize = max(chunkSize, 1 << 20)
        self.minimumSize = max(minimumSize, 1 << 20)

        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.default
            configuration.httpShouldSetCookies = true
            configuration.httpCookieAcceptPolicy = .always
            configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            configuration.urlCache = nil
            configuration.timeoutIntervalForRequest = 30
            configuration.timeoutIntervalForResource = 3600
            self.session = URLSession(configuration: configuration)
        }
    }

    deinit {
        session.invalidateAndCancel()
    }

    /// 下载文件到 `destination`。进度回调为 0.0 ~ 1.0，可能来自后台线程。
    func download(from url: URL,
                  to destination: URL,
                  concurrency: Int,
                  progress: @escaping (Double) -> Void) async throws {
        let total = try await probe(url)

        guard total >= minimumSize else {
            throw DownloadError.rangeUnsupported
        }

        try prepare(destination: destination, size: total)

        let queue = ChunkQueue(total: total, chunkSize: chunkSize)
        let counter = ProgressCounter(total: total, progress: progress)
        let workerCount = max(1, min(concurrency, queue.count))

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<workerCount {
                group.addTask {
                    try await self.runWorker(url: url, destination: destination, queue: queue, counter: counter)
                }
            }

            try await group.waitForAll()
        }

        guard counter.received == total else {
            throw DownloadError.incomplete(expected: total, received: counter.received)
        }

        progress(1.0)
    }

    // MARK: - 探测

    private func probe(_ url: URL) async throws -> Int64 {
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("bytes=0-0", forHTTPHeaderField: "Range")

        let (_, response) = try await session.data(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 206,
              let contentRange = http.value(forHTTPHeaderField: "Content-Range"),
              let total = SegmentedDownloader.totalSize(from: contentRange),
              total > 0 else {
            throw DownloadError.rangeUnsupported
        }

        return total
    }

    // MARK: - 写盘

    private func prepare(destination: URL, size: Int64) throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(at: destination.deletingLastPathComponent(),
                                        withIntermediateDirectories: true)

        if fileManager.fileExists(atPath: destination.path) {
            try fileManager.removeItem(at: destination)
        }

        guard fileManager.createFile(atPath: destination.path, contents: nil) else {
            throw DownloadError.invalidResponse("无法创建目标文件")
        }

        let handle = try FileHandle(forWritingTo: destination)
        defer { try? handle.close() }

        // 预分配并占位，后续各 worker 按偏移写入。
        try handle.truncate(atOffset: UInt64(size))
    }

    // MARK: - Worker

    private func runWorker(url: URL,
                           destination: URL,
                           queue: ChunkQueue,
                           counter: ProgressCounter) async throws {
        let handle = try FileHandle(forWritingTo: destination)
        defer { try? handle.close() }

        while let chunk = queue.next() {
            try Task.checkCancellation()
            try await downloadChunk(url: url, chunk: chunk, handle: handle, counter: counter)
        }
    }

    private func downloadChunk(url: URL,
                               chunk: ChunkQueue.Chunk,
                               handle: FileHandle,
                               counter: ProgressCounter) async throws {
        var attempt = 0

        while true {
            attempt += 1

            do {
                try await perform(url: url, chunk: chunk, handle: handle, counter: counter)
                return
            } catch is CancellationError {
                throw CancellationError()
            } catch let DownloadError.httpStatus(status) where status == 401 || status == 403 {
                // 签名 URL 失效，重试没有意义。
                throw DownloadError.httpStatus(status)
            } catch DownloadError.incomplete {
                if attempt >= maxAttempts {
                    throw DownloadError.invalidResponse("分段重试次数已用尽")
                }

                try await Task.sleep(nanoseconds: UInt64(attempt) * 1_000_000_000)
            } catch {
                if attempt >= maxAttempts {
                    throw error
                }

                try await Task.sleep(nanoseconds: UInt64(attempt) * 1_000_000_000)
            }
        }
    }

    private func perform(url: URL,
                         chunk: ChunkQueue.Chunk,
                         handle: FileHandle,
                         counter: ProgressCounter) async throws {
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("bytes=\(chunk.start)-\(chunk.end)", forHTTPHeaderField: "Range")

        let (data, response) = try await session.data(for: request)

        guard let http = response as? HTTPURLResponse else {
            throw DownloadError.invalidResponse("缺少 HTTP 响应")
        }

        guard http.statusCode == 206 else {
            throw DownloadError.httpStatus(http.statusCode)
        }

        guard let contentRange = http.value(forHTTPHeaderField: "Content-Range"),
              SegmentedDownloader.rangeStart(from: contentRange) == chunk.start else {
            throw DownloadError.invalidResponse("Content-Range 与请求不一致")
        }

        let expected = chunk.end - chunk.start + 1
        guard Int64(data.count) == expected else {
            throw DownloadError.incomplete(expected: expected, received: Int64(data.count))
        }

        try handle.seek(toOffset: UInt64(chunk.start))
        try handle.write(contentsOf: data)

        counter.add(Int64(data.count))
    }

    // MARK: - 解析

    private static func totalSize(from contentRange: String) -> Int64? {
        guard let totalPart = contentRange.split(separator: "/").last,
              let total = Int64(totalPart.trimmingCharacters(in: .whitespaces)) else {
            return nil
        }

        return total
    }

    private static func rangeStart(from contentRange: String) -> Int64? {
        // 形如 "bytes 0-1048575/1670088184"
        let parts = contentRange.split(separator: " ", maxSplits: 1)
        guard parts.count == 2 else { return nil }

        let bounds = parts[1].split(separator: "/").first ?? ""
        let startText = bounds.split(separator: "-").first ?? ""

        return Int64(startText)
    }
}

// MARK: - 分块队列

private final class ChunkQueue {
    struct Chunk {
        let start: Int64
        let end: Int64
    }

    private let lock = NSLock()
    private var index = 0
    private let chunks: [Chunk]

    init(total: Int64, chunkSize: Int64) {
        var built: [Chunk] = []
        var start: Int64 = 0

        while start < total {
            let end = min(start + chunkSize, total) - 1
            built.append(Chunk(start: start, end: end))
            start = end + 1
        }

        self.chunks = built
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }

        return chunks.count
    }

    func next() -> Chunk? {
        lock.lock()
        defer { lock.unlock() }

        guard index < chunks.count else { return nil }

        let chunk = chunks[index]
        index += 1

        return chunk
    }
}

// MARK: - 进度

private final class ProgressCounter {
    private let lock = NSLock()
    private let total: Int64
    private let progress: (Double) -> Void
    private var written: Int64 = 0
    private var lastReport = Date.distantPast

    init(total: Int64, progress: @escaping (Double) -> Void) {
        self.total = total
        self.progress = progress
    }

    var received: Int64 {
        lock.lock()
        defer { lock.unlock() }

        return written
    }

    func add(_ bytes: Int64) {
        lock.lock()
        written += bytes
        let snapshot = written
        let now = Date()
        let shouldReport = now.timeIntervalSince(lastReport) >= 0.1 || snapshot >= total
        if shouldReport {
            lastReport = now
        }
        lock.unlock()

        if shouldReport, total > 0 {
            progress(min(1.0, Double(snapshot) / Double(total)))
        }
    }
}
