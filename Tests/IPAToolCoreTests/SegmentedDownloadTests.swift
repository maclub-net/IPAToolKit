import Foundation
import XCTest
@testable import IPAToolCore

/// 用本地 URLProtocol 模拟支持 Range 的 CDN，验证分段下载的写入位置与完整性。
final class SegmentedDownloadTests: XCTestCase {
    private final class RangeURLProtocol: URLProtocol {
        static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?

        override class func canInit(with request: URLRequest) -> Bool { true }

        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

        override func startLoading() {
            guard let handler = Self.handler else {
                client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
                return
            }

            let (response, data) = handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        }

        override func stopLoading() {}
    }

    private final class ProgressRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [Double] = []

        func append(_ value: Double) {
            lock.lock()
            values.append(value)
            lock.unlock()
        }

        var all: [Double] {
            lock.lock()
            defer { lock.unlock() }

            return values
        }
    }

    private var session: URLSession!

    override func setUp() {
        super.setUp()

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RangeURLProtocol.self]
        session = URLSession(configuration: configuration)
    }

    override func tearDown() {
        session.invalidateAndCancel()
        session = nil
        RangeURLProtocol.handler = nil

        super.tearDown()
    }

    func testDownloadsAllChunksInParallel() async throws {
        let payload = Data((0..<(3 * 1024 * 1024 + 123_456)).map { UInt8($0 % 251) })
        RangeURLProtocol.handler = { request in
            Self.rangeResponse(for: request, payload: payload)
        }

        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("segmented-\(UUID().uuidString).bin")
        defer { try? FileManager.default.removeItem(at: destination) }

        let downloader = SegmentedDownloader(chunkSize: 1 << 20,
                                             minimumSize: 1 << 20,
                                             session: session)
        let recorder = ProgressRecorder()

        try await downloader.download(from: URL(string: "https://example.com/file")!,
                                      to: destination,
                                      concurrency: 3) { recorder.append($0) }

        let written = try Data(contentsOf: destination)

        XCTAssertEqual(written.count, payload.count)
        XCTAssertEqual(written, payload)
        XCTAssertEqual(recorder.all.last, 1.0)
    }

    func testFallsBackWhenServerIgnoresRange() async {
        let payload = Data(repeating: 0x7A, count: 2 << 20)
        RangeURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: "HTTP/1.1",
                                           headerFields: ["Content-Length": "\(payload.count)"])!
            return (response, payload)
        }

        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("segmented-\(UUID().uuidString).bin")
        defer { try? FileManager.default.removeItem(at: destination) }

        let downloader = SegmentedDownloader(chunkSize: 1 << 20,
                                             minimumSize: 1 << 20,
                                             session: session)

        do {
            try await downloader.download(from: URL(string: "https://example.com/file")!,
                                          to: destination,
                                          concurrency: 3) { _ in }
            XCTFail("服务器不支持 Range 时应抛出 rangeUnsupported")
        } catch SegmentedDownloader.DownloadError.rangeUnsupported {
            // 预期行为：调用方回退单连接。
        } catch {
            XCTFail("抛出了非预期错误: \(error)")
        }
    }

    private static func rangeResponse(for request: URLRequest, payload: Data) -> (HTTPURLResponse, Data) {
        let header = request.value(forHTTPHeaderField: "Range") ?? "bytes=0-\(payload.count - 1)"
        let bounds = header.replacingOccurrences(of: "bytes=", with: "").split(separator: "-")
        let start = Int(bounds.first ?? "0") ?? 0
        let end = min(Int(bounds.last ?? "0") ?? (payload.count - 1), payload.count - 1)

        let body = payload.subdata(in: start..<(end + 1))
        let response = HTTPURLResponse(url: request.url!,
                                       statusCode: 206,
                                       httpVersion: "HTTP/1.1",
                                       headerFields: [
                                           "Content-Length": "\(body.count)",
                                           "Content-Range": "bytes \(start)-\(end)/\(payload.count)",
                                           "Accept-Ranges": "bytes"
                                       ])!

        return (response, body)
    }
}
