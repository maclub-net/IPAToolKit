import XCTest
@testable import IPAToolCore

final class StoreEmulatorSmokeTests: XCTestCase {
    func testOpensPinnedStoreRuntime() throws {
        guard ProcessInfo.processInfo.environment["IPATOOL_STORE_AMD_SMOKE"] == "1" else {
            throw XCTSkip("set IPATOOL_STORE_AMD_SMOKE=1 to run the Store emulator smoke test")
        }

        let assets = try StoreProfileAssets.load()
        let defaultImage = NSString(
            string: "~/Library/Caches/ipatool/sap/apple-assets-macos-27-26A434-arm64-v4/AppleMediaServices"
        ).expandingTildeInPath
        let path = ProcessInfo.processInfo.environment["IPATOOL_STORE_IMAGE"] ?? defaultImage
        let image = [UInt8](try Data(contentsOf: URL(fileURLWithPath: path)))

        let runtime = try StoreRuntime.open(imageData: image, prepared: assets)
        defer { try? runtime.close() }

        let url = try runtime.newObject(
            "NSURL",
            .string("https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/")
        )
        let request = try runtime.invoke(runtime.classAddress("NSURLRequest"), "requestWithURL:", [url])

        XCTAssertNotEqual(request, 0)
    }
}
