import XCTest
@testable import IPAToolCore

final class StoreAuthenticationTests: XCTestCase {
    private func url(_ string: String) -> URL {
        guard let url = URL(string: string) else {
            fatalError("invalid test URL: \(string)")
        }

        return url
    }

    func testRecognizesOnlyNativeAuthenticationEndpoints() {
        for path in ["/auth/v1/native", "/auth/v1/native/", "/auth/v1/native/fast", "/auth/v1/native/fast/"] {
            XCTAssertTrue(
                StoreAuthenticationEndpoint.isNative(url("https://auth.itunes.apple.com" + path)),
                path
            )
        }

        for string in [
            "http://auth.itunes.apple.com/auth/v1/native",
            "https://auth.itunes.apple.com.example.invalid/auth/v1/native",
            "https://auth.itunes.apple.com:8443/auth/v1/native",
            "https://auth.itunes.apple.com/auth/v1/native%2ffast",
            "https://auth.itunes.apple.com/auth/v1/native/other",
            "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/",
        ] {
            XCTAssertFalse(StoreAuthenticationEndpoint.isNative(url(string)), string)
        }
    }

    func testAllowsOnlyAppStoreAuthenticationHosts() {
        XCTAssertTrue(
            StoreAuthenticationEndpoint.isAllowed(
                url("https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/")
            )
        )
        XCTAssertTrue(StoreAuthenticationEndpoint.isAllowed(url("https://p69-buy.itunes.apple.com/authenticate")))
        XCTAssertTrue(StoreAuthenticationEndpoint.isAllowed(url("https://auth.itunes.apple.com/auth/v1/native")))

        for string in [
            "https://example.invalid/authenticate",
            "https://buy.itunes.apple.com.example.invalid/authenticate",
            "https://buy.itunes.apple.com@example.invalid/authenticate",
            "https://pbuy.itunes.apple.com/authenticate",
            "http://buy.itunes.apple.com/authenticate",
            "https://auth.itunes.apple.com/auth/v1/native/other",
        ] {
            XCTAssertFalse(StoreAuthenticationEndpoint.isAllowed(url(string)), string)
        }
    }

    func testStoreAMDHeadersAreAllOrNothing() {
        let headers = StoreAuthenticationEndpoint.storeAMDHeaders(
            for: url("https://auth.itunes.apple.com/auth/v1/native")
        )

        if headers.isEmpty {
            return
        }

        XCTAssertNotNil(headers["X-Apple-AMD"])
        XCTAssertNotNil(headers["X-Apple-AMD-M"])
    }
}
