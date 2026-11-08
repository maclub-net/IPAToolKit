import XCTest
@testable import IPAToolCore

final class StoreAuthTests: XCTestCase {
    private let goState = """
    {"Identifier":"AAECAwQFBgcICQoLDA0ODw==","Provisioning":null,"RoutingInfo":0}
    """

    func testDecodesGoPersistedState() throws {
        let state = try AnisetteState.decode(Data(goState.utf8))

        XCTAssertEqual(state.identifier, Data((0 ... 15).map { UInt8($0) }))
        XCTAssertNil(state.provisioning)
        XCTAssertEqual(state.routingInfo, 0)
    }

    func testEmptyStateGeneratesRandomIdentity() throws {
        let first = try AnisetteState.decode(nil)
        let second = try AnisetteState.decode(Data())

        XCTAssertEqual(first.identifier.count, 16)
        XCTAssertEqual(second.identifier.count, 16)
        XCTAssertNotEqual(first.identifier, second.identifier)
    }

    func testRejectsInvalidState() {
        let shortIdentifier = Data(#"{"Identifier":"AAECAwQ=","Provisioning":null,"RoutingInfo":0}"#.utf8)

        XCTAssertThrowsError(try AnisetteState.decode(shortIdentifier))
    }

    func testEncodesGoCompatibleKeys() throws {
        let state = AnisetteState(
            identifier: Data(repeating: 7, count: 16),
            provisioning: Data([9, 8, 7]),
            routingInfo: 17_166_426
        )

        let object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: state.encoded()) as? [String: Any]
        )

        XCTAssertEqual(object["Identifier"] as? String, "BwcHBwcHBwcHBwcHBwcHBw==")
        XCTAssertEqual(object["Provisioning"] as? String, "CQgH")
        XCTAssertEqual(object["RoutingInfo"] as? UInt64, 17_166_426)
    }

    func testIdentityHeadersMatchGoDerivation() {
        let state = AnisetteState(identifier: Data((0 ... 15).map { UInt8($0) }))
        let identity = state.identityHeaders()

        XCTAssertEqual(identity.deviceID, "00010203-0405-0607-0809-0a0b0c0d0e0f")
        XCTAssertEqual(identity.localUserID.count, 64)
        XCTAssertTrue(identity.localUserID.allSatisfy(\.isHexDigit))
    }

    func testAnisetteHeaders() {
        let state = AnisetteState(identifier: Data(repeating: 1, count: 16), routingInfo: 17_166_426)
        let headers = state.headers(otp: Data([1, 2]), mid: Data([3, 4]))

        XCTAssertEqual(headers["X-Apple-I-MD"], "AQI=")
        XCTAssertEqual(headers["X-Apple-I-MD-M"], "AwQ=")
        XCTAssertEqual(headers["X-Apple-I-MD-RINFO"], "17166426")
        XCTAssertEqual(headers["X-Apple-I-SRL-NO"], "0")
        XCTAssertEqual(headers["X-Apple-Locale"], "en_US")
        XCTAssertEqual(headers["X-MMe-Client-Info"], AnisetteState.clientInfo)
        XCTAssertEqual(headers["X-Mme-Device-Id"], state.identityHeaders().deviceID)
        XCTAssertEqual(headers["X-Apple-I-MD-LU"], state.identityHeaders().localUserID)
        XCTAssertNotNil(headers["X-Apple-I-Client-Time"])
    }

    func testHeaderValueValidation() {
        XCTAssertTrue(AnisetteState.isValidHeaderValue("0", limit: 8))
        XCTAssertFalse(AnisetteState.isValidHeaderValue("", limit: 8))
        XCTAssertFalse(AnisetteState.isValidHeaderValue("123456789", limit: 8))
        XCTAssertFalse(AnisetteState.isValidHeaderValue("line\nbreak", limit: 64))
    }
}
