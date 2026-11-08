import XCTest
@testable import IPAToolCore

final class StoreAMDLiveTests: XCTestCase {
    func testProvisionsMachineIdentity() async throws {
        guard ProcessInfo.processInfo.environment["IPATOOL_ANISETTE_PROVISION"] == "1" else {
            throw XCTSkip("set IPATOOL_ANISETTE_PROVISION=1 to provision against Apple")
        }

        let result = try await AnisetteProvisioner.headers(state: nil)
        let state = try AnisetteState.decode(result.state)

        print("Provisioned routing info: \(state.routingInfo)")
        XCTAssertNotNil(result.headers["X-Apple-I-MD"])
        XCTAssertNotNil(result.headers["X-Apple-I-MD-M"])
        XCTAssertFalse(state.provisioning?.isEmpty ?? true)
        XCTAssertNotEqual(state.routingInfo, 0)
    }

    func testGeneratesHeadersFromProvisionedState() throws {
        guard let path = ProcessInfo.processInfo.environment["IPATOOL_ANISETTE_STATE_FILE"] else {
            throw XCTSkip("set IPATOOL_ANISETTE_STATE_FILE to a provisioned anisette state")
        }

        let state = try Data(contentsOf: URL(fileURLWithPath: path))
        let identity = try currentMachineIdentity()
        let endpoint = "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=\(identity.guid)"

        let proof = try StoreAMD.headers(
            state: state,
            endpoint: endpoint,
            hardwareID: identity.hardwareID
        )

        print("Store AMD headers: \(proof.headers.keys.sorted())")
        XCTAssertFalse(proof.headers.isEmpty)
        XCTAssertNotNil(proof.headers["X-Apple-AMD"])
        XCTAssertNotNil(proof.headers["X-Apple-AMD-M"])
        XCTAssertFalse(try AnisetteState.decode(proof.state).provisioning?.isEmpty ?? true)
    }
}
