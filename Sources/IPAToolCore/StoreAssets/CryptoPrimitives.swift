import CommonCrypto
import CryptoKit
import Foundation

/// AEA 需要的密码学原语：SHA-256、HMAC、HKDF、AES-CTR、HPKE(base) 与 PKCS#8 解析。
enum AssetCrypto {
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func sha256Hex(_ data: Data) -> String {
        sha256(data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - HMAC / HKDF

    static func hmacSHA256(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
    }

    static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        let effectiveSalt = salt.isEmpty ? Data(repeating: 0, count: 32) : salt
        return hmacSHA256(key: effectiveSalt, data: ikm)
    }

    static func hkdfExpand(prk: Data, info: Data, count: Int) -> Data {
        var output = Data()
        var previous = Data()
        var counter: UInt8 = 1

        while output.count < count {
            var input = previous
            input.append(info)
            input.append(counter)
            previous = hmacSHA256(key: prk, data: input)
            output.append(previous)
            counter = counter &+ 1
        }

        return output.prefix(count)
    }

    // MARK: - AES-CTR

    /// JSON 里的 AES-CTR 使用大端计数器，与 Go 的 `cipher.NewCTR` 一致。
    static func aesCTR(_ data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == 16 || key.count == 32, iv.count == 16 else {
            throw StoreAuthError.failure("AES-CTR 的 key 或 iv 长度无效")
        }
        guard !data.isEmpty else {
            return Data()
        }

        var cryptor: CCCryptorRef?
        let created = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBytes.baseAddress,
                    keyBytes.baseAddress,
                    key.count,
                    nil, 0, 0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
        guard created == kCCSuccess, let cryptor else {
            throw StoreAuthError.failure("AES-CTR 初始化失败：\(created)")
        }
        defer { CCCryptorRelease(cryptor) }

        var output = Data(count: data.count)
        var moved = 0
        let updated = data.withUnsafeBytes { input in
            output.withUnsafeMutableBytes { destination in
                CCCryptorUpdate(cryptor, input.baseAddress, data.count,
                                destination.baseAddress, data.count, &moved)
            }
        }
        guard updated == kCCSuccess, moved == data.count else {
            throw StoreAuthError.failure("AES-CTR 解密失败：\(updated)")
        }

        return output
    }

    // MARK: - AES-GCM

    static func aesGCMOpen(key: Data, nonce: Data, ciphertext: Data) throws -> Data {
        guard ciphertext.count >= 16 else {
            throw StoreAuthError.failure("AES-GCM 密文过短")
        }

        let body = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)
        let box = try AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: nonce),
            ciphertext: body,
            tag: tag
        )
        return try AES.GCM.open(box, using: SymmetricKey(data: key))
    }

    // MARK: - PKCS#8

    /// 取出 P-256 私钥的 32 字节标量。支持 PKCS#8 与 SEC1 两种包裹。
    static func p256PrivateScalar(pkcs8 der: Data) throws -> Data {
        var outer = DERReader(data: der)
        let outerContent = try outer.readEncodedSequence()
        let innerContent: Data

        if DERReader.looksLikeECPrivateKey(outerContent) {
            innerContent = outerContent
        } else {
            var info = DERReader(data: outerContent)
            _ = try info.readInteger()
            _ = try info.readSequenceContent()
            innerContent = try info.readOctetString()
        }

        var ec = DERReader(data: innerContent)
        let ecContent = try ec.readEncodedSequence()
        var fields = DERReader(data: ecContent)
        _ = try fields.readInteger()
        let scalar = try fields.readOctetString()

        guard scalar.count <= 32 else {
            throw StoreAuthError.failure("P-256 私钥长度异常：\(scalar.count)")
        }

        return scalar.count == 32 ? scalar : Data(repeating: 0, count: 32 - scalar.count) + scalar
    }

    // MARK: - HPKE

    /// RFC 9180 的 base 模式：DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM。
    enum HPKE {
        static let kemID: UInt16 = 0x0010
        static let kdfID: UInt16 = 0x0001
        static let aeadID: UInt16 = 0x0002

        static var suiteID: Data {
            var suite = Data("HPKE".utf8)
            suite.append(contentsOf: [UInt8(kemID >> 8), UInt8(kemID & 0xFF)])
            suite.append(contentsOf: [UInt8(kdfID >> 8), UInt8(kdfID & 0xFF)])
            suite.append(contentsOf: [UInt8(aeadID >> 8), UInt8(aeadID & 0xFF)])
            return suite
        }

        /// RFC 9180 规定 DHKEM 阶段使用独立的 `"KEM" || kem_id`。
        static var kemSuiteID: Data {
            var suite = Data("KEM".utf8)
            suite.append(contentsOf: [UInt8(kemID >> 8), UInt8(kemID & 0xFF)])
            return suite
        }

        /// 解密 `wrapped-key`：`ciphertext` 为 AES-GCM 的密文 + tag。
        static func openBaseP256(recipientPrivateKey: Data,
                                 encapsulation: Data,
                                 ciphertext: Data,
                                 info: Data = Data()) throws -> Data {
            guard encapsulation.count == 65, encapsulation.first == 0x04 else {
                throw StoreAuthError.failure("HPKE encapsulation 长度异常：\(encapsulation.count)")
            }

            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKey)
            // CryptoKit 的 rawRepresentation 是去掉 0x04 前缀的 x||y，x963 才是 RFC 9180 的 65 字节编码。
            let recipientPublic = privateKey.publicKey.x963Representation
            let ephemeralPublic = try P256.KeyAgreement.PublicKey(
                rawRepresentation: Data(encapsulation.dropFirst())
            )
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublic)
            let dh = sharedSecret.withUnsafeBytes { Data($0) }

            var kemContext = encapsulation
            kemContext.append(recipientPublic)

            let eaePRK = labeledExtract(suiteID: kemSuiteID, salt: Data(), label: "eae_prk", ikm: dh)
            let kemSecret = try labeledExpand(suiteID: kemSuiteID, prk: eaePRK, label: "shared_secret",
                                              info: kemContext, count: 32)

            let pskIDHash = labeledExtract(suiteID: suiteID, salt: Data(), label: "psk_id_hash", ikm: Data())
            let infoHash = labeledExtract(suiteID: suiteID, salt: Data(), label: "info_hash", ikm: info)
            var context = Data([0x00])
            context.append(pskIDHash)
            context.append(infoHash)

            let secret = labeledExtract(suiteID: suiteID, salt: kemSecret, label: "secret", ikm: Data())
            let key = try labeledExpand(suiteID: suiteID, prk: secret, label: "key",
                                        info: context, count: 32)
            let baseNonce = try labeledExpand(suiteID: suiteID, prk: secret, label: "base_nonce",
                                              info: context, count: 12)

            return try AssetCrypto.aesGCMOpen(key: key, nonce: baseNonce, ciphertext: ciphertext)
        }

        static func labeledExtract(suiteID: Data, salt: Data, label: String, ikm: Data) -> Data {
            var input = Data("HPKE-v1".utf8)
            input.append(suiteID)
            input.append(contentsOf: Data(label.utf8))
            input.append(ikm)
            return AssetCrypto.hkdfExtract(salt: salt, ikm: input)
        }

        static func labeledExpand(suiteID: Data, prk: Data, label: String, info: Data,
                                  count: Int) throws -> Data {
            guard count <= 0xFFFF else {
                throw StoreAuthError.failure("HPKE 输出长度超出范围")
            }

            var input = Data([UInt8(count >> 8), UInt8(count & 0xFF)])
            input.append(contentsOf: Data("HPKE-v1".utf8))
            input.append(suiteID)
            input.append(contentsOf: Data(label.utf8))
            input.append(info)

            return AssetCrypto.hkdfExpand(prk: prk, info: input, count: count)
        }
    }
}

// MARK: - 最小 DER 读取

struct DERReader {
    let data: Data
    var offset: Int = 0

    init(data: Data) {
        self.data = data
    }

    static func looksLikeECPrivateKey(_ data: Data) -> Bool {
        guard let first = data.first else {
            return false
        }

        return first == 0x30
    }

    mutating func readTLV() throws -> (tag: UInt8, content: Data) {
        guard offset + 2 <= data.count else {
            throw StoreAuthError.failure("DER 数据被截断")
        }

        let tag = data.byte(at: offset)
        offset += 1
        var length = Int(data.byte(at: offset))
        offset += 1

        if length & 0x80 != 0 {
            let byteCount = length & 0x7F
            guard byteCount > 0, byteCount <= 4, offset + byteCount <= data.count else {
                throw StoreAuthError.failure("DER 长度字段无效")
            }

            length = 0
            for _ in 0..<byteCount {
                length = (length << 8) | Int(data.byte(at: offset))
                offset += 1
            }
        }

        guard length >= 0, offset + length <= data.count else {
            throw StoreAuthError.failure("DER 内容超出范围")
        }

        let content = data.subdata(in: offset..<(offset + length))
        offset += length
        return (tag, content)
    }

    mutating func readEncodedSequence() throws -> Data {
        let element = try readTLV()
        guard element.tag == 0x30 else {
            throw StoreAuthError.failure("DER 缺少 SEQUENCE")
        }

        return element.content
    }

    mutating func readSequenceContent() throws -> Data {
        try readEncodedSequence()
    }

    mutating func readInteger() throws -> UInt32 {
        let element = try readTLV()
        guard element.tag == 0x02, element.content.count <= 4 else {
            throw StoreAuthError.failure("DER 缺少 INTEGER")
        }

        var value: UInt32 = 0
        for byte in element.content {
            value = (value << 8) | UInt32(byte)
        }
        return value
    }

    mutating func readOctetString() throws -> Data {
        let element = try readTLV()
        guard element.tag == 0x04 else {
            throw StoreAuthError.failure("DER 缺少 OCTET STRING")
        }

        return element.content
    }
}
