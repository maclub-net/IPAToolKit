import Compression
import CSAP
import Foundation

#if canImport(zlib)
import zlib
#endif

/// 镜像里用到的压缩格式：zlib raw deflate、bzip2、LZFSE、LZBITMAP。
enum CompressionCodecs {
    /// raw deflate（无 zlib 头），用于 ZIP 成员。
    static func inflateRaw(_ data: Data, expectedSize: Int) throws -> Data {
        try inflateStream(data, expectedSize: expectedSize, windowBits: -15, name: "deflate")
    }

    /// zlib 包裹的 deflate，用于 UDIF 的 ZLIB 块。
    static func inflateZlib(_ data: Data, expectedSize: Int) throws -> Data {
        try inflateStream(data, expectedSize: expectedSize, windowBits: 15, name: "zlib")
    }

    private static func inflateStream(_ data: Data, expectedSize: Int,
                                      windowBits: Int32, name: String) throws -> Data {
        #if canImport(zlib)
        guard expectedSize > 0 else {
            throw StoreAuthError.failure("\(name) 解压目标尺寸无效")
        }

        var output = Data(count: expectedSize)
        var produced = 0

        let status = data.withUnsafeBytes { input in
            output.withUnsafeMutableBytes { destination -> Int32 in
                guard let inputBase = input.bindMemory(to: UInt8.self).baseAddress,
                      let outputBase = destination.bindMemory(to: UInt8.self).baseAddress else {
                    return Z_DATA_ERROR
                }

                var stream = z_stream()
                stream.next_in = UnsafeMutablePointer<UInt8>(mutating: inputBase)
                stream.avail_in = UInt32(data.count)
                stream.next_out = outputBase
                stream.avail_out = UInt32(expectedSize)

                let initialized = inflateInit2_(&stream, windowBits, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
                guard initialized == Z_OK else {
                    return initialized
                }

                let result = inflate(&stream, Z_FINISH)
                produced = expectedSize - Int(stream.avail_out)
                inflateEnd(&stream)
                return result
            }
        }

        guard status == Z_STREAM_END || status == Z_OK else {
            throw StoreAuthError.failure("\(name) 解压失败：\(status)")
        }
        guard produced == expectedSize else {
            throw StoreAuthError.failure("\(name) 解压得到 \(produced) 字节，期望 \(expectedSize)")
        }

        return output
        #else
        throw StoreAuthError.failure("当前平台没有 zlib")
        #endif
    }

    /// bzip2 解压，复用 CSAP 内嵌实现。
    static func bunzip2(_ data: Data) throws -> Data {
        guard !data.isEmpty else {
            throw StoreAuthError.failure("bzip2 输入为空")
        }

        var output: UnsafeMutablePointer<UInt8>?
        var outputSize = 0
        let status = data.withUnsafeBytes { input in
            csap_bz2_decompress(input.bindMemory(to: UInt8.self).baseAddress, data.count,
                                &output, &outputSize)
        }

        guard status == 0, let output, outputSize > 0 else {
            throw StoreAuthError.failure("bzip2 解压失败：\(status)")
        }

        return Data(bytesNoCopy: output, count: outputSize, deallocator: .free)
    }

    /// LZFSE，用于 AEA segment 与内核缓存。
    static func lzfse(_ data: Data, expectedSize: Int) throws -> Data {
        try decompress(data, expectedSize: expectedSize, algorithm: COMPRESSION_LZFSE, name: "LZFSE")
    }

    /// LZBITMAP，用于 decmpfs 压缩块。
    static func lzbitmap(_ data: Data, expectedSize: Int) throws -> Data {
        try decompress(data, expectedSize: expectedSize, algorithm: COMPRESSION_LZBITMAP, name: "LZBITMAP")
    }

    /// raw LZVN 流，用于 decmpfs type 8 的每个 64 KiB 分块。
    /// 端口自 `go-compressions/lzfse` 的 `lzvnDecode`。
    static func lzvn(_ data: Data, maximumSize: Int) throws -> Data {
        guard maximumSize > 0 else {
            throw StoreAuthError.failure("LZVN 解压目标尺寸无效")
        }

        let source = [UInt8](data)
        var output = [UInt8](repeating: 0, count: maximumSize)
        var destination = 0
        var position = 0
        var previousDistance = 0

        func copyMatch(distance: Int, length: Int) throws {
            guard distance > 0, destination - distance >= 0,
                  destination + length <= maximumSize else {
                throw StoreAuthError.failure("LZVN 匹配距离或长度无效")
            }
            for index in 0..<length {
                output[destination + index] = output[destination - distance + index]
            }
            destination += length
        }

        while position < source.count {
            let opcode = source[position]
            position += 1

            switch opcode {
            case 0x06: // eos
                position += 7
                return Data(output[0..<destination])

            case 0x0E, 0x16: // nop
                continue

            case 0xF0, 0xF1...0xFF: // lrg_m / sml_m
                let length: Int
                if opcode == 0xF0 {
                    guard position < source.count else {
                        throw StoreAuthError.failure("LZVN lrg_m 被截断")
                    }
                    length = Int(source[position]) + 16
                    position += 1
                } else {
                    length = Int(opcode & 0x0F)
                }
                guard previousDistance != 0 else {
                    throw StoreAuthError.failure("LZVN 匹配缺少前置距离")
                }
                try copyMatch(distance: previousDistance, length: length)

            case 0xE0, 0xE1...0xEF: // lrg_l / sml_l
                let length: Int
                if opcode == 0xE0 {
                    guard position < source.count else {
                        throw StoreAuthError.failure("LZVN lrg_l 被截断")
                    }
                    length = Int(source[position]) + 16
                    position += 1
                } else {
                    length = Int(opcode & 0x0F)
                }
                guard position + length <= source.count, destination + length <= maximumSize else {
                    throw StoreAuthError.failure("LZVN 字面量越界")
                }
                output[destination..<(destination + length)] = source[position..<(position + length)]
                destination += length
                position += length

            case 0xA0...0xBF: // med_d
                guard position + 2 <= source.count else {
                    throw StoreAuthError.failure("LZVN med_d 被截断")
                }
                let first = source[position]
                let second = source[position + 1]
                position += 2
                let literals = Int((opcode >> 3) & 0x03)
                let length = Int((opcode & 0x07) << 2 | first & 0x03) + 3
                let distance = Int(first >> 2) | Int(second) << 6
                guard distance != 0 else {
                    throw StoreAuthError.failure("LZVN 匹配距离为零")
                }
                guard position + literals <= source.count, destination + literals <= maximumSize else {
                    throw StoreAuthError.failure("LZVN med_d 字面量越界")
                }
                output[destination..<(destination + literals)] = source[position..<(position + literals)]
                destination += literals
                position += literals
                try copyMatch(distance: distance, length: length)
                previousDistance = distance

            default:
                switch opcode & 0x07 {
                case 0...5: // sml_d
                    guard position < source.count else {
                        throw StoreAuthError.failure("LZVN sml_d 被截断")
                    }
                    let first = source[position]
                    position += 1
                    let literals = Int(opcode >> 6)
                    let length = Int((opcode >> 3) & 0x07) + 3
                    let distance = Int(opcode & 0x07) << 8 | Int(first)
                    guard distance != 0 else {
                        throw StoreAuthError.failure("LZVN 匹配距离为零")
                    }
                    guard position + literals <= source.count, destination + literals <= maximumSize else {
                        throw StoreAuthError.failure("LZVN sml_d 字面量越界")
                    }
                    output[destination..<(destination + literals)] = source[position..<(position + literals)]
                    destination += literals
                    position += literals
                    try copyMatch(distance: distance, length: length)
                    previousDistance = distance

                case 6: // pre_d
                    let literals = Int(opcode >> 6)
                    let length = Int((opcode >> 3) & 0x07) + 3
                    guard previousDistance != 0 else {
                        throw StoreAuthError.failure("LZVN pre_d 缺少前置距离")
                    }
                    guard position + literals <= source.count, destination + literals <= maximumSize else {
                        throw StoreAuthError.failure("LZVN pre_d 字面量越界")
                    }
                    output[destination..<(destination + literals)] = source[position..<(position + literals)]
                    destination += literals
                    position += literals
                    try copyMatch(distance: previousDistance, length: length)

                default: // lrg_d
                    guard position + 2 <= source.count else {
                        throw StoreAuthError.failure("LZVN lrg_d 被截断")
                    }
                    let distance = Int(source[position]) | Int(source[position + 1]) << 8
                    position += 2
                    let literals = Int(opcode >> 6)
                    let length = Int((opcode >> 3) & 0x07) + 3
                    guard distance != 0 else {
                        throw StoreAuthError.failure("LZVN 匹配距离为零")
                    }
                    guard position + literals <= source.count, destination + literals <= maximumSize else {
                        throw StoreAuthError.failure("LZVN lrg_d 字面量越界")
                    }
                    output[destination..<(destination + literals)] = source[position..<(position + literals)]
                    destination += literals
                    position += literals
                    try copyMatch(distance: distance, length: length)
                    previousDistance = distance
                }
            }
        }

        return Data(output[0..<destination])
    }

    /// decmpfs 压缩块分派。输入首字节为「未压缩」标记时直接剥离。
    static func decmpfsBlock(_ block: Data, method: UInt32, maximumSize: Int) throws -> Data {
        guard !block.isEmpty else {
            throw StoreAuthError.failure("decmpfs 压缩块为空")
        }

        switch method {
        case 8: // LZVN
            if block[block.startIndex] == 0x06 {
                return Data(block.dropFirst())
            }
            return try lzvn(block, maximumSize: maximumSize)

        case 12: // LZFSE
            if block[block.startIndex] != UInt8(ascii: "b") {
                return Data(block.dropFirst())
            }
            return try lzfse(block, expectedSize: maximumSize)

        case 14: // LZBitmap
            if block[block.startIndex] == 0xFF {
                return Data(block.dropFirst())
            }
            return try lzbitmap(block, expectedSize: maximumSize)

        default:
            throw StoreAuthError.failure("decmpfs 使用了不支持的压缩类型 \(method)")
        }
    }

    private static func decompress(_ data: Data, expectedSize: Int,
                                   algorithm: compression_algorithm, name: String) throws -> Data {
        guard expectedSize > 0 else {
            throw StoreAuthError.failure("\(name) 解压目标尺寸无效")
        }

        var output = Data(count: expectedSize)
        let produced = data.withUnsafeBytes { input in
            output.withUnsafeMutableBytes { destination in
                compression_decode_buffer(
                    destination.bindMemory(to: UInt8.self).baseAddress!, expectedSize,
                    input.bindMemory(to: UInt8.self).baseAddress!, data.count,
                    nil, algorithm
                )
            }
        }

        guard produced > 0 else {
            throw StoreAuthError.failure("\(name) 解压失败")
        }

        return output.prefix(produced)
    }
}
