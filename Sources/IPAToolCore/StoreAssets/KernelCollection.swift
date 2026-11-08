import Foundation

/// 内核集合（kernelcache）里的 FairPlayIOKit 提取。
/// 对应 Go 侧 `internal/sap/assets/kernel.go`。
enum KernelCollection {
    static let maximumSymbols = 1 << 20

    private static let filesetEntryCommand: UInt32 = 0x8000_0035
    private static let symtabCommand: UInt32 = 0x02
    private static let filesetType: UInt32 = 0x0c
    private static let externalFlag: UInt8 = 0x01
    private static let typeMask: UInt8 = 0x0e
    private static let absoluteExternalType: UInt8 = 0x03

    /// 集合成员（`LC_FILESET_ENTRY`）。
    private struct Entry {
        let identifier: String
        let fileOffset: UInt64
    }

    /// 集合外层段，用来把成员的 VM 地址换算成镜像内的文件偏移。
    private struct Segment {
        let address: UInt64
        let memorySize: UInt64
        let fileOffset: UInt64
    }

    private struct Collection {
        let image: Data
        let segments: [Segment]
        let entries: [Entry]
    }

    /// 打开的集合成员。
    private struct Member {
        let header: Data
        let commands: Data
        let layout: MachOLayout
    }

    // MARK: - 入口

    /// 从 zip 成员数据（IM4P 容器）导出 FairPlayIOKit。
    static func fairPlayKext(archive data: Data) throws -> Data {
        let payload = try im4pPayload(data)
        guard payload.count == Int(IPSWAssetSpec.kernelCachePayloadSize) else {
            throw StoreAuthError.failure("内核载荷大小为 \(payload.count)")
        }

        let image = try CompressionCodecs.lzfse(payload,
                                                expectedSize: Int(IPSWAssetSpec.kernelCacheImageSize))
        guard image.count == Int(IPSWAssetSpec.kernelCacheImageSize) else {
            throw StoreAuthError.failure("内核镜像大小为 \(image.count)")
        }

        return try exportFairPlayKext(image: image)
    }

    /// 从解压后的内核集合导出 FairPlayIOKit。
    static func exportFairPlayKext(image: Data) throws -> Data {
        let collection = try open(image)
        guard image.uint32LE(at: 12) == filesetType else {
            throw StoreAuthError.failure("内核集合不是 fileset")
        }

        let source = exportSource(collection)
        var symbols: [Data: MachOBuilder.Symbol] = [:]

        for entry in collection.entries {
            guard let member = try? openMember(collection, entry: entry),
                  member.layout.command(symtabCommand) != nil,
                  let memberSymbols = try? MachOBuilder.readSymbols(source: source,
                                                                    layout: member.layout,
                                                                    loadCommands: member.commands) else {
                continue
            }

            for symbol in memberSymbols where symbol.type & externalFlag != 0
                && symbol.type & typeMask != 0
                && symbol.value != 0 {
                symbols[symbol.name] = symbol
                guard symbols.count <= maximumSymbols else {
                    throw StoreAuthError.failure("内核集合符号过多")
                }
            }
        }

        let identifier = IPSWAssetSpec.fairPlayKextIdentifier
        guard let target = collection.entries.first(where: {
            $0.identifier.caseInsensitiveCompare(identifier) == .orderedSame
                || $0.identifier.lowercased().hasSuffix(identifier.lowercased())
        }) else {
            throw StoreAuthError.failure("内核集合缺少 FairPlayIOKit")
        }

        let member = try openMember(collection, entry: target)
        var resolved: [MachOBuilder.Symbol] = []
        if member.layout.command(symtabCommand) != nil {
            let memberSymbols = try MachOBuilder.readSymbols(source: source,
                                                             layout: member.layout,
                                                             loadCommands: member.commands)
            for symbol in memberSymbols where symbol.type & typeMask == 0 && !symbol.name.isEmpty {
                guard let definition = symbols[symbol.name] else {
                    continue
                }

                resolved.append(MachOBuilder.Symbol(name: symbol.name,
                                                    type: absoluteExternalType,
                                                    section: 0,
                                                    description: symbol.description,
                                                    value: definition.value))
            }
        }

        return try MachOBuilder.export(header: member.header,
                                       loadCommands: member.commands,
                                       source: source,
                                       locals: resolved)
    }

    // MARK: - IM4P

    /// 取出 IM4P 容器里的载荷（ASN.1 DER 的 OCTET STRING）。
    static func im4pPayload(_ data: Data) throws -> Data {
        var outer = DERReader(data: data)
        let contents: Data
        do {
            contents = try outer.readEncodedSequence()
        } catch {
            throw StoreAuthError.failure("IM4P 容器无效")
        }
        guard outer.offset == data.count else {
            throw StoreAuthError.failure("IM4P 容器无效")
        }

        var reader = DERReader(data: contents)
        var fields: [(tag: UInt8, content: Data)] = []
        for _ in 0..<4 {
            guard reader.offset < contents.count else {
                break
            }
            do {
                fields.append(try reader.readTLV())
            } catch {
                throw StoreAuthError.failure("IM4P 字段无效")
            }
        }

        guard fields.count == 4,
              fields[0].tag == 0x16, fields[0].content == Data("IM4P".utf8),
              fields[1].tag == 0x16, fields[1].content == Data("krnl".utf8),
              fields[3].tag == 0x04 else {
            throw StoreAuthError.failure("IM4P 内核载荷无效")
        }

        return fields[3].content
    }

    // MARK: - 集合解析

    private static func open(_ image: Data) throws -> Collection {
        guard image.count >= 32 else {
            throw StoreAuthError.failure("内核集合被截断")
        }

        let header = image.slice(at: 0, count: 32)
        guard header.uint32LE(at: 0) == MachOLayout.magic64 else {
            throw StoreAuthError.failure("内核集合不是 Mach-O")
        }

        let commandSize = Int(header.uint32LE(at: 20))
        guard commandSize > 0, 32 + commandSize <= image.count else {
            throw StoreAuthError.failure("内核集合的加载命令无效")
        }

        let commands = image.slice(at: 32, count: commandSize)
        let layout = try MachOLayout(header: header, loadCommands: commands)
        let segments = layout.segments.map {
            Segment(address: $0.address, memorySize: $0.memorySize, fileOffset: $0.fileOffset)
        }

        var entries: [Entry] = []
        for command in layout.commands where command.command == filesetEntryCommand {
            guard command.size >= 32 else {
                throw StoreAuthError.failure("内核集合条目命令被截断")
            }

            let identifierOffset = Int(commands.uint32LE(at: command.offset + 24))
            guard identifierOffset > 0, identifierOffset < command.size else {
                throw StoreAuthError.failure("内核集合条目标识无效")
            }

            let identifier = commands.nullTerminatedString(at: command.offset + identifierOffset,
                                                           maxLength: command.size - identifierOffset)
            entries.append(Entry(identifier: identifier ?? "",
                                 fileOffset: commands.uint64LE(at: command.offset + 16)))
        }

        return Collection(image: image, segments: segments, entries: entries)
    }

    private static func openMember(_ collection: Collection, entry: Entry) throws -> Member {
        let image = collection.image
        guard entry.fileOffset <= UInt64(image.count),
              UInt64(image.count) - entry.fileOffset >= 32 else {
            throw StoreAuthError.failure("内核集合成员被截断")
        }

        let offset = Int(entry.fileOffset)
        let header = image.slice(at: offset, count: 32)
        guard header.uint32LE(at: 0) == MachOLayout.magic64 else {
            throw StoreAuthError.failure("内核集合成员不是 Mach-O")
        }

        let commandSize = Int(header.uint32LE(at: 20))
        guard commandSize > 0, 32 + commandSize <= image.count - offset else {
            throw StoreAuthError.failure("内核集合成员的加载命令无效")
        }

        let commands = image.slice(at: offset + 32, count: commandSize)
        return Member(header: header,
                      commands: commands,
                      layout: try MachOLayout(header: header, loadCommands: commands))
    }

    // MARK: - 数据读取

    private static func exportSource(_ collection: Collection) -> MachOBuilder.ExportSource {
        MachOBuilder.ExportSource(
            readAddress: { address, count in
                try read(collection, atAddress: address, count: count)
            },
            readLinkedit: { offset, size in
                try read(collection, atOffset: UInt64(offset), count: Int(size))
            },
            size: Int64(collection.image.count),
            applySlide: nil
        )
    }

    private static func read(_ collection: Collection, atAddress address: UInt64,
                             count: Int) throws -> Data {
        guard let segment = collection.segments.first(where: {
            address >= $0.address && address - $0.address < $0.memorySize
        }) else {
            throw StoreAuthError.failure("内核集合地址不在任何段内")
        }

        return try read(collection, atOffset: segment.fileOffset + (address - segment.address),
                        count: count)
    }

    private static func read(_ collection: Collection, atOffset offset: UInt64,
                             count: Int) throws -> Data {
        let end = offset + UInt64(count)
        guard end >= offset, end <= UInt64(collection.image.count) else {
            throw StoreAuthError.failure("内核集合读取超出镜像")
        }

        return collection.image.slice(at: Int(offset), count: count)
    }
}
