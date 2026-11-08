import Foundation

/// 解析后的 Mach-O 头部与加载命令布局。
struct MachOLayout {
    struct Command {
        let command: UInt32
        let offset: Int
        let size: Int
    }

    struct Section {
        let name: String
        let segmentName: String
        let address: UInt64
        let size: UInt64
        let fileOffset: UInt32
        let align: UInt32
        let reloffset: UInt32
        let nreloc: UInt32
        let flags: UInt32
        let reserved1: UInt32
        let reserved2: UInt32
        let reserved3: UInt32
    }

    struct Segment {
        let name: String
        let address: UInt64
        let memorySize: UInt64
        let fileOffset: UInt64
        let fileSize: UInt64
        let maximumProtection: UInt32
        let initialProtection: UInt32
        let flags: UInt32
        let command: Command
        let sectionRange: Range<Int>
    }

    static let magic64: UInt32 = 0xfeed_facf
    static let segment64Command: UInt32 = 0x19

    let header: Data
    let loadCommands: Data
    let commands: [Command]
    let segments: [Segment]
    let sections: [Section]

    init(header: Data, loadCommands: Data) throws {
        guard header.count >= 32, header.uint32LE(at: 0) == Self.magic64 else {
            throw StoreAuthError.failure("Mach-O 头部无效")
        }

        let commandCount = Int(header.uint32LE(at: 16))
        guard commandCount >= 0, commandCount <= 1 << 16 else {
            throw StoreAuthError.failure("Mach-O 加载命令数量无效")
        }

        var commands: [Command] = []
        commands.reserveCapacity(commandCount)
        var offset = 0
        for _ in 0..<commandCount {
            guard loadCommands.count - offset >= 8 else {
                throw StoreAuthError.failure("Mach-O 加载命令被截断")
            }

            let command = loadCommands.uint32LE(at: offset)
            let size = Int(loadCommands.uint32LE(at: offset + 4))
            guard size >= 8, size <= loadCommands.count - offset else {
                throw StoreAuthError.failure("Mach-O 加载命令大小无效")
            }

            commands.append(Command(command: command, offset: offset, size: size))
            offset += size
        }

        var sections: [Section] = []
        var segments: [Segment] = []
        for command in commands where command.command == Self.segment64Command {
            guard command.size >= 72 else {
                throw StoreAuthError.failure("Mach-O 段命令被截断")
            }

            let sectionCount = Int(loadCommands.uint32LE(at: command.offset + 64))
            guard sectionCount >= 0, 72 + sectionCount * 80 <= command.size else {
                throw StoreAuthError.failure("Mach-O 段命令的节数量无效")
            }

            let sectionStart = sections.count
            for index in 0..<sectionCount {
                let base = command.offset + 72 + index * 80
                sections.append(Section(
                    name: Self.string(loadCommands, at: base, length: 16),
                    segmentName: Self.string(loadCommands, at: base + 16, length: 16),
                    address: loadCommands.uint64LE(at: base + 32),
                    size: loadCommands.uint64LE(at: base + 40),
                    fileOffset: loadCommands.uint32LE(at: base + 48),
                    align: loadCommands.uint32LE(at: base + 52),
                    reloffset: loadCommands.uint32LE(at: base + 56),
                    nreloc: loadCommands.uint32LE(at: base + 60),
                    flags: loadCommands.uint32LE(at: base + 64),
                    reserved1: loadCommands.uint32LE(at: base + 68),
                    reserved2: loadCommands.uint32LE(at: base + 72),
                    reserved3: loadCommands.uint32LE(at: base + 76)
                ))
            }

            segments.append(Segment(
                name: Self.string(loadCommands, at: command.offset + 8, length: 16),
                address: loadCommands.uint64LE(at: command.offset + 24),
                memorySize: loadCommands.uint64LE(at: command.offset + 32),
                fileOffset: loadCommands.uint64LE(at: command.offset + 40),
                fileSize: loadCommands.uint64LE(at: command.offset + 48),
                maximumProtection: loadCommands.uint32LE(at: command.offset + 56),
                initialProtection: loadCommands.uint32LE(at: command.offset + 60),
                flags: loadCommands.uint32LE(at: command.offset + 68),
                command: command,
                sectionRange: sectionStart..<sections.count
            ))
        }

        self.header = header
        self.loadCommands = loadCommands
        self.commands = commands
        self.segments = segments
        self.sections = sections
    }

    func command(_ value: UInt32) -> Command? {
        commands.first { $0.command == value }
    }

    private static func string(_ data: Data, at offset: Int, length: Int) -> String {
        String(decoding: data.slice(at: offset, count: length).prefix { $0 != 0 }, as: UTF8.self)
    }
}

/// 把 dyld 共享缓存中的 in-cache 镜像重排为可独立加载的 Mach-O。
///
/// 逐字复刻 go-macho `File.Export` 的导出结果：段按页对齐重排、
/// 加载命令偏移重映射、重建 __LINKEDIT 的导出 trie / 符号表 / 字符串池，
/// 剥离 `LC_DYLD_CHAINED_FIXUPS` 与 in-cache 位，最后执行 slide 指针回写。
enum MachOBuilder {
    static let pageSize: UInt64 = 0x4000
    static let pointerSize = 8

    private static let segment64Command: UInt32 = 0x19
    private static let symtabCommand: UInt32 = 0x2
    private static let dysymtabCommand: UInt32 = 0xb
    private static let dyldInfoCommand: UInt32 = 0x22
    private static let dyldInfoOnlyCommand: UInt32 = 0x8000_0022
    private static let functionStartsCommand: UInt32 = 0x26
    private static let dataInCodeCommand: UInt32 = 0x29
    private static let dylibCodeSignDRSCommand: UInt32 = 0x2b
    private static let encryptionInfoCommand: UInt32 = 0x21
    private static let encryptionInfo64Command: UInt32 = 0x2c
    private static let linkerOptimizationHintCommand: UInt32 = 0x2e
    private static let dyldExportsTrieCommand: UInt32 = 0x8000_0033
    private static let chainedFixupsCommand: UInt32 = 0x8000_0034
    private static let filesetEntryCommand: UInt32 = 0x8000_0035
    private static let functionVariantsCommand: UInt32 = 0x37
    private static let functionVariantFixupsCommand: UInt32 = 0x38

    private struct ExportSegment {
        let name: String
        let address: UInt64
        let originalFileSize: UInt64
        let newStart: UInt64
        var newEnd: UInt64
        var newMemorySize: UInt64

        var newFileSize: UInt64 { newEnd - newStart }
    }

    /// 追加到导出符号表里的符号（内核集合解析出的导入）。
    struct Symbol {
        let name: Data
        let type: UInt8
        let section: UInt8
        let description: UInt16
        let value: UInt64
    }

    /// 镜像数据的来源：按 VM 地址读段、按文件偏移读 __LINKEDIT。
    struct ExportSource {
        let readAddress: (UInt64, Int) throws -> Data
        let readLinkedit: (UInt32, UInt32) throws -> Data
        /// __LINKEDIT 所在文件的长度，用于区间校验。
        let size: Int64
        /// 导出后回写 slide 指针；内核集合没有 slide。
        let applySlide: ((inout Data) throws -> Void)?
    }

    private struct TrieNode {
        let offset: Int
        let name: Data
    }

    private struct TrieExport {
        let name: Data
        let reExport: Data
        let flags: UInt64
        let address: UInt64
    }

    private struct TrieReader {
        let data: Data
        var position: Int

        mutating func readByte() -> UInt8? {
            guard position >= 0, position < data.count else {
                return nil
            }

            defer { position += 1 }
            return data[data.startIndex + position]
        }

        mutating func readULEB128() throws -> UInt64 {
            var result: UInt64 = 0
            var shift: UInt64 = 0
            while true {
                guard let byte = readByte() else {
                    throw StoreAuthError.failure("导出 trie 被截断")
                }

                guard shift < 64 else {
                    throw StoreAuthError.failure("导出 trie 的 ULEB128 过长")
                }

                result |= UInt64(byte & 0x7f) << shift
                if byte & 0x80 == 0 {
                    return result
                }

                shift += 7
            }
        }

        mutating func readCString() -> Data {
            var bytes = Data()
            while let byte = readByte() {
                if byte == 0 {
                    break
                }

                bytes.append(byte)
            }

            return bytes
        }
    }

    // MARK: - 导出入口

    static func export(cache: DyldSharedCache, image: DyldSharedCache.Image) throws -> Data {
        let memberSize = cache.size(ofMember: image.member)
        let header = try cache.read(member: image.member, at: image.offset, count: 32)
        let commandSize = Int(header.uint32LE(at: 20))
        guard commandSize > 0, commandSize <= DyldSharedCache.maximumLoadCommandsSize,
              Int64(commandSize) <= memberSize - image.offset - 32 else {
            throw StoreAuthError.failure("共享缓存镜像的加载命令无效")
        }

        let loadCommands = try cache.read(member: image.member,
                                          at: image.offset + 32,
                                          count: commandSize)
        let layout = try MachOLayout(header: header, loadCommands: loadCommands)
        guard let linkedit = layout.segments.first(where: { $0.name == "__LINKEDIT" }),
              let mapping = cache.mapping(forAddress: linkedit.address) else {
            throw StoreAuthError.failure("__LINKEDIT 不在共享缓存映射内")
        }

        let source = ExportSource(
            readAddress: { address, count in
                try cache.read(atAddress: address, count: count)
            },
            readLinkedit: { offset, count in
                try cache.read(member: mapping.member, at: Int64(offset), count: Int(count))
            },
            size: cache.size(ofMember: mapping.member),
            applySlide: { data in
                try cache.applySlide(&data)
            }
        )

        return try export(header: header,
                          loadCommands: loadCommands,
                          source: source,
                          locals: [])
    }

    /// 把 in-cache 镜像重排成可独立加载的 Mach-O。
    ///
    /// 复刻 go-macho `File.Export` 的 in-cache 分支：段按页对齐重排、
    /// 重建 __LINKEDIT，并剥离 in-cache 位与 `LC_DYLD_CHAINED_FIXUPS`。
    static func export(header: Data,
                       loadCommands sourceCommands: Data,
                       source: ExportSource,
                       locals: [Symbol]) throws -> Data {
        guard header.count >= 32, header.uint32LE(at: 0) == MachOLayout.magic64 else {
            throw StoreAuthError.failure("共享缓存镜像不是 Mach-O")
        }
        guard header.uint32LE(at: 24) & DyldSharedCache.inCacheFlag != 0 else {
            throw StoreAuthError.failure("共享缓存镜像缺少 in-cache 标记")
        }
        guard Int(header.uint32LE(at: 20)) == sourceCommands.count else {
            throw StoreAuthError.failure("共享缓存镜像的加载命令长度不一致")
        }

        var loadCommands = sourceCommands
        let layout = try MachOLayout(header: header, loadCommands: loadCommands)

        // 段按加载顺序重新排布，New.Start 逐个页对齐累加。
        var segments: [ExportSegment] = []
        segments.reserveCapacity(layout.segments.count)
        var next: UInt64 = 0
        for segment in layout.segments {
            let end = next + pageAlign(segment.fileSize)
            guard end >= next else {
                throw StoreAuthError.failure("Mach-O 段大小溢出")
            }

            segments.append(ExportSegment(name: segment.name,
                                          address: segment.address,
                                          originalFileSize: segment.fileSize,
                                          newStart: next,
                                          newEnd: end,
                                          newMemorySize: segment.memorySize))
            next = end
        }

        // __TEXT 数据写入起点取首个非零偏移节相对 __TEXT 的地址差。
        var textRelativeOffset: UInt64 = 0
        if let text = layout.segments.first(where: { $0.name == "__TEXT" }) {
            for sectionIndex in text.sectionRange {
                let section = layout.sections[sectionIndex]
                guard section.fileOffset != 0 else {
                    continue
                }
                guard section.address >= text.address else {
                    throw StoreAuthError.failure("__TEXT 节地址早于段地址")
                }

                textRelativeOffset = section.address - text.address
                break
            }
        }

        for (index, segment) in layout.segments.enumerated() {
            var entry = segments[index]
            let newFileSize = entry.newEnd - entry.newStart
            let newMemorySize = segment.memorySize > segment.fileSize
                ? newFileSize + (segment.memorySize - segment.fileSize)
                : newFileSize
            entry.newMemorySize = newMemorySize
            segments[index] = entry

            try setUInt64(newMemorySize, &loadCommands, at: segment.command.offset + 32)
            try setUInt64(entry.newStart, &loadCommands, at: segment.command.offset + 40)
            try setUInt64(newFileSize, &loadCommands, at: segment.command.offset + 48)

            for (sectionIndex, section) in segment.sectionRange.enumerated() {
                let section = layout.sections[section]
                guard section.fileOffset != 0 else {
                    continue
                }
                guard section.address >= segment.address else {
                    throw StoreAuthError.failure("节地址早于所在段地址")
                }

                let offset = entry.newStart + (section.address - segment.address)
                guard offset <= UInt64(UInt32.max) else {
                    throw StoreAuthError.failure("节的文件偏移超出 32 位")
                }

                try setUInt32(UInt32(offset), &loadCommands, at: segment.command.offset + 72 + sectionIndex * 80 + 48)
            }
        }

        for command in layout.commands {
            switch command.command {
            case encryptionInfoCommand, encryptionInfo64Command,
                 dylibCodeSignDRSCommand, linkerOptimizationHintCommand:
                let value = UInt64(loadCommands.uint32LE(at: command.offset + 8))
                let remapped = try remap(value, segments: segments, layout: layout)
                try setUInt32(UInt32(truncatingIfNeeded: remapped), &loadCommands, at: command.offset + 8)
            case filesetEntryCommand:
                let value = loadCommands.uint64LE(at: command.offset + 16)
                let remapped = try remap(value, segments: segments, layout: layout)
                try setUInt64(remapped, &loadCommands, at: command.offset + 16)
            default:
                break
            }
        }

        guard let linkeditIndex = layout.segments.firstIndex(where: { $0.name == "__LINKEDIT" }) else {
            throw StoreAuthError.failure("镜像缺少 __LINKEDIT 段")
        }

        let linkedit = try optimizeLinkedit(source: source,
                                            layout: layout,
                                            loadCommands: &loadCommands,
                                            segments: segments,
                                            linkeditIndex: linkeditIndex,
                                            locals: locals)
        segments[linkeditIndex].newEnd = segments[linkeditIndex].newStart + UInt64(linkedit.count)
        segments[linkeditIndex].newMemorySize = pageAlign(UInt64(linkedit.count))

        // 剥离 in-cache 标记与 LC_DYLD_CHAINED_FIXUPS。
        var outputCommands = Data()
        var removedCommandSize = 0
        var removedCommand = false
        for command in layout.commands {
            if command.command == chainedFixupsCommand && !removedCommand {
                removedCommand = true
                removedCommandSize = command.size
                continue
            }

            outputCommands.append(loadCommands.slice(at: command.offset, count: command.size))
        }

        var outputHeader = header
        try setUInt32(header.uint32LE(at: 24) & ~DyldSharedCache.inCacheFlag, &outputHeader, at: 24)
        let commandCount = layout.commands.count - (removedCommand ? 1 : 0)
        try setUInt32(UInt32(commandCount), &outputHeader, at: 16)
        let outputCommandSize = Int(header.uint32LE(at: 20)) - removedCommandSize
        guard outputCommandSize >= 0 else {
            throw StoreAuthError.failure("Mach-O 加载命令大小无效")
        }
        try setUInt32(UInt32(outputCommandSize), &outputHeader, at: 20)

        var output = Data()
        output.reserveCapacity(Int(segments.last?.newEnd ?? 0))
        output.append(outputHeader)
        output.append(outputCommands)
        let endOfLoads = UInt64(output.count)

        for (index, segment) in layout.segments.enumerated() {
            let entry = segments[index]
            if entry.newFileSize > 0 {
                if UInt64(output.count) < entry.newStart {
                    output.append(Data(count: Int(entry.newStart - UInt64(output.count))))
                }

                if segment.name == "__TEXT" {
                    let data = try source.readAddress(segment.address,
                                                      Int(entry.originalFileSize))
                    let dataStart = max(textRelativeOffset, endOfLoads)
                    guard dataStart <= UInt64(data.count) else {
                        throw StoreAuthError.failure("__TEXT 数据起点超出段范围")
                    }

                    if dataStart > endOfLoads {
                        output.append(Data(count: Int(dataStart - endOfLoads)))
                    }

                    output.append(data.slice(at: Int(dataStart), count: data.count - Int(dataStart)))
                } else if segment.name == "__LINKEDIT" {
                    output.append(linkedit)
                } else {
                    let data = try source.readAddress(segment.address,
                                                      Int(entry.originalFileSize))
                    output.append(data)
                }
            }

            if UInt64(output.count) < entry.newEnd {
                output.append(Data(count: Int(entry.newEnd - UInt64(output.count))))
            }
        }

        if let applySlide = source.applySlide {
            try applySlide(&output)
        }
        return output
    }

    // MARK: - __LINKEDIT 重建

    private static func optimizeLinkedit(source: ExportSource,
                                         layout: MachOLayout,
                                         loadCommands: inout Data,
                                         segments: [ExportSegment],
                                         linkeditIndex: Int,
                                         locals: [Symbol]) throws -> Data {
        guard layout.command(symtabCommand) != nil else {
            throw StoreAuthError.failure("镜像缺少 LC_SYMTAB")
        }
        guard layout.command(dysymtabCommand) != nil else {
            throw StoreAuthError.failure("镜像缺少 LC_DYSYMTAB")
        }

        let linkeditOffset = segments[linkeditIndex].newStart
        var buffer = Data()
        var stringPool = Data([0])

        func readLinkedit(at offset: UInt32, size: UInt32) throws -> Data {
            try source.readLinkedit(offset, size)
        }

        func appendAligned(_ data: Data) {
            buffer.append(data)
            let padding = pointerAlignPad(buffer.count)
            if padding != 0 {
                buffer.append(Data(count: padding))
            }
        }

        // 导出 trie 先解析，随后把原始数据搬到新的 __LINKEDIT。
        var exports: [TrieExport] = []
        if let command = layout.command(dyldExportsTrieCommand) {
            let offset = loadCommands.uint32LE(at: command.offset + 8)
            let size = loadCommands.uint32LE(at: command.offset + 12)
            let trie = try readLinkedit(at: offset, size: size)
            if !trie.isEmpty {
                exports = try parseTrieExports(trie, loadAddress: preferredLoadAddress(layout))
            }

            try setUInt32(UInt32(truncatingIfNeeded: linkeditOffset + UInt64(buffer.count)),
                          &loadCommands, at: command.offset + 8)
            appendAligned(trie)
        }

        if let command = layout.command(dataInCodeCommand) {
            let offset = loadCommands.uint32LE(at: command.offset + 8)
            let size = loadCommands.uint32LE(at: command.offset + 12)
            try setUInt32(UInt32(truncatingIfNeeded: linkeditOffset + UInt64(buffer.count)),
                          &loadCommands, at: command.offset + 8)
            appendAligned(try readLinkedit(at: offset, size: size))
        }

        if let command = layout.command(functionStartsCommand) {
            let offset = loadCommands.uint32LE(at: command.offset + 8)
            let size = loadCommands.uint32LE(at: command.offset + 12)
            try setUInt32(UInt32(truncatingIfNeeded: linkeditOffset + UInt64(buffer.count)),
                          &loadCommands, at: command.offset + 8)
            appendAligned(try readLinkedit(at: offset, size: size))
        }

        for commandValue in [functionVariantsCommand, functionVariantFixupsCommand] {
            guard let command = layout.command(commandValue) else {
                continue
            }

            let offset = loadCommands.uint32LE(at: command.offset + 8)
            let size = loadCommands.uint32LE(at: command.offset + 12)
            try setUInt32(UInt32(truncatingIfNeeded: linkeditOffset + UInt64(buffer.count)),
                          &loadCommands, at: command.offset + 8)
            appendAligned(try readLinkedit(at: offset, size: size))
        }

        if let command = layout.command(dyldInfoCommand) ?? layout.command(dyldInfoOnlyCommand) {
            let pairs = [8, 16, 24, 32, 40]
            for fieldOffset in pairs {
                let offset = loadCommands.uint32LE(at: command.offset + fieldOffset)
                let size = loadCommands.uint32LE(at: command.offset + fieldOffset + 4)
                if size == 0 {
                    continue
                }

                let data = try readLinkedit(at: offset, size: size)
                try setUInt32(UInt32(truncatingIfNeeded: linkeditOffset + UInt64(buffer.count)),
                              &loadCommands, at: command.offset + fieldOffset)
                buffer.append(data)
            }

            let padding = pointerAlignPad(buffer.count)
            if padding != 0 {
                buffer.append(Data(count: padding))
            }
        }

        let symtabOffset = buffer.count
        let symbols = try readSymbols(source: source,
                                      layout: layout,
                                      loadCommands: loadCommands)

        var localSymbols: [Symbol] = []
        var externalSymbols: [Symbol] = []
        var undefinedSymbols: [Symbol] = []

        // 内核集合解析出的导入先写入外部已定义符号。
        for symbol in locals {
            if symbol.type & 0x01 == 0 {
                localSymbols.append(symbol)
            } else if symbol.type & 0x0e == 0x00 {
                undefinedSymbols.append(symbol)
            } else {
                externalSymbols.append(symbol)
            }
        }

        let redacted = Data("<redacted>".utf8)
        for symbol in symbols where symbol.name != redacted {
            if symbol.type & 0x01 == 0 {
                localSymbols.append(symbol)
            } else if symbol.type & 0x0e == 0x00 {
                undefinedSymbols.append(symbol)
            } else {
                externalSymbols.append(symbol)
            }
        }

        var entries: [(symbol: Symbol, name: Data)] = []
        entries.append(contentsOf: localSymbols.map { ($0, $0.name) })
        entries.append(contentsOf: externalSymbols.map { ($0, $0.name) })
        for export in exports where export.flags & 0x03 != 0 || export.flags == 0x08 {
            var name = export.name
            name.append(0)
            name.append(export.reExport)
            entries.append((Symbol(name: export.name, type: 0x0a | 0x01, section: 0,
                                   description: 0, value: export.address), name))
        }
        entries.append(contentsOf: undefinedSymbols.map { ($0, $0.name) })

        for entry in entries {
            guard stringPool.count <= Int(UInt32.max) else {
                throw StoreAuthError.failure("Mach-O 字符串池过大")
            }

            var nlist = Data(count: 16)
            try setUInt32(UInt32(stringPool.count), &nlist, at: 0)
            nlist[4] = entry.symbol.type
            nlist[5] = entry.symbol.section
            try setUInt16(entry.symbol.description, &nlist, at: 6)
            try setUInt64(entry.symbol.value, &nlist, at: 8)
            buffer.append(nlist)
            stringPool.append(entry.name)
            stringPool.append(0)
        }

        let padding = pointerAlignPad(buffer.count)
        if padding != 0 {
            buffer.append(Data(count: padding))
        }

        let indirectOffset = buffer.count
        let dysymtab = layout.command(dysymtabCommand)!
        let indirectCount = UInt32(loadCommands.uint32LE(at: dysymtab.offset + 60))
        let indirectOffsetInSource = UInt32(loadCommands.uint32LE(at: dysymtab.offset + 56))
        guard indirectCount <= 4 << 20 else {
            throw StoreAuthError.failure("镜像的间接符号表过大")
        }
        if indirectCount > 0 {
            var table = try readLinkedit(at: indirectOffsetInSource, size: indirectCount * 4)
            if !locals.isEmpty {
                for offset in stride(from: 0, to: table.count, by: 4) {
                    let value = table.uint32LE(at: offset)
                    if value & 0x8000_0000 != 0 {
                        continue
                    }

                    try setUInt32(value &+ UInt32(locals.count), &table, at: offset)
                }
            }
            buffer.append(table)
        }

        let indirectPadding = pointerAlignPad(buffer.count)
        if indirectPadding != 0 {
            buffer.append(Data(count: indirectPadding))
        }

        let stringPoolOffset = buffer.count
        let stringPadding = pointerAlignPad(stringPool.count)
        if stringPadding != 0 {
            stringPool.append(Data(count: stringPadding))
        }
        buffer.append(stringPool)

        if let command = layout.command(dataInCodeCommand),
           loadCommands.uint32LE(at: command.offset + 12) == 0 {
            try setUInt32(UInt32(truncatingIfNeeded: linkeditOffset + UInt64(symtabOffset)),
                          &loadCommands, at: command.offset + 8)
        }

        let symtab = layout.command(symtabCommand)!
        try setUInt32(UInt32(truncatingIfNeeded: linkeditOffset + UInt64(symtabOffset)),
                      &loadCommands, at: symtab.offset + 8)
        try setUInt32(UInt32(truncatingIfNeeded: entries.count), &loadCommands, at: symtab.offset + 12)
        try setUInt32(UInt32(truncatingIfNeeded: linkeditOffset + UInt64(stringPoolOffset)),
                      &loadCommands, at: symtab.offset + 16)
        try setUInt32(UInt32(stringPool.count), &loadCommands, at: symtab.offset + 20)

        try setUInt32(0, &loadCommands, at: dysymtab.offset + 8)
        try setUInt32(UInt32(localSymbols.count), &loadCommands, at: dysymtab.offset + 12)
        try setUInt32(UInt32(localSymbols.count), &loadCommands, at: dysymtab.offset + 16)
        try setUInt32(UInt32(externalSymbols.count), &loadCommands, at: dysymtab.offset + 20)
        try setUInt32(UInt32(localSymbols.count + externalSymbols.count), &loadCommands, at: dysymtab.offset + 24)
        try setUInt32(UInt32(undefinedSymbols.count), &loadCommands, at: dysymtab.offset + 28)
        try setUInt32(0, &loadCommands, at: dysymtab.offset + 64)
        try setUInt32(0, &loadCommands, at: dysymtab.offset + 68)
        try setUInt32(0, &loadCommands, at: dysymtab.offset + 72)
        try setUInt32(0, &loadCommands, at: dysymtab.offset + 76)
        try setUInt32(indirectCount, &loadCommands, at: dysymtab.offset + 60)
        try setUInt32(UInt32(truncatingIfNeeded: linkeditOffset + UInt64(indirectOffset)),
                      &loadCommands, at: dysymtab.offset + 56)

        // __LINKEDIT 的新大小。
        let linkeditCommand = layout.segments[linkeditIndex].command
        try setUInt64(UInt64(buffer.count), &loadCommands, at: linkeditCommand.offset + 48)
        try setUInt64(pageAlign(UInt64(buffer.count)), &loadCommands, at: linkeditCommand.offset + 32)

        return buffer
    }

    static func readSymbols(source: ExportSource,
                            layout: MachOLayout,
                            loadCommands: Data) throws -> [Symbol] {
        let symtab = layout.command(symtabCommand)!
        let symbolOffset = loadCommands.uint32LE(at: symtab.offset + 8)
        let symbolCount = loadCommands.uint32LE(at: symtab.offset + 12)
        let stringOffset = loadCommands.uint32LE(at: symtab.offset + 16)
        let stringSize = loadCommands.uint32LE(at: symtab.offset + 20)
        guard symbolCount <= 4 << 20,
              validRange(size: source.size,
                         offset: UInt64(symbolOffset),
                         length: UInt64(symbolCount) * 16),
              validRange(size: source.size,
                         offset: UInt64(stringOffset),
                         length: UInt64(stringSize)) else {
            throw StoreAuthError.failure("镜像的符号表区间无效")
        }

        let table = try source.readLinkedit(symbolOffset, symbolCount * 16)
        var symbols: [Symbol] = []
        symbols.reserveCapacity(Int(symbolCount))
        for index in 0..<Int(symbolCount) {
            let base = index * 16
            let nameIndex = table.uint32LE(at: base)
            var name = Data()
            if UInt64(nameIndex) < UInt64(stringSize) {
                name = try readCString(source: source,
                                       offset: UInt64(stringOffset) + UInt64(nameIndex),
                                       limit: UInt64(stringOffset) + UInt64(stringSize))
            }
            name = normalizedSymbolName(name)

            symbols.append(Symbol(name: name,
                                  type: table.byte(at: base + 4),
                                  section: table.byte(at: base + 5),
                                  description: table.uint16LE(at: base + 6),
                                  value: table.uint64LE(at: base + 8)))
        }

        return symbols
    }

    private static func readCString(source: ExportSource,
                                    offset: UInt64,
                                    limit: UInt64) throws -> Data {
        guard validRange(size: source.size, offset: offset, length: 1) else {
            throw StoreAuthError.failure("符号名偏移无效")
        }

        let count = Int(min(UInt64(DyldSharedCache.maximumPathLength), limit - offset))
        let data = try source.readLinkedit(UInt32(offset), UInt32(count))
        guard let end = data.firstIndex(of: 0) else {
            throw StoreAuthError.failure("符号名未终止")
        }

        return data[..<end]
    }

    /// 与 go-macho `parseSymtab` 一致：带点号的符号去掉开头的下划线。
    static func normalizedSymbolName(_ name: Data) -> Data {
        if name.first == 0x5f, name.contains(0x2e) {
            return Data(name.dropFirst())
        }

        return name
    }

    // MARK: - 导出 trie

    private static func parseTrieExports(_ data: Data, loadAddress: UInt64) throws -> [TrieExport] {
        var reader = TrieReader(data: data, position: 0)
        var nodes: [TrieNode] = []
        try parseTrie(&reader, position: 0, cumulative: Data(), depth: 0, nodes: &nodes)

        var exports: [TrieExport] = []
        exports.reserveCapacity(nodes.count)
        for node in nodes {
            var exportReader = TrieReader(data: data, position: node.offset)
            exports.append(try readExport(&exportReader, name: node.name, loadAddress: loadAddress))
        }

        return exports
    }

    private static func parseTrie(_ reader: inout TrieReader,
                                  position: Int,
                                  cumulative: Data,
                                  depth: Int,
                                  nodes: inout [TrieNode]) throws {
        guard depth <= 4096, position >= 0, position <= reader.data.count else {
            throw StoreAuthError.failure("导出 trie 结构无效")
        }

        reader.position = position
        let terminalSize = try reader.readULEB128()
        if terminalSize != 0 {
            nodes.append(TrieNode(offset: reader.position, name: cumulative))
        }

        let next = UInt64(position) + terminalSize + 1
        guard next <= UInt64(Int.max) else {
            throw StoreAuthError.failure("导出 trie 偏移溢出")
        }
        reader.position = Int(next)
        guard let children = reader.readByte() else {
            throw StoreAuthError.failure("导出 trie 缺少子节点数")
        }

        for _ in 0..<children {
            let suffix = reader.readCString()
            let childOffset = try reader.readULEB128()
            guard childOffset <= UInt64(Int.max) else {
                throw StoreAuthError.failure("导出 trie 子节点偏移溢出")
            }

            let current = reader.position
            var child = cumulative
            child.append(suffix)
            try parseTrie(&reader, position: Int(childOffset), cumulative: child, depth: depth + 1, nodes: &nodes)
            reader.position = current
        }
    }

    private static func readExport(_ reader: inout TrieReader,
                                   name: Data,
                                   loadAddress: UInt64) throws -> TrieExport {
        let flags = try reader.readULEB128()
        var reExport = Data()
        if flags == 0x08 {
            _ = try reader.readULEB128()
            reExport = reader.readCString()
        } else if flags == 0x10 {
            _ = try reader.readULEB128() &+ loadAddress
        }

        var value = try reader.readULEB128()
        let kind = flags & 0x03
        if (kind == 0 || kind == 1) && flags != 0x08 {
            value = value &+ loadAddress
        }

        return TrieExport(name: name, reExport: reExport, flags: flags, address: value)
    }

    private static func preferredLoadAddress(_ layout: MachOLayout) -> UInt64 {
        layout.segments.first(where: { $0.name == "__TEXT" })?.address ?? 0
    }

    // MARK: - 辅助

    private static func remap(_ offset: UInt64,
                              segments: [ExportSegment],
                              layout: MachOLayout) throws -> UInt64 {
        for (index, segment) in layout.segments.enumerated() {
            let start = segment.fileOffset
            let end = start + segment.fileSize
            if offset >= start && offset <= end {
                return segments[index].newStart + (offset - start)
            }
        }

        throw StoreAuthError.failure("无法重映射加载命令中的文件偏移")
    }

    private static func pageAlign(_ value: UInt64) -> UInt64 {
        guard value > 0 else {
            return 0
        }

        let remainder = value % pageSize
        return remainder == 0 ? value : value + (pageSize - remainder)
    }

    private static func pointerAlignPad(_ offset: Int) -> Int {
        let remainder = offset % pointerSize
        return remainder == 0 ? 0 : pointerSize - remainder
    }

    private static func validRange(size: Int64, offset: UInt64, length: UInt64) -> Bool {
        guard size >= 0, offset <= UInt64(size) else {
            return false
        }

        return length <= UInt64(size) - offset
    }

    private static func setUInt16(_ value: UInt16, _ data: inout Data, at offset: Int) throws {
        guard offset >= 0, offset + 2 <= data.count else {
            throw StoreAuthError.failure("写入 Mach-O 字段越界")
        }

        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.replaceSubrange(offset..<offset + 2, with: $0) }
    }

    private static func setUInt32(_ value: UInt32, _ data: inout Data, at offset: Int) throws {
        guard offset >= 0, offset + 4 <= data.count else {
            throw StoreAuthError.failure("写入 Mach-O 字段越界")
        }

        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.replaceSubrange(offset..<offset + 4, with: $0) }
    }

    private static func setUInt64(_ value: UInt64, _ data: inout Data, at offset: Int) throws {
        guard offset >= 0, offset + 8 <= data.count else {
            throw StoreAuthError.failure("写入 Mach-O 字段越界")
        }

        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.replaceSubrange(offset..<offset + 8, with: $0) }
    }
}
