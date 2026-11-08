import Foundation

/// dyld 共享缓存的只读访问器，对应 Go 侧 `dyldCache`。
///
/// 只实现导出 in-cache 镜像所需的子集：主缓存与子缓存成员、映射表、
/// 镜像表、slide v5 解码与 `applySlide` 指针回写。
final class DyldSharedCache {
    /// 一个映射：虚拟地址区间与其在成员文件中的位置。
    struct Mapping {
        let address: UInt64
        let size: UInt64
        let fileOffset: UInt64
        let slideInfoOffset: UInt64
        let slideInfoSize: UInt64
        let member: Int
    }

    /// 共享缓存中的一个镜像位置。
    struct Image {
        let member: Int
        let address: UInt64
        let offset: Int64
    }

    /// slide v5 的页面与指针编码参数。
    struct SlideInfo5 {
        let pageSize: UInt32
        let pageStartsCount: UInt32
        let valueAdd: UInt64

        func decode(_ pointer: UInt64) -> UInt64 {
            if pointer == 0 {
                return 0
            }

            var target = pointer & ((UInt64(1) << 34) - 1)
            if pointer >> 63 == 0 {
                target |= (pointer >> 34 & 0xff) << 56
            }

            return valueAdd &+ target
        }
    }

    typealias Opener = (String) throws -> RangeReadable

    static let headerSize = 568
    static let mappingSize = 56
    static let imageInfoSize = 32
    static let subcacheEntrySize = 56
    static let maximumMappings = 64
    static let maximumImages = 100_000
    static let maximumSubcaches = 128
    static let maximumPathLength = 4096
    static let slideInfo5Size = 24
    static let maximumLoadCommandsSize = 16 << 20
    static let maximumSlideChainPointers = 1 << 16
    static let inCacheFlag: UInt32 = 0x8000_0000

    private struct Member {
        let source: RangeReadable
        let size: Int64
        let uuid: Data
        let mappings: [Mapping]
    }

    private var members: [Member]
    let slideInfo: SlideInfo5
    private let primarySize: Int64

    init(opener: Opener) throws {
        let primary = try Self.openMember(opener: opener, suffix: "", memberIndex: 0)
        var members = [primary.member]

        let subcacheOffset = UInt64(primary.header.uint32LE(at: 392))
        let subcacheCount = UInt64(primary.header.uint32LE(at: 396))
        guard subcacheCount <= UInt64(Self.maximumSubcaches) else {
            throw StoreAuthError.failure("共享缓存包含过多的子缓存")
        }
        guard subcacheCount == 0
            || Self.validRange(size: primary.member.size,
                               offset: subcacheOffset,
                               length: subcacheCount * UInt64(Self.subcacheEntrySize)) else {
            throw StoreAuthError.failure("共享缓存的子缓存表无效")
        }

        let entries: Data
        if subcacheCount == 0 {
            entries = Data()
        } else {
            entries = try primary.member.source.readExact(at: Int64(subcacheOffset),
                                                          count: Int(subcacheCount) * Self.subcacheEntrySize)
        }

        for index in 0..<Int(subcacheCount) {
            let base = index * Self.subcacheEntrySize
            let suffixData = entries.slice(at: base + 24, count: 32)
            let suffix = String(decoding: suffixData.prefix { $0 != 0 }, as: UTF8.self)
            guard !suffix.isEmpty, !suffix.contains("/"), !suffix.contains("\\") else {
                throw StoreAuthError.failure("共享缓存包含无效的子缓存后缀")
            }

            let member = try Self.openMember(opener: opener, suffix: suffix, memberIndex: members.count)
            guard member.member.uuid == entries.slice(at: base, count: 16) else {
                throw StoreAuthError.failure("共享缓存子成员 \(suffix) 的 UUID 不匹配")
            }

            members.append(member.member)
        }

        var resolvedSlideInfo: SlideInfo5?
        for member in members {
            for mapping in member.mappings where mapping.slideInfoSize != 0 {
                guard try Self.slideVersion(member: member, mapping: mapping) == 5 else {
                    throw StoreAuthError.failure("共享缓存使用了不支持的 slide 版本")
                }

                let slide = try Self.slideInfo(member: member, mapping: mapping)
                if let existing = resolvedSlideInfo {
                    guard existing.pageSize == slide.pageSize, existing.valueAdd == slide.valueAdd else {
                        throw StoreAuthError.failure("共享缓存成员的 slide 参数不一致")
                    }
                } else {
                    resolvedSlideInfo = slide
                }
            }
        }

        guard let resolvedSlideInfo else {
            throw StoreAuthError.failure("共享缓存不包含 slide 信息")
        }

        self.members = members
        slideInfo = resolvedSlideInfo
        primarySize = primary.member.size
    }

    // MARK: - 成员与映射

    func size(ofMember index: Int) -> Int64 {
        members[index].size
    }

    func read(member: Int, at offset: Int64, count: Int) throws -> Data {
        guard count >= 0, offset >= 0 else {
            throw StoreAuthError.failure("共享缓存读取区间无效")
        }

        return try members[member].source.readExact(at: offset, count: count)
    }

    /// 按虚拟地址读取，跨映射时自动分段（对应 Go 的 `ReadAtAddr`）。
    func read(atAddress address: UInt64, count: Int) throws -> Data {
        guard count >= 0 else {
            throw StoreAuthError.failure("共享缓存读取长度为负")
        }

        var output = Data(capacity: count)
        var current = address
        var remaining = count
        while remaining > 0 {
            guard let located = mapping(forAddress: current) else {
                throw StoreAuthError.failure("虚拟地址超出共享缓存范围：\(String(format: "0x%llx", current))")
            }

            let mapping = located.mapping
            let available = mapping.address + mapping.size - current
            let chunk = min(UInt64(remaining), available)
            let offset = mapping.fileOffset + current - mapping.address
            let data = try read(member: located.member, at: Int64(offset), count: Int(chunk))
            guard data.count == Int(chunk) else {
                throw StoreAuthError.failure("共享缓存映射读取不完整")
            }

            output.append(data)
            current += chunk
            remaining -= Int(chunk)
        }

        return output
    }

    func mapping(forAddress address: UInt64) -> (member: Int, mapping: Mapping)? {
        for (memberIndex, member) in members.enumerated() {
            for mapping in member.mappings where mapping.address <= address && address - mapping.address < mapping.size {
                return (memberIndex, mapping)
            }
        }

        return nil
    }

    // MARK: - 镜像表

    func image(at path: String) throws -> Image {
        let header = try members[0].source.readExact(at: 0, count: Self.headerSize)
        let imagesOffset = UInt64(header.uint32LE(at: 448))
        let imagesCount = UInt64(header.uint32LE(at: 452))
        guard imagesCount > 0, imagesCount <= UInt64(Self.maximumImages),
              Self.validRange(size: primarySize, offset: imagesOffset,
                              length: imagesCount * UInt64(Self.imageInfoSize)) else {
            throw StoreAuthError.failure("共享缓存的镜像表无效")
        }

        let table = try members[0].source.readExact(at: Int64(imagesOffset),
                                                    count: Int(imagesCount) * Self.imageInfoSize)
        for index in 0..<Int(imagesCount) {
            let base = index * Self.imageInfoSize
            let address = table.uint64LE(at: base)
            let pathOffset = UInt64(table.uint32LE(at: base + 24))
            let name = try Self.readCString(member: members[0], offset: pathOffset)
            if name != path {
                continue
            }

            guard let located = mapping(forAddress: address) else {
                throw StoreAuthError.failure("共享缓存镜像地址不在映射内")
            }

            return Image(member: located.member,
                         address: address,
                         offset: Int64(located.mapping.fileOffset + address - located.mapping.address))
        }

        throw StoreAuthError.failure("共享缓存中未找到镜像 \(path)")
    }

    // MARK: - Slide

    /// 把导出的镜像中的 slide 链目标写回文件（对应 Go 的 `applySlide`）。
    func applySlide(_ data: inout Data) throws {
        guard data.count >= 32 else {
            throw StoreAuthError.failure("导出镜像过小")
        }

        let header = data.slice(at: 0, count: 32)
        let commandSize = Int(header.uint32LE(at: 20))
        guard commandSize >= 0, commandSize <= data.count - 32 else {
            throw StoreAuthError.failure("导出镜像的加载命令无效")
        }

        let layout = try MachOLayout(header: header,
                                     loadCommands: data.slice(at: 32, count: commandSize))
        for segment in layout.segments {
            guard let located = mapping(forAddress: segment.address) else {
                throw StoreAuthError.failure("导出镜像的段不在共享缓存内：\(segment.name)")
            }

            let mapping = located.mapping
            if mapping.slideInfoOffset == 0 {
                continue
            }

            let slide = try Self.slideInfo(member: members[located.member], mapping: mapping)
            let pageSize = UInt64(slide.pageSize)
            let start = (segment.address - mapping.address) / pageSize
            let end = (segment.address + segment.memorySize - mapping.address + pageSize) / pageSize
            let rebases = try rebases(mapping: mapping, startPage: start, endPage: end)
            for rebase in rebases {
                guard let offset = exportedOffset(of: rebase.address, in: layout),
                      offset <= UInt64(Int.max - 8) else {
                    continue
                }

                let index = Int(offset)
                if index + 8 > data.count {
                    data.append(Data(count: index + 8 - data.count))
                }

                Self.writeUInt64LE(rebase.target, to: &data, at: index)
            }
        }
    }

    private func rebases(mapping: Mapping,
                         startPage: UInt64,
                         endPage: UInt64) throws -> [(address: UInt64, target: UInt64)] {
        let member = members[mapping.member]
        guard try Self.slideVersion(member: member, mapping: mapping) == 5 else {
            throw StoreAuthError.failure("共享缓存使用了不支持的 slide 版本")
        }

        let slide = try Self.slideInfo(member: member, mapping: mapping)
        let starts = try Self.slideStarts(member: member, mapping: mapping, count: slide.pageStartsCount)
        var end = endPage
        if end == 0 || end > UInt64(starts.count) {
            end = UInt64(starts.count)
        }
        guard startPage <= end else {
            throw StoreAuthError.failure("共享缓存 slide 页面区间无效")
        }

        var output: [(address: UInt64, target: UInt64)] = []
        for page in startPage..<end {
            let start = UInt64(starts[Int(page)])
            if start == 0xffff {
                continue
            }

            let pageSize = UInt64(slide.pageSize)
            let pageFileOffset = mapping.fileOffset + page * pageSize
            let pageAddress = mapping.address + page * pageSize
            var offset = start
            for count in 0..<Self.maximumSlideChainPointers {
                guard offset + 8 <= pageSize else {
                    throw StoreAuthError.failure("共享缓存 slide 链越过了页面边界")
                }

                let data = try member.source.readExact(at: Int64(pageFileOffset + offset), count: 8)
                let pointer = data.uint64LE(at: 0)
                output.append((pageAddress + offset, slide.decode(pointer)))
                let next = pointer >> 52 & 0x7ff
                if next == 0 {
                    break
                }

                offset += next * 8
                if count == Self.maximumSlideChainPointers - 1 {
                    throw StoreAuthError.failure("共享缓存 slide 链过长")
                }
            }
        }

        return output
    }

    private func exportedOffset(of address: UInt64, in layout: MachOLayout) -> UInt64? {
        for segment in layout.segments
        where address >= segment.address && address - segment.address < segment.memorySize {
            return segment.fileOffset + (address - segment.address)
        }

        return nil
    }

    private static func slideVersion(member: Member, mapping: Mapping) throws -> UInt32 {
        guard mapping.slideInfoSize >= 4 else {
            throw StoreAuthError.failure("共享缓存的 slide 信息被截断")
        }

        let data = try member.source.readExact(at: Int64(mapping.slideInfoOffset), count: 4)
        return data.uint32LE(at: 0)
    }

    private static func slideInfo(member: Member, mapping: Mapping) throws -> SlideInfo5 {
        guard mapping.slideInfoSize >= UInt64(slideInfo5Size) else {
            throw StoreAuthError.failure("共享缓存的 slide 信息被截断")
        }

        let data = try member.source.readExact(at: Int64(mapping.slideInfoOffset), count: slideInfo5Size)
        guard data.uint32LE(at: 0) == 5 else {
            throw StoreAuthError.failure("共享缓存使用了不支持的 slide 版本")
        }

        let info = SlideInfo5(pageSize: data.uint32LE(at: 4),
                              pageStartsCount: data.uint32LE(at: 8),
                              valueAdd: data.uint64LE(at: 16))
        guard info.pageSize != 0,
              UInt64(slideInfo5Size) + UInt64(info.pageStartsCount) * 2 <= mapping.slideInfoSize else {
            throw StoreAuthError.failure("共享缓存的 slide 信息无效")
        }

        return info
    }

    private static func slideStarts(member: Member, mapping: Mapping, count: UInt32) throws -> [UInt16] {
        guard count > 0 else {
            return []
        }

        let data = try member.source.readExact(at: Int64(mapping.slideInfoOffset + UInt64(slideInfo5Size)),
                                               count: Int(count) * 2)
        var values: [UInt16] = []
        values.reserveCapacity(Int(count))
        for index in 0..<Int(count) {
            values.append(data.uint16LE(at: index * 2))
        }

        return values
    }

    // MARK: - 成员打开

    private static func openMember(opener: Opener,
                                   suffix: String,
                                   memberIndex: Int) throws -> (member: Member, header: Data) {
        let source = try opener(suffix)
        let size = source.size
        guard size >= Int64(headerSize) else {
            throw StoreAuthError.failure("共享缓存成员 \(suffix) 过小")
        }

        let header = try source.readExact(at: 0, count: headerSize)
        let magic = String(decoding: header.prefix(16).prefix { $0 != 0 }, as: UTF8.self)
        guard magic == "dyld_v1  arm64e" else {
            throw StoreAuthError.failure("不支持的共享缓存格式 \(magic)")
        }

        let mappingOffset = UInt64(header.uint32LE(at: 312))
        let mappingCount = UInt64(header.uint32LE(at: 316))
        guard mappingCount > 0, mappingCount <= UInt64(maximumMappings),
              validRange(size: size, offset: mappingOffset,
                         length: mappingCount * UInt64(mappingSize)) else {
            throw StoreAuthError.failure("共享缓存成员的映射表无效")
        }

        let mappingData = try source.readExact(at: Int64(mappingOffset),
                                               count: Int(mappingCount) * mappingSize)
        let uuid = header.slice(at: 88, count: 16)
        var mappings: [Mapping] = []
        mappings.reserveCapacity(Int(mappingCount))
        for index in 0..<Int(mappingCount) {
            let base = index * mappingSize
            let address = mappingData.uint64LE(at: base)
            let size = mappingData.uint64LE(at: base + 8)
            let fileOffset = mappingData.uint64LE(at: base + 16)
            let slideInfoOffset = mappingData.uint64LE(at: base + 24)
            let slideInfoSize = mappingData.uint64LE(at: base + 32)
            guard size > 0, address &+ size >= address,
                  validRange(size: source.size, offset: fileOffset, length: size),
                  slideInfoSize == 0
                    || validRange(size: source.size, offset: slideInfoOffset, length: slideInfoSize) else {
                throw StoreAuthError.failure("共享缓存成员包含无效映射")
            }

            mappings.append(Mapping(address: address,
                                    size: size,
                                    fileOffset: fileOffset,
                                    slideInfoOffset: slideInfoOffset,
                                    slideInfoSize: slideInfoSize,
                                    member: memberIndex))
        }

        return (Member(source: source, size: source.size, uuid: uuid, mappings: mappings), header)
    }

    private static func readCString(member: Member, offset: UInt64) throws -> String {
        guard validRange(size: member.size, offset: offset, length: 1) else {
            throw StoreAuthError.failure("共享缓存包含无效的字符串偏移")
        }

        let limit = min(UInt64(maximumPathLength), UInt64(member.size) - offset)
        let data = try member.source.readExact(at: Int64(offset), count: Int(limit))
        guard let end = data.firstIndex(of: 0) else {
            throw StoreAuthError.failure("共享缓存字符串未终止")
        }

        return String(decoding: data[..<end], as: UTF8.self)
    }

    private static func validRange(size: Int64, offset: UInt64, length: UInt64) -> Bool {
        guard size >= 0, offset <= UInt64(size) else {
            return false
        }

        return length <= UInt64(size) - offset
    }

    private static func writeUInt64LE(_ value: UInt64, to data: inout Data, at offset: Int) {
        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.replaceSubrange(offset..<offset + 8, with: $0) }
    }
}
