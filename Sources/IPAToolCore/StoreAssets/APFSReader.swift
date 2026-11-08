import Foundation

/// 一个 APFS 块设备：既接受裸 APFS 容器，也接受 UDIF 磁盘映像。
final class APFSBlockDevice {
    static let blockSize = 4096

    let source: RangeReadable
    var size: Int64 { source.size }

    init(source: RangeReadable) throws {
        let header = try source.readExact(at: 0, count: 36)
        if header.slice(at: 32, count: 4) == Data("NXSB".utf8) {
            self.source = source
        } else {
            self.source = try UDIFDiskImage(source: source)
        }
    }

    func readBlock(_ address: UInt64) throws -> Data {
        guard address <= UInt64(Int64.max / Int64(Self.blockSize)) else {
            throw StoreAuthError.failure("APFS 块地址溢出：\(address)")
        }

        return try source.readExact(at: Int64(address) * Int64(Self.blockSize), count: Self.blockSize)
    }
}

/// APFS 中一个逻辑到物理的连续区间。
struct APFSExtent {
    let logical: Int64
    let physical: UInt64
    let length: Int64
}

/// 只读 APFS 卷解析器，对应 Go 侧 `apfsExtractor`。
///
/// 只实现提取资产所需的最小子集：容器/卷 superblock、容器与卷 OMAP、
/// 命名空间 B-tree 遍历、inode/extent/xattr/drec 记录、以及 sealed 节点校验。
final class APFSReader {
    static let fsRootOID: UInt64 = 2

    private static let blockSize = APFSBlockDevice.blockSize
    private static let objectTypeMask: UInt32 = 0x0000_FFFF
    private static let objectTypeNXSuperblock: UInt32 = 1
    private static let objectTypeOMap: UInt32 = 11
    private static let nodeRootFlag: UInt16 = 0x0001
    private static let nodeLeafFlag: UInt16 = 0x0002
    private static let nodeFixedKVFlag: UInt16 = 0x0004
    private static let nodeHashedFlag: UInt16 = 0x0008
    private static let maximumTreeDepth = 32
    private static let btreeInfoSize = 40
    private static let nodeHeaderSize = 56

    private static let keyTypeInode: UInt64 = 3
    private static let keyTypeXattr: UInt64 = 4
    private static let keyTypeFileExtent: UInt64 = 8
    private static let keyTypeDirectoryEntry: UInt64 = 9
    private static let objectIDMask: UInt64 = 0x0FFF_FFFF_FFFF_FFFF
    private static let objectTypeShift: UInt64 = 60

    private static let xattrDataStream: UInt16 = 0x0001
    private static let xattrDataEmbedded: UInt16 = 0x0002
    private static let decmpfsXattrName = "com.apple.decmpfs"
    private static let resourceForkXattrName = "com.apple.ResourceFork"

    private let device: APFSBlockDevice
    private let fsRootBase: UInt64
    private let volumeXid: UInt64
    private let transactionID: UInt64
    private let volumeOmapRoot: APFSReader.Node
    private let fsRootNode: APFSReader.Node
    private let fextTreeOID: UInt64

    private struct Node {
        let block: Data
        let flags: UInt16
        let level: UInt16
        let keyCount: Int
        let tableSpaceLength: Int

        var isRoot: Bool { flags & APFSReader.nodeRootFlag != 0 }
        var isLeaf: Bool { flags & APFSReader.nodeLeafFlag != 0 }
        var isFixedKV: Bool { flags & APFSReader.nodeFixedKVFlag != 0 }
        var isHashed: Bool { flags & APFSReader.nodeHashedFlag != 0 }
    }

    private struct Entry {
        let keyOffset: Int
        let keyLength: Int
        let valueOffset: Int
        let valueLength: Int
    }

    private struct Inode {
        var privateID: UInt64 = 0
        var uncompressedSize: UInt64 = 0
        var dataStreamSize: UInt64?
    }

    private struct ExtendedAttribute {
        let name: String
        let flags: UInt16
        let embeddedData: Data
        let streamObjectID: UInt64
        let streamSize: UInt64
    }

    init(source: RangeReadable) throws {
        let device = try APFSBlockDevice(source: source)
        self.device = device

        let container = try APFSReader.containerSuperblock(device: device)
        guard container.uint64LE(at: 96) > 0 else {
            throw StoreAuthError.failure("APFS 容器的 xid 无效")
        }

        let containerOmapOID = container.uint64LE(at: 160)
        let (containerOmap, _) = try APFSReader.omapRoot(
            device: device, objectAddress: containerOmapOID
        )

        let maximumFileSystems = min(Int(container.uint32LE(at: 180)), 100)
        var volumeOID: UInt64 = 0
        for index in 0..<max(maximumFileSystems, 1) {
            let candidate = container.uint64LE(at: 184 + index * 8)
            if candidate != 0 {
                volumeOID = candidate
                break
            }
        }
        guard volumeOID != 0 else {
            throw StoreAuthError.failure("APFS 容器中没有卷")
        }

        let containerXid = container.uint64LE(at: 16)
        let volumeAddress = try APFSReader.omapLookup(
            device: device, root: containerOmap, objectID: volumeOID, maximumXid: containerXid
        )
        let volume = try device.readBlock(volumeAddress)
        guard APFSReader.fletcherVerified(volume),
              String(decoding: volume.slice(at: 32, count: 4), as: UTF8.self) == "APSB" else {
            throw StoreAuthError.failure("APFS 卷 superblock 无效")
        }

        let volumeOmapOID = volume.uint64LE(at: 128)
        let (volumeOmap, volumeOmapXid) = try APFSReader.omapRoot(
            device: device, objectAddress: volumeOmapOID
        )
        volumeOmapRoot = volumeOmap
        // 卷根树用卷 superblock 的 xid 查找；树内子节点用卷 OMAP 对象的 xid
        // （与 Go 参考实现 `NewAPFS` / `apfsExtractor.transactionID` 一致）。
        volumeXid = volume.uint64LE(at: 16)
        transactionID = volumeOmapXid

        let rootTreeOID = volume.uint64LE(at: 136)
        fsRootBase = rootTreeOID
        let rootAddress = try APFSReader.omapLookup(
            device: device, root: volumeOmapRoot, objectID: rootTreeOID, maximumXid: volumeXid
        )
        let rootBlock = try device.readBlock(rootAddress)
        fsRootNode = try APFSReader.parseNode(rootBlock)

        // apfs_fext_tree_oid 位于 apfs_superblock_t 的第 1032 字节。
        fextTreeOID = volume.uint64LE(at: 1032)
    }

    // MARK: - 文件访问

    /// 打开卷内路径对应的文件，返回可按范围读取的句柄。
    func openFile(at path: String) throws -> RangeReadable {
        let objectID = try resolveObjectID(path: path)
        let records: [Record] = try records(for: objectID)

        guard let inode = records.compactMap({ record -> Inode? in
            if case let .inode(inode) = record { return inode }
            return nil
        }).first else {
            throw StoreAuthError.failure("文件缺少 inode 记录：\(path)")
        }

        var compression: (method: UInt32, size: UInt64)?
        var resourceFork: (objectID: UInt64, size: UInt64)?
        var extents: [APFSExtent] = []

        for record in records {
            switch record {
            case let .fileExtent(extent):
                extents.append(extent)
            case let .xattr(xattr):
                if xattr.name == APFSReader.decmpfsXattrName {
                    compression = try APFSReader.decmpfsHeader(xattr.embeddedData)
                } else if xattr.name == APFSReader.resourceForkXattrName {
                    resourceFork = (xattr.streamObjectID, xattr.streamSize)
                }
            default:
                break
            }
        }

        if let compression {
            guard [8, 12, 14].contains(compression.method) else {
                throw StoreAuthError.failure("文件使用了不支持的 decmpfs 压缩类型 \(compression.method)")
            }
            guard let resourceFork else {
                throw StoreAuthError.failure("压缩文件缺少资源分支：\(path)")
            }

            let resourceExtents = try dataExtents(objectID: resourceFork.objectID)
            let resourceReader = try APFSExtentReader(device: device,
                                                      extents: resourceExtents,
                                                      size: resourceFork.size)
            return try DecmpfsReader(source: resourceReader,
                                     outputSize: compression.size,
                                     method: compression.method)
        }

        let size = inode.dataStreamSize ?? inode.uncompressedSize
        if extents.isEmpty, size != 0 {
            extents = try dataExtents(objectID: inode.privateID)
        }

        return try APFSExtentReader(device: device, extents: extents, size: size)
    }

    /// 把卷内文件写入目标路径。
    func extractFile(at path: String, to destination: URL) throws {
        let reader = try openFile(at: path)

        guard FileManager.default.createFile(atPath: destination.path, contents: nil) else {
            throw StoreAuthError.failure("无法创建输出文件 \(destination.path)")
        }

        let handle = try FileHandle(forWritingTo: destination)
        defer { try? handle.close() }

        let chunkSize = 4 << 20
        var offset: Int64 = 0
        while offset < reader.size {
            let count = Int(min(Int64(chunkSize), reader.size - offset))
            let data = try reader.read(at: offset, count: count)
            guard !data.isEmpty else {
                throw StoreAuthError.failure("文件在 offset \(offset) 处提前结束：\(path)")
            }
            try handle.write(contentsOf: data)
            offset += Int64(data.count)
        }
    }

    // MARK: - 路径与记录

    private func resolveObjectID(path: String) throws -> UInt64 {
        var objectID = APFSReader.fsRootOID

        for component in path.split(separator: "/") {
            let name = String(component)
            let records = try records(for: objectID)
            var found: UInt64?

            for record in records {
                if case let .directoryEntry(entryName, fileID) = record, entryName == name {
                    found = fileID
                    break
                }
            }

            guard let found else {
                throw StoreAuthError.failure("APFS 路径不存在：\(path)（缺少 \(name)）")
            }
            objectID = found
        }

        return objectID
    }

    private enum Record {
        case inode(Inode)
        case fileExtent(APFSExtent)
        case xattr(ExtendedAttribute)
        case directoryEntry(name: String, fileID: UInt64)
        case other
    }

    private func records(for objectID: UInt64) throws -> [Record] {
        var output: [Record] = []
        var visited: Set<UInt64> = []
        try collectRecords(node: fsRootNode, objectID: objectID, depth: 0,
                           visited: &visited, into: &output)
        return output
    }

    private func collectRecords(node: Node, objectID: UInt64, depth: Int,
                                visited: inout Set<UInt64>, into: inout [Record]) throws {
        guard depth <= APFSReader.maximumTreeDepth else {
            throw StoreAuthError.failure("APFS 文件系统树超过最大深度")
        }

        let entries = try entries(of: node)
        if node.isLeaf {
            for entry in entries {
                let key = try keyData(node: node, entry: entry)
                guard key.count >= 8 else {
                    continue
                }

                let idAndType = key.uint64LE(at: 0)
                guard idAndType & APFSReader.objectIDMask == objectID else {
                    continue
                }

                let type = (idAndType >> APFSReader.objectTypeShift) & 0xF
                let value = try valueData(node: node, entry: entry)
                into.append(try parseRecord(type: type, key: key, value: value))
            }
            return
        }

        for index in entries.indices {
            let entry = entries[index]
            let key = try keyData(node: node, entry: entry)
            guard key.count >= 8 else {
                continue
            }

            let lower = key.uint64LE(at: 0) & APFSReader.objectIDMask
            var upper = UInt64.max
            if index + 1 < entries.count {
                let nextKey = try keyData(node: node, entry: entries[index + 1])
                if nextKey.count >= 8 {
                    upper = nextKey.uint64LE(at: 0) & APFSReader.objectIDMask
                }
            }
            if objectID < lower || objectID > upper {
                continue
            }

            let child = try childReference(node: node, entry: entry)
            guard !visited.contains(child.address) else {
                continue
            }
            visited.insert(child.address)

            let block = try device.readBlock(child.address)
            if let hash = child.hash, AssetCrypto.sha256(block) != hash {
                throw StoreAuthError.failure("APFS sealed 节点 SHA-256 不匹配")
            }

            let childNode = try APFSReader.parseNode(block)
            try collectRecords(node: childNode, objectID: objectID, depth: depth + 1,
                               visited: &visited, into: &into)
        }
    }

    private func childReference(node: Node, entry: Entry) throws -> (address: UInt64, hash: Data?) {
        let value = try valueData(node: node, entry: entry)
        guard value.count >= 8 else {
            throw StoreAuthError.failure("APFS 树索引项缺少子节点引用")
        }

        if node.isHashed {
            guard value.count >= 40 else {
                throw StoreAuthError.failure("APFS sealed 索引项被截断")
            }
            let childOID = value.uint64LE(at: 0)
            let objectID = fsRootBase &+ childOID
            let address = try APFSReader.omapLookup(
                device: device, root: volumeOmapRoot, objectID: objectID, maximumXid: transactionID
            )
            return (address, value.slice(at: 8, count: 32))
        }

        let objectID = value.uint64LE(at: 0)
        let address = try APFSReader.omapLookup(
            device: device, root: volumeOmapRoot, objectID: objectID, maximumXid: transactionID
        )
        return (address, nil)
    }

    private func parseRecord(type: UInt64, key: Data, value: Data) throws -> Record {
        switch type {
        case APFSReader.keyTypeInode:
            guard value.count >= 92 else {
                throw StoreAuthError.failure("APFS inode 记录被截断")
            }
            var inode = Inode(
                privateID: value.uint64LE(at: 8),
                uncompressedSize: value.uint64LE(at: 84)
            )
            inode.dataStreamSize = APFSReader.dataStreamSize(inodeValue: value)
            return .inode(inode)

        case APFSReader.keyTypeFileExtent:
            guard key.count >= 16, value.count >= 24 else {
                throw StoreAuthError.failure("APFS 文件区间记录被截断")
            }
            let logical = key.uint64LE(at: 8)
            let length = value.uint64LE(at: 0) & 0x00FF_FFFF_FFFF_FFFF
            let physical = value.uint64LE(at: 8)
            guard logical <= UInt64(Int64.max), length <= UInt64(Int64.max) else {
                throw StoreAuthError.failure("APFS 文件区间溢出")
            }
            return .fileExtent(APFSExtent(logical: Int64(logical),
                                          physical: physical,
                                          length: Int64(length)))

        case APFSReader.keyTypeXattr:
            guard key.count >= 10, value.count >= 4 else {
                throw StoreAuthError.failure("APFS 扩展属性记录被截断")
            }
            let nameLength = Int(key.uint16LE(at: 8))
            guard 10 + nameLength <= key.count else {
                throw StoreAuthError.failure("APFS 扩展属性名被截断")
            }
            let name = APFSReader.trimmedName(key.slice(at: 10, count: nameLength))
            let flags = value.uint16LE(at: 0)
            let dataLength = Int(value.uint16LE(at: 2))

            if flags & APFSReader.xattrDataEmbedded != 0 {
                guard 4 + dataLength <= value.count else {
                    throw StoreAuthError.failure("APFS 扩展属性数据被截断")
                }
                return .xattr(ExtendedAttribute(
                    name: name, flags: flags,
                    embeddedData: value.slice(at: 4, count: dataLength),
                    streamObjectID: 0, streamSize: 0
                ))
            }

            guard value.count >= 52 else {
                throw StoreAuthError.failure("APFS 扩展属性数据流被截断")
            }
            return .xattr(ExtendedAttribute(
                name: name, flags: flags, embeddedData: Data(),
                streamObjectID: value.uint64LE(at: 4),
                streamSize: value.uint64LE(at: 12)
            ))

        case APFSReader.keyTypeDirectoryEntry:
            guard key.count >= 12, value.count >= 8 else {
                throw StoreAuthError.failure("APFS 目录项记录被截断")
            }
            let nameLength = Int(key.uint32LE(at: 8) & 0x3FF)
            guard 12 + nameLength <= key.count else {
                throw StoreAuthError.failure("APFS 目录项名被截断")
            }
            let name = APFSReader.trimmedName(key.slice(at: 12, count: nameLength))
            return .directoryEntry(name: name, fileID: value.uint64LE(at: 0))

        default:
            return .other
        }
    }

    /// APFS 的 drec/xattr 名称长度包含结尾的 NUL，与 Go 侧 `strings.Trim(name, "\x00")` 一致。
    private static func trimmedName(_ data: Data) -> String {
        var start = 0
        var end = data.count
        while start < end, data[start] == 0 {
            start += 1
        }
        while end > start, data[end - 1] == 0 {
            end -= 1
        }

        return String(decoding: data[start..<end], as: UTF8.self)
    }

    /// 从 inode 值的 xfields 中找 dstream 长度。
    private static func dataStreamSize(inodeValue value: Data) -> UInt64? {
        guard value.count > 92 else {
            return nil
        }

        let numberOfExtents = Int(value.uint16LE(at: 92))
        guard numberOfExtents > 0 else {
            return nil
        }

        var headerOffset = 96
        var dataOffset = 96 + numberOfExtents * 4
        guard dataOffset <= value.count else {
            return nil
        }

        for _ in 0..<numberOfExtents {
            guard headerOffset + 4 <= value.count else {
                return nil
            }
            let type = value.byte(at: headerOffset)
            let size = Int(value.uint16LE(at: headerOffset + 2))
            headerOffset += 4

            if dataOffset + size > value.count {
                return nil
            }
            if type == 8, size >= 8 {
                return value.uint64LE(at: dataOffset)
            }

            dataOffset += size
            let padding = (8 - size % 8) % 8
            dataOffset += padding
        }

        return nil
    }

    // MARK: - decmpfs 头

    private static func decmpfsHeader(_ data: Data) throws -> (method: UInt32, size: UInt64) {
        // 魔数 0x636d7066（"cmpf"）以小端序存储，文件里呈现为 "fpmc"。
        guard data.count >= 16, data.uint32LE(at: 0) == 0x636D_7066 else {
            throw StoreAuthError.failure("decmpfs 头无效")
        }

        return (data.uint32LE(at: 4), data.uint64LE(at: 8))
    }

    // MARK: - 物理区间

    private func dataExtents(objectID: UInt64) throws -> [APFSExtent] {
        if fextTreeOID != 0 {
            return try physicalExtents(objectID: objectID)
        }

        return try records(for: objectID).compactMap { record in
            if case let .fileExtent(extent) = record {
                return extent
            }
            return nil
        }
    }

    /// sealed 卷的物理区间树（fext tree），key 为 (private_id, logical_addr)。
    private func physicalExtents(objectID: UInt64) throws -> [APFSExtent] {
        let rootBlock = try device.readBlock(fextTreeOID)
        let root = try APFSReader.parseNode(rootBlock)

        var extents: [APFSExtent] = []
        var visited: Set<UInt64> = []
        try collectPhysicalExtents(node: root, objectID: objectID, depth: 0,
                                   visited: &visited, into: &extents)
        extents.sort { $0.logical < $1.logical }
        return extents
    }

    private func collectPhysicalExtents(node: Node, objectID: UInt64, depth: Int,
                                        visited: inout Set<UInt64>,
                                        into: inout [APFSExtent]) throws {
        guard depth <= APFSReader.maximumTreeDepth else {
            throw StoreAuthError.failure("APFS 物理区间树超过最大深度")
        }

        let entries = try entries(of: node)
        if node.isLeaf {
            for entry in entries {
                let key = try keyData(node: node, entry: entry)
                guard key.count >= 16, key.uint64LE(at: 0) == objectID else {
                    continue
                }
                let value = try valueData(node: node, entry: entry)
                guard value.count >= 16 else {
                    throw StoreAuthError.failure("APFS 物理区间记录被截断")
                }
                let length = value.uint64LE(at: 0) & 0x00FF_FFFF_FFFF_FFFF
                let logical = key.uint64LE(at: 8)
                guard logical <= UInt64(Int64.max), length <= UInt64(Int64.max) else {
                    throw StoreAuthError.failure("APFS 物理区间溢出")
                }
                into.append(APFSExtent(logical: Int64(logical),
                                       physical: value.uint64LE(at: 8),
                                       length: Int64(length)))
            }
            return
        }

        for index in entries.indices {
            let entry = entries[index]
            let key = try keyData(node: node, entry: entry)
            guard key.count >= 8 else {
                continue
            }
            let lower = key.uint64LE(at: 0)
            var upper = UInt64.max
            if index + 1 < entries.count {
                let nextKey = try keyData(node: node, entry: entries[index + 1])
                if nextKey.count >= 8 {
                    upper = nextKey.uint64LE(at: 0)
                }
            }
            if objectID < lower || objectID > upper {
                continue
            }

            let value = try valueData(node: node, entry: entry)
            guard value.count >= 8 else {
                throw StoreAuthError.failure("APFS 物理区间树索引项被截断")
            }
            let address = value.uint64LE(at: 0)
            guard !visited.contains(address) else {
                continue
            }
            visited.insert(address)

            let block = try device.readBlock(address)
            let child = try APFSReader.parseNode(block)
            try collectPhysicalExtents(node: child, objectID: objectID, depth: depth + 1,
                                       visited: &visited, into: &into)
        }
    }

    // MARK: - B-tree 节点

    private func entries(of node: Node) throws -> [Entry] {
        try APFSReader.entries(of: node)
    }

    private func keyData(node: Node, entry: Entry) throws -> Data {
        try APFSReader.keyData(node: node, entry: entry)
    }

    private func valueData(node: Node, entry: Entry) throws -> Data {
        try APFSReader.valueData(node: node, entry: entry)
    }

    private static func parseNode(_ block: Data) throws -> Node {
        guard block.count == blockSize else {
            throw StoreAuthError.failure("APFS 节点块尺寸为 \(block.count)，期望 \(blockSize)")
        }

        let flags = block.uint16LE(at: 32)
        let level = block.uint16LE(at: 34)
        let keyCount = Int(block.uint32LE(at: 36))
        let tableSpaceLength = Int(block.uint16LE(at: 42))

        guard keyCount >= 0, keyCount <= blockSize / 4 else {
            throw StoreAuthError.failure("APFS 节点 key 数量无效")
        }

        return Node(block: block, flags: flags, level: level,
                    keyCount: keyCount, tableSpaceLength: tableSpaceLength)
    }

    // MARK: - OMAP

    private static func omapRoot(device: APFSBlockDevice,
                                 objectAddress: UInt64) throws -> (root: Node, xid: UInt64) {
        guard objectAddress != 0 else {
            throw StoreAuthError.failure("APFS 对象映射表地址为空")
        }

        let object = try device.readBlock(objectAddress)
        guard fletcherVerified(object),
              object.uint32LE(at: 24) & objectTypeMask == objectTypeOMap else {
            throw StoreAuthError.failure("APFS 对象映射表无效")
        }

        let treeOID = object.uint64LE(at: 48)
        let treeBlock = try device.readBlock(treeOID)
        return (try parseNode(treeBlock), object.uint64LE(at: 16))
    }

    private static func omapLookup(device: APFSBlockDevice, root: Node,
                                   objectID: UInt64, maximumXid: UInt64) throws -> UInt64 {
        var node = root

        for _ in 0...maximumTreeDepth {
            let entries = try entries(of: node)
            var chosenKey: (objectID: UInt64, xid: UInt64)?
            var chosenValue = Data()

            for entry in entries {
                let key = try keyData(node: node, entry: entry)
                guard key.count >= 16 else {
                    throw StoreAuthError.failure("APFS 对象映射键被截断")
                }
                let keyObject = key.uint64LE(at: 0)
                let keyXid = key.uint64LE(at: 8)
                if keyObject < objectID || (keyObject == objectID && keyXid <= maximumXid) {
                    chosenKey = (keyObject, keyXid)
                    chosenValue = try valueData(node: node, entry: entry)
                } else {
                    break
                }
            }

            guard let chosenKey else {
                throw StoreAuthError.failure("APFS 对象映射中没有 \(objectID) 的记录")
            }

            if node.isLeaf {
                guard chosenKey.objectID == objectID, chosenValue.count >= 16 else {
                    throw StoreAuthError.failure("APFS 对象映射中没有 \(objectID) 的物理地址")
                }
                return chosenValue.uint64LE(at: 8)
            }

            guard chosenValue.count >= 8 else {
                throw StoreAuthError.failure("APFS 对象映射索引项被截断")
            }
            let address = chosenValue.uint64LE(at: 0)
            node = try parseNode(device.readBlock(address))
        }

        throw StoreAuthError.failure("APFS 对象映射树超过最大深度")
    }

    private static func entries(of node: Node) throws -> [Entry] {
        var result: [Entry] = []
        result.reserveCapacity(node.keyCount)

        var cursor = nodeHeaderSize
        let tableEnd = nodeHeaderSize + node.tableSpaceLength

        for _ in 0..<node.keyCount {
            if node.isFixedKV {
                guard cursor + 4 <= tableEnd else {
                    throw StoreAuthError.failure("APFS 节点 TOC 被截断")
                }
                // 固定长度节点在资产提取路径上只会是对象映射表/物理区间树：
                // key 恒为 16 字节；索引项 value 是 paddr（8 字节），
                // 叶子项 value 是 omap_val_t / fext_tree_val_t（16 字节）。
                result.append(Entry(keyOffset: Int(node.block.uint16LE(at: cursor)),
                                    keyLength: 16,
                                    valueOffset: Int(node.block.uint16LE(at: cursor + 2)),
                                    valueLength: node.level > 0 ? 8 : 16))
                cursor += 4
            } else {
                guard cursor + 8 <= tableEnd else {
                    throw StoreAuthError.failure("APFS 节点 TOC 被截断")
                }
                result.append(Entry(keyOffset: Int(node.block.uint16LE(at: cursor)),
                                    keyLength: Int(node.block.uint16LE(at: cursor + 2)),
                                    valueOffset: Int(node.block.uint16LE(at: cursor + 4)),
                                    valueLength: Int(node.block.uint16LE(at: cursor + 6))))
                cursor += 8
            }
        }

        return result
    }

    private static func keyData(node: Node, entry: Entry) throws -> Data {
        let start = entry.keyOffset + node.tableSpaceLength + nodeHeaderSize
        guard start >= 0, start + entry.keyLength <= blockSize else {
            throw StoreAuthError.failure("APFS 节点 key 越界")
        }
        return node.block.slice(at: start, count: entry.keyLength)
    }

    private static func valueData(node: Node, entry: Entry) throws -> Data {
        guard entry.valueOffset != 0xFFFF else {
            return Data()
        }

        let dataEnd = blockSize - (node.isRoot ? btreeInfoSize : 0)
        let start = dataEnd - entry.valueOffset
        guard start >= 0, start + entry.valueLength <= dataEnd else {
            throw StoreAuthError.failure("APFS 节点 value 越界")
        }
        return node.block.slice(at: start, count: entry.valueLength)
    }

    // MARK: - 容器 superblock 与校验和

    /// 扫描 checkpoint 描述区，返回最新的容器 superblock。
    private static func containerSuperblock(device: APFSBlockDevice) throws -> Data {
        let primary = try device.readBlock(0)
        guard String(decoding: primary.slice(at: 32, count: 4), as: UTF8.self) == "NXSB" else {
            throw StoreAuthError.failure("APFS 容器 superblock 无效")
        }

        let descriptorBlocks = Int(primary.uint32LE(at: 104) & 0x7FFF_FFFF)
        let descriptorBase = primary.uint64LE(at: 112)
        guard descriptorBlocks > 0, descriptorBlocks <= 4096 else {
            return primary
        }

        var latest = primary
        for index in 0..<descriptorBlocks {
            let address = descriptorBase + UInt64(index)
            let block = try device.readBlock(address)
            guard block.uint32LE(at: 24) & objectTypeMask == objectTypeNXSuperblock,
                  String(decoding: block.slice(at: 32, count: 4), as: UTF8.self) == "NXSB",
                  fletcherVerified(block) else {
                continue
            }
            latest = block
        }

        return latest
    }

    private static func fletcherVerified(_ block: Data) -> Bool {
        var copy = block
        guard copy.count >= 8 else {
            return false
        }
        copy.replaceSubrange(copy.startIndex..<(copy.startIndex + 8), with: Data(count: 8))
        return fletcher64(copy) == block.uint64LE(at: 0)
    }

    private static func fletcher64(_ data: Data) -> UInt64 {
        let modulus: UInt64 = 0xFFFF_FFFF
        var sum1: UInt64 = 0
        var sum2: UInt64 = 0

        var index = 0
        while index + 4 <= data.count {
            let word = UInt64(data.uint32LE(at: index))
            sum1 = (sum1 + word) % modulus
            sum2 = (sum2 + sum1) % modulus
            index += 4
        }

        let check1 = modulus - ((sum1 + sum2) % modulus)
        let check2 = modulus - ((sum1 + check1) % modulus)
        return (check2 << 32) | check1
    }
}

/// 由物理区间链拼出的文件读取器。
final class APFSExtentReader: RangeReadable {
    private let device: APFSBlockDevice
    private let extents: [APFSExtent]
    private let logicalStarts: [Int64]

    let size: Int64

    init(device: APFSBlockDevice, extents: [APFSExtent], size: UInt64) throws {
        guard size <= UInt64(Int64.max) else {
            throw StoreAuthError.failure("APFS 文件尺寸溢出")
        }
        self.device = device
        self.size = Int64(size)

        let sorted = extents.filter { $0.length > 0 }.sorted { $0.logical < $1.logical }
        var expected: Int64 = 0
        for extent in sorted {
            guard extent.logical == expected else {
                throw StoreAuthError.failure("APFS 文件区间不连续：\(extent.logical)，期望 \(expected)")
            }
            guard extent.physical <= UInt64(Int64.max / Int64(APFSBlockDevice.blockSize)) else {
                throw StoreAuthError.failure("APFS 文件区间物理地址溢出")
            }
            let physicalBytes = Int64(extent.physical) * Int64(APFSBlockDevice.blockSize)
            guard physicalBytes <= device.size, extent.length <= device.size - physicalBytes else {
                throw StoreAuthError.failure("APFS 文件区间超出设备范围")
            }
            expected += extent.length
            guard expected >= 0 else {
                throw StoreAuthError.failure("APFS 文件区间长度溢出")
            }
        }

        guard expected >= Int64(size) else {
            throw StoreAuthError.failure("APFS 文件区间只覆盖 \(expected) 字节，期望 \(size)")
        }

        self.extents = sorted
        self.logicalStarts = sorted.map(\.logical)
    }

    func read(at offset: Int64, count: Int) throws -> Data {
        guard count > 0 else {
            return Data()
        }
        guard offset >= 0 else {
            throw StoreAuthError.failure("APFS 读取偏移为负：\(offset)")
        }
        guard offset < size else {
            return Data()
        }

        var output = Data(capacity: min(count, Int(size - offset)))
        var absolute = offset
        var remaining = Int(min(Int64(count), size - offset))

        while remaining > 0 {
            guard let index = extentIndex(containing: absolute) else {
                throw StoreAuthError.failure("APFS 文件在 offset \(absolute) 处出现空洞")
            }

            let extent = extents[index]
            let delta = absolute - extent.logical
            let available = extent.length - delta
            let take = Int(min(Int64(remaining), available))
            guard take > 0 else {
                throw StoreAuthError.failure("APFS 文件区间在 offset \(absolute) 处长度为负")
            }

            let physical = Int64(extent.physical) * Int64(APFSBlockDevice.blockSize) + delta
            output.append(try device.source.readExact(at: physical, count: take))

            absolute += Int64(take)
            remaining -= take
        }

        return output
    }

    private func extentIndex(containing offset: Int64) -> Int? {
        var low = 0
        var high = logicalStarts.count - 1

        while low <= high {
            let middle = (low + high) / 2
            let start = logicalStarts[middle]
            if offset < start {
                high = middle - 1
            } else if offset - start >= extents[middle].length {
                low = middle + 1
            } else {
                return middle
            }
        }

        return nil
    }
}
