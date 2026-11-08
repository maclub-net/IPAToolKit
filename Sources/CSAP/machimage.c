#include "machimage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// ==================== Mach-O 结构体定义 ====================

#pragma pack(push, 1)

typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} csap_mh_header_64_t;

typedef struct {
    uint32_t magic;
    uint32_t nfat_arch;
} csap_fat_header_t;

typedef struct {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} csap_fat_arch_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} csap_load_command_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} csap_segment_command_64_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t rebase_off;
    uint32_t rebase_size;
    uint32_t bind_off;
    uint32_t bind_size;
    uint32_t weak_bind_off;
    uint32_t weak_bind_size;
    uint32_t lazy_bind_off;
    uint32_t lazy_bind_size;
    uint32_t export_off;
    uint32_t export_size;
} csap_dyld_info_command_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
} csap_linkedit_data_command_t;

typedef struct {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint64_t offset;
    uint64_t size;
    uint32_t align;
    uint32_t reserved;
} csap_fat_arch_64_t;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} csap_section_64_t;

typedef struct {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
} csap_chained_fixups_header_t;

typedef struct {
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint16_t page_count;
} csap_chained_starts_in_segment_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
} csap_symtab_command_t;

struct nlist_64 {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

_Static_assert(sizeof(struct nlist_64) == sizeof(csap_macho_nlist_t), "nlist layout");

_Static_assert(sizeof(csap_section_64_t) == 80, "section layout");

#pragma pack(pop)

// ==================== 辅助函数 ====================

static inline uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

static inline uint32_t read_u32_le(const uint8_t* p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8)  | ((uint32_t)p[0]);
}

static inline uint64_t read_u64_le(const uint8_t* p) {
    return ((uint64_t)p[7] << 56) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[1] << 8)  | ((uint64_t)p[0]);
}

static inline void write_u64_le(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

// ULEB128 解码
static uint64_t read_uleb128(const uint8_t** pp, const uint8_t* end) {
    uint64_t result = 0;
    int shift = 0;
    while (*pp < end) {
        uint8_t byte = *(*pp)++;
        result |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

// SLEB128 解码
static int64_t read_sleb128(const uint8_t** pp, const uint8_t* end) {
    int64_t result = 0;
    int shift = 0;
    uint8_t byte;
    do {
        if (*pp >= end) break;
        byte = *(*pp)++;
        result |= ((int64_t)(byte & 0x7f)) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 64 && (byte & 0x40)) {
        result |= -(1LL << shift);
    }
    return result;
}

static uint64_t align_up(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static bool add_check(uint64_t left, uint64_t right, uint64_t* result) {
    *result = left + right;
    return right <= (UINT64_MAX - left);
}

// ==================== Fat Binary 解析 ====================

// 从 universal binary 中提取指定架构的切片
static uint8_t* extract_slice(const uint8_t* data, uint64_t size, bool arm64, uint64_t* out_size) {
    if (size < sizeof(csap_fat_header_t)) {
        return NULL;
    }

    uint32_t magic = read_u32_be(data);
    if (magic != CSAP_FAT_MAGIC && magic != CSAP_FAT_MAGIC_64) {
        // 不是 fat binary，直接返回原始数据的拷贝
        uint8_t* copy = malloc(size);
        if (copy == NULL) return NULL;
        memcpy(copy, data, size);
        *out_size = size;
        return copy;
    }

    csap_fat_header_t* fh = (csap_fat_header_t*)data;
    uint32_t nfat = read_u32_be((const uint8_t*)&fh->nfat_arch);
    bool wide = magic == CSAP_FAT_MAGIC_64;

    for (uint32_t i = 0; i < nfat; i++) {
        uint32_t cputype = 0;
        uint32_t cpusubtype = 0;
        uint64_t offset = 0;
        uint64_t asize = 0;

        if (wide) {
            uint64_t entry = sizeof(csap_fat_header_t) + (uint64_t)i * sizeof(csap_fat_arch_64_t);
            if (entry + sizeof(csap_fat_arch_64_t) > size) return NULL;
            csap_fat_arch_64_t* arch = (csap_fat_arch_64_t*)(data + entry);
            cputype = read_u32_be((const uint8_t*)&arch->cputype);
            cpusubtype = read_u32_be((const uint8_t*)&arch->cpusubtype);
            // fat_arch_64 的 offset/size 为大端 64 位字段
            offset = ((uint64_t)read_u32_be(data + entry + 8) << 32) | read_u32_be(data + entry + 12);
            asize = ((uint64_t)read_u32_be(data + entry + 16) << 32) | read_u32_be(data + entry + 20);
        } else {
            uint64_t entry = sizeof(csap_fat_header_t) + (uint64_t)i * sizeof(csap_fat_arch_t);
            if (entry + sizeof(csap_fat_arch_t) > size) return NULL;
            csap_fat_arch_t* arch = (csap_fat_arch_t*)(data + entry);
            cputype = read_u32_be((const uint8_t*)&arch->cputype);
            cpusubtype = read_u32_be((const uint8_t*)&arch->cpusubtype);
            offset = read_u32_be((const uint8_t*)&arch->offset);
            asize = read_u32_be((const uint8_t*)&arch->size);
        }

        if (arm64) {
            if (cputype != CSAP_CPU_TYPE_ARM64) continue;
            if ((cpusubtype & CSAP_CPU_SUBTYPE_MASK) != CSAP_CPU_SUBTYPE_ARM64E) continue;
        } else if (cputype != CSAP_CPU_TYPE_X86_64) {
            continue;
        }

        if (offset > size || asize > size - offset) return NULL;
        uint8_t* copy = malloc((size_t)asize);
        if (copy == NULL) return NULL;
        memcpy(copy, data + offset, (size_t)asize);
        *out_size = asize;
        return copy;
    }

    return NULL;
}

// ==================== Dyld Info 解析 ====================

// Bind opcodes (opcode = high nibble, imm = low nibble)
#define BIND_OPCODE_DONE                             0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB           0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM    0x40
#define BIND_OPCODE_SET_TYPE_IMM                     0x50
#define BIND_OPCODE_SET_ADDEND_SLEB                  0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB      0x70
#define BIND_OPCODE_ADD_ADDR_ULEB                    0x80
#define BIND_OPCODE_DO_BIND                          0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            0xa0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED      0xb0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xc0

// Rebase opcodes (opcode = high nibble, imm = low nibble)
#define REBASE_OPCODE_DONE                               0x00
#define REBASE_OPCODE_SET_TYPE_IMM                       0x10
#define REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        0x20
#define REBASE_OPCODE_ADD_ADDR_ULEB                      0x30
#define REBASE_OPCODE_ADD_ADDR_IMM_SCALED                0x40
#define REBASE_OPCODE_DO_REBASE_IMM_TIMES                0x50
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES               0x60
#define REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB            0x70
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80

// 解析 bind 信息
static int parse_binds(csap_macho_image_t* image, const uint8_t* bind_data, uint32_t bind_size) {
    if (bind_size == 0) return 0;

    const uint8_t* p = bind_data;
    const uint8_t* end = bind_data + bind_size;

    uint64_t seg_offset = 0;
    uint8_t seg_index = 0;
    int64_t addend = 0;
    uint8_t type = CSAP_BIND_TYPE_POINTER;
    char* symbol = NULL;
    uint32_t cap = 0;

    while (p < end) {
        uint8_t opcode = *p & 0xf0;
        uint8_t imm = *p & 0x0f;
        p++;

        switch (opcode) {
        case BIND_OPCODE_DONE:
            // lazy bind 流中可能有多个 DONE，每个分隔一个条目
            // 重置状态并继续解析
            seg_offset = 0;
            seg_index = 0;
            addend = 0;
            type = CSAP_BIND_TYPE_POINTER;
            free(symbol);
            symbol = NULL;
            continue;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            if (opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB) {
                read_uleb128(&p, end);
            }
            break;

        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            // 特殊库 ordinal，imm 低 4 位有符号
            break;

        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
            // symbol 是尾随的以 null 结尾的字符串
            const char* s = (const char*)p;
            size_t slen = strnlen(s, (size_t)(end - p));
            if (slen >= (size_t)(end - p)) break;
            free(symbol);
            symbol = strdup(s);
            cap = (uint32_t)slen;
            (void)cap;
            p += slen + 1;
            break;
        }

        case BIND_OPCODE_SET_TYPE_IMM:
            type = imm;
            break;

        case BIND_OPCODE_SET_ADDEND_SLEB:
            addend = read_sleb128(&p, end);
            break;

        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index = imm;
            seg_offset = read_uleb128(&p, end);
            break;

        case BIND_OPCODE_ADD_ADDR_ULEB:
            seg_offset += read_uleb128(&p, end);
            break;

        case BIND_OPCODE_DO_BIND: {
            if (symbol != NULL) {
                image->binds = realloc(image->binds, (image->bind_count + 1) * sizeof(csap_macho_bind_t));
                csap_macho_bind_t* b = &image->binds[image->bind_count++];
                b->name = strdup(symbol);
                b->seg_offset = seg_offset;
                b->addend = addend;
                b->type = type;
                b->seg_index = seg_index;
            }
            seg_offset += 8;
            break;
        }

        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
            if (symbol != NULL) {
                image->binds = realloc(image->binds, (image->bind_count + 1) * sizeof(csap_macho_bind_t));
                csap_macho_bind_t* b = &image->binds[image->bind_count++];
                b->name = strdup(symbol);
                b->seg_offset = seg_offset;
                b->addend = addend;
                b->type = type;
                b->seg_index = seg_index;
            }
            seg_offset += read_uleb128(&p, end) + 8;
            break;
        }

        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
            if (symbol != NULL) {
                image->binds = realloc(image->binds, (image->bind_count + 1) * sizeof(csap_macho_bind_t));
                csap_macho_bind_t* b = &image->binds[image->bind_count++];
                b->name = strdup(symbol);
                b->seg_offset = seg_offset;
                b->addend = addend;
                b->type = type;
                b->seg_index = seg_index;
            }
            seg_offset += (uint64_t)(imm) * CSAP_POINTER_SIZE + 8;
            break;
        }

        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
            uint64_t count = read_uleb128(&p, end);
            uint64_t skip = read_uleb128(&p, end);
            for (uint64_t i = 0; i < count && symbol != NULL; i++) {
                image->binds = realloc(image->binds, (image->bind_count + 1) * sizeof(csap_macho_bind_t));
                csap_macho_bind_t* b = &image->binds[image->bind_count++];
                b->name = strdup(symbol);
                b->seg_offset = seg_offset;
                b->addend = addend;
                b->type = type;
                b->seg_index = seg_index;
                seg_offset += skip + 8;
            }
            break;
        }

        default:
            // 未知 opcode，停止
            goto done;
        }
    }
done:
    free(symbol);
    return 0;
}

// 解析 rebase 信息
static int parse_rebases(csap_macho_image_t* image, const uint8_t* rebase_data, uint32_t rebase_size) {
    if (rebase_size == 0) return 0;

    const uint8_t* p = rebase_data;
    const uint8_t* end = rebase_data + rebase_size;

    uint64_t seg_offset = 0;
    uint8_t seg_index = 0;
    uint8_t type = CSAP_REBASE_TYPE_POINTER;

    while (p < end) {
        uint8_t opcode = *p & 0xf0;
        uint8_t imm = *p & 0x0f;
        p++;

        switch (opcode) {
        case REBASE_OPCODE_DONE:
            goto done;

        case REBASE_OPCODE_SET_TYPE_IMM:
            type = imm;
            break;

        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index = imm;
            seg_offset = read_uleb128(&p, end);
            break;

        case REBASE_OPCODE_ADD_ADDR_ULEB:
            seg_offset += read_uleb128(&p, end);
            break;

        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            seg_offset += (uint64_t)(imm) * CSAP_POINTER_SIZE;
            break;

        case REBASE_OPCODE_DO_REBASE_IMM_TIMES: {
            uint64_t count = imm;
            for (uint64_t i = 0; i < count; i++) {
                image->rebases = realloc(image->rebases, (image->rebase_count + 1) * sizeof(csap_macho_rebase_t));
                csap_macho_rebase_t* r = &image->rebases[image->rebase_count++];
                r->seg_index = seg_index;
                r->seg_offset = seg_offset;
                r->type = type;
                r->value = 0; // 实际值在 relocate 时计算
                seg_offset += CSAP_POINTER_SIZE;
            }
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
            uint64_t count = read_uleb128(&p, end);
            for (uint64_t i = 0; i < count; i++) {
                image->rebases = realloc(image->rebases, (image->rebase_count + 1) * sizeof(csap_macho_rebase_t));
                csap_macho_rebase_t* r = &image->rebases[image->rebase_count++];
                r->seg_index = seg_index;
                r->seg_offset = seg_offset;
                r->type = type;
                r->value = 0;
                seg_offset += CSAP_POINTER_SIZE;
            }
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
            image->rebases = realloc(image->rebases, (image->rebase_count + 1) * sizeof(csap_macho_rebase_t));
            csap_macho_rebase_t* r = &image->rebases[image->rebase_count++];
            r->seg_index = seg_index;
            r->seg_offset = seg_offset;
            r->type = type;
            r->value = 0;
            seg_offset += read_uleb128(&p, end) + CSAP_POINTER_SIZE;
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
            uint64_t count = read_uleb128(&p, end);
            uint64_t skip = read_uleb128(&p, end);
            for (uint64_t i = 0; i < count; i++) {
                image->rebases = realloc(image->rebases, (image->rebase_count + 1) * sizeof(csap_macho_rebase_t));
                csap_macho_rebase_t* r = &image->rebases[image->rebase_count++];
                r->seg_index = seg_index;
                r->seg_offset = seg_offset;
                r->type = type;
                r->value = 0;
                seg_offset += skip + CSAP_POINTER_SIZE;
            }
            break;
        }

        default:
            goto done;
        }
    }
done:
    return 0;
}

// ==================== Export Trie 解析 ====================

// 查找 export trie 中的符号
static uint64_t find_export_symbol(const uint8_t* trie, uint32_t trie_size, const char* name) {
    if (trie == NULL || trie_size == 0) return 0;

    size_t name_len = strlen(name);
    const uint8_t* end = trie + trie_size;
    const uint8_t* node = trie;
    size_t name_idx = 0;

    while (node < end) {
        const uint8_t* p = node;

        // 读取节点大小 (ULEB128) - 不包括自身
        uint64_t node_size = read_uleb128(&p, end);

        // terminal info 区域
        const uint8_t* term_start = p;
        const uint8_t* term_end = p + node_size;

        if (name_idx == name_len) {
            // 精确匹配，解析 terminal info
            if (node_size == 0) return 0;

            const uint8_t* tp = term_start;
            uint64_t flags = read_uleb128(&tp, term_end);

            if (flags & 0x08) {
                // EXPORT_SYMBOL_FLAGS_REEXPORT - 跳过
                return 0;
            } else if (flags & 0x10) {
                // EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER
                return read_uleb128(&tp, term_end);  // stub address
            } else {
                // 普通符号: address
                return read_uleb128(&tp, term_end);
            }
        }

        // 跳过 terminal info，读取子节点数量
        p = term_end;
        if (p >= end) return 0;
        uint8_t child_count = *p++;

        bool found = false;
        for (uint8_t i = 0; i < child_count; i++) {
            if (p >= end) return 0;
            const char* edge = (const char*)p;
            size_t edge_len = strnlen(edge, (size_t)(end - p));
            if (edge_len >= (size_t)(end - p)) return 0;
            p += edge_len + 1;

            uint64_t child_offset = read_uleb128(&p, end);

            if (strncmp(edge, name + name_idx, edge_len) == 0) {
                name_idx += edge_len;
                node = trie + child_offset;
                found = true;
                break;
            }
        }

        if (!found) return 0;
    }

    return 0;
}

// ==================== Chained Fixups 解析 ====================

static int append_chained(csap_macho_image_t* image, csap_macho_segment_t* seg, uint64_t seg_offset,
                          uint16_t pointer_format);

// 把 chained fixup 链中的每个位置记录成 (文件偏移, 原始指针)。
static int parse_chained_fixups(csap_macho_image_t* image, const uint8_t* blob, uint32_t blob_size) {
    if (blob == NULL || blob_size < sizeof(csap_chained_fixups_header_t)) return -1;

    csap_chained_fixups_header_t* h = (csap_chained_fixups_header_t*)blob;
    uint32_t starts_offset = read_u32_le((const uint8_t*)&h->starts_offset);
    uint32_t imports_offset = read_u32_le((const uint8_t*)&h->imports_offset);
    uint32_t symbols_offset = read_u32_le((const uint8_t*)&h->symbols_offset);
    uint32_t imports_count = read_u32_le((const uint8_t*)&h->imports_count);
    uint32_t imports_format = read_u32_le((const uint8_t*)&h->imports_format);

    if (starts_offset >= blob_size) return -1;

    image->import_format = imports_format;
    image->import_symbols = blob + symbols_offset;
    image->import_symbols_size = blob_size > symbols_offset ? blob_size - symbols_offset : 0;

    // 读取导入符号表
    for (uint32_t i = 0; i < imports_count; i++) {
        uint64_t name_offset = 0;
        int64_t addend = 0;
        uint64_t entry_size = 0;

        switch (imports_format) {
        case CSAP_CHAINED_IMPORT: {
            uint64_t pos = (uint64_t)imports_offset + (uint64_t)i * 4;
            if (pos + 4 > blob_size) return -1;
            uint32_t value = read_u32_le(blob + pos);
            name_offset = value >> 9;
            entry_size = 4;
            break;
        }
        case CSAP_CHAINED_IMPORT_ADDEND: {
            uint64_t pos = (uint64_t)imports_offset + (uint64_t)i * 8;
            if (pos + 8 > blob_size) return -1;
            uint32_t value = read_u32_le(blob + pos);
            name_offset = value >> 9;
            addend = (int32_t)read_u32_le(blob + pos + 4);
            entry_size = 8;
            break;
        }
        case CSAP_CHAINED_IMPORT_ADDEND64: {
            uint64_t pos = (uint64_t)imports_offset + (uint64_t)i * 16;
            if (pos + 16 > blob_size) return -1;
            uint64_t value = read_u64_le(blob + pos);
            name_offset = value >> 32;
            addend = (int64_t)read_u64_le(blob + pos + 8);
            entry_size = 16;
            break;
        }
        default:
            return -1;
        }

        (void)entry_size;
        if (symbols_offset + name_offset >= blob_size) return -1;

        image->imports = realloc(image->imports, (image->import_count + 1) * sizeof(csap_macho_import_t));
        csap_macho_import_t* item = &image->imports[image->import_count++];
        item->name = strdup((const char*)blob + symbols_offset + name_offset);
        item->addend = addend;
    }

    // starts_in_image: uint32 seg_count; uint32 seg_info_offset[seg_count]
    uint32_t seg_count = read_u32_le(blob + starts_offset);
    if (starts_offset + 4 + (uint64_t)seg_count * 4 > blob_size) return -1;

    for (uint32_t s = 0; s < seg_count; s++) {
        uint32_t info_offset = read_u32_le(blob + starts_offset + 4 + s * 4);
        if (info_offset == 0) continue;
        if (s >= image->segment_count) continue;

        uint64_t info_pos = (uint64_t)starts_offset + info_offset;
        if (info_pos + sizeof(csap_chained_starts_in_segment_t) > blob_size) return -1;

        csap_chained_starts_in_segment_t* info = (csap_chained_starts_in_segment_t*)(blob + info_pos);
        uint16_t page_size = info->page_size;
        uint16_t pointer_format = info->pointer_format;
        uint16_t page_count = info->page_count;
        uint64_t page_start_pos = info_pos + 22;
        if (page_start_pos + (uint64_t)page_count * 2 > blob_size) return -1;

        const uint8_t* page_start = blob + page_start_pos;
        csap_macho_segment_t* seg = &image->segments[s];

        for (uint16_t page = 0; page < page_count; page++) {
            uint16_t start = (uint16_t)(page_start[page * 2] | (page_start[page * 2 + 1] << 8));
            if (start == 0xffff) continue;

            if (start & 0x8000) {
                // 多链：低 15 位是页起始数组之后的 16 位溢出表索引，末项带 0x8000。
                uint32_t index = start & 0x7fff;
                uint16_t entry = 0;
                do {
                    uint64_t pos = page_start_pos + (uint64_t)page_count * 2 + (uint64_t)index * 2;
                    if (pos + 2 > blob_size) return -1;
                    entry = (uint16_t)(blob[pos] | (blob[pos + 1] << 8));
                    index++;
                    if (append_chained(image, seg, (uint64_t)page * page_size + (entry & 0x7fff),
                                       pointer_format) != 0) {
                        return -1;
                    }
                } while (!(entry & 0x8000));
                continue;
            }

            if (append_chained(image, seg, (uint64_t)page * page_size + start, pointer_format) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

// 沿一条链记录所有 fixup 位置。
static int append_chained(csap_macho_image_t* image, csap_macho_segment_t* seg, uint64_t seg_offset,
                          uint16_t pointer_format) {
    uint64_t stride = pointer_format == CSAP_CHAINED_PTR_64 || pointer_format == CSAP_CHAINED_PTR_64_OFFSET ? 4 : 8;

    for (;;) {
        if (seg_offset + 8 > seg->file_size) return -1;
        uint64_t file_offset = seg->file_off + seg_offset;
        if (file_offset + 8 > image->data_size) return -1;

        uint64_t raw = read_u64_le(image->data + file_offset);

        image->chained = realloc(image->chained, (image->chained_count + 1) * sizeof(csap_macho_chained_t));
        csap_macho_chained_t* item = &image->chained[image->chained_count++];
        item->file_offset = file_offset;
        item->pointer_format = (uint8_t)pointer_format;
        item->raw = raw;

        uint64_t next = (raw >> 51) & 0x7ff;
        if (next == 0) break;
        seg_offset += next * stride;
    }

    return 0;
}

// ==================== Pointer Authentication ====================

uint32_t csap_macho_strip_pointer_authentication(uint32_t instruction) {
    const uint32_t nop = 0xd503201f;
    uint32_t replacement = 0;

    switch (instruction & 0xfffffc00) {
    case 0xd71f0800: case 0xd71f0c00: case 0xd61f0800: case 0xd61f0c00:
        replacement = 0xd61f0000 | (instruction & 0x3e0);  // br xN
        break;
    case 0xd73f0800: case 0xd73f0c00: case 0xd63f0800: case 0xd63f0c00:
        replacement = 0xd63f0000 | (instruction & 0x3e0);  // blr xN
        break;
    case 0xdac10000: case 0xdac10400: case 0xdac10800: case 0xdac10c00:
    case 0xdac11000: case 0xdac11400: case 0xdac11800: case 0xdac11c00:
        replacement = nop;
        break;
    default:
        switch (instruction) {
        case 0xd65f0bff: case 0xd65f0fff:
            replacement = 0xd65f03c0;  // ret
            break;
        case 0xd503211f: case 0xd503215f: case 0xd503219f: case 0xd50321df:
        case 0xd503233f: case 0xd503237f: case 0xd50323bf: case 0xd50323ff:
        case 0xd50320ff:
            replacement = nop;
            break;
        default: {
            uint32_t opcode = instruction & 0xffffffe0;
            if (opcode == 0xdac123e0 || opcode == 0xdac127e0 ||
                opcode == 0xdac12be0 || opcode == 0xdac12fe0 ||
                opcode == 0xdac133e0 || opcode == 0xdac137e0 ||
                opcode == 0xdac13be0 || opcode == 0xdac13fe0 ||
                opcode == 0xdac143e0 || opcode == 0xdac147e0) {
                replacement = nop;
            }
            break;
        }
        }
        break;
    }

    return replacement == 0 ? instruction : replacement;
}

// 在指令段中就地移除 PAC 指令。
static void strip_image_pointer_authentication(csap_macho_image_t* image, uint64_t section_offset, uint64_t section_size) {
    if (section_offset > image->data_size || section_size > image->data_size - section_offset) return;

    uint64_t end = section_offset + section_size;
    for (uint64_t offset = section_offset; offset + 4 <= end; offset += 4) {
        uint32_t instruction = read_u32_le(image->data + offset);
        uint32_t replacement = csap_macho_strip_pointer_authentication(instruction);
        if (replacement != instruction) {
            image->data[offset] = (uint8_t)(replacement);
            image->data[offset + 1] = (uint8_t)(replacement >> 8);
            image->data[offset + 2] = (uint8_t)(replacement >> 16);
            image->data[offset + 3] = (uint8_t)(replacement >> 24);
        }
    }
}

// ==================== 公开 API ====================

static csap_macho_image_t* open_image(const char* name, const uint8_t* data, uint64_t size, bool arm64) {
    if (data == NULL || size < sizeof(csap_mh_header_64_t)) {
        return NULL;
    }

    csap_macho_image_t* image = calloc(1, sizeof(csap_macho_image_t));
    if (image == NULL) return NULL;

    image->name = strdup(name ? name : "unknown");

    // 提取目标架构切片
    image->data = extract_slice(data, size, arm64, &image->data_size);
    if (image->data == NULL) {
        fprintf(stderr, "csap: %s: failed to extract %s slice\n", image->name, arm64 ? "arm64e" : "x86-64");
        csap_macho_free(image);
        return NULL;
    }

    // 验证 Mach-O header
    if (image->data_size < sizeof(csap_mh_header_64_t)) {
        fprintf(stderr, "csap: %s: too small for Mach-O header\n", image->name);
        csap_macho_free(image);
        return NULL;
    }

    csap_mh_header_64_t* hdr = (csap_mh_header_64_t*)image->data;
    if (read_u32_le((const uint8_t*)&hdr->magic) != CSAP_MH_MAGIC_64) {
        fprintf(stderr, "csap: %s: not a 64-bit Mach-O\n", image->name);
        csap_macho_free(image);
        return NULL;
    }
    uint32_t expected_cputype = arm64 ? CSAP_CPU_TYPE_ARM64 : CSAP_CPU_TYPE_X86_64;
    if (read_u32_le((const uint8_t*)&hdr->cputype) != expected_cputype) {
        fprintf(stderr, "csap: %s: unexpected CPU type\n", image->name);
        csap_macho_free(image);
        return NULL;
    }

    uint32_t ncmds = read_u32_le((const uint8_t*)&hdr->ncmds);
    uint32_t sizeofcmds = read_u32_le((const uint8_t*)&hdr->sizeofcmds);

    uint32_t chained_off = 0;
    uint32_t chained_size = 0;

    // 遍历 load commands
    const uint8_t* lc_ptr = image->data + sizeof(csap_mh_header_64_t);
    const uint8_t* lc_end = lc_ptr + sizeofcmds;

    for (uint32_t i = 0; i < ncmds && lc_ptr < lc_end; i++) {
        csap_load_command_t* lc = (csap_load_command_t*)lc_ptr;
        uint32_t cmd = read_u32_le((const uint8_t*)&lc->cmd);
        uint32_t cmdsize = read_u32_le((const uint8_t*)&lc->cmdsize);

        switch (cmd) {
        case CSAP_LC_SEGMENT_64: {
            csap_segment_command_64_t* seg = (csap_segment_command_64_t*)lc_ptr;
            image->segments = realloc(image->segments, (image->segment_count + 1) * sizeof(csap_macho_segment_t));
            csap_macho_segment_t* s = &image->segments[image->segment_count++];
            memcpy(s->name, seg->segname, 16);
            s->name[15] = '\0';
            s->address = read_u64_le((const uint8_t*)&seg->vmaddr);
            s->size = read_u64_le((const uint8_t*)&seg->vmsize);
            s->file_off = read_u64_le((const uint8_t*)&seg->fileoff);
            s->file_size = read_u64_le((const uint8_t*)&seg->filesize);

            if (arm64) {
                uint32_t nsects = read_u32_le((const uint8_t*)&seg->nsects);
                const uint8_t* sect_ptr = lc_ptr + sizeof(csap_segment_command_64_t);
                for (uint32_t n = 0; n < nsects; n++, sect_ptr += sizeof(csap_section_64_t)) {
                    if (sect_ptr + sizeof(csap_section_64_t) > lc_ptr + cmdsize) break;
                    csap_section_64_t* section = (csap_section_64_t*)sect_ptr;
                    uint32_t flags = read_u32_le((const uint8_t*)&section->flags);
                    if ((flags & CSAP_S_ATTR_PURE_INSTRUCTIONS) == 0 &&
                        (flags & CSAP_S_ATTR_SOME_INSTRUCTIONS) == 0) {
                        continue;
                    }
                    uint32_t offset = read_u32_le((const uint8_t*)&section->offset);
                    uint64_t ssize = read_u64_le((const uint8_t*)&section->size);
                    strip_image_pointer_authentication(image, offset, ssize);
                }
            }

            {
                uint32_t nsects = read_u32_le((const uint8_t*)&seg->nsects);
                const uint8_t* sect_ptr = lc_ptr + sizeof(csap_segment_command_64_t);
                for (uint32_t n = 0; n < nsects; n++, sect_ptr += sizeof(csap_section_64_t)) {
                    if (sect_ptr + sizeof(csap_section_64_t) > lc_ptr + cmdsize) break;
                    csap_section_64_t* section = (csap_section_64_t*)sect_ptr;
                    image->sections = realloc(image->sections, (image->section_count + 1) * sizeof(csap_macho_section_t));
                    csap_macho_section_t* entry = &image->sections[image->section_count++];
                    memcpy(entry->sectname, section->sectname, 16);
                    entry->sectname[15] = '\0';
                    memcpy(entry->segname, section->segname, 16);
                    entry->segname[15] = '\0';
                    entry->address = read_u64_le((const uint8_t*)&section->addr);
                    entry->size = read_u64_le((const uint8_t*)&section->size);
                    entry->flags = read_u32_le((const uint8_t*)&section->flags);
                }
            }
            break;
        }

        case CSAP_LC_DYLD_INFO:
        case CSAP_LC_DYLD_INFO_ONLY: {
            csap_dyld_info_command_t* dyld = (csap_dyld_info_command_t*)lc_ptr;
            uint32_t rebase_off = read_u32_le((const uint8_t*)&dyld->rebase_off);
            uint32_t rebase_size = read_u32_le((const uint8_t*)&dyld->rebase_size);
            uint32_t bind_off = read_u32_le((const uint8_t*)&dyld->bind_off);
            uint32_t bind_size = read_u32_le((const uint8_t*)&dyld->bind_size);
            uint32_t weak_bind_off = read_u32_le((const uint8_t*)&dyld->weak_bind_off);
            uint32_t weak_bind_size = read_u32_le((const uint8_t*)&dyld->weak_bind_size);
            uint32_t lazy_bind_off = read_u32_le((const uint8_t*)&dyld->lazy_bind_off);
            uint32_t lazy_bind_size = read_u32_le((const uint8_t*)&dyld->lazy_bind_size);
            uint32_t export_off = read_u32_le((const uint8_t*)&dyld->export_off);
            uint32_t export_size = read_u32_le((const uint8_t*)&dyld->export_size);

            if (rebase_off + rebase_size <= image->data_size && rebase_size > 0) {
                parse_rebases(image, image->data + rebase_off, rebase_size);
            }
            if (bind_off + bind_size <= image->data_size && bind_size > 0) {
                parse_binds(image, image->data + bind_off, bind_size);
            }
            if (weak_bind_off + weak_bind_size <= image->data_size && weak_bind_size > 0) {
                parse_binds(image, image->data + weak_bind_off, weak_bind_size);
            }
            if (lazy_bind_off + lazy_bind_size <= image->data_size && lazy_bind_size > 0) {
                parse_binds(image, image->data + lazy_bind_off, lazy_bind_size);
            }
            if (export_off + export_size <= image->data_size && export_size > 0) {
                image->export_trie = malloc(export_size);
                if (image->export_trie) {
                    memcpy(image->export_trie, image->data + export_off, export_size);
                    image->export_trie_size = export_size;
                }
            }
            break;
        }

        case CSAP_LC_DYLD_EXPORTS_TRIE: {
            csap_linkedit_data_command_t* linkedit = (csap_linkedit_data_command_t*)lc_ptr;
            uint32_t dataoff = read_u32_le((const uint8_t*)&linkedit->dataoff);
            uint32_t datasize = read_u32_le((const uint8_t*)&linkedit->datasize);
            if ((uint64_t)dataoff + datasize <= image->data_size && datasize > 0) {
                image->export_trie = malloc(datasize);
                if (image->export_trie) {
                    memcpy(image->export_trie, image->data + dataoff, datasize);
                    image->export_trie_size = datasize;
                }
            }
            break;
        }

        case CSAP_LC_DYLD_CHAINED_FIXUPS: {
            csap_linkedit_data_command_t* linkedit = (csap_linkedit_data_command_t*)lc_ptr;
            chained_off = read_u32_le((const uint8_t*)&linkedit->dataoff);
            chained_size = read_u32_le((const uint8_t*)&linkedit->datasize);
            break;
        }

        case CSAP_LC_SYMTAB: {
            csap_symtab_command_t* symtab = (csap_symtab_command_t*)lc_ptr;
            uint32_t symoff = read_u32_le((const uint8_t*)&symtab->symoff);
            uint32_t nsyms = read_u32_le((const uint8_t*)&symtab->nsyms);
            uint32_t stroff = read_u32_le((const uint8_t*)&symtab->stroff);
            uint32_t strsize = read_u32_le((const uint8_t*)&symtab->strsize);

            if (symoff + nsyms * sizeof(struct nlist_64) <= image->data_size) {
                image->symtab = malloc(nsyms * sizeof(struct nlist_64));
                if (image->symtab) {
                    memcpy(image->symtab, image->data + symoff, nsyms * sizeof(struct nlist_64));
                    image->symtab_count = nsyms;
                }
            }
            if (stroff + strsize <= image->data_size) {
                image->strtab = malloc(strsize);
                if (image->strtab) {
                    memcpy(image->strtab, image->data + stroff, strsize);
                    image->strtab_size = strsize;
                }
            }
            break;
        }

        default:
            break;
        }

        lc_ptr += cmdsize;
    }

    // 计算 base address（第一个非 __PAGEZERO segment 的地址）
    image->base = 0;
    for (uint32_t i = 0; i < image->segment_count; i++) {
        if (strcmp(image->segments[i].name, "__PAGEZERO") != 0 && image->segments[i].size > 0) {
            image->base = image->segments[i].address;
            break;
        }
    }

    if (chained_size > 0 && (uint64_t)chained_off + chained_size <= image->data_size) {
        if (parse_chained_fixups(image, image->data + chained_off, chained_size) != 0) {
            fprintf(stderr, "csap: %s: failed to parse chained fixups\n", image->name);
            csap_macho_free(image);
            return NULL;
        }
    }

    return image;
}

csap_macho_image_t* csap_macho_open(const char* name, const uint8_t* data, uint64_t size) {
    return open_image(name, data, size, false);
}

csap_macho_image_t* csap_macho_open_arm64(const char* name, const uint8_t* data, uint64_t size) {
    return open_image(name, data, size, true);
}

int csap_macho_export(csap_macho_image_t* image, const char* name, uint64_t load_base, uint64_t* out_address) {
    if (image == NULL || name == NULL || out_address == NULL) return -1;

    uint64_t address = 0;

    // 首先尝试 export trie（trie 中的名字通常不带前导下划线）。
    if (image->export_trie != NULL) {
        address = find_export_symbol(image->export_trie, image->export_trie_size, name);
        if (address == 0 && name[0] == '_') {
            address = find_export_symbol(image->export_trie, image->export_trie_size, name + 1);
        }
    }

    // 如果 export trie 没找到，尝试符号表；符号表中的名字带前导下划线。
    if (address == 0 && image->symtab != NULL && image->strtab != NULL) {
        for (uint32_t i = 0; i < image->symtab_count; i++) {
            csap_macho_nlist_t* sym = &image->symtab[i];
            uint32_t strx = read_u32_le((const uint8_t*)&sym->n_strx);
            if (strx >= image->strtab_size) continue;

            const char* symname = image->strtab + strx;
            if (strcmp(symname, name) != 0 &&
                !(symname[0] == '_' && strcmp(symname + 1, name) == 0)) {
                continue;
            }

            address = read_u64_le((const uint8_t*)&sym->n_value);
            break;
        }
    }

    if (address == 0) {
        return -1;
    }

    if (address < image->base) {
        return -1;
    }

    uint64_t result;
    if (!add_check(load_base, address - image->base, &result)) {
        return -1;
    }

    *out_address = result;
    return 0;
}

// 查找 segment 在文件中的偏移
static int segment_file_offset(csap_macho_image_t* image, uint8_t seg_index, uint64_t offset, uint64_t size, uint64_t* out_offset) {
    if (seg_index >= image->segment_count) return -1;
    csap_macho_segment_t* seg = &image->segments[seg_index];

    uint64_t seg_end;
    if (!add_check(offset, size, &seg_end)) return -1;
    if (seg_end > seg->size) return -1;

    uint64_t result;
    if (!add_check(seg->file_off, offset, &result)) return -1;

    uint64_t end;
    if (!add_check(result, size, &end)) return -1;
    if (end > image->data_size) return -1;

    *out_offset = result;
    return 0;
}

static int64_t sign_extend_64(uint64_t value, int bits) {
    uint64_t sign = 1ULL << (bits - 1);
    return (int64_t)((value ^ sign) - sign);
}

static bool image_contains_address(csap_macho_image_t* image, uint64_t address) {
    for (uint32_t i = 0; i < image->segment_count; i++) {
        csap_macho_segment_t* seg = &image->segments[i];
        if (address >= seg->address && address - seg->address < seg->size) {
            return true;
        }
    }
    return false;
}

// 处理 chained fixups：绑定经 resolver 解析，rebase 按新基址重写。
static int relocate_chained(csap_macho_image_t* image, uint64_t load_base,
                            csap_symbol_resolver_t resolver, void* resolver_ctx) {
    for (uint32_t i = 0; i < image->chained_count; i++) {
        csap_macho_chained_t* entry = &image->chained[i];
        uint64_t raw = entry->raw;
        bool is_bind = ((raw >> 62) & 1) != 0;
        bool is_auth = ((raw >> 63) & 1) != 0;
        uint64_t address = 0;

        if (is_bind) {
            uint64_t ordinal;
            int64_t addend = 0;

            if (entry->pointer_format == CSAP_CHAINED_PTR_ARM64E) {
                ordinal = raw & 0xffff;
            } else {
                ordinal = raw & 0xffffff;
            }

            if (!is_auth) {
                addend = sign_extend_64((raw >> 32) & 0x7ffff, 19);
            }

            if (ordinal >= image->import_count) {
                fprintf(stderr, "csap: %s chained import %llu out of range\n",
                        image->name, (unsigned long long)ordinal);
                return -1;
            }

            csap_macho_import_t* import = &image->imports[ordinal];
            if (resolver == NULL || resolver(import->name, &address, resolver_ctx) != 0) {
                fprintf(stderr, "csap: %s failed to resolve %s\n", image->name, import->name);
                return -1;
            }

            addend += import->addend;
            address = (uint64_t)((int64_t)address + addend);
        } else if (is_auth) {
            // 认证 rebase 的 target 是 32 位镜像内偏移
            address = load_base + (raw & 0xffffffff);
        } else if (entry->pointer_format == CSAP_CHAINED_PTR_ARM64E) {
            uint64_t absolute = (((raw >> 43) & 0xff) << 56) | (raw & 0x7ffffffffffULL);
            if (absolute < image->base) {
                fprintf(stderr, "csap: %s chained rebase precedes image base\n", image->name);
                return -1;
            }
            address = load_base + (absolute - image->base);
        } else {
            // ARM64E_USERLAND / USERLAND24 的 target 是镜像内偏移
            address = load_base + (raw & 0x7ffffffffffULL);
        }

        write_u64_le(image->data + entry->file_offset, address);
    }

    return 0;
}

int csap_macho_relocate(csap_macho_image_t* image, uint64_t load_base,
                        csap_symbol_resolver_t resolver, void* resolver_ctx) {
    if (image == NULL) return -1;
    if (image->relocated) {
        fprintf(stderr, "csap: %s already relocated\n", image->name);
        return -1;
    }

    // 处理 rebases
    for (uint32_t i = 0; i < image->rebase_count; i++) {
        csap_macho_rebase_t* r = &image->rebases[i];
        if (r->type != CSAP_REBASE_TYPE_POINTER) {
            fprintf(stderr, "csap: %s unsupported rebase type %d\n", image->name, r->type);
            return -1;
        }

        uint64_t file_off;
        if (segment_file_offset(image, r->seg_index, r->seg_offset, CSAP_POINTER_SIZE, &file_off) != 0) {
            fprintf(stderr, "csap: %s rebase segment offset error\n", image->name);
            return -1;
        }

        // rebase 值 = load_base + (原始地址 - base)
        // 原始地址存储在该位置，读取它，加上 slide
        uint64_t original = read_u64_le(image->data + file_off);
        uint64_t slide = load_base - image->base;
        uint64_t new_addr = original + slide;

        write_u64_le(image->data + file_off, new_addr);
    }

    // 处理 binds
    for (uint32_t i = 0; i < image->bind_count; i++) {
        csap_macho_bind_t* b = &image->binds[i];

        uint64_t file_off;
        if (segment_file_offset(image, b->seg_index, b->seg_offset, CSAP_POINTER_SIZE, &file_off) != 0) {
            fprintf(stderr, "csap: %s bind segment offset error for %s\n", image->name, b->name);
            return -1;
        }

        uint64_t address = 0;
        if (resolver != NULL) {
            if (resolver(b->name, &address, resolver_ctx) != 0) {
                fprintf(stderr, "csap: %s failed to resolve %s\n", image->name, b->name);
                return -1;
            }
        }

        // 应用 addend
        if (b->addend >= 0) {
            address += (uint64_t)b->addend;
        } else {
            address -= (uint64_t)(-b->addend);
        }

        write_u64_le(image->data + file_off, address);
    }

    if (relocate_chained(image, load_base, resolver, resolver_ctx) != 0) {
        return -1;
    }

    image->relocated = true;
    image->loaded_base = load_base;
    return 0;
}

int csap_macho_prepare_prelinked(csap_macho_image_t* image,
                                 const csap_macho_prelink_symbol_t* symbols, uint32_t symbol_count,
                                 csap_symbol_resolver_t resolver, void* resolver_ctx) {
    if (image == NULL) return -1;
    if (image->relocated) {
        fprintf(stderr, "csap: %s already relocated\n", image->name);
        return -1;
    }

    for (uint32_t i = 0; i < image->segment_count; i++) {
        csap_macho_segment_t* seg = &image->segments[i];
        if (strcmp(seg->name, "__TEXT") == 0 || strcmp(seg->name, "__LINKEDIT") == 0 ||
            seg->file_size < CSAP_POINTER_SIZE) {
            continue;
        }

        uint64_t start = seg->file_off;
        uint64_t remainder = seg->address % CSAP_POINTER_SIZE;
        if (remainder != 0) {
            start += CSAP_POINTER_SIZE - remainder;
        }
        uint64_t end = seg->file_off + seg->file_size;
        if (end > image->data_size) return -1;

        for (uint64_t offset = start; offset + CSAP_POINTER_SIZE <= end; offset += CSAP_POINTER_SIZE) {
            uint64_t current = read_u64_le(image->data + offset);
            if (current == 0) continue;

            const char* name = NULL;
            for (uint32_t n = 0; n < symbol_count; n++) {
                if (symbols[n].address == current) {
                    name = symbols[n].name;
                    break;
                }
            }
            if (name == NULL) continue;

            uint64_t value = 0;
            if (resolver == NULL || resolver(name, &value, resolver_ctx) != 0) {
                fprintf(stderr, "csap: %s failed to resolve prelinked %s\n", image->name, name);
                return -1;
            }

            write_u64_le(image->data + offset, value);
        }
    }

    image->relocated = true;
    image->loaded_base = image->base;
    return 0;
}

int csap_macho_relocate_kernel_cache(csap_macho_image_t* image, uint64_t load_base, uint64_t kernel_base,
                                     csap_symbol_resolver_t resolver, void* resolver_ctx) {
    if (image == NULL) return -1;

    for (uint32_t i = 0; i < image->segment_count; i++) {
        csap_macho_segment_t* seg = &image->segments[i];
        if (strcmp(seg->name, "__TEXT") == 0 || strcmp(seg->name, "__TEXT_EXEC") == 0 ||
            strcmp(seg->name, "__LINKEDIT") == 0 || seg->file_size < CSAP_POINTER_SIZE) {
            continue;
        }

        const uint64_t stride = 4;
        uint64_t start = seg->file_off;
        uint64_t remainder = seg->address % stride;
        if (remainder != 0) {
            start += stride - remainder;
        }
        uint64_t end = seg->file_off + seg->file_size;
        if (end > image->data_size) return -1;

        for (uint64_t offset = start; offset + CSAP_POINTER_SIZE <= end; offset += stride) {
            uint64_t raw = read_u64_le(image->data + offset);
            uint64_t target = raw & 0x3fffffffULL;
            uint64_t cache_level = (raw >> 30) & 0x3;
            if (cache_level != 0 || target == 0) continue;

            uint64_t original;
            if (!add_check(kernel_base, target, &original)) continue;

            uint64_t relocated = 0;
            if (image_contains_address(image, original)) {
                if (!add_check(load_base, original - image->base, &relocated)) {
                    fprintf(stderr, "csap: %s kernel-cache pointer overflows\n", image->name);
                    return -1;
                }
            } else {
                const char* name = NULL;
                for (uint32_t s = 0; s < image->symtab_count; s++) {
                    csap_macho_nlist_t* sym = &image->symtab[s];
                    uint64_t value = read_u64_le((const uint8_t*)&sym->n_value);
                    if (value != original) continue;
                    uint32_t strx = read_u32_le((const uint8_t*)&sym->n_strx);
                    if (strx >= image->strtab_size) continue;
                    name = image->strtab + strx;
                    break;
                }
                if (name == NULL) continue;
                if (resolver == NULL || resolver(name, &relocated, resolver_ctx) != 0) {
                    fprintf(stderr, "csap: %s failed to resolve kernel-cache %s\n", image->name, name);
                    return -1;
                }
            }

            write_u64_le(image->data + offset, relocated);
        }
    }

    return 0;
}

typedef struct {
    uint64_t start;
    uint64_t end;
} csap_mem_range_t;

static int compare_mem_ranges(const void* left, const void* right) {
    const csap_mem_range_t* a = left;
    const csap_mem_range_t* b = right;
    if (a->start < b->start) return -1;
    if (a->start > b->start) return 1;
    return 0;
}

int csap_macho_load(csap_macho_image_t* image,
                    csap_mem_map_fn mem_map, csap_mem_write_fn mem_write, void* mem_ctx) {
    if (image == NULL) return -1;
    if (!image->relocated) {
        fprintf(stderr, "csap: %s must be relocated before loading\n", image->name);
        return -1;
    }

    // shared-cache 镜像的各段地址彼此分离，必须逐段映射，不能当作连续区间。
    uint32_t capacity = image->segment_count > 0 ? image->segment_count : 1;
    csap_mem_range_t* ranges = calloc(capacity, sizeof(*ranges));
    if (ranges == NULL) return -1;

    uint32_t count = 0;
    for (uint32_t i = 0; i < image->segment_count; i++) {
        csap_macho_segment_t* seg = &image->segments[i];
        if (strcmp(seg->name, "__PAGEZERO") == 0 || seg->size == 0) continue;

        if (seg->address < image->base) {
            fprintf(stderr, "csap: %s segment %s precedes the image base\n", image->name, seg->name);
            free(ranges);
            return -1;
        }

        uint64_t address;
        if (!add_check(image->loaded_base, seg->address - image->base, &address)) {
            fprintf(stderr, "csap: %s segment %s address overflows\n", image->name, seg->name);
            free(ranges);
            return -1;
        }

        uint64_t end;
        if (!add_check(address, seg->size, &end)) {
            fprintf(stderr, "csap: %s segment %s range overflows\n", image->name, seg->name);
            free(ranges);
            return -1;
        }

        ranges[count].start = address & ~(CSAP_PAGE_SIZE - 1);
        ranges[count].end = align_up(end, CSAP_PAGE_SIZE);
        count++;
    }

    if (count == 0) {
        fprintf(stderr, "csap: %s has no loadable segments\n", image->name);
        free(ranges);
        return -1;
    }

    qsort(ranges, count, sizeof(*ranges), compare_mem_ranges);

    uint32_t merged = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (merged > 0 && ranges[i].start <= ranges[merged - 1].end) {
            if (ranges[i].end > ranges[merged - 1].end) {
                ranges[merged - 1].end = ranges[i].end;
            }
            continue;
        }
        ranges[merged++] = ranges[i];
    }

    uint64_t mapped_total = 0;
    for (uint32_t i = 0; i < merged; i++) {
        if (!add_check(mapped_total, ranges[i].end - ranges[i].start, &mapped_total)) {
            free(ranges);
            return -1;
        }
        if (mapped_total > CSAP_MAX_IMAGE_SPAN) {
            fprintf(stderr, "csap: mapped segments make %s too large\n", image->name);
            free(ranges);
            return -1;
        }
        if (mem_map && mem_map(ranges[i].start, ranges[i].end - ranges[i].start, mem_ctx) != 0) {
            fprintf(stderr, "csap: %s mem_map failed\n", image->name);
            free(ranges);
            return -1;
        }
    }

    free(ranges);

    for (uint32_t i = 0; i < image->segment_count; i++) {
        csap_macho_segment_t* seg = &image->segments[i];
        if (strcmp(seg->name, "__PAGEZERO") == 0 || seg->file_size == 0) continue;

        uint64_t offset = seg->address - image->base;
        uint64_t address;
        if (!add_check(image->loaded_base, offset, &address)) return -1;

        if (mem_write && mem_write(address, image->data + seg->file_off, seg->file_size, mem_ctx) != 0) {
            fprintf(stderr, "csap: %s mem_write failed for segment %s\n", image->name, seg->name);
            return -1;
        }
    }

    return 0;
}

void csap_macho_free(csap_macho_image_t* image) {
    if (image == NULL) return;
    free(image->name);
    free(image->data);
    free(image->segments);
    for (uint32_t i = 0; i < image->bind_count; i++) {
        free(image->binds[i].name);
    }
    free(image->binds);
    free(image->rebases);
    free(image->sections);
    for (uint32_t i = 0; i < image->import_count; i++) {
        free(image->imports[i].name);
    }
    free(image->imports);
    free(image->chained);
    free(image->export_trie);
    free(image->symtab);
    free(image->strtab);
    free(image);
}
