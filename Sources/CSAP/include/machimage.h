#ifndef CSAP_MACHIMAGE_H
#define CSAP_MACHIMAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CSAP_PAGE_SIZE      0x1000
#define CSAP_MAX_IMAGE_SPAN (1ULL << 30)
#define CSAP_POINTER_SIZE   8

// Mach-O magic numbers
#define CSAP_MH_MAGIC_64    0xfeedfacf
#define CSAP_FAT_MAGIC      0xcafebabe
#define CSAP_FAT_MAGIC_64   0xcafebabf

// CPU types
#define CSAP_CPU_TYPE_X86_64 0x01000007
#define CSAP_CPU_TYPE_ARM64  0x0100000C

// CPU subtypes
#define CSAP_CPU_SUBTYPE_MASK  0x00ffffff
#define CSAP_CPU_SUBTYPE_ARM64E 2

// Load commands
#define CSAP_LC_SEGMENT_64          0x19
#define CSAP_LC_DYLD_INFO           0x22
#define CSAP_LC_DYLD_INFO_ONLY      0x80000022
#define CSAP_LC_SYMTAB              0x02
#define CSAP_LC_DYSYMTAB            0x0b
#define CSAP_LC_DYLD_EXPORTS_TRIE   0x80000033
#define CSAP_LC_DYLD_CHAINED_FIXUPS 0x80000034

// Section flags
#define CSAP_S_ATTR_PURE_INSTRUCTIONS 0x80000000
#define CSAP_S_ATTR_SOME_INSTRUCTIONS 0x00000400

// Chained fixup pointer formats
#define CSAP_CHAINED_PTR_ARM64E           1
#define CSAP_CHAINED_PTR_64               2
#define CSAP_CHAINED_PTR_64_OFFSET        6
#define CSAP_CHAINED_PTR_ARM64E_USERLAND  9
#define CSAP_CHAINED_PTR_ARM64E_USERLAND24 12

// Chained import formats
#define CSAP_CHAINED_IMPORT             1
#define CSAP_CHAINED_IMPORT_ADDEND      2
#define CSAP_CHAINED_IMPORT_ADDEND64    3

// Bind types
#define CSAP_BIND_TYPE_POINTER    1
#define CSAP_REBASE_TYPE_POINTER  1

// Segment info
typedef struct {
    char     name[16];
    uint64_t address;
    uint64_t size;
    uint64_t file_off;
    uint64_t file_size;
} csap_macho_segment_t;

// Bind info
typedef struct {
    char*    name;
    uint64_t seg_offset;
    int64_t  addend;
    uint8_t  type;
    uint8_t  seg_index;  // segment index in image
} csap_macho_bind_t;

// Rebase info
typedef struct {
    uint64_t value;
    uint8_t  type;
    uint8_t  seg_index;
    uint64_t seg_offset;
} csap_macho_rebase_t;

// Chained fixup（已在文件中定位）
typedef struct {
    uint64_t file_offset;
    uint8_t  pointer_format;
    uint64_t raw;
} csap_macho_chained_t;

// Chained fixup 导入符号
typedef struct {
    char*   name;
    int64_t addend;
} csap_macho_import_t;

// Prelinked 外部指针（shared cache 地址 -> 符号名）
typedef struct {
    uint64_t    address;
    const char* name;
} csap_macho_prelink_symbol_t;

// Section header（供 codeRanges 与 __objc_ivar 偏移回填使用）
typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t address;
    uint64_t size;
    uint32_t flags;
} csap_macho_section_t;

// Symbol table entry（与 struct nlist_64 布局一致）
typedef struct {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
} csap_macho_nlist_t;

// Mach-O image
typedef struct {
    char*                 name;
    uint8_t*              data;
    uint64_t              data_size;
    uint64_t              base;
    csap_macho_segment_t* segments;
    uint32_t              segment_count;
    csap_macho_bind_t*    binds;
    uint32_t              bind_count;
    csap_macho_rebase_t*  rebases;
    uint32_t              rebase_count;

    // section headers
    csap_macho_section_t* sections;
    uint32_t              section_count;

    bool                  relocated;
    uint64_t              loaded_base;

    // export trie data
    uint8_t*              export_trie;
    uint32_t              export_trie_size;

    // symbol table
    csap_macho_nlist_t*   symtab;
    uint32_t              symtab_count;
    char*                 strtab;
    uint32_t              strtab_size;

    // chained fixups
    csap_macho_chained_t* chained;
    uint32_t              chained_count;
    csap_macho_import_t*  imports;
    uint32_t              import_count;
    uint32_t              import_format;
    uint32_t              import_symbols_offset;
    const uint8_t*        import_symbols;
    uint64_t              import_symbols_size;
} csap_macho_image_t;

// Symbol resolver callback
typedef int (*csap_symbol_resolver_t)(const char* name, uint64_t* address, void* ctx);

// Memory interface
typedef int (*csap_mem_map_fn)(uint64_t address, uint64_t size, void* ctx);
typedef int (*csap_mem_write_fn)(uint64_t address, const void* data, uint64_t size, void* ctx);

// Open and parse a Mach-O image
csap_macho_image_t* csap_macho_open(const char* name, const uint8_t* data, uint64_t size);

// Open the arm64e slice of a universal Mach-O image
csap_macho_image_t* csap_macho_open_arm64(const char* name, const uint8_t* data, uint64_t size);

// Find an exported symbol address (relative to load_base)
int csap_macho_export(csap_macho_image_t* image, const char* name, uint64_t load_base, uint64_t* out_address);

// Apply relocations (rebases + binds)
int csap_macho_relocate(csap_macho_image_t* image, uint64_t load_base,
                        csap_symbol_resolver_t resolver, void* resolver_ctx);

// Load image into memory
int csap_macho_load(csap_macho_image_t* image,
                    csap_mem_map_fn mem_map, csap_mem_write_fn mem_write, void* mem_ctx);

// Prepare an image extracted from a dyld shared cache; it keeps its preferred addresses.
int csap_macho_prepare_prelinked(csap_macho_image_t* image,
                                 const csap_macho_prelink_symbol_t* symbols, uint32_t symbol_count,
                                 csap_symbol_resolver_t resolver, void* resolver_ctx);

// Decode authenticated pointers embedded in a kernel-collection executable.
int csap_macho_relocate_kernel_cache(csap_macho_image_t* image, uint64_t load_base, uint64_t kernel_base,
                                     csap_symbol_resolver_t resolver, void* resolver_ctx);

// Rewrite an ARM64e pointer-authentication instruction for an unsigned VM.
uint32_t csap_macho_strip_pointer_authentication(uint32_t instruction);

// Free image
void csap_macho_free(csap_macho_image_t* image);

#ifdef __cplusplus
}
#endif

#endif // CSAP_MACHIMAGE_H
