#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guest.h"

#define CSAP_GUEST_RETURN_ADDRESS   0x0000000100000000ULL
#define CSAP_GUEST_COREFP_BASE      0x0000100000000000ULL
#define CSAP_GUEST_SCRATCH_BASE     0x0000300000000000ULL
#define CSAP_GUEST_SCRATCH_SIZE     (32ULL << 20)
#define CSAP_GUEST_HEAP_BASE        0x0000400000000000ULL
#define CSAP_GUEST_HEAP_SIZE        (64ULL << 20)
#define CSAP_GUEST_STACK_BASE       0x0000500000000000ULL
#define CSAP_GUEST_STACK_SIZE       (8ULL << 20)
#define CSAP_GUEST_STACK_END        (CSAP_GUEST_STACK_BASE + CSAP_GUEST_STACK_SIZE)
#define CSAP_GUEST_PAGE_SIZE        0x1000ULL
#define CSAP_GUEST_TIMEOUT_US       (60ULL * 1000ULL * 1000ULL)

typedef struct {
    char*  name;
    uint64_t address;
} guest_export_t;

typedef struct {
    char*    name;
    uint8_t* data;
    uint64_t size;
    bool     owns_data;
    csap_macho_image_t* image;
} guest_image_t;

struct csap_guest {
    csap_uc_engine_t* engine;
    csap_shims_t*     shims;
    guest_image_t*    images;
    uint32_t          image_count;
    guest_export_t*   exports;
    uint32_t          export_count;
    uint64_t          scratch_cursor;
    bool              closed;
};

static uint64_t align_up(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static uint32_t read_u32_le_local(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void write_u64_le_local(uint8_t* p, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(value >> (i * 8));
    }
}

static guest_image_t* find_image(csap_guest_t* guest, const char* name) {
    for (uint32_t i = 0; i < guest->image_count; i++) {
        if (strcmp(guest->images[i].name, name) == 0) {
            return &guest->images[i];
        }
    }
    return NULL;
}

static uint64_t lookup_export(csap_guest_t* guest, const char* name) {
    for (uint32_t i = 0; i < guest->export_count; i++) {
        if (strcmp(guest->exports[i].name, name) == 0) {
            return guest->exports[i].address;
        }
    }
    return 0;
}

static void add_export(csap_guest_t* guest, const char* name, uint64_t address) {
    guest->exports = realloc(guest->exports, (guest->export_count + 1) * sizeof(guest_export_t));
    guest->exports[guest->export_count].name = strdup(name);
    guest->exports[guest->export_count].address = address;
    guest->export_count++;
}

// 把镜像中给定地址范围所在页映射到引擎。
static int map_symbol_pages(csap_guest_t* guest, const csap_guest_symbol_t* symbols, uint32_t count,
                            uint64_t extra_size) {
    for (uint32_t i = 0; i < count; i++) {
        uint64_t start = symbols[i].address & ~(CSAP_GUEST_PAGE_SIZE - 1);
        uint64_t end = (symbols[i].address + extra_size) & ~(CSAP_GUEST_PAGE_SIZE - 1);
        for (uint64_t page = start; page <= end; page += CSAP_GUEST_PAGE_SIZE) {
            // 已映射的地址会返回错误，忽略即可。
            csap_uc_mem_map(guest->engine, page, CSAP_GUEST_PAGE_SIZE, CSAP_UC_PROT_ALL);
        }
    }
    return 0;
}

// 解析器：先查导出表，再交给 shims。
static uint64_t guest_resolver(const char* name, void* ctx) {
    csap_guest_t* guest = ctx;
    uint64_t address = lookup_export(guest, name);
    if (address != 0) {
        return address;
    }
    return csap_shims_resolve(guest->shims, name);
}

static int guest_mem_map(uint64_t address, uint64_t size, void* ctx) {
    csap_guest_t* guest = ctx;
    return csap_uc_mem_map(guest->engine, address, size, CSAP_UC_PROT_ALL) == 0 ? 0 : -1;
}

static int guest_mem_write(uint64_t address, const void* data, uint64_t size, void* ctx) {
    csap_guest_t* guest = ctx;
    return csap_uc_mem_write(guest->engine, address, data, size) == 0 ? 0 : -1;
}

static int guest_resolve_callback(const char* name, uint64_t* address, void* ctx) {
    uint64_t value = guest_resolver(name, ctx);
    if (value == 0) return -1;
    *address = value;
    return 0;
}

// shared-cache 函数：写入 ldr x16, #8; br x16; <target>
static int load_prelinked_functions(csap_guest_t* guest, const csap_guest_symbol_t* functions, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        uint64_t target = guest_resolver(functions[i].name, guest);
        if (target == 0) {
            fprintf(stderr, "csap guest: failed to resolve prelinked %s\n", functions[i].name);
            return -1;
        }

        uint8_t trampoline[16];
        trampoline[0] = 0x50; trampoline[1] = 0x00; trampoline[2] = 0x00; trampoline[3] = 0x58; // ldr x16, #8
        trampoline[4] = 0x00; trampoline[5] = 0x02; trampoline[6] = 0x1f; trampoline[7] = 0xd6; // br x16
        for (int b = 0; b < 8; b++) {
            trampoline[8 + b] = (uint8_t)(target >> (b * 8));
        }

        if (csap_uc_mem_write(guest->engine, functions[i].address, trampoline, sizeof(trampoline)) != 0) {
            fprintf(stderr, "csap guest: failed to write trampoline for %s\n", functions[i].name);
            return -1;
        }
    }
    return 0;
}

static int load_prelinked_slots(csap_guest_t* guest, const csap_guest_symbol_t* slots, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        uint64_t value = guest_resolver(slots[i].name, guest);
        if (value == 0) {
            fprintf(stderr, "csap guest: failed to resolve slot %s\n", slots[i].name);
            return -1;
        }
        uint8_t data[8];
        write_u64_le_local(data, value);
        if (csap_uc_mem_write(guest->engine, slots[i].address, data, sizeof(data)) != 0) {
            return -1;
        }
    }
    return 0;
}

// ==================== ARM64 非法指令兼容 ====================

static uint64_t read_general_register(csap_guest_t* guest, uint32_t index) {
    uint64_t value = 0;
    if (index == 31) return 0;
    if (index <= 28) {
        csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_X0 + (int32_t)index, &value);
    } else if (index == 29) {
        csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_X29, &value);
    } else if (index == 30) {
        csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_X30, &value);
    }
    return value;
}

static void write_general_register(csap_guest_t* guest, uint32_t index, uint64_t value) {
    if (index == 31) return;
    if (index <= 28) {
        csap_uc_reg_write(guest->engine, CSAP_ARM64_REG_X0 + (int32_t)index, value);
    } else if (index == 29) {
        csap_uc_reg_write(guest->engine, CSAP_ARM64_REG_X29, value);
    } else if (index == 30) {
        csap_uc_reg_write(guest->engine, CSAP_ARM64_REG_X30, value);
    }
}

static uint64_t read_base_register(csap_guest_t* guest, uint32_t index) {
    if (index == 31) {
        uint64_t sp = 0;
        csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_SP, &sp);
        return sp;
    }
    return read_general_register(guest, index);
}

static int emulate_eor3(csap_guest_t* guest, uint32_t instruction) {
    uint32_t destination = instruction & 31;
    uint32_t first = (instruction >> 5) & 31;
    uint32_t third = (instruction >> 10) & 31;
    uint32_t second = (instruction >> 16) & 31;

    uint8_t a[16], b[16], c[16];
    if (csap_uc_reg_read128(guest->engine, CSAP_ARM64_REG_V0 + (int32_t)first, a) != 0 ||
        csap_uc_reg_read128(guest->engine, CSAP_ARM64_REG_V0 + (int32_t)second, b) != 0 ||
        csap_uc_reg_read128(guest->engine, CSAP_ARM64_REG_V0 + (int32_t)third, c) != 0) {
        return -1;
    }

    uint8_t result[16];
    for (int i = 0; i < 16; i++) {
        result[i] = a[i] ^ b[i] ^ c[i];
    }

    return csap_uc_reg_write128(guest->engine, CSAP_ARM64_REG_V0 + (int32_t)destination, result);
}

// Unicorn 2.1 不支持的新指令在此模拟。
static int emulate_invalid_instruction(csap_guest_t* guest, bool* handled) {
    *handled = false;

    uint64_t pc = 0;
    if (csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_PC, &pc) != 0) {
        return -1;
    }

    uint8_t bytes[4];
    if (csap_uc_mem_read(guest->engine, pc, bytes, 4) != 0) {
        return 0;
    }
    uint32_t instruction = read_u32_le_local(bytes);

    if ((instruction & 0xffe08000) == 0xce000000) { // EOR3
        if (emulate_eor3(guest, instruction) != 0) return -1;
        csap_uc_reg_write(guest->engine, CSAP_ARM64_REG_PC, pc + 4);
        *handled = true;
        return 0;
    }

    uint32_t opcode = instruction & 0xffe0fc00;
    uint64_t width = 0;

    switch (opcode) {
    case 0x88e0fc00: case 0xb8e08000: width = 4; break; // CASAL32 / SWPAL32
    case 0xc8e0fc00: case 0xf8e08000: width = 8; break; // CASAL64 / SWPAL64
    default: return 0;
    }

    uint32_t source = (instruction >> 16) & 31;
    uint32_t base = (instruction >> 5) & 31;
    uint32_t destination = instruction & 31;

    uint64_t address = read_base_register(guest, base);
    uint8_t memory[8] = {0};
    if (csap_uc_mem_read(guest->engine, address, memory, width) != 0) {
        fprintf(stderr, "csap guest: failed to read atomic operand at %#llx\n", (unsigned long long)address);
        return -1;
    }

    uint64_t old_value = 0;
    for (uint64_t i = 0; i < width; i++) {
        old_value |= (uint64_t)memory[i] << (i * 8);
    }

    uint64_t source_value = read_general_register(guest, source);
    if (width == 4) source_value = (uint32_t)source_value;

    if (opcode == 0x88e0fc00 || opcode == 0xc8e0fc00) {
        uint64_t new_value = read_general_register(guest, destination);
        if (width == 4) new_value = (uint32_t)new_value;
        if (old_value == source_value) {
            uint8_t data[8];
            write_u64_le_local(data, new_value);
            if (csap_uc_mem_write(guest->engine, address, data, width) != 0) return -1;
        }
        write_general_register(guest, source, old_value);
    } else {
        uint8_t data[8];
        write_u64_le_local(data, source_value);
        if (csap_uc_mem_write(guest->engine, address, data, width) != 0) return -1;
        write_general_register(guest, destination, old_value);
    }

    csap_uc_reg_write(guest->engine, CSAP_ARM64_REG_PC, pc + 4);
    *handled = true;
    return 0;
}

// ==================== 公开 API ====================

csap_guest_t* csap_guest_open(const csap_guest_image_t* specs, uint32_t image_count,
                              const csap_guest_options_t* options) {
    if (specs == NULL || image_count == 0 || options == NULL) return NULL;

    csap_guest_t* guest = calloc(1, sizeof(csap_guest_t));
    if (guest == NULL) return NULL;

    guest->engine = csap_uc_open(CSAP_UC_ARCH_ARM64, CSAP_UC_MODE_ARM);
    if (guest->engine == NULL) {
        fprintf(stderr, "csap guest: failed to open Unicorn engine\n");
        goto fail;
    }

    csap_uc_set_max_cpu_model(guest->engine);

    for (int i = 0; i < 4; i++) {
        uint64_t address = i == 0 ? CSAP_GUEST_RETURN_ADDRESS :
                           i == 1 ? CSAP_GUEST_SCRATCH_BASE :
                           i == 2 ? CSAP_GUEST_HEAP_BASE : CSAP_GUEST_STACK_BASE;
        uint64_t size = i == 0 ? CSAP_GUEST_PAGE_SIZE :
                        i == 1 ? CSAP_GUEST_SCRATCH_SIZE :
                        i == 2 ? CSAP_GUEST_HEAP_SIZE : CSAP_GUEST_STACK_SIZE;
        if (csap_uc_mem_map(guest->engine, address, size, CSAP_UC_PROT_ALL) != 0) {
            fprintf(stderr, "csap guest: failed to map memory at %#llx\n", (unsigned long long)address);
            goto fail;
        }
    }

    {
        uint8_t brk[4] = {0x00, 0x00, 0x20, 0xd4};
        if (csap_uc_mem_write(guest->engine, CSAP_GUEST_RETURN_ADDRESS, brk, 4) != 0) goto fail;
    }

    // 解析 CoreFP 导出
    guest->images = calloc(image_count, sizeof(guest_image_t));
    if (guest->images == NULL) goto fail;
    guest->image_count = image_count;

    for (uint32_t i = 0; i < image_count; i++) {
        guest->images[i].name = strdup(specs[i].name);
        guest->images[i].image = csap_macho_open_arm64(specs[i].name, specs[i].data, specs[i].size);
        if (guest->images[i].image == NULL) {
            fprintf(stderr, "csap guest: failed to open %s\n", specs[i].name);
            goto fail;
        }
    }

    csap_macho_image_t* corefp = find_image(guest, "CoreFP") ? find_image(guest, "CoreFP")->image : NULL;
    if (corefp == NULL) {
        fprintf(stderr, "csap guest: missing CoreFP image\n");
        goto fail;
    }

    csap_core_export_t* core_exports = NULL;
    if (options->core_export_count > 0) {
        core_exports = calloc(options->core_export_count, sizeof(csap_core_export_t));
        if (core_exports == NULL) goto fail;
    }

    for (uint32_t i = 0; i < options->core_export_count; i++) {
        uint64_t address = 0;
        if (csap_macho_export(corefp, options->core_export_names[i], CSAP_GUEST_COREFP_BASE, &address) != 0) {
            fprintf(stderr, "csap guest: failed to resolve CoreFP export %s\n", options->core_export_names[i]);
            free(core_exports);
            goto fail;
        }
        core_exports[i].name = options->core_export_names[i];
        core_exports[i].address = address;
        add_export(guest, options->core_export_names[i], address);
    }

    guest->shims = csap_shims_create_ex(guest->engine, CSAP_SHIM_ABI_ARM64,
                                        core_exports, options->core_export_count,
                                        options->corefp_icxs, options->corefp_icxs_size);
    free(core_exports);
    if (guest->shims == NULL) goto fail;

    if (options->configure_shims != NULL) {
        options->configure_shims(guest->shims, options->configure_context);
    }

    // AppleMediaServices 入口符号
    csap_macho_image_t* apple = find_image(guest, "AppleMediaServices") ?
                                find_image(guest, "AppleMediaServices")->image : NULL;
    if (apple == NULL) {
        fprintf(stderr, "csap guest: missing AppleMediaServices image\n");
        goto fail;
    }
    for (uint32_t i = 0; i < options->entry_count; i++) {
        uint64_t address = 0;
        if (csap_macho_export(apple, options->entry_names[i], apple->base, &address) != 0) {
            fprintf(stderr, "csap guest: failed to resolve entry %s\n", options->entry_names[i]);
            goto fail;
        }
        add_export(guest, options->entry_names[i], address);
    }

    // shared-cache 槽位与函数
    for (uint32_t i = 0; i < image_count; i++) {
        if (specs[i].slots != NULL && specs[i].slot_count > 0) {
            map_symbol_pages(guest, specs[i].slots, specs[i].slot_count, 0);
        }
        if (specs[i].functions != NULL && specs[i].function_count > 0) {
            map_symbol_pages(guest, specs[i].functions, specs[i].function_count, 15);
        }
        if (specs[i].prelinked_symbols != NULL && specs[i].prelinked_symbol_count > 0) {
            // prelinked 镜像的外部指针在 PreparePrelinked 时解析，无需额外映射。
        }
    }

    for (uint32_t i = 0; i < image_count; i++) {
        if (specs[i].slots != NULL && specs[i].slot_count > 0) {
            if (load_prelinked_slots(guest, specs[i].slots, specs[i].slot_count) != 0) goto fail;
        }
        if (specs[i].functions != NULL && specs[i].function_count > 0) {
            if (load_prelinked_functions(guest, specs[i].functions, specs[i].function_count) != 0) goto fail;
        }
    }

    // 装载镜像
    for (uint32_t i = 0; i < image_count; i++) {
        csap_macho_image_t* image = guest->images[i].image;
        if (specs[i].prelinked) {
            if (csap_macho_prepare_prelinked(image, specs[i].prelinked_symbols,
                                             specs[i].prelinked_symbol_count,
                                             guest_resolve_callback, guest) != 0) {
                goto fail;
            }
        } else if (csap_macho_relocate(image, specs[i].base, guest_resolve_callback, guest) != 0) {
            goto fail;
        }

        if (specs[i].kernel_base != 0) {
            if (csap_macho_relocate_kernel_cache(image, specs[i].base, specs[i].kernel_base,
                                                 guest_resolve_callback, guest) != 0) {
                goto fail;
            }
        }

        if (csap_macho_load(image, guest_mem_map, guest_mem_write, guest) != 0) {
            fprintf(stderr, "csap guest: failed to load %s\n", specs[i].name);
            goto fail;
        }
    }

    return guest;

fail:
    csap_guest_close(guest);
    return NULL;
}

uint64_t csap_guest_export(csap_guest_t* guest, const char* name) {
    if (guest == NULL || name == NULL) return 0;
    return lookup_export(guest, name);
}

void csap_guest_begin_call(csap_guest_t* guest) {
    if (guest != NULL) guest->scratch_cursor = 0;
}

void csap_guest_clear_scratch(csap_guest_t* guest) {
    if (guest == NULL) return;

    // 与 Go 的 clearScratch 一致：清零已用区域后再重置游标。
    static const uint8_t zeros[4096];
    for (uint64_t offset = 0; offset < guest->scratch_cursor; offset += sizeof(zeros)) {
        uint64_t chunk = guest->scratch_cursor - offset;
        if (chunk > sizeof(zeros)) chunk = sizeof(zeros);
        if (csap_uc_mem_write(guest->engine, CSAP_GUEST_SCRATCH_BASE + offset,
                              zeros, chunk) != 0) {
            break;
        }
    }

    guest->scratch_cursor = 0;
}

uint64_t csap_guest_scratch(csap_guest_t* guest, const void* data,
                            uint64_t data_size, uint64_t reserve_size) {
    if (guest == NULL) return 0;

    uint64_t reserved = align_up(reserve_size > 0 ? reserve_size : 1, 16);
    if (guest->scratch_cursor > CSAP_GUEST_SCRATCH_SIZE ||
        reserved > CSAP_GUEST_SCRATCH_SIZE - guest->scratch_cursor) {
        fprintf(stderr, "csap guest: scratch space exhausted\n");
        return 0;
    }

    uint64_t address = CSAP_GUEST_SCRATCH_BASE + guest->scratch_cursor;
    guest->scratch_cursor += reserved;

    if (data != NULL && data_size > 0) {
        if (data_size > reserve_size) {
            fprintf(stderr, "csap guest: scratch data exceeds reservation\n");
            return 0;
        }
        if (csap_uc_mem_write(guest->engine, address, data, data_size) != 0) {
            return 0;
        }
    } else if (reserve_size > 0) {
        static const uint8_t zeros[4096];
        for (uint64_t offset = 0; offset < reserve_size; offset += sizeof(zeros)) {
            uint64_t chunk = reserve_size - offset;
            if (chunk > sizeof(zeros)) chunk = sizeof(zeros);
            if (csap_uc_mem_write(guest->engine, address + offset, zeros, chunk) != 0) {
                return 0;
            }
        }
    }

    return address;
}

int csap_guest_read(csap_guest_t* guest, uint64_t address, void* buffer, uint64_t size) {
    if (guest == NULL || buffer == NULL) return -1;
    return csap_uc_mem_read(guest->engine, address, buffer, size);
}

int csap_guest_write(csap_guest_t* guest, uint64_t address, const void* buffer, uint64_t size) {
    if (guest == NULL || buffer == NULL) return -1;
    return csap_uc_mem_write(guest->engine, address, buffer, size);
}

csap_shims_t* csap_guest_shims(csap_guest_t* guest) {
    return guest ? guest->shims : NULL;
}

const char* csap_guest_fault(csap_guest_t* guest) {
    return guest && guest->shims ? csap_shims_fault(guest->shims) : NULL;
}

void csap_guest_reset_fault(csap_guest_t* guest) {
    if (guest && guest->shims) csap_shims_reset_fault(guest->shims);
}

int csap_guest_invoke(csap_guest_t* guest, uint64_t function,
                      const uint64_t* arguments, uint32_t argument_count,
                      uint64_t* result) {
    if (guest == NULL || guest->closed) return -1;
    if (function == 0) {
        fprintf(stderr, "csap guest: entry point is unavailable\n");
        return -1;
    }

    static const int32_t registers[8] = {
        CSAP_ARM64_REG_X0, CSAP_ARM64_REG_X1, CSAP_ARM64_REG_X2, CSAP_ARM64_REG_X3,
        CSAP_ARM64_REG_X4, CSAP_ARM64_REG_X5, CSAP_ARM64_REG_X6, CSAP_ARM64_REG_X7,
    };

    for (uint32_t i = 0; i < 8; i++) {
        uint64_t value = i < argument_count ? arguments[i] : 0;
        if (csap_uc_reg_write(guest->engine, registers[i], value) != 0) return -1;
    }

    uint32_t extra = argument_count > 8 ? argument_count - 8 : 0;
    uint64_t stack_pointer = CSAP_GUEST_STACK_END - (uint64_t)extra * 8;
    stack_pointer &= ~15ULL;

    for (uint32_t i = 0; i < extra; i++) {
        uint8_t data[8];
        write_u64_le_local(data, arguments[8 + i]);
        if (csap_uc_mem_write(guest->engine, stack_pointer + (uint64_t)i * 8, data, 8) != 0) {
            return -1;
        }
    }

    if (csap_uc_reg_write(guest->engine, CSAP_ARM64_REG_SP, stack_pointer) != 0) return -1;
    if (csap_uc_reg_write(guest->engine, CSAP_ARM64_REG_X30, CSAP_GUEST_RETURN_ADDRESS) != 0) return -1;

    csap_guest_reset_fault(guest);

    uint64_t next = function;
    for (;;) {
        int execution = csap_uc_emu_start(guest->engine, next, CSAP_GUEST_RETURN_ADDRESS,
                                          CSAP_GUEST_TIMEOUT_US, 0);
        if (execution == 0) break;

        if (csap_guest_fault(guest) != NULL) {
            return -1;
        }

        bool handled = false;
        if (emulate_invalid_instruction(guest, &handled) != 0) {
            return -1;
        }
        if (handled) {
            if (csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_PC, &next) != 0) return -1;
            continue;
        }

        uint64_t pc = 0, link = 0;
        csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_PC, &pc);
        csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_X30, &link);
        fprintf(stderr, "csap guest: execution failed at %#llx from %#llx (%s)\n",
                (unsigned long long)pc, (unsigned long long)link, csap_uc_strerror(execution));
        return -1;
    }

    uint64_t instruction = 0;
    if (csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_PC, &instruction) != 0) return -1;
    if (instruction != CSAP_GUEST_RETURN_ADDRESS) {
        fprintf(stderr, "csap guest: stopped unexpectedly at %#llx\n", (unsigned long long)instruction);
        return -1;
    }

    if (result != NULL) {
        if (csap_uc_reg_read(guest->engine, CSAP_ARM64_REG_X0, result) != 0) return -1;
    }
    return 0;
}

void csap_guest_close(csap_guest_t* guest) {
    if (guest == NULL) return;
    if (guest->closed) return;
    guest->closed = true;

    csap_shims_close(guest->shims);

    for (uint32_t i = 0; i < guest->image_count; i++) {
        free(guest->images[i].name);
        csap_macho_free(guest->images[i].image);
    }
    free(guest->images);

    for (uint32_t i = 0; i < guest->export_count; i++) {
        free(guest->exports[i].name);
    }
    free(guest->exports);

    csap_uc_close(guest->engine);
    free(guest);
}
