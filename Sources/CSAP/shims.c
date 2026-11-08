#include "shims.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ==================== 内部数据结构 ====================

typedef struct {
    char* name;
    uint64_t address;
    csap_shim_handler_t handler;
    void* ctx;
} csap_shim_entry_t;

typedef struct {
    char* name;
    uint64_t address;
} csap_symbol_entry_t;

typedef struct {
    uint64_t address;
    uint64_t size;
    uint64_t reserved;
} csap_allocation_t;

typedef struct {
    uint64_t address;
    uint64_t size;
} csap_free_block_t;

typedef struct {
    uint64_t      address;
    uint8_t*      data;
    uint64_t      size;
    uint64_t      data_address;
    bool          has_data;
} csap_xpc_object_t;

typedef struct {
    char*     path;
    uint8_t*  data;
    uint64_t  size;
} csap_adi_file_t;

struct csap_shims {
    csap_uc_engine_t* engine;
    csap_uc_hook_t hook;

    csap_shim_entry_t* entries;
    uint32_t entry_count;
    uint32_t entry_cap;

    csap_symbol_entry_t* symbols;
    uint32_t symbol_count;
    uint32_t symbol_cap;

    uint64_t code_cursor;
    uint64_t data_cursor;

    char* fault;

    csap_macho_image_t* corefp;
    uint8_t* icxs;
    uint64_t icxs_size;

    uint64_t errno_val;

    // 堆管理
    uint64_t heap_cursor;
    csap_allocation_t* allocations;
    uint32_t allocation_count;
    uint32_t allocation_cap;
    csap_free_block_t* free_blocks;
    uint32_t free_block_count;
    uint32_t free_block_cap;

    // 平台服务状态
    uint64_t errno_addr;
    uint64_t icxs_offset;
    uint32_t iterator;

    // ABI 与 ARM64 Store 运行时
    csap_shim_abi_t abi;
    csap_core_export_t* core_exports;
    uint32_t core_export_count;
    uint8_t host_uuid[16];
    bool has_host_uuid;
    void* platform_state;

    // Store 平台服务：XPC
    csap_xpc_object_t* xpc_objects;
    uint32_t xpc_object_count;
    uint32_t xpc_object_cap;
    uint64_t xpc_next_object;
    uint8_t* xpc_data;
    uint64_t xpc_data_size;
    uint8_t* xpc_sync_reply;
    uint64_t xpc_sync_reply_size;
    uint8_t* xpc_reply;
    uint64_t xpc_reply_size;
    bool xpc_replied;
    uint64_t xpc_event_handler;

    // Store 平台服务：Mach
    uint64_t mach_port_callback;
    uint64_t mach_port_context;
    uint64_t mach_port_info;
    uint8_t* mach_message_reply;
    uint64_t mach_message_reply_size;

    // Store 平台服务：回调与 ADI 状态文件
    uint64_t* callback_returns;
    uint32_t callback_return_count;
    uint32_t callback_return_cap;

    csap_adi_file_t* adi_files;
    uint32_t adi_file_count;
    uint32_t adi_file_cap;
    char adi_path[512];
    uint64_t adi_offset;

    bool pause_run_loop;

    uint64_t kernel_service;
    uint64_t buffer_vtable;

    csap_shims_fairplay_handler_t fairplay_handler;
    void* fairplay_context;
    csap_shims_mach_rpc_handler_t mach_rpc_handler;
    void* mach_rpc_context;
};

// ==================== 符号表查找 ====================

static uint64_t find_symbol(csap_shims_t* s, const char* name) {
    for (uint32_t i = 0; i < s->symbol_count; i++) {
        if (strcmp(s->symbols[i].name, name) == 0) {
            return s->symbols[i].address;
        }
    }
    return 0;
}

static void add_symbol(csap_shims_t* s, const char* name, uint64_t address) {
    for (uint32_t i = 0; i < s->symbol_count; i++) {
        if (strcmp(s->symbols[i].name, name) == 0) return;
    }
    if (s->symbol_count >= s->symbol_cap) {
        s->symbol_cap = s->symbol_cap ? s->symbol_cap * 2 : 64;
        s->symbols = realloc(s->symbols, s->symbol_cap * sizeof(csap_symbol_entry_t));
    }
    s->symbols[s->symbol_count].name = strdup(name);
    s->symbols[s->symbol_count].address = address;
    s->symbol_count++;
}

// ==================== Shim 条目 ====================

static csap_shim_entry_t* find_entry(csap_shims_t* s, uint64_t address) {
    for (uint32_t i = 0; i < s->entry_count; i++) {
        if (s->entries[i].address == address) {
            return &s->entries[i];
        }
    }
    return NULL;
}

static void add_entry(csap_shims_t* s, const char* name, uint64_t address,
                      csap_shim_handler_t handler, void* ctx) {
    for (uint32_t i = 0; i < s->entry_count; i++) {
        if (strcmp(s->entries[i].name, name) == 0) return;
    }
    if (s->entry_count >= s->entry_cap) {
        s->entry_cap = s->entry_cap ? s->entry_cap * 2 : 64;
        s->entries = realloc(s->entries, s->entry_cap * sizeof(csap_shim_entry_t));
    }
    s->entries[s->entry_count].name = strdup(name);
    s->entries[s->entry_count].address = address;
    s->entries[s->entry_count].handler = handler;
    s->entries[s->entry_count].ctx = ctx;
    s->entry_count++;
}

// ==================== Dispatch hook ====================

static void shim_dispatch(csap_uc_engine_t* uc, uint64_t address, uint32_t size, void* user_data) {
    (void)uc;
    (void)size;
    csap_shims_t* s = (csap_shims_t*)user_data;

    csap_shim_entry_t* entry = find_entry(s, address);
    if (entry == NULL) {
        char buf[128];
        snprintf(buf, sizeof(buf), "guest entered unknown service address 0x%llx",
                 (unsigned long long)address);
        if (s->fault == NULL) s->fault = strdup(buf);
        csap_uc_emu_stop(uc);
        return;
    }

    if (entry->handler != NULL) {
        int ret = entry->handler(s, entry->ctx);
        if (ret != 0 && s->fault == NULL) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%s: handler failed", entry->name);
            s->fault = strdup(buf);
            csap_uc_emu_stop(uc);
        }
    }
}

// ==================== 默认 unsupported handler ====================

static int unsupported_handler(csap_shims_t* s, void* ctx) {
    (void)s;
    const char* name = (const char*)ctx;
    fprintf(stderr, "csap: guest called unsupported import %s\n", name);
    return -1;
}

// ==================== 公开 API ====================

csap_shims_t* csap_shims_create(csap_uc_engine_t* engine,
                                csap_macho_image_t* corefp_image,
                                const uint8_t* icxs, uint64_t icxs_size) {
    csap_shims_t* s = csap_shims_create_ex(engine, CSAP_SHIM_ABI_X86_64, NULL, 0, icxs, icxs_size);
    if (s != NULL) {
        s->corefp = corefp_image;
    }
    return s;
}

csap_shims_t* csap_shims_create_ex(csap_uc_engine_t* engine, csap_shim_abi_t abi,
                                   const csap_core_export_t* core_exports, uint32_t core_export_count,
                                   const uint8_t* icxs, uint64_t icxs_size) {
    if (engine == NULL) return NULL;

    // 映射 shim 区域
    if (csap_uc_mem_map(engine, CSAP_SHIM_BASE, CSAP_SHIM_SIZE, CSAP_UC_PROT_ALL) != 0) {
        fprintf(stderr, "csap: failed to map shim area\n");
        return NULL;
    }

    csap_shims_t* s = calloc(1, sizeof(csap_shims_t));
    if (s == NULL) return NULL;

    s->engine = engine;
    s->code_cursor = CSAP_SHIM_BASE;
    s->data_cursor = CSAP_SHIM_BASE + CSAP_SHIM_CODE_SIZE;
    s->abi = abi;
    s->xpc_next_object = 0xffff000000000000ULL;

    if (core_exports != NULL && core_export_count > 0) {
        s->core_exports = malloc(core_export_count * sizeof(csap_core_export_t));
        if (s->core_exports != NULL) {
            for (uint32_t i = 0; i < core_export_count; i++) {
                s->core_exports[i].name = strdup(core_exports[i].name);
                s->core_exports[i].address = core_exports[i].address;
            }
            s->core_export_count = core_export_count;
        }
    }

    if (icxs != NULL && icxs_size > 0) {
        s->icxs = malloc(icxs_size);
        if (s->icxs) {
            memcpy(s->icxs, icxs, icxs_size);
            s->icxs_size = icxs_size;
        }
    }

    // 注册代码 hook
    {
        int ret = csap_uc_hook_add(engine, &s->hook, CSAP_UC_HOOK_CODE,
                                   shim_dispatch, s,
                                   CSAP_SHIM_BASE, CSAP_SHIM_BASE + CSAP_SHIM_CODE_SIZE - 1);
        if (ret != 0) {
            fprintf(stderr, "csap: failed to add shim hook: %s (code %d)\n",
                    csap_uc_strerror(ret), ret);
            csap_shims_close(s);
            return NULL;
        }
    }

    // 注册内存服务
    if (csap_shims_register_memory_services(s) != 0) {
        fprintf(stderr, "csap: failed to register memory services\n");
        csap_shims_close(s);
        return NULL;
    }

    // 注册平台服务
    if (csap_shims_register_platform_services(s) != 0) {
        fprintf(stderr, "csap: failed to register platform services\n");
        csap_shims_close(s);
        return NULL;
    }

    return s;
}

void csap_shims_close(csap_shims_t* s) {
    if (s == NULL) return;

    if (s->hook != 0) {
        csap_uc_hook_del(s->engine, s->hook);
    }

    for (uint32_t i = 0; i < s->entry_count; i++) {
        free(s->entries[i].name);
    }
    free(s->entries);

    for (uint32_t i = 0; i < s->symbol_count; i++) {
        free(s->symbols[i].name);
    }
    free(s->symbols);

    free(s->fault);
    free(s->icxs);
    free(s->allocations);
    free(s->free_blocks);
    for (uint32_t i = 0; i < s->core_export_count; i++) {
        free((void*)s->core_exports[i].name);
    }
    free(s->core_exports);

    for (uint32_t i = 0; i < s->xpc_object_count; i++) {
        free(s->xpc_objects[i].data);
    }
    free(s->xpc_objects);
    free(s->xpc_data);
    free(s->xpc_sync_reply);
    free(s->xpc_reply);
    free(s->mach_message_reply);
    free(s->callback_returns);

    for (uint32_t i = 0; i < s->adi_file_count; i++) {
        free(s->adi_files[i].path);
        free(s->adi_files[i].data);
    }
    free(s->adi_files);

    free(s);
}

uint64_t csap_shims_resolve(csap_shims_t* s, const char* name) {
    if (s == NULL || name == NULL) return 0;

    uint64_t addr = find_symbol(s, name);
    if (addr != 0) return addr;

    return csap_shims_add_function(s, name, unsupported_handler, (void*)name);
}

uint64_t csap_shims_add_function(csap_shims_t* s, const char* name,
                                 csap_shim_handler_t handler, void* ctx) {
    if (s == NULL || name == NULL) return 0;

    uint64_t existing = find_symbol(s, name);
    if (existing != 0) return existing;

    if (s->code_cursor + CSAP_SHIM_SLOT_SIZE > CSAP_SHIM_BASE + CSAP_SHIM_CODE_SIZE) {
        fprintf(stderr, "csap: shim code area is full\n");
        return 0;
    }

    uint64_t address = s->code_cursor;
    s->code_cursor += CSAP_SHIM_SLOT_SIZE;

    // 写入 stub：x86-64 是 ret，ARM64 是 ret（0xD65F03C0）
    if (s->abi == CSAP_SHIM_ABI_ARM64) {
        uint8_t ret[4] = {0xC0, 0x03, 0x5F, 0xD6};
        if (csap_uc_mem_write(s->engine, address, ret, 4) != 0) {
            fprintf(stderr, "csap: failed to write shim stub for %s\n", name);
            return 0;
        }
    } else {
        uint8_t ret = 0xC3;
        if (csap_uc_mem_write(s->engine, address, &ret, 1) != 0) {
            fprintf(stderr, "csap: failed to write shim stub for %s\n", name);
            return 0;
        }
    }

    add_entry(s, name, address, handler, ctx);
    add_symbol(s, name, address);

    return address;
}

uint64_t csap_shims_add_data(csap_shims_t* s, const char* name,
                             const void* data, uint64_t size) {
    if (s == NULL || name == NULL) return 0;

    uint64_t existing = find_symbol(s, name);
    if (existing != 0) return existing;

    // 8 字节对齐
    s->data_cursor = (s->data_cursor + 7) & ~7ULL;
    if (s->data_cursor + size > CSAP_SHIM_BASE + CSAP_SHIM_SIZE) {
        fprintf(stderr, "csap: shim data area is full\n");
        return 0;
    }

    uint64_t address = s->data_cursor;
    s->data_cursor += size > 8 ? size : 8;

    if (data != NULL && size > 0) {
        if (csap_uc_mem_write(s->engine, address, data, size) != 0) {
            fprintf(stderr, "csap: failed to write shim data for %s\n", name);
            return 0;
        }
    }

    add_symbol(s, name, address);
    return address;
}

const char* csap_shims_fault(csap_shims_t* s) {
    return s ? s->fault : NULL;
}

void csap_shims_reset_fault(csap_shims_t* s) {
    if (s == NULL) return;
    free(s->fault);
    s->fault = NULL;
}

// ==================== 辅助函数 ====================

int csap_shims_arg(csap_shims_t* s, int index, uint64_t* value) {
    if (s == NULL || value == NULL) return -1;

    if (s->abi == CSAP_SHIM_ABI_ARM64) {
        static const int32_t arm_regs[] = {
            CSAP_ARM64_REG_X0, CSAP_ARM64_REG_X1, CSAP_ARM64_REG_X2, CSAP_ARM64_REG_X3,
            CSAP_ARM64_REG_X4, CSAP_ARM64_REG_X5, CSAP_ARM64_REG_X6, CSAP_ARM64_REG_X7,
        };
        const int arm_count = (int)(sizeof(arm_regs) / sizeof(arm_regs[0]));

        if (index >= 0 && index < arm_count) {
            return csap_uc_reg_read(s->engine, arm_regs[index], value);
        }
        if (index < 0) return -1;

        uint64_t sp;
        if (csap_uc_reg_read(s->engine, CSAP_ARM64_REG_SP, &sp) != 0) return -1;

        return csap_uc_mem_read(s->engine, sp + (uint64_t)(index - arm_count) * 8, value, 8);
    }

    static const int32_t regs[] = {
        CSAP_REG_RDI, CSAP_REG_RSI, CSAP_REG_RDX,
        CSAP_REG_RCX, CSAP_REG_R8,  CSAP_REG_R9
    };
    const int reg_count = (int)(sizeof(regs) / sizeof(regs[0]));

    if (index >= 0 && index < reg_count) {
        return csap_uc_reg_read(s->engine, regs[index], value);
    }

    if (index < 0) return -1;

    // 从栈读取
    uint64_t rsp;
    if (csap_uc_reg_read(s->engine, CSAP_REG_RSP, &rsp) != 0) return -1;

    // 返回地址占 8 字节，然后是第 7 个及以后的参数
    uint64_t stack_off = 8 + (uint64_t)(index - reg_count) * 8;
    return csap_uc_mem_read(s->engine, rsp + stack_off, value, 8);
}

int csap_shims_set_result(csap_shims_t* s, uint64_t value) {
    if (s == NULL) return -1;
    if (s->abi == CSAP_SHIM_ABI_ARM64) {
        return csap_uc_reg_write(s->engine, CSAP_ARM64_REG_X0, value);
    }
    return csap_uc_reg_write(s->engine, CSAP_REG_RAX, value);
}

int csap_shims_read_u32(csap_shims_t* s, uint64_t addr, uint32_t* value) {
    uint8_t buf[4];
    if (csap_uc_mem_read(s->engine, addr, buf, 4) != 0) return -1;
    *value = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
             ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return 0;
}

int csap_shims_write_u32(csap_shims_t* s, uint64_t addr, uint32_t value) {
    uint8_t buf[4] = {
        (uint8_t)(value), (uint8_t)(value >> 8),
        (uint8_t)(value >> 16), (uint8_t)(value >> 24)
    };
    return csap_uc_mem_write(s->engine, addr, buf, 4);
}

int csap_shims_read_u64(csap_shims_t* s, uint64_t addr, uint64_t* value) {
    uint8_t buf[8];
    if (csap_uc_mem_read(s->engine, addr, buf, 8) != 0) return -1;
    *value = 0;
    for (int i = 0; i < 8; i++) {
        *value |= ((uint64_t)buf[i]) << (i * 8);
    }
    return 0;
}

int csap_shims_write_u64(csap_shims_t* s, uint64_t addr, uint64_t value) {
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)(value >> (i * 8));
    }
    return csap_uc_mem_write(s->engine, addr, buf, 8);
}

int csap_shims_read_mem(csap_shims_t* s, uint64_t addr, void* buf, uint64_t size) {
    return csap_uc_mem_read(s->engine, addr, buf, size);
}

int csap_shims_write_mem(csap_shims_t* s, uint64_t addr, const void* buf, uint64_t size) {
    return csap_uc_mem_write(s->engine, addr, buf, size);
}

int csap_shims_read_cstring(csap_shims_t* s, uint64_t addr, char* buf, size_t max_len) {
    if (s == NULL || buf == NULL || max_len == 0) return -1;

    size_t i = 0;
    while (i < max_len - 1) {
        uint8_t ch;
        if (csap_uc_mem_read(s->engine, addr + i, &ch, 1) != 0) return -1;
        if (ch == 0) {
            buf[i] = '\0';
            return 0;
        }
        buf[i] = (char)ch;
        i++;
    }
    buf[max_len - 1] = '\0';
    return 0;
}

uint64_t csap_shims_errno(csap_shims_t* s) {
    return s ? s->errno_val : 0;
}

void csap_shims_set_errno(csap_shims_t* s, uint64_t value) {
    if (s) s->errno_val = value;
}

csap_uc_engine_t* csap_shims_engine(csap_shims_t* s) {
    return s ? s->engine : NULL;
}

uint64_t csap_shims_errno_addr(csap_shims_t* s) {
    return s ? s->errno_addr : 0;
}

void csap_shims_set_errno_addr(csap_shims_t* s, uint64_t addr) {
    if (s) s->errno_addr = addr;
}

uint64_t csap_shims_icxs_offset(csap_shims_t* s) {
    return s ? s->icxs_offset : 0;
}

void csap_shims_set_icxs_offset(csap_shims_t* s, uint64_t offset) {
    if (s) s->icxs_offset = offset;
}

uint32_t csap_shims_iterator(csap_shims_t* s) {
    return s ? s->iterator : 0;
}

void csap_shims_set_iterator(csap_shims_t* s, uint32_t iter) {
    if (s) s->iterator = iter;
}

const uint8_t* csap_shims_icxs(csap_shims_t* s) {
    return s ? s->icxs : NULL;
}

uint64_t csap_shims_icxs_size(csap_shims_t* s) {
    return s ? s->icxs_size : 0;
}

csap_macho_image_t* csap_shims_corefp(csap_shims_t* s) {
    return s ? s->corefp : NULL;
}

bool csap_shims_is_arm64(csap_shims_t* s) {
    return s != NULL && s->abi == CSAP_SHIM_ABI_ARM64;
}

uint64_t csap_shims_core_export(csap_shims_t* s, const char* name) {
    if (s == NULL || name == NULL) return 0;
    for (uint32_t i = 0; i < s->core_export_count; i++) {
        if (strcmp(s->core_exports[i].name, name) == 0) {
            return s->core_exports[i].address;
        }
    }
    return 0;
}

static int shim_noop_zero(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, 0);
}

int csap_shims_add_zero_return_alias(csap_shims_t* s, const char* name) {
    if (s == NULL || name == NULL) return -1;
    if (find_symbol(s, name) != 0) {
        return 0;
    }
    return csap_shims_add_function(s, name, shim_noop_zero, NULL) != 0 ? 0 : -1;
}

void csap_shims_set_host_uuid(csap_shims_t* s, const uint8_t uuid[16]) {
    if (s == NULL || uuid == NULL) return;
    memcpy(s->host_uuid, uuid, 16);
    s->has_host_uuid = true;
}

int csap_shims_host_uuid(csap_shims_t* s, uint8_t out[16]) {
    if (s == NULL || out == NULL || !s->has_host_uuid) return -1;
    memcpy(out, s->host_uuid, 16);
    return 0;
}

void* csap_shims_platform_state(csap_shims_t* s) {
    return s ? s->platform_state : NULL;
}

void csap_shims_set_platform_state(csap_shims_t* s, void* state) {
    if (s != NULL) s->platform_state = state;
}

// ==================== 堆管理 ====================

static uint64_t align_up(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static void coalesce_free_blocks(csap_shims_t* s) {
    // 按地址排序
    for (uint32_t i = 0; i < s->free_block_count; i++) {
        for (uint32_t j = i + 1; j < s->free_block_count; j++) {
            if (s->free_blocks[j].address < s->free_blocks[i].address) {
                csap_free_block_t tmp = s->free_blocks[i];
                s->free_blocks[i] = s->free_blocks[j];
                s->free_blocks[j] = tmp;
            }
        }
    }

    // 合并相邻块
    uint32_t write = 0;
    for (uint32_t i = 0; i < s->free_block_count; i++) {
        if (write > 0) {
            csap_free_block_t* last = &s->free_blocks[write - 1];
            if (last->address + last->size == s->free_blocks[i].address) {
                last->size += s->free_blocks[i].size;
                continue;
            }
        }
        s->free_blocks[write++] = s->free_blocks[i];
    }
    s->free_block_count = write;

    // 回收堆末尾的空闲块
    while (s->free_block_count > 0) {
        csap_free_block_t* last = &s->free_blocks[s->free_block_count - 1];
        if (last->address + last->size != CSAP_HEAP_BASE + s->heap_cursor) break;
        s->heap_cursor -= last->size;
        s->free_block_count--;
    }
}

uint64_t csap_shims_allocate(csap_shims_t* s, uint64_t size) {
    if (s == NULL) return 0;
    if (size > CSAP_MAX_GUEST_TRANSFER) return 0;

    uint64_t reserved = align_up(size > 0 ? size : 1, 16);

    // 尝试从空闲块分配
    for (uint32_t i = 0; i < s->free_block_count; i++) {
        if (s->free_blocks[i].size < reserved) continue;

        uint64_t address = s->free_blocks[i].address;
        if (s->free_blocks[i].size == reserved) {
            // 移除这个块
            for (uint32_t j = i; j < s->free_block_count - 1; j++) {
                s->free_blocks[j] = s->free_blocks[j + 1];
            }
            s->free_block_count--;
        } else {
            s->free_blocks[i].address += reserved;
            s->free_blocks[i].size -= reserved;
        }

        // 记录分配
        if (s->allocation_count >= s->allocation_cap) {
            s->allocation_cap = s->allocation_cap ? s->allocation_cap * 2 : 64;
            s->allocations = realloc(s->allocations, s->allocation_cap * sizeof(csap_allocation_t));
        }
        s->allocations[s->allocation_count].address = address;
        s->allocations[s->allocation_count].size = size;
        s->allocations[s->allocation_count].reserved = reserved;
        s->allocation_count++;

        return address;
    }

    // 从堆顶分配
    if (s->heap_cursor > CSAP_HEAP_SIZE || reserved > CSAP_HEAP_SIZE - s->heap_cursor) {
        return 0;  // 堆耗尽
    }

    uint64_t address = CSAP_HEAP_BASE + s->heap_cursor;
    s->heap_cursor += reserved;

    if (s->allocation_count >= s->allocation_cap) {
        s->allocation_cap = s->allocation_cap ? s->allocation_cap * 2 : 64;
        s->allocations = realloc(s->allocations, s->allocation_cap * sizeof(csap_allocation_t));
    }
    s->allocations[s->allocation_count].address = address;
    s->allocations[s->allocation_count].size = size;
    s->allocations[s->allocation_count].reserved = reserved;
    s->allocation_count++;

    return address;
}

uint64_t csap_shims_allocate_aligned(csap_shims_t* s, uint64_t size, uint64_t alignment) {
    if (s == NULL) return 0;
    if (size > CSAP_MAX_GUEST_TRANSFER) return 0;
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) return 0;

    uint64_t reserved = align_up(size > 0 ? size : 1, alignment);
    uint64_t cursor = align_up(s->heap_cursor, alignment);
    if (cursor > CSAP_HEAP_SIZE || reserved > CSAP_HEAP_SIZE - cursor) {
        return 0;
    }

    uint64_t address = CSAP_HEAP_BASE + cursor;
    s->heap_cursor = cursor + reserved;

    if (s->allocation_count >= s->allocation_cap) {
        s->allocation_cap = s->allocation_cap ? s->allocation_cap * 2 : 64;
        s->allocations = realloc(s->allocations, s->allocation_cap * sizeof(csap_allocation_t));
    }
    s->allocations[s->allocation_count].address = address;
    s->allocations[s->allocation_count].size = size;
    s->allocations[s->allocation_count].reserved = reserved;
    s->allocation_count++;

    return address;
}

int csap_shims_release(csap_shims_t* s, uint64_t address) {
    if (s == NULL || address == 0) return -1;

    // 查找分配记录
    int found = -1;
    for (uint32_t i = 0; i < s->allocation_count; i++) {
        if (s->allocations[i].address == address) {
            found = (int)i;
            break;
        }
    }
    if (found < 0) return -1;

    uint64_t reserved = s->allocations[found].reserved;

    // 清零内存（分块写入，避免逐字节调用）
    uint8_t zeros[4096] = {0};
    uint64_t remaining = reserved;
    uint64_t cursor = address;
    while (remaining > 0) {
        uint64_t chunk = remaining < sizeof(zeros) ? remaining : sizeof(zeros);
        if (csap_uc_mem_write(s->engine, cursor, zeros, chunk) != 0) return -1;
        cursor += chunk;
        remaining -= chunk;
    }

    // 移除分配记录
    for (uint32_t i = (uint32_t)found; i < s->allocation_count - 1; i++) {
        s->allocations[i] = s->allocations[i + 1];
    }
    s->allocation_count--;

    // 添加到空闲块
    if (s->free_block_count >= s->free_block_cap) {
        s->free_block_cap = s->free_block_cap ? s->free_block_cap * 2 : 64;
        s->free_blocks = realloc(s->free_blocks, s->free_block_cap * sizeof(csap_free_block_t));
    }
    s->free_blocks[s->free_block_count].address = address;
    s->free_blocks[s->free_block_count].size = reserved;
    s->free_block_count++;

    coalesce_free_blocks(s);
    return 0;
}

uint64_t csap_shims_allocation_size(csap_shims_t* s, uint64_t address) {
    if (s == NULL) return 0;
    for (uint32_t i = 0; i < s->allocation_count; i++) {
        if (s->allocations[i].address == address) {
            return s->allocations[i].reserved;
        }
    }
    return 0;
}

// ==================== ARM64 Store 运行时状态 ====================

void csap_shims_set_fairplay_handler(csap_shims_t* s, csap_shims_fairplay_handler_t handler, void* ctx) {
    if (s == NULL) return;
    s->fairplay_handler = handler;
    s->fairplay_context = ctx;
}

csap_shims_fairplay_handler_t csap_shims_fairplay_handler(csap_shims_t* s) {
    return s ? s->fairplay_handler : NULL;
}

void* csap_shims_fairplay_context(csap_shims_t* s) {
    return s ? s->fairplay_context : NULL;
}

void csap_shims_set_mach_rpc_handler(csap_shims_t* s, csap_shims_mach_rpc_handler_t handler, void* ctx) {
    if (s == NULL) return;
    s->mach_rpc_handler = handler;
    s->mach_rpc_context = ctx;
}

csap_shims_mach_rpc_handler_t csap_shims_mach_rpc_handler(csap_shims_t* s) {
    return s ? s->mach_rpc_handler : NULL;
}

void* csap_shims_mach_rpc_context(csap_shims_t* s) {
    return s ? s->mach_rpc_context : NULL;
}

void csap_shims_set_pause_run_loop(csap_shims_t* s, bool pause) {
    if (s) s->pause_run_loop = pause;
}

bool csap_shims_pause_run_loop(csap_shims_t* s) {
    return s ? s->pause_run_loop : false;
}

int csap_shims_add_zero_return_aliases(csap_shims_t* s, const char* const* names, uint32_t count) {
    if (s == NULL || (names == NULL && count > 0)) return -1;
    for (uint32_t i = 0; i < count; i++) {
        if (csap_shims_add_zero_return_alias(s, names[i]) != 0) return -1;
    }
    return 0;
}

int csap_shims_invoke_callback(csap_shims_t* s, uint64_t initializer) {
    if (s == NULL || initializer == 0 || s->abi != CSAP_SHIM_ABI_ARM64) return -1;

    uint64_t completion = find_symbol(s, "callback.complete");
    if (completion == 0) return -1;

    uint64_t link = 0;
    if (csap_uc_reg_read(s->engine, CSAP_ARM64_REG_X30, &link) != 0) return -1;

    if (s->callback_return_count >= s->callback_return_cap) {
        s->callback_return_cap = s->callback_return_cap ? s->callback_return_cap * 2 : 16;
        s->callback_returns = realloc(s->callback_returns,
                                      s->callback_return_cap * sizeof(uint64_t));
        if (s->callback_returns == NULL) return -1;
    }
    s->callback_returns[s->callback_return_count++] = link;

    if (csap_uc_reg_write(s->engine, CSAP_ARM64_REG_X30, completion) != 0) return -1;
    return csap_uc_reg_write(s->engine, CSAP_ARM64_REG_PC, initializer);
}

int csap_shims_complete_callback(csap_shims_t* s) {
    if (s == NULL || s->callback_return_count == 0) return -1;

    uint64_t link = s->callback_returns[--s->callback_return_count];
    if (csap_uc_reg_write(s->engine, CSAP_ARM64_REG_X30, link) != 0) return -1;
    return csap_shims_set_result(s, 0);
}

// ==================== XPC 对象 ====================

static csap_xpc_object_t* find_xpc_object(csap_shims_t* s, uint64_t address) {
    for (uint32_t i = 0; i < s->xpc_object_count; i++) {
        if (s->xpc_objects[i].address == address) {
            return &s->xpc_objects[i];
        }
    }
    return NULL;
}

static csap_xpc_object_t* ensure_xpc_object(csap_shims_t* s, uint64_t address) {
    csap_xpc_object_t* object = find_xpc_object(s, address);
    if (object != NULL) return object;

    if (s->xpc_object_count >= s->xpc_object_cap) {
        s->xpc_object_cap = s->xpc_object_cap ? s->xpc_object_cap * 2 : 64;
        s->xpc_objects = realloc(s->xpc_objects, s->xpc_object_cap * sizeof(csap_xpc_object_t));
        if (s->xpc_objects == NULL) return NULL;
    }

    object = &s->xpc_objects[s->xpc_object_count++];
    memset(object, 0, sizeof(*object));
    object->address = address;
    return object;
}

uint64_t csap_shims_new_xpc_object(csap_shims_t* s, const void* data, uint64_t size, bool has_data) {
    if (s == NULL) return 0;

    uint64_t address = ++s->xpc_next_object;
    csap_xpc_object_t* object = ensure_xpc_object(s, address);
    if (object == NULL) return 0;

    if (data != NULL && size > 0) {
        object->data = malloc(size);
        if (object->data == NULL) return 0;
        memcpy(object->data, data, size);
        object->size = size;
    }
    object->has_data = has_data;
    return address;
}

void csap_shims_set_xpc_object_data(csap_shims_t* s, uint64_t object_address,
                                    const void* data, uint64_t size) {
    if (s == NULL) return;

    csap_xpc_object_t* object = ensure_xpc_object(s, object_address);
    if (object == NULL) return;

    free(object->data);
    object->data = NULL;
    object->size = 0;
    object->data_address = 0;

    if (data != NULL && size > 0) {
        object->data = malloc(size);
        if (object->data == NULL) return;
        memcpy(object->data, data, size);
        object->size = size;
    }
    object->has_data = true;

    free(s->xpc_data);
    s->xpc_data = NULL;
    s->xpc_data_size = 0;
    if (data != NULL && size > 0) {
        s->xpc_data = malloc(size);
        if (s->xpc_data != NULL) {
            memcpy(s->xpc_data, data, size);
            s->xpc_data_size = size;
        }
    }
}

uint64_t csap_shims_xpc_object_address(csap_shims_t* s, uint64_t object_address,
                                       uint64_t* size, bool* has_data) {
    if (has_data) *has_data = false;
    if (size) *size = 0;
    if (s == NULL) return 0;

    csap_xpc_object_t* object = find_xpc_object(s, object_address);
    if (object == NULL || !object->has_data) return 0;

    if (has_data) *has_data = true;
    if (size) *size = object->size;

    if (object->data_address == 0) {
        uint64_t reserved = object->size > 0 ? object->size : 1;
        object->data_address = csap_shims_allocate(s, reserved);
        if (object->data_address == 0) {
            if (has_data) *has_data = false;
            if (size) *size = 0;
            return 0;
        }
        if (object->size > 0) {
            csap_uc_mem_write(s->engine, object->data_address, object->data, object->size);
        }
    }

    return object->data_address;
}

const uint8_t* csap_shims_xpc_object_data(csap_shims_t* s, uint64_t object_address, uint64_t* size) {
    if (size) *size = 0;
    if (s == NULL) return NULL;

    csap_xpc_object_t* object = find_xpc_object(s, object_address);
    if (object == NULL) return NULL;

    if (size) *size = object->size;
    return object->data;
}

bool csap_shims_xpc_object_exists(csap_shims_t* s, uint64_t object_address) {
    return s != NULL && find_xpc_object(s, object_address) != NULL;
}

void csap_shims_set_xpc_sync_reply(csap_shims_t* s, const void* data, uint64_t size) {
    if (s == NULL) return;
    free(s->xpc_sync_reply);
    s->xpc_sync_reply = NULL;
    s->xpc_sync_reply_size = 0;
    if (data != NULL && size > 0) {
        s->xpc_sync_reply = malloc(size);
        if (s->xpc_sync_reply != NULL) {
            memcpy(s->xpc_sync_reply, data, size);
            s->xpc_sync_reply_size = size;
        }
    }
}

const uint8_t* csap_shims_xpc_sync_reply(csap_shims_t* s, uint64_t* size) {
    if (size) *size = s ? s->xpc_sync_reply_size : 0;
    return s ? s->xpc_sync_reply : NULL;
}

void csap_shims_set_xpc_reply(csap_shims_t* s, const void* data, uint64_t size, bool replied) {
    if (s == NULL) return;
    free(s->xpc_reply);
    s->xpc_reply = NULL;
    s->xpc_reply_size = 0;
    if (data != NULL && size > 0) {
        s->xpc_reply = malloc(size);
        if (s->xpc_reply != NULL) {
            memcpy(s->xpc_reply, data, size);
            s->xpc_reply_size = size;
        }
    }
    s->xpc_replied = replied;
}

const uint8_t* csap_shims_xpc_reply(csap_shims_t* s, uint64_t* size) {
    if (size) *size = s ? s->xpc_reply_size : 0;
    return s ? s->xpc_reply : NULL;
}

bool csap_shims_xpc_replied(csap_shims_t* s) {
    return s ? s->xpc_replied : false;
}

void csap_shims_clear_xpc_reply(csap_shims_t* s) {
    if (s == NULL) return;
    free(s->xpc_reply);
    s->xpc_reply = NULL;
    s->xpc_reply_size = 0;
    s->xpc_replied = false;
}

const uint8_t* csap_shims_xpc_data(csap_shims_t* s, uint64_t* size) {
    if (size) *size = s ? s->xpc_data_size : 0;
    return s ? s->xpc_data : NULL;
}

void csap_shims_clear_xpc_data(csap_shims_t* s) {
    if (s == NULL) return;
    free(s->xpc_data);
    s->xpc_data = NULL;
    s->xpc_data_size = 0;
}

void csap_shims_set_xpc_event_handler(csap_shims_t* s, uint64_t address) {
    if (s) s->xpc_event_handler = address;
}

uint64_t csap_shims_xpc_event_handler(csap_shims_t* s) {
    return s ? s->xpc_event_handler : 0;
}

// ==================== Mach 状态 ====================

void csap_shims_set_mach_port(csap_shims_t* s, uint64_t callback, uint64_t context, uint64_t info) {
    if (s == NULL) return;
    s->mach_port_callback = callback;
    s->mach_port_context = context;
    s->mach_port_info = info;
}

uint64_t csap_shims_mach_port_callback(csap_shims_t* s) {
    return s ? s->mach_port_callback : 0;
}

uint64_t csap_shims_mach_port_context(csap_shims_t* s) {
    return s ? s->mach_port_context : 0;
}

uint64_t csap_shims_mach_port_info(csap_shims_t* s) {
    return s ? s->mach_port_info : 0;
}

void csap_shims_set_mach_message_reply(csap_shims_t* s, const void* data, uint64_t size) {
    if (s == NULL) return;
    free(s->mach_message_reply);
    s->mach_message_reply = NULL;
    s->mach_message_reply_size = 0;
    if (data != NULL && size > 0) {
        s->mach_message_reply = malloc(size);
        if (s->mach_message_reply != NULL) {
            memcpy(s->mach_message_reply, data, size);
            s->mach_message_reply_size = size;
        }
    }
}

const uint8_t* csap_shims_mach_message_reply(csap_shims_t* s, uint64_t* size) {
    if (size) *size = s ? s->mach_message_reply_size : 0;
    return s ? s->mach_message_reply : NULL;
}

void csap_shims_clear_mach_message_reply(csap_shims_t* s) {
    if (s == NULL) return;
    free(s->mach_message_reply);
    s->mach_message_reply = NULL;
    s->mach_message_reply_size = 0;
}

// ==================== ADI 状态文件 ====================

bool csap_shims_is_adi_state_path(const char* path) {
    return path != NULL && strcmp(path, "/var/db/fpsd/adi/adi.pb") == 0;
}

static csap_adi_file_t* find_adi_file(csap_shims_t* s, const char* path) {
    for (uint32_t i = 0; i < s->adi_file_count; i++) {
        if (strcmp(s->adi_files[i].path, path) == 0) {
            return &s->adi_files[i];
        }
    }
    return NULL;
}

int csap_shims_set_adi_file(csap_shims_t* s, const char* path, const void* data, uint64_t size) {
    if (s == NULL || path == NULL) return -1;

    csap_adi_file_t* file = find_adi_file(s, path);
    if (file == NULL) {
        if (s->adi_file_count >= s->adi_file_cap) {
            s->adi_file_cap = s->adi_file_cap ? s->adi_file_cap * 2 : 8;
            s->adi_files = realloc(s->adi_files, s->adi_file_cap * sizeof(csap_adi_file_t));
            if (s->adi_files == NULL) return -1;
        }
        file = &s->adi_files[s->adi_file_count];
        memset(file, 0, sizeof(*file));
        file->path = strdup(path);
        if (file->path == NULL) return -1;
        s->adi_file_count++;
    }

    free(file->data);
    file->data = NULL;
    file->size = 0;

    if (data != NULL && size > 0) {
        file->data = malloc(size);
        if (file->data == NULL) return -1;
        memcpy(file->data, data, size);
        file->size = size;
    }

    return 0;
}

bool csap_shims_has_adi_file(csap_shims_t* s, const char* path) {
    return s != NULL && path != NULL && find_adi_file(s, path) != NULL;
}

const uint8_t* csap_shims_adi_file(csap_shims_t* s, const char* path, uint64_t* size) {
    if (size) *size = 0;
    if (s == NULL || path == NULL) return NULL;

    csap_adi_file_t* file = find_adi_file(s, path);
    if (file == NULL) return NULL;

    if (size) *size = file->size;
    return file->data;
}

const uint8_t* csap_shims_adi_file_by_name(csap_shims_t* s, const char* base_name, uint64_t* size) {
    if (size) *size = 0;
    if (s == NULL || base_name == NULL) return NULL;

    for (uint32_t i = 0; i < s->adi_file_count; i++) {
        const char* path = s->adi_files[i].path;
        const char* base = strrchr(path, '/');
        base = base != NULL ? base + 1 : path;
        if (strcmp(base, base_name) == 0) {
            if (size) *size = s->adi_files[i].size;
            return s->adi_files[i].data;
        }
    }
    return NULL;
}

void csap_shims_set_adi_path(csap_shims_t* s, const char* path) {
    if (s == NULL) return;
    if (path == NULL) {
        s->adi_path[0] = '\0';
        return;
    }
    snprintf(s->adi_path, sizeof(s->adi_path), "%s", path);
}

const char* csap_shims_adi_path(csap_shims_t* s) {
    return s ? s->adi_path : NULL;
}

void csap_shims_set_adi_offset(csap_shims_t* s, uint64_t offset) {
    if (s) s->adi_offset = offset;
}

uint64_t csap_shims_adi_offset(csap_shims_t* s) {
    return s ? s->adi_offset : 0;
}

void csap_shims_remove_adi_file(csap_shims_t* s, const char* path) {
    if (s == NULL || path == NULL) return;

    for (uint32_t i = 0; i < s->adi_file_count; i++) {
        if (strcmp(s->adi_files[i].path, path) != 0) continue;

        free(s->adi_files[i].path);
        free(s->adi_files[i].data);
        for (uint32_t j = i + 1; j < s->adi_file_count; j++) {
            s->adi_files[j - 1] = s->adi_files[j];
        }
        s->adi_file_count--;
        return;
    }
}

uint64_t csap_shims_symbol(csap_shims_t* s, const char* name) {
    if (s == NULL || name == NULL) return 0;
    return find_symbol(s, name);
}

uint64_t csap_shims_kernel_service(csap_shims_t* s) {
    return s ? s->kernel_service : 0;
}

void csap_shims_set_kernel_service(csap_shims_t* s, uint64_t address) {
    if (s) s->kernel_service = address;
}

uint64_t csap_shims_buffer_vtable(csap_shims_t* s) {
    return s ? s->buffer_vtable : 0;
}

void csap_shims_set_buffer_vtable(csap_shims_t* s, uint64_t address) {
    if (s) s->buffer_vtable = address;
}
