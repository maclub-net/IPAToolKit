#include "shims.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ==================== 辅助 ====================

static int checked_size(uint64_t value, size_t* out) {
    if (value > CSAP_MAX_GUEST_TRANSFER) return -1;
    *out = (size_t)value;
    return 0;
}

static int clear_guest(csap_shims_t* s, uint64_t address, uint64_t size) {
    if (size == 0) return 0;

    uint8_t zeros[4096] = {0};
    uint64_t remaining = size;
    uint64_t cursor = address;
    while (remaining > 0) {
        uint64_t chunk = remaining < sizeof(zeros) ? remaining : sizeof(zeros);
        if (csap_uc_mem_write(csap_shims_engine(s), cursor, zeros, chunk) != 0) return -1;
        cursor += chunk;
        remaining -= chunk;
    }
    return 0;
}

// ==================== malloc 系列 ====================

static int shim_malloc(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t size;
    if (csap_shims_arg(s, 0, &size) != 0) return -1;

    uint64_t addr = csap_shims_allocate(s, size);
    if (addr == 0) return -1;

    return csap_shims_set_result(s, addr);
}

static int shim_malloc_aligned(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t size, alignment;
    if (csap_shims_arg(s, 0, &size) != 0) return -1;
    if (csap_shims_arg(s, 1, &alignment) != 0) return -1;

    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        fprintf(stderr, "csap: invalid allocation alignment %#llx\n",
                (unsigned long long)alignment);
        return -1;
    }

    uint64_t addr = csap_shims_allocate_aligned(s, size, alignment);
    if (addr == 0) return -1;

    return csap_shims_set_result(s, addr);
}

// IOMallocTypeImpl：从对象的 type descriptor 读取大小。
static int shim_malloc_typed(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t view;
    if (csap_shims_arg(s, 0, &view) != 0) return -1;

    uint32_t size;
    if (csap_shims_read_u32(s, view + 44, &size) != 0) return -1;

    uint64_t addr = csap_shims_allocate(s, (uint64_t)(size & 0x00ffffff));
    if (addr == 0) return -1;

    return csap_shims_set_result(s, addr);
}

static int shim_malloc_typed_variable(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t size;
    if (csap_shims_arg(s, 1, &size) != 0) return -1;

    uint64_t addr = csap_shims_allocate(s, size);
    if (addr == 0) return -1;

    return csap_shims_set_result(s, addr);
}

static int shim_malloc_lock(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t addr = csap_shims_allocate(s, 8);
    if (addr == 0) return -1;

    if (clear_guest(s, addr, 8) != 0) {
        csap_shims_release(s, addr);
        return -1;
    }

    return csap_shims_set_result(s, addr);
}

static int shim_free_typed(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t addr;
    if (csap_shims_arg(s, 1, &addr) != 0) return -1;

    if (addr != 0) {
        if (csap_shims_release(s, addr) != 0) return -1;
    }

    return csap_shims_set_result(s, 0);
}

static int shim_malloc_good_size(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t size;
    if (csap_shims_arg(s, 0, &size) != 0) return -1;
    if (size < 1) size = 1;
    return csap_shims_set_result(s, (size + 15) & ~15ULL);
}

static int shim_malloc_size(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t addr;
    if (csap_shims_arg(s, 0, &addr) != 0) return -1;

    uint64_t sz = csap_shims_allocation_size(s, addr);
    return csap_shims_set_result(s, sz);
}

static int shim_calloc(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t count, size;
    if (csap_shims_arg(s, 0, &count) != 0) return -1;
    if (csap_shims_arg(s, 1, &size) != 0) return -1;

    if (count != 0 && size > UINT64_MAX / count) return -1;
    uint64_t total = count * size;

    uint64_t addr = csap_shims_allocate(s, total);
    if (addr == 0) return -1;

    if (clear_guest(s, addr, total) != 0) {
        csap_shims_release(s, addr);
        return -1;
    }

    return csap_shims_set_result(s, addr);
}

static int shim_realloc(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t old_addr, new_size;
    if (csap_shims_arg(s, 0, &old_addr) != 0) return -1;
    if (csap_shims_arg(s, 1, &new_size) != 0) return -1;

    if (old_addr == 0) {
        uint64_t addr = csap_shims_allocate(s, new_size);
        if (addr == 0) return -1;
        return csap_shims_set_result(s, addr);
    }

    uint64_t old_reserved = csap_shims_allocation_size(s, old_addr);
    if (old_reserved == 0) return -1;  // 未知指针

    if (new_size <= old_reserved) {
        return csap_shims_set_result(s, old_addr);
    }

    uint64_t new_addr = csap_shims_allocate(s, new_size);
    if (new_addr == 0) return -1;

    // 复制旧数据
    uint8_t* buf = malloc((size_t)old_reserved);
    if (buf == NULL) {
        csap_shims_release(s, new_addr);
        return -1;
    }
    csap_uc_engine_t* eng = csap_shims_engine(s);
    if (csap_uc_mem_read(eng, old_addr, buf, old_reserved) != 0 ||
        csap_uc_mem_write(eng, new_addr, buf, old_reserved) != 0) {
        free(buf);
        csap_shims_release(s, new_addr);
        return -1;
    }
    free(buf);

    csap_shims_release(s, old_addr);
    return csap_shims_set_result(s, new_addr);
}

static int shim_free(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t addr;
    if (csap_shims_arg(s, 0, &addr) != 0) return -1;

    if (addr != 0) {
        if (csap_shims_release(s, addr) != 0) return -1;
    }
    return csap_shims_set_result(s, 0);
}

// ==================== 虚拟内存 ====================

static int shim_mmap(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t length;
    if (csap_shims_arg(s, 1, &length) != 0) return -1;

    uint64_t address = csap_shims_allocate_aligned(s, length, 0x1000);
    if (address == 0) {
        return csap_shims_set_result(s, UINT64_MAX);
    }

    if (clear_guest(s, address, length) != 0) {
        csap_shims_release(s, address);
        return -1;
    }

    return csap_shims_set_result(s, address);
}

static int shim_munmap(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t address;
    if (csap_shims_arg(s, 0, &address) != 0) return -1;

    if (csap_shims_release(s, address) != 0) {
        return csap_shims_set_result(s, UINT64_MAX);
    }

    return csap_shims_set_result(s, 0);
}

static int shim_vm_allocate(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t field, size;
    if (csap_shims_arg(s, 1, &field) != 0) return -1;
    if (csap_shims_arg(s, 2, &size) != 0) return -1;

    uint64_t address = csap_shims_allocate_aligned(s, size, 0x1000);
    if (address == 0) {
        return csap_shims_set_result(s, 3); // KERN_NO_SPACE
    }

    if (clear_guest(s, address, size) != 0) {
        csap_shims_release(s, address);
        return -1;
    }

    if (csap_shims_write_u64(s, field, address) != 0) {
        csap_shims_release(s, address);
        return -1;
    }

    return csap_shims_set_result(s, 0);
}

static int shim_vm_deallocate(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t address;
    if (csap_shims_arg(s, 1, &address) != 0) return -1;

    if (csap_shims_release(s, address) != 0) {
        return csap_shims_set_result(s, 1); // KERN_INVALID_ADDRESS
    }

    return csap_shims_set_result(s, 0);
}

// ==================== 内存操作 ====================

static int shim_memmove(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t dst, src, len;
    if (csap_shims_arg(s, 0, &dst) != 0) return -1;
    if (csap_shims_arg(s, 1, &src) != 0) return -1;
    if (csap_shims_arg(s, 2, &len) != 0) return -1;

    size_t size;
    if (checked_size(len, &size) != 0) return -1;
    if (size == 0) return csap_shims_set_result(s, dst);

    uint8_t* buf = malloc(size);
    if (buf == NULL) return -1;

    csap_uc_engine_t* eng = csap_shims_engine(s);
    if (csap_uc_mem_read(eng, src, buf, len) != 0 ||
        csap_uc_mem_write(eng, dst, buf, len) != 0) {
        free(buf);
        return -1;
    }
    free(buf);

    return csap_shims_set_result(s, dst);
}

static int shim_memset(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t dst, value, len;
    if (csap_shims_arg(s, 0, &dst) != 0) return -1;
    if (csap_shims_arg(s, 1, &value) != 0) return -1;
    if (csap_shims_arg(s, 2, &len) != 0) return -1;

    size_t size;
    if (checked_size(len, &size) != 0) return -1;
    if (size == 0) return csap_shims_set_result(s, dst);

    uint8_t* buf = malloc(size);
    if (buf == NULL) return -1;
    memset(buf, (int)value, size);

    int status = csap_uc_mem_write(csap_shims_engine(s), dst, buf, len);
    free(buf);
    if (status != 0) return -1;

    return csap_shims_set_result(s, dst);
}

static int shim_bzero(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t dst, len;
    if (csap_shims_arg(s, 0, &dst) != 0) return -1;
    if (csap_shims_arg(s, 1, &len) != 0) return -1;

    size_t size;
    if (checked_size(len, &size) != 0) return -1;
    if (size == 0) return csap_shims_set_result(s, dst);

    if (clear_guest(s, dst, len) != 0) return -1;
    return csap_shims_set_result(s, dst);
}

static int shim_checked_memcpy(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t len, cap;
    if (csap_shims_arg(s, 2, &len) != 0) return -1;
    if (csap_shims_arg(s, 3, &cap) != 0) return -1;
    if (len > cap) return -1;
    return shim_memmove(s, ctx);
}

static int shim_checked_memset(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t len, cap;
    if (csap_shims_arg(s, 2, &len) != 0) return -1;
    if (csap_shims_arg(s, 3, &cap) != 0) return -1;
    if (len > cap) return -1;
    return shim_memset(s, ctx);
}

static int shim_memcmp(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t left, right, len;
    if (csap_shims_arg(s, 0, &left) != 0) return -1;
    if (csap_shims_arg(s, 1, &right) != 0) return -1;
    if (csap_shims_arg(s, 2, &len) != 0) return -1;

    size_t size;
    if (checked_size(len, &size) != 0) return -1;
    if (size == 0) return csap_shims_set_result(s, 0);

    uint8_t* a = malloc(size);
    uint8_t* b = malloc(size);
    if (a == NULL || b == NULL) { free(a); free(b); return -1; }

    csap_uc_engine_t* eng = csap_shims_engine(s);
    if (csap_uc_mem_read(eng, left, a, len) != 0 ||
        csap_uc_mem_read(eng, right, b, len) != 0) {
        free(a);
        free(b);
        return -1;
    }

    int result = memcmp(a, b, size);
    free(a);
    free(b);

    return csap_shims_set_result(s, (uint64_t)(int64_t)result);
}

static int shim_strcmp(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t left, right;
    if (csap_shims_arg(s, 0, &left) != 0) return -1;
    if (csap_shims_arg(s, 1, &right) != 0) return -1;

    char a[4096], b[4096];
    if (csap_shims_read_cstring(s, left, a, sizeof(a)) != 0) return -1;
    if (csap_shims_read_cstring(s, right, b, sizeof(b)) != 0) return -1;

    int result = strcmp(a, b);
    return csap_shims_set_result(s, (uint64_t)(int64_t)result);
}

static int shim_strncmp(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t left, right, len;
    if (csap_shims_arg(s, 0, &left) != 0) return -1;
    if (csap_shims_arg(s, 1, &right) != 0) return -1;
    if (csap_shims_arg(s, 2, &len) != 0) return -1;

    size_t size;
    if (checked_size(len, &size) != 0) return -1;
    if (size == 0) return csap_shims_set_result(s, 0);

    uint8_t* a = malloc(size);
    uint8_t* b = malloc(size);
    if (a == NULL || b == NULL) { free(a); free(b); return -1; }

    csap_uc_engine_t* eng = csap_shims_engine(s);
    if (csap_uc_mem_read(eng, left, a, len) != 0 ||
        csap_uc_mem_read(eng, right, b, len) != 0) {
        free(a);
        free(b);
        return -1;
    }

    int result = 0;
    for (size_t i = 0; i < size; i++) {
        if (a[i] != b[i]) {
            result = (int)a[i] - (int)b[i];
            break;
        }
        if (a[i] == 0) break;
    }
    free(a);
    free(b);

    return csap_shims_set_result(s, (uint64_t)(int64_t)result);
}

static int shim_strlen(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t addr;
    if (csap_shims_arg(s, 0, &addr) != 0) return -1;

    char buf[4096];
    if (csap_shims_read_cstring(s, addr, buf, sizeof(buf)) != 0) return -1;

    return csap_shims_set_result(s, (uint64_t)strlen(buf));
}

static int shim_strnlen(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t addr, limit;
    if (csap_shims_arg(s, 0, &addr) != 0) return -1;
    if (csap_shims_arg(s, 1, &limit) != 0) return -1;

    if (limit > CSAP_MAX_GUEST_TRANSFER) {
        fprintf(stderr, "csap: string length limit %llu exceeds maximum\n",
                (unsigned long long)limit);
        return -1;
    }

    csap_uc_engine_t* eng = csap_shims_engine(s);
    for (uint64_t offset = 0; offset < limit;) {
        uint64_t page_room = 0x1000 - (addr + offset) % 0x1000;
        uint64_t chunk = limit - offset < page_room ? limit - offset : page_room;

        uint8_t data[4096];
        if (csap_uc_mem_read(eng, addr + offset, data, chunk) != 0) return -1;

        for (uint64_t i = 0; i < chunk; i++) {
            if (data[i] == 0) {
                return csap_shims_set_result(s, offset + i);
            }
        }
        offset += chunk;
    }

    return csap_shims_set_result(s, limit);
}

// ==================== 注册 ====================

static void add_alias(csap_shims_t* s, const char** names, int count, csap_shim_handler_t handler) {
    for (int i = 0; i < count; i++) {
        csap_shims_add_function(s, names[i], handler, NULL);
    }
}

int csap_shims_register_memory_services(csap_shims_t* s) {
    if (s == NULL) return -1;

    const char* malloc_names[] = {"_malloc", "_IOMalloc", "_IOMallocData"};
    const char* malloc_aligned_names[] = {"_IOMallocAligned"};
    const char* malloc_typed_names[] = {"_IOMallocTypeImpl"};
    const char* malloc_typed_var_names[] = {"_IOMallocTypeVarImpl", "_OSObject_typed_operator_new"};
    const char* malloc_lock_names[] = {"_IOLockAlloc", "_IORWLockAlloc"};
    const char* malloc_good_names[] = {"_malloc_good_size"};
    const char* malloc_size_names[] = {"_malloc_size"};
    const char* calloc_names[] = {"_calloc"};
    const char* realloc_names[] = {"_realloc", "_reallocf"};
    const char* free_names[] = {
        "_free", "_IOFree", "_IOFreeAligned", "_IOFreeData",
        "_IOLockFree", "_IORWLockFree", "_OSObject_typed_operator_delete",
    };
    const char* free_typed_names[] = {"_IOFreeTypeImpl", "_IOFreeTypeVarImpl"};
    const char* mmap_names[] = {"_mmap"};
    const char* munmap_names[] = {"_munmap"};
    const char* vm_allocate_names[] = {"_vm_allocate"};
    const char* vm_deallocate_names[] = {"_vm_deallocate"};
    const char* memmove_names[] = {"_memcpy", "_memmove"};
    const char* memset_names[] = {"_memset"};
    const char* bzero_names[] = {"___bzero"};
    const char* chk_memcpy_names[] = {"___memcpy_chk"};
    const char* chk_memset_names[] = {"___memset_chk"};
    const char* memcmp_names[] = {"_memcmp"};
    const char* strcmp_names[] = {"_strcmp"};
    const char* strncmp_names[] = {"_strncmp"};
    const char* strlen_names[] = {"_strlen"};
    const char* strnlen_names[] = {"_strnlen"};

    add_alias(s, malloc_names, 3, shim_malloc);
    add_alias(s, malloc_aligned_names, 1, shim_malloc_aligned);
    add_alias(s, malloc_typed_names, 1, shim_malloc_typed);
    add_alias(s, malloc_typed_var_names, 2, shim_malloc_typed_variable);
    add_alias(s, malloc_lock_names, 2, shim_malloc_lock);
    add_alias(s, malloc_good_names, 1, shim_malloc_good_size);
    add_alias(s, malloc_size_names, 1, shim_malloc_size);
    add_alias(s, calloc_names, 1, shim_calloc);
    add_alias(s, realloc_names, 2, shim_realloc);
    add_alias(s, free_names, 7, shim_free);
    add_alias(s, free_typed_names, 2, shim_free_typed);
    add_alias(s, mmap_names, 1, shim_mmap);
    add_alias(s, munmap_names, 1, shim_munmap);
    add_alias(s, vm_allocate_names, 1, shim_vm_allocate);
    add_alias(s, vm_deallocate_names, 1, shim_vm_deallocate);
    add_alias(s, memmove_names, 2, shim_memmove);
    add_alias(s, memset_names, 1, shim_memset);
    add_alias(s, bzero_names, 1, shim_bzero);
    add_alias(s, chk_memcpy_names, 1, shim_checked_memcpy);
    add_alias(s, chk_memset_names, 1, shim_checked_memset);
    add_alias(s, memcmp_names, 1, shim_memcmp);
    add_alias(s, strcmp_names, 1, shim_strcmp);
    add_alias(s, strncmp_names, 1, shim_strncmp);
    add_alias(s, strlen_names, 1, shim_strlen);
    add_alias(s, strnlen_names, 1, shim_strnlen);

    return 0;
}
