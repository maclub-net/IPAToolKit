#include "shims.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <CommonCrypto/CommonCrypto.h>

#define CSAP_FAKE_HANDLE   UINT64_MAX
#define CSAP_COREFP_FILE   3
#define CSAP_ADI_FILE      5
#define CSAP_COREFP_PATH   "/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP"
#define CSAP_ICXS_PATH     "./../CoreFP.icxs"
#define CSAP_KEY_SERIAL    "IOPlatformSerialNumber"
#define CSAP_KEY_UUID      "IOPlatformUUID"
#define CSAP_KEY_BOARD     "board-id"
#define CSAP_KEYED_MESSAGE "objectForKey:"
#define CSAP_XPC_DICT_TYPE 0xffff100000000001ULL

// ==================== 通用辅助 ====================

static void add_alias(csap_shims_t* s, const char** names, int count, csap_shim_handler_t handler) {
    for (int i = 0; i < count; i++) {
        csap_shims_add_function(s, names[i], handler, NULL);
    }
}

static int read_string_arg(csap_shims_t* s, int index, char* buffer, size_t capacity) {
    uint64_t address = 0;
    if (csap_shims_arg(s, index, &address) != 0) return -1;
    return csap_shims_read_cstring(s, address, buffer, capacity);
}

// ==================== 简单返回值 ====================

static int shim_return_zero(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, 0);
}

static int shim_return_one(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, 1);
}

static int shim_return_two(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, 2);
}

static int shim_return_three(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, 3);
}

static int shim_return_unchanged(csap_shims_t* s, void* ctx) {
    (void)ctx;
    (void)s;
    return 0;
}

static int shim_return_fake_handle(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, CSAP_FAKE_HANDLE);
}

static int shim_return_uint32_max(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, UINT32_MAX);
}

static int shim_return_minus_one(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, UINT64_MAX);
}

// ==================== x86 兼容服务 ====================

static int shim_cf_string_create(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char value[256];
    if (read_string_arg(s, 1, value, sizeof(value)) != 0) return -1;

    if (strcmp(value, CSAP_KEY_SERIAL) == 0 ||
        strcmp(value, CSAP_KEY_UUID) == 0 ||
        strcmp(value, CSAP_KEY_BOARD) == 0) {
        return csap_shims_set_result(s, CSAP_FAKE_HANDLE);
    }
    return csap_shims_set_result(s, 0);
}

static int shim_cf_string_get_cstring(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t buffer, capacity;
    if (csap_shims_arg(s, 1, &buffer) != 0) return -1;
    if (csap_shims_arg(s, 2, &capacity) != 0) return -1;

    if (buffer == 0 || capacity == 0) {
        return csap_shims_set_result(s, 0);
    }

    uint8_t zero = 0;
    csap_uc_mem_write(csap_shims_engine(s), buffer, &zero, 1);
    return csap_shims_set_result(s, 1);
}

static int shim_io_iterator_next(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint32_t iter = csap_shims_iterator(s) + 1;
    csap_shims_set_iterator(s, iter);
    return csap_shims_set_result(s, (uint64_t)(iter % 2));
}

static int shim_io_registry_entry_get_parent(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t parent;
    if (csap_shims_arg(s, 2, &parent) != 0) return -1;
    if (parent == 0) return -1;

    csap_shims_write_u32(s, parent, UINT32_MAX);
    return csap_shims_set_result(s, 0);
}

static int shim_io_service_get_matching_services(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t iterator;
    if (csap_shims_arg(s, 2, &iterator) != 0) return -1;
    if (iterator == 0) return -1;

    csap_shims_set_iterator(s, 0);
    csap_shims_write_u32(s, iterator, UINT32_MAX);
    return csap_shims_set_result(s, 0);
}

static int shim_compare_and_swap32(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t old_val, new_val, address;
    if (csap_shims_arg(s, 0, &old_val) != 0) return -1;
    if (csap_shims_arg(s, 1, &new_val) != 0) return -1;
    if (csap_shims_arg(s, 2, &address) != 0) return -1;

    uint32_t current;
    if (csap_shims_read_u32(s, address, &current) != 0) return -1;

    if (current != (uint32_t)old_val) {
        return csap_shims_set_result(s, 0);
    }
    csap_shims_write_u32(s, address, (uint32_t)new_val);
    return csap_shims_set_result(s, 1);
}

static int shim_error_pointer(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, csap_shims_errno_addr(s));
}

static int shim_abort(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t pc = 0;
    csap_uc_reg_read(csap_shims_engine(s),
                     csap_shims_is_arm64(s) ? CSAP_ARM64_REG_PC : CSAP_REG_RIP, &pc);
    fprintf(stderr, "csap: guest aborted at 0x%llx\n", (unsigned long long)pc);
    return -1;
}

static int shim_arc4random(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint32_t value = 0;
    arc4random_buf(&value, sizeof(value));
    return csap_shims_set_result(s, (uint64_t)value);
}

static int shim_dlopen(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char path[512];
    if (read_string_arg(s, 0, path, sizeof(path)) != 0) return -1;

    if (strcmp(path, CSAP_COREFP_PATH) == 0) {
        return csap_shims_set_result(s, CSAP_FAKE_HANDLE);
    }
    return csap_shims_set_result(s, 0);
}

static int shim_dlsym(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char name[256];
    if (read_string_arg(s, 1, name, sizeof(name)) != 0) return -1;

    char full_name[260];
    snprintf(full_name, sizeof(full_name), "_%s", name);

    uint64_t address = 0;
    csap_macho_image_t* corefp = csap_shims_corefp(s);
    if (corefp != NULL) {
        csap_macho_export(corefp, full_name, 0x100000000000ULL, &address);
    }
    return csap_shims_set_result(s, address);
}

static int shim_gettimeofday(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t time_addr, zone_addr;
    if (csap_shims_arg(s, 0, &time_addr) != 0) return -1;
    if (csap_shims_arg(s, 1, &zone_addr) != 0) return -1;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    if (time_addr != 0) {
        uint8_t buf[16] = {0};
        uint64_t sec = (uint64_t)ts.tv_sec;
        uint32_t usec = (uint32_t)(ts.tv_nsec / 1000);
        for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(sec >> (i * 8));
        for (int i = 0; i < 4; i++) buf[8 + i] = (uint8_t)(usec >> (i * 8));
        csap_uc_mem_write(csap_shims_engine(s), time_addr, buf, 16);
    }
    if (zone_addr != 0) {
        uint8_t zero[8] = {0};
        csap_uc_mem_write(csap_shims_engine(s), zone_addr, zero, 8);
    }
    return csap_shims_set_result(s, 0);
}

static int shim_objc_msg_send(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char selector[256];
    if (read_string_arg(s, 1, selector, sizeof(selector)) != 0) return -1;

    if (strcmp(selector, CSAP_KEYED_MESSAGE) == 0) {
        return csap_shims_set_result(s, CSAP_FAKE_HANDLE);
    }
    return csap_shims_set_result(s, 0);
}

static int shim_open(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char path[512];
    if (read_string_arg(s, 0, path, sizeof(path)) != 0) return -1;

    if (strcmp(path, CSAP_ICXS_PATH) == 0) {
        csap_shims_set_icxs_offset(s, 0);
        return csap_shims_set_result(s, CSAP_COREFP_FILE);
    }
    return shim_return_minus_one(s, ctx);
}

static int shim_pthread_once(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t control, initializer;
    if (csap_shims_arg(s, 0, &control) != 0) return -1;
    if (csap_shims_arg(s, 1, &initializer) != 0) return -1;

    uint64_t value;
    if (csap_shims_read_u64(s, control, &value) != 0) return -1;

    if (value == 0) {
        return csap_shims_set_result(s, 0);
    }

    csap_shims_write_u64(s, control, 0);

    // 将 initializer 压入栈，让 ret 跳转到它
    uint64_t rsp;
    csap_uc_reg_read(csap_shims_engine(s), CSAP_REG_RSP, &rsp);
    rsp -= 8;
    csap_shims_write_u64(s, rsp, initializer);
    csap_uc_reg_write(csap_shims_engine(s), CSAP_REG_RSP, rsp);

    return csap_shims_set_result(s, 0);
}

static int shim_read(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t fd, buffer, requested;
    if (csap_shims_arg(s, 0, &fd) != 0) return -1;
    if (csap_shims_arg(s, 1, &buffer) != 0) return -1;
    if (csap_shims_arg(s, 2, &requested) != 0) return -1;

    if (fd != CSAP_COREFP_FILE) {
        return shim_return_minus_one(s, ctx);
    }

    uint64_t icxs_size = csap_shims_icxs_size(s);
    uint64_t offset = csap_shims_icxs_offset(s);
    uint64_t remaining = icxs_size - offset;
    uint64_t size = requested < remaining ? requested : remaining;

    if (size > 0) {
        const uint8_t* icxs = csap_shims_icxs(s);
        csap_uc_mem_write(csap_shims_engine(s), buffer, icxs + offset, size);
        csap_shims_set_icxs_offset(s, offset + size);
    }
    return csap_shims_set_result(s, size);
}

static int shim_sysctlbyname(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t length_addr;
    if (csap_shims_arg(s, 2, &length_addr) != 0) return -1;
    if (length_addr != 0) {
        csap_shims_write_u64(s, length_addr, 0);
    }
    return csap_shims_set_result(s, 0);
}

// ==================== ARM64 Store 平台服务 ====================

static int store_cf_run_loop_run(csap_shims_t* s, void* ctx) {
    (void)ctx;
    if (!csap_shims_pause_run_loop(s)) {
        return csap_shims_set_result(s, 0);
    }
    return csap_uc_emu_stop(csap_shims_engine(s)) == 0 ? 0 : -1;
}

static int store_cf_mach_port_create_with_port(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t callback = 0, context = 0, should_free_info = 0;
    if (csap_shims_arg(s, 2, &callback) != 0) return -1;
    if (csap_shims_arg(s, 3, &context) != 0) return -1;

    uint64_t info = 0;
    if (context != 0) {
        csap_shims_read_u64(s, context + 8, &info);
    }
    csap_shims_set_mach_port(s, callback, context, info);

    if (csap_shims_arg(s, 4, &should_free_info) == 0 && should_free_info != 0) {
        uint8_t zero = 0;
        csap_uc_mem_write(csap_shims_engine(s), should_free_info, &zero, 1);
    }

    return csap_shims_set_result(s, CSAP_FAKE_HANDLE);
}

static int store_mach_msg_rpc_from_kernel(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t message, send_size, receive_size;
    if (csap_shims_arg(s, 0, &message) != 0) return -1;
    if (csap_shims_arg(s, 1, &send_size) != 0) return -1;
    if (csap_shims_arg(s, 2, &receive_size) != 0) return -1;

    if (send_size == 0 || send_size > (1ULL << 20) || receive_size > (1ULL << 20)) {
        fprintf(stderr, "csap: kernel Mach RPC size is invalid\n");
        return -1;
    }

    csap_shims_mach_rpc_handler_t handler = csap_shims_mach_rpc_handler(s);
    if (handler == NULL) {
        fprintf(stderr, "csap: kernel Mach RPC handler is unavailable\n");
        return -1;
    }

    uint8_t* request = malloc((size_t)send_size);
    if (request == NULL) return -1;
    if (csap_uc_mem_read(csap_shims_engine(s), message, request, send_size) != 0) {
        free(request);
        return -1;
    }

    csap_shims_mach_rpc_call_t call;
    memset(&call, 0, sizeof(call));
    call.request = request;
    call.request_size = send_size;
    call.receive_size = (int)receive_size;

    int status = handler(csap_shims_mach_rpc_context(s), &call);
    free(request);

    if (status != 0) return -1;
    if (call.reply_size == 0 || call.reply_size > receive_size) {
        fprintf(stderr, "csap: kernel Mach RPC reply is invalid\n");
        return -1;
    }
    if (csap_uc_mem_write(csap_shims_engine(s), message, call.reply, call.reply_size) != 0) {
        return -1;
    }

    return csap_shims_set_result(s, 0);
}

static int store_mach_msg(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t message, send_size;
    if (csap_shims_arg(s, 0, &message) != 0) return -1;
    if (csap_shims_arg(s, 2, &send_size) != 0) return -1;

    if (send_size == 0 || send_size > (1ULL << 20)) {
        return csap_shims_set_result(s, 0);
    }

    uint8_t* reply = malloc((size_t)send_size);
    if (reply == NULL) return -1;
    if (csap_uc_mem_read(csap_shims_engine(s), message, reply, send_size) != 0) {
        free(reply);
        return -1;
    }

    csap_shims_set_mach_message_reply(s, reply, send_size);
    free(reply);

    return csap_shims_set_result(s, 0);
}

static int store_kqueue(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, 6);
}

static int store_xpc_connection_send_message_with_reply_sync(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t size = 0;
    const uint8_t* data = csap_shims_xpc_sync_reply(s, &size);
    uint64_t object = csap_shims_new_xpc_object(s, data, size, data != NULL);
    return csap_shims_set_result(s, object);
}

static int store_xpc_connection_create_mach_service(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, csap_shims_new_xpc_object(s, NULL, 0, false));
}

static int store_xpc_connection_set_event_handler(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t block;
    if (csap_shims_arg(s, 1, &block) != 0) return -1;

    uint64_t copy = csap_shims_allocate(s, 64);
    if (copy == 0) return -1;

    uint8_t data[64];
    if (csap_uc_mem_read(csap_shims_engine(s), block, data, sizeof(data)) != 0) return -1;
    if (csap_uc_mem_write(csap_shims_engine(s), copy, data, sizeof(data)) != 0) return -1;

    csap_shims_set_xpc_event_handler(s, copy);
    return csap_shims_set_result(s, 0);
}

static int store_xpc_dictionary_create_empty(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, csap_shims_new_xpc_object(s, NULL, 0, false));
}

static int store_xpc_dictionary_create_reply(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_set_result(s, csap_shims_new_xpc_object(s, NULL, 0, false));
}

static int store_xpc_dictionary_get_audit_token(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t token;
    if (csap_shims_arg(s, 1, &token) != 0) return -1;

    if (token != 0) {
        uint8_t value[32] = {0};
        value[0] = 0xff; value[1] = 0xff; value[2] = 0xff; value[3] = 0xff;
        value[20] = 123; value[24] = 0xa0; value[25] = 0x86; value[26] = 0x01;
        value[28] = 1;
        if (csap_uc_mem_write(csap_shims_engine(s), token, value, sizeof(value)) != 0) return -1;
    }

    return csap_shims_set_result(s, 0);
}

static int store_xpc_dictionary_send_reply(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t object;
    if (csap_shims_arg(s, 0, &object) != 0) return -1;

    uint64_t size = 0;
    const uint8_t* data = csap_shims_xpc_object_data(s, object, &size);
    csap_shims_set_xpc_reply(s, data, size, true);
    return csap_shims_set_result(s, 0);
}

static int store_xpc_get_type(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t object;
    if (csap_shims_arg(s, 0, &object) != 0) return -1;

    if (csap_shims_xpc_object_exists(s, object)) {
        return csap_shims_set_result(s, csap_shims_symbol(s, "__xpc_type_dictionary"));
    }
    return csap_shims_set_result(s, 0);
}

static int store_xpc_dictionary_set_data(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t object, address, length;
    if (csap_shims_arg(s, 0, &object) != 0) return -1;
    if (csap_shims_arg(s, 2, &address) != 0) return -1;
    if (csap_shims_arg(s, 3, &length) != 0) return -1;

    if (length > (1ULL << 20)) {
        fprintf(stderr, "csap: XPC data exceeds guest limit\n");
        return -1;
    }

    uint8_t* data = NULL;
    if (length > 0) {
        data = malloc((size_t)length);
        if (data == NULL) return -1;
        if (csap_uc_mem_read(csap_shims_engine(s), address, data, length) != 0) {
            free(data);
            return -1;
        }
    }

    csap_shims_set_xpc_object_data(s, object, data, length);
    free(data);

    return csap_shims_set_result(s, 0);
}

static int store_xpc_dictionary_get_data(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t object, length_address;
    if (csap_shims_arg(s, 0, &object) != 0) return -1;
    if (csap_shims_arg(s, 2, &length_address) != 0) return -1;

    uint64_t size = 0;
    bool has_data = false;
    uint64_t address = csap_shims_xpc_object_address(s, object, &size, &has_data);

    if (!has_data) {
        if (length_address != 0) {
            if (csap_shims_write_u64(s, length_address, 0) != 0) return -1;
        }
        return csap_shims_set_result(s, 0);
    }

    if (length_address != 0) {
        if (csap_shims_write_u64(s, length_address, size) != 0) return -1;
    }

    return csap_shims_set_result(s, address);
}

static int store_cf_string_create(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char value[256];
    if (read_string_arg(s, 1, value, sizeof(value)) != 0) return -1;

    if (strcmp(value, CSAP_KEY_SERIAL) == 0 ||
        strcmp(value, CSAP_KEY_UUID) == 0 ||
        strcmp(value, CSAP_KEY_BOARD) == 0) {
        return csap_shims_set_result(s, CSAP_FAKE_HANDLE);
    }
    return csap_shims_set_result(s, 0);
}

static int store_cf_number_get_value(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t address;
    if (csap_shims_arg(s, 2, &address) != 0) return -1;

    if (address != 0) {
        if (csap_shims_write_u32(s, address, 3184554750u) != 0) return -1;
    }
    return csap_shims_set_result(s, 1);
}

static int store_cf_string_create_no_copy(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t address;
    if (csap_shims_arg(s, 1, &address) != 0) return -1;
    return csap_shims_set_result(s, address);
}

static int store_cf_string_get_cstring(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t value_address, buffer, capacity;
    if (csap_shims_arg(s, 0, &value_address) != 0) return -1;
    if (csap_shims_arg(s, 1, &buffer) != 0) return -1;
    if (csap_shims_arg(s, 2, &capacity) != 0) return -1;

    if (buffer == 0 || capacity == 0) {
        return csap_shims_set_result(s, 0);
    }

    char value[4096] = {0};
    if (value_address != 0 && value_address != CSAP_FAKE_HANDLE) {
        char decoded[4096];
        if (csap_shims_read_cstring(s, value_address, decoded, sizeof(decoded)) == 0) {
            snprintf(value, sizeof(value), "%s", decoded);
        }
    }

    size_t length = strlen(value) + 1;
    if ((uint64_t)length > capacity) {
        return csap_shims_set_result(s, 0);
    }
    if (csap_uc_mem_write(csap_shims_engine(s), buffer, value, length) != 0) return -1;

    return csap_shims_set_result(s, 1);
}

static int store_io_connect_call_struct_method(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t selector, input_size, output_size_address, input_address, output_address;
    if (csap_shims_arg(s, 1, &selector) != 0) return -1;
    if (csap_shims_arg(s, 3, &input_size) != 0) return -1;
    if (csap_shims_arg(s, 5, &output_size_address) != 0) return -1;

    uint64_t output_size = 0;
    if (output_size_address != 0) {
        csap_shims_read_u64(s, output_size_address, &output_size);
    }
    if (input_size > (1ULL << 20) || output_size > (1ULL << 20)) {
        fprintf(stderr, "csap: FairPlay IOKit buffer exceeds guest limit\n");
        return -1;
    }

    if (csap_shims_arg(s, 2, &input_address) != 0) return -1;
    if (csap_shims_arg(s, 4, &output_address) != 0) return -1;

    uint8_t* input = NULL;
    if (input_size > 0) {
        input = malloc((size_t)input_size);
        if (input == NULL) return -1;
        if (csap_uc_mem_read(csap_shims_engine(s), input_address, input, input_size) != 0) {
            free(input);
            return -1;
        }
    }

    uint8_t* indirect = NULL;
    uint64_t indirect_address = 0, indirect_size = 0;
    if (selector == 26 && input_size == 16) {
        indirect_address = 0;
        for (int i = 0; i < 8; i++) {
            indirect_address |= (uint64_t)input[i] << (i * 8);
            indirect_size |= (uint64_t)input[8 + i] << (i * 8);
        }
        if (indirect_size == 0 || indirect_size > (1ULL << 20)) {
            free(input);
            fprintf(stderr, "csap: FairPlay IOKit indirect buffer is invalid\n");
            return -1;
        }
        indirect = malloc((size_t)indirect_size);
        if (indirect == NULL) {
            free(input);
            return -1;
        }
        if (csap_uc_mem_read(csap_shims_engine(s), indirect_address, indirect,
                             indirect_size) != 0) {
            free(indirect);
            free(input);
            return -1;
        }
    }

    csap_shims_fairplay_handler_t handler = csap_shims_fairplay_handler(s);
    if (handler == NULL) {
        free(indirect);
        free(input);
        fprintf(stderr, "csap: emulated FairPlay IOKit handler is unavailable\n");
        return -1;
    }

    csap_shims_fairplay_call_t call;
    memset(&call, 0, sizeof(call));
    call.input = input;
    call.input_size = input_size;
    call.indirect = indirect;
    call.indirect_size = indirect_size;
    call.output_capacity = (int)output_size;

    if (handler(csap_shims_fairplay_context(s), &call) != 0) {
        free(indirect);
        free(input);
        return -1;
    }

    const uint8_t* output = call.output;
    uint64_t output_length = call.output_size;
    const uint8_t* indirect_output = call.indirect_output;
    uint64_t indirect_output_length = call.indirect_output_size;
    uint8_t* scratch = NULL;
    int32_t code = call.code;

    if (code != 0 && selector == 26 && indirect_size >= 16 && input_size == output_size) {
        // FairPlay 的包装层期望间接缓冲区尾部携带输入数据的摘要。
        scratch = malloc((size_t)(indirect_size + input_size));
        if (scratch == NULL) {
            free(indirect);
            free(input);
            return -1;
        }
        memcpy(scratch, indirect, (size_t)indirect_size);

        uint8_t digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(scratch, (CC_LONG)(indirect_size - 16), digest);
        memcpy(scratch + indirect_size - 16, digest, 16);

        uint8_t* output_copy = scratch + indirect_size;
        memcpy(output_copy, input, (size_t)input_size);

        indirect_output = scratch;
        indirect_output_length = indirect_size;
        output = output_copy;
        output_length = input_size;
        code = 0;
    }

    uint8_t* patched = NULL;
    if (indirect_output_length != 0 && indirect_address != 0) {
        if (csap_uc_mem_write(csap_shims_engine(s), indirect_address,
                              indirect_output, indirect_output_length) != 0) {
            free(scratch);
            free(indirect);
            free(input);
            return -1;
        }
        if (output_length >= 8 && output != NULL) {
            patched = malloc((size_t)output_length);
            if (patched == NULL) {
                free(scratch);
                free(indirect);
                free(input);
                return -1;
            }
            memcpy(patched, output, (size_t)output_length);
            for (int i = 0; i < 8; i++) {
                patched[i] = (uint8_t)(indirect_address >> (i * 8));
            }
            output = patched;
        }
    }

    if (output_length != 0 && output != NULL) {
        if (csap_uc_mem_write(csap_shims_engine(s), output_address, output, output_length) != 0) {
            free(patched);
            free(scratch);
            free(indirect);
            free(input);
            return -1;
        }
    }

    if (output_size_address != 0) {
        if (csap_shims_write_u64(s, output_size_address, output_length) != 0) {
            free(patched);
            free(scratch);
            free(indirect);
            free(input);
            return -1;
        }
    }

    free(patched);
    free(scratch);
    free(indirect);
    free(input);

    return csap_shims_set_result(s, (uint64_t)(uint32_t)code);
}

static int store_io_main_port(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t port;
    if (csap_shims_arg(s, 1, &port) != 0) return -1;

    if (port != 0) {
        if (csap_shims_write_u32(s, port, 1) != 0) return -1;
    }
    return csap_shims_set_result(s, 0);
}

static uint64_t store_add_function(csap_shims_t* s, const char* name, csap_shim_handler_t handler) {
    return csap_shims_add_function(s, name, handler, NULL);
}

static int store_io_aes_perform(csap_shims_t* s, void* ctx);

static int store_random31(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint32_t value = 0;
    arc4random_buf(&value, sizeof(value));
    return csap_shims_set_result(s, (uint64_t)(value & 0x7fffffff));
}

static int store_wait_for_kernel_service(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char name[256];
    if (read_string_arg(s, 0, name, sizeof(name)) != 0) return -1;

    if (strcmp(name, "IOAESAccelerator") != 0) {
        return csap_shims_set_result(s, 0);
    }

    // 该服务在运行时中是单例；重复等待时复用已构建的 vtable。
    uint64_t service = csap_shims_kernel_service(s);
    if (service != 0) {
        return csap_shims_set_result(s, service);
    }

    uint64_t unhandled = store_add_function(s, "$IOAESAccelerator.unhandled", shim_return_zero);
    uint64_t retain = store_add_function(s, "$IOAESAccelerator.retain", shim_return_unchanged);
    uint64_t perform = store_add_function(s, "$IOAESAccelerator.performAES", store_io_aes_perform);
    if (unhandled == 0 || retain == 0 || perform == 0) return -1;

    uint8_t* vtable = malloc(0x900);
    if (vtable == NULL) return -1;
    for (size_t offset = 0; offset < 0x900; offset += 8) {
        uint64_t value = unhandled;
        memcpy(vtable + offset, &value, 8);
    }
    memcpy(vtable + 0x20, &retain, 8);
    memcpy(vtable + 0x550, &perform, 8);
    memcpy(vtable + 0x890, &perform, 8);

    uint64_t vtable_address = csap_shims_add_data(s, "kernel.ioaes.vtable", vtable, 0x900);
    free(vtable);
    if (vtable_address == 0) return -1;

    uint64_t service_address = csap_shims_allocate(s, 16);
    if (service_address == 0) return -1;
    if (csap_shims_write_u64(s, service_address, vtable_address) != 0) return -1;

    csap_shims_set_kernel_service(s, service_address);
    return csap_shims_set_result(s, service_address);
}

static int store_create_kernel_buffer_descriptor(csap_shims_t* s,
                                                 uint64_t buffer, uint64_t capacity);

static int store_new_kernel_buffer_descriptor(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t capacity;
    if (csap_shims_arg(s, 2, &capacity) != 0) return -1;

    if (capacity == 0 || capacity > CSAP_MAX_GUEST_TRANSFER) {
        return csap_shims_set_result(s, 0);
    }

    uint64_t buffer = csap_shims_allocate_aligned(s, capacity, 16);
    if (buffer == 0) return -1;

    uint8_t* zeros = calloc((size_t)capacity, 1);
    if (zeros == NULL) return -1;
    int status = csap_uc_mem_write(csap_shims_engine(s), buffer, zeros, capacity);
    free(zeros);
    if (status != 0) return -1;

    return store_create_kernel_buffer_descriptor(s, buffer, capacity);
}

static int store_new_kernel_buffer_descriptor_at(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t buffer, capacity;
    if (csap_shims_arg(s, 0, &buffer) != 0) return -1;
    if (csap_shims_arg(s, 1, &capacity) != 0) return -1;

    if (buffer == 0 || capacity == 0 || capacity > CSAP_MAX_GUEST_TRANSFER) {
        return csap_shims_set_result(s, 0);
    }

    return store_create_kernel_buffer_descriptor(s, buffer, capacity);
}

static int store_unsupported_kernel_buffer_method(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t link = 0;
    csap_uc_reg_read(csap_shims_engine(s), CSAP_ARM64_REG_X30, &link);
    fprintf(stderr, "csap: unsupported IOMemoryDescriptor virtual method from 0x%llx\n",
            (unsigned long long)link);
    return -1;
}

static int store_kernel_buffer_prepare(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t descriptor, buffer, capacity;
    if (csap_shims_arg(s, 0, &descriptor) != 0) return -1;
    if (csap_shims_read_u64(s, descriptor + 8, &buffer) != 0) return -1;
    if (csap_shims_read_u64(s, descriptor + 16, &capacity) != 0) return -1;

    if (buffer == 0 || capacity == 0 || capacity > CSAP_MAX_GUEST_TRANSFER) {
        return csap_shims_set_result(s, 3);
    }
    return csap_shims_set_result(s, 0);
}

static int store_kernel_buffer_address(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t descriptor, address;
    if (csap_shims_arg(s, 0, &descriptor) != 0) return -1;
    if (csap_shims_read_u64(s, descriptor + 8, &address) != 0) return -1;
    return csap_shims_set_result(s, address);
}

static int store_transfer_kernel_buffer(csap_shims_t* s, bool write) {
    uint64_t descriptor, offset, address, length;
    if (csap_shims_arg(s, 0, &descriptor) != 0) return -1;
    if (csap_shims_arg(s, 1, &offset) != 0) return -1;
    if (csap_shims_arg(s, 2, &address) != 0) return -1;
    if (csap_shims_arg(s, 3, &length) != 0) return -1;

    uint64_t buffer, capacity;
    if (csap_shims_read_u64(s, descriptor + 8, &buffer) != 0) return -1;
    if (csap_shims_read_u64(s, descriptor + 16, &capacity) != 0) return -1;

    if (offset > capacity || length > capacity - offset || length > CSAP_MAX_GUEST_TRANSFER) {
        return csap_shims_set_result(s, 0);
    }

    uint64_t source = write ? address : buffer + offset;
    uint64_t destination = write ? buffer + offset : address;

    if (length > 0) {
        uint8_t* data = malloc((size_t)length);
        if (data == NULL) return -1;
        if (csap_uc_mem_read(csap_shims_engine(s), source, data, length) != 0 ||
            csap_uc_mem_write(csap_shims_engine(s), destination, data, length) != 0) {
            free(data);
            return -1;
        }
        free(data);
    }

    return csap_shims_set_result(s, length);
}

static int store_kernel_buffer_read(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return store_transfer_kernel_buffer(s, false);
}

static int store_kernel_buffer_write(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return store_transfer_kernel_buffer(s, true);
}

static int store_create_kernel_buffer_descriptor(csap_shims_t* s,
                                                 uint64_t buffer, uint64_t capacity) {
    uint64_t vtable = csap_shims_buffer_vtable(s);
    if (vtable == 0) {
        uint64_t unhandled = store_add_function(s, "$IOBufferMemoryDescriptor.unhandled",
                                                store_unsupported_kernel_buffer_method);
        uint64_t prepare = store_add_function(s, "$IOBufferMemoryDescriptor.prepare",
                                              store_kernel_buffer_prepare);
        uint64_t complete = store_add_function(s, "$IOBufferMemoryDescriptor.complete",
                                               shim_return_zero);
        uint64_t address = store_add_function(s, "$IOBufferMemoryDescriptor.getVirtualAddress",
                                              store_kernel_buffer_address);
        uint64_t read = store_add_function(s, "$IOMemoryDescriptor.readBytes",
                                           store_kernel_buffer_read);
        uint64_t write = store_add_function(s, "$IOMemoryDescriptor.writeBytes",
                                            store_kernel_buffer_write);
        uint64_t release = store_add_function(s, "$IOBufferMemoryDescriptor.release",
                                              shim_return_zero);
        if (unhandled == 0 || prepare == 0 || complete == 0 || address == 0 ||
            read == 0 || write == 0 || release == 0) {
            return -1;
        }

        uint8_t* data = malloc(0x1000);
        if (data == NULL) return -1;
        for (size_t offset = 0; offset < 0x1000; offset += 8) {
            memcpy(data + offset, &unhandled, 8);
        }
        memcpy(data + 0x28, &release, 8);
        memcpy(data + 0xc8, &read, 8);
        memcpy(data + 0xd0, &write, 8);
        memcpy(data + 0xd8, &prepare, 8);
        memcpy(data + 0xe0, &complete, 8);
        memcpy(data + 0x148, &address, 8);
        memcpy(data + 0x218, &prepare, 8);
        memcpy(data + 0x220, &complete, 8);
        memcpy(data + 0x308, &address, 8);

        vtable = csap_shims_add_data(s, "kernel.iobuffer.vtable", data, 0x1000);
        free(data);
        if (vtable == 0) return -1;

        csap_shims_set_buffer_vtable(s, vtable);
    }

    uint64_t descriptor = csap_shims_allocate(s, 24);
    if (descriptor == 0) return -1;
    if (csap_shims_write_u64(s, descriptor, vtable) != 0) return -1;
    if (csap_shims_write_u64(s, descriptor + 8, buffer) != 0) return -1;
    if (csap_shims_write_u64(s, descriptor + 16, capacity) != 0) return -1;

    return csap_shims_set_result(s, descriptor);
}

static int store_io_aes_perform(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t arguments[9];
    for (int i = 0; i < 9; i++) {
        if (csap_shims_arg(s, i, &arguments[i]) != 0) return -1;
    }

    uint64_t length = arguments[3];
    if (length == 0 || length > CSAP_MAX_GUEST_TRANSFER || length % 16 != 0) {
        return csap_shims_set_result(s, 3);
    }

    uint64_t source_base, source_capacity, destination_base, destination_capacity;
    if (csap_shims_read_u64(s, arguments[1] + 8, &source_base) != 0) return -1;
    if (csap_shims_read_u64(s, arguments[1] + 16, &source_capacity) != 0) return -1;
    if (csap_shims_read_u64(s, arguments[2] + 8, &destination_base) != 0) return -1;
    if (csap_shims_read_u64(s, arguments[2] + 16, &destination_capacity) != 0) return -1;

    uint64_t destination_offset = arguments[8];
    if (arguments[7] > source_capacity || length > source_capacity - arguments[7] ||
        destination_offset > destination_capacity ||
        length > destination_capacity - destination_offset) {
        return csap_shims_set_result(s, 3);
    }

    uint8_t* source = malloc((size_t)length);
    uint8_t* destination = malloc((size_t)length);
    uint8_t iv[16];
    uint8_t key[40];
    uint8_t output_iv[16];

    if (source == NULL || destination == NULL) {
        free(source);
        free(destination);
        return -1;
    }

    csap_uc_engine_t* engine = csap_shims_engine(s);
    if (csap_uc_mem_read(engine, source_base + arguments[7], source, length) != 0 ||
        csap_uc_mem_read(engine, arguments[4], iv, 16) != 0 ||
        csap_uc_mem_read(engine, arguments[6], key, 40) != 0) {
        free(source);
        free(destination);
        return -1;
    }

    uint32_t handle = 0;
    for (int i = 0; i < 4; i++) {
        handle |= (uint32_t)key[36 + i] << (i * 8);
    }
    if (handle != 0x89c) {
        fprintf(stderr, "csap: unsupported IOAES key handle %#x\n", handle);
        free(source);
        free(destination);
        return -1;
    }

    uint32_t operation = (uint32_t)arguments[5];
    if (operation > 1) {
        fprintf(stderr, "csap: unsupported IOAES operation %#x\n", operation);
        free(source);
        free(destination);
        return -1;
    }

    uint8_t zero_key[16] = {0};
    size_t moved = 0;
    CCCryptorStatus status = CCCrypt(operation == 0 ? kCCEncrypt : kCCDecrypt,
                                     kCCAlgorithmAES, 0,
                                     zero_key, sizeof(zero_key), iv,
                                     source, (size_t)length,
                                     destination, (size_t)length, &moved);
    if (status != kCCSuccess || moved != (size_t)length) {
        free(source);
        free(destination);
        return -1;
    }

    if (operation == 0) {
        memcpy(output_iv, destination + length - 16, 16);
    } else {
        memcpy(output_iv, source + length - 16, 16);
    }

    int rc = 0;
    if (csap_uc_mem_write(engine, destination_base + destination_offset, destination, length) != 0 ||
        csap_uc_mem_write(engine, arguments[4], output_iv, 16) != 0) {
        rc = -1;
    }

    free(source);
    free(destination);
    if (rc != 0) return -1;

    return csap_shims_set_result(s, 0);
}

static int store_io_service_open(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t connection;
    if (csap_shims_arg(s, 3, &connection) != 0) return -1;

    if (connection != 0) {
        if (csap_shims_write_u32(s, connection, 7) != 0) return -1;
    }
    return csap_shims_set_result(s, 0);
}

static int store_io_registry_entry_get_parent_entry(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t parent;
    if (csap_shims_arg(s, 2, &parent) != 0) return -1;
    if (parent == 0) {
        fprintf(stderr, "csap: parent registry entry output is null\n");
        return -1;
    }

    if (csap_shims_write_u32(s, parent, UINT32_MAX) != 0) return -1;
    return csap_shims_set_result(s, 0);
}

static int store_io_service_get_matching_services(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t iterator;
    if (csap_shims_arg(s, 2, &iterator) != 0) return -1;
    if (iterator == 0) {
        fprintf(stderr, "csap: matching services iterator output is null\n");
        return -1;
    }

    csap_shims_set_iterator(s, 0);
    if (csap_shims_write_u32(s, iterator, UINT32_MAX) != 0) return -1;
    return csap_shims_set_result(s, 0);
}

static int store_arc4random_uniform(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t upper;
    if (csap_shims_arg(s, 0, &upper) != 0) return -1;

    if (upper < 2) {
        return csap_shims_set_result(s, 0);
    }

    uint64_t limit = (uint64_t)UINT32_MAX + 1;
    limit -= limit % upper;

    for (;;) {
        uint32_t value = 0;
        arc4random_buf(&value, sizeof(value));
        if ((uint64_t)value < limit) {
            return csap_shims_set_result(s, (uint64_t)value % upper);
        }
    }
}

static int store_read_random(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t address, length;
    if (csap_shims_arg(s, 0, &address) != 0) return -1;
    if (csap_shims_arg(s, 1, &length) != 0) return -1;

    if (length > CSAP_MAX_GUEST_TRANSFER) {
        fprintf(stderr, "csap: random request size exceeds limit\n");
        return -1;
    }

    if (length > 0) {
        uint8_t* data = malloc((size_t)length);
        if (data == NULL) return -1;
        arc4random_buf(data, (size_t)length);
        int status = csap_uc_mem_write(csap_shims_engine(s), address, data, length);
        free(data);
        if (status != 0) return -1;
    }

    return csap_shims_set_result(s, 0);
}

static int store_notify_register_check(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t token;
    if (csap_shims_arg(s, 1, &token) != 0) return -1;
    if (token != 0) {
        if (csap_shims_write_u32(s, token, 1) != 0) return -1;
    }
    return csap_shims_set_result(s, 0);
}

static int store_notify_check(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t changed;
    if (csap_shims_arg(s, 1, &changed) != 0) return -1;
    if (changed != 0) {
        if (csap_shims_write_u32(s, changed, 0) != 0) return -1;
    }
    return csap_shims_set_result(s, 0);
}

static int store_notify_get_state(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t state;
    if (csap_shims_arg(s, 1, &state) != 0) return -1;
    if (state != 0) {
        if (csap_shims_write_u64(s, state, 0) != 0) return -1;
    }
    return csap_shims_set_result(s, 0);
}

static int store_audit_token_to_au32(csap_shims_t* s, void* ctx) {
    (void)ctx;
    const uint32_t values[8] = {0, 0, 0, 0, 0, 123, 100000, 1};
    for (int index = 0; index < 8; index++) {
        uint64_t address;
        if (csap_shims_arg(s, index + 1, &address) != 0) return -1;
        if (address != 0) {
            if (csap_shims_write_u32(s, address, values[index]) != 0) return -1;
        }
    }
    return csap_shims_set_result(s, 0);
}

static int store_basename(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t address;
    if (csap_shims_arg(s, 0, &address) != 0) return -1;

    char value[4096];
    if (csap_shims_read_cstring(s, address, value, sizeof(value)) != 0) return -1;

    size_t length = strlen(value);
    while (length > 0 && value[length - 1] == '/') {
        length--;
    }
    value[length] = '\0';

    char* slash = strrchr(value, '/');
    if (slash != NULL) {
        address += (uint64_t)(slash - value) + 1;
    }
    return csap_shims_set_result(s, address);
}

static int store_lstat(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char path[512];
    if (read_string_arg(s, 0, path, sizeof(path)) != 0) return -1;

    bool is_directory = strcmp(path, "/var/db/fpsd/adi") == 0 ||
                        strcmp(path, "/var/db") == 0 ||
                        strcmp(path, "/var/setup") == 0;
    bool is_file = csap_shims_has_adi_file(s, path);

    if (!is_directory && !(csap_shims_is_adi_state_path(path) && is_file)) {
        return shim_return_minus_one(s, ctx);
    }

    uint64_t result;
    if (csap_shims_arg(s, 1, &result) != 0) return -1;

    // Darwin 的 stat 结构把 st_mode 放在偏移 4。
    uint8_t mode[2] = {0xed, 0x41}; // S_IFDIR | 0755
    if (is_file) {
        mode[0] = 0x80;
        mode[1] = 0x81; // S_IFREG | 0600
    }
    if (csap_uc_mem_write(csap_shims_engine(s), result + 4, mode, sizeof(mode)) != 0) return -1;

    return csap_shims_set_result(s, 0);
}

static int store_bootstrap_look_up(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t service;
    if (csap_shims_arg(s, 2, &service) != 0) return -1;
    if (service != 0) {
        if (csap_shims_write_u32(s, service, 0) != 0) return -1;
    }
    return csap_shims_set_result(s, 5); // KERN_FAILURE
}

static int store_bootstrap_check_in(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t port;
    if (csap_shims_arg(s, 2, &port) != 0) return -1;
    if (port != 0) {
        if (csap_shims_write_u32(s, port, 1) != 0) return -1;
    }
    return csap_shims_set_result(s, 0);
}

static int store_dlopen(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char path[512];
    if (read_string_arg(s, 0, path, sizeof(path)) != 0) return -1;

    if (strcmp(path, CSAP_COREFP_PATH) == 0) {
        return csap_shims_set_result(s, CSAP_FAKE_HANDLE);
    }
    return csap_shims_set_result(s, 0);
}

static int store_dlsym(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char name[256];
    if (read_string_arg(s, 1, name, sizeof(name)) != 0) return -1;

    char full_name[260];
    snprintf(full_name, sizeof(full_name), "_%s", name);
    return csap_shims_set_result(s, csap_shims_core_export(s, full_name));
}

static int store_current_time(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t address;
    if (csap_shims_arg(s, 0, &address) != 0) return -1;

    uint64_t seconds = (uint64_t)time(NULL);
    if (address != 0) {
        if (csap_shims_write_u64(s, address, seconds) != 0) return -1;
    }
    return csap_shims_set_result(s, seconds);
}

static int store_clock_get_calendar_microtime(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t seconds_address, microseconds_address;
    if (csap_shims_arg(s, 0, &seconds_address) != 0) return -1;
    if (csap_shims_arg(s, 1, &microseconds_address) != 0) return -1;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    if (csap_shims_write_u32(s, seconds_address, (uint32_t)ts.tv_sec) != 0) return -1;
    if (csap_shims_write_u32(s, microseconds_address,
                             (uint32_t)(ts.tv_nsec / 1000)) != 0) return -1;

    return csap_shims_set_result(s, 0);
}

static int store_gettimeofday(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t time_address, zone_address;
    if (csap_shims_arg(s, 0, &time_address) != 0) return -1;
    if (csap_shims_arg(s, 1, &zone_address) != 0) return -1;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    if (time_address != 0) {
        uint8_t value[16] = {0};
        uint64_t seconds = (uint64_t)ts.tv_sec;
        uint32_t microseconds = (uint32_t)(ts.tv_nsec / 1000);
        for (int i = 0; i < 8; i++) value[i] = (uint8_t)(seconds >> (i * 8));
        for (int i = 0; i < 4; i++) value[8 + i] = (uint8_t)(microseconds >> (i * 8));
        if (csap_uc_mem_write(csap_shims_engine(s), time_address, value, sizeof(value)) != 0) {
            return -1;
        }
    }

    if (zone_address != 0) {
        uint8_t zero[8] = {0};
        if (csap_uc_mem_write(csap_shims_engine(s), zone_address, zero, sizeof(zero)) != 0) {
            return -1;
        }
    }

    return csap_shims_set_result(s, 0);
}

static int store_gethostuuid(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint8_t uuid[16];
    if (csap_shims_host_uuid(s, uuid) != 0) {
        fprintf(stderr, "csap: guest host UUID is unavailable\n");
        return -1;
    }

    uint64_t address;
    if (csap_shims_arg(s, 0, &address) != 0) return -1;
    if (address != 0) {
        if (csap_uc_mem_write(csap_shims_engine(s), address, uuid, sizeof(uuid)) != 0) return -1;
    }

    return csap_shims_set_result(s, 0);
}

static int store_objc_msg_send(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char selector[256];
    if (read_string_arg(s, 1, selector, sizeof(selector)) != 0) return -1;

    if (strcmp(selector, CSAP_KEYED_MESSAGE) == 0) {
        return csap_shims_set_result(s, CSAP_FAKE_HANDLE);
    }
    return csap_shims_set_result(s, 0);
}

static int store_open(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char path[512];
    if (read_string_arg(s, 0, path, sizeof(path)) != 0) return -1;

    uint64_t flags;
    if (csap_shims_arg(s, 1, &flags) != 0) return -1;

    if (strcmp(path, "/var/db") == 0 || strcmp(path, "/var/setup") == 0) {
        return csap_shims_set_result(s, 4);
    }

    if (csap_shims_is_adi_state_path(path)) {
        if (!csap_shims_has_adi_file(s, path)) {
            if ((flags & 0x200) == 0) { // O_CREAT
                return shim_return_minus_one(s, ctx);
            }
            if (csap_shims_set_adi_file(s, path, NULL, 0) != 0) return -1;
        }
        csap_shims_set_adi_path(s, path);
        csap_shims_set_adi_offset(s, 0);
        return csap_shims_set_result(s, CSAP_ADI_FILE);
    }

    if (strcmp(path, CSAP_ICXS_PATH) == 0) {
        csap_shims_set_icxs_offset(s, 0);
        return csap_shims_set_result(s, CSAP_COREFP_FILE);
    }

    return shim_return_minus_one(s, ctx);
}

static int store_fstat(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t descriptor, result;
    if (csap_shims_arg(s, 0, &descriptor) != 0) return -1;
    if (descriptor != CSAP_ADI_FILE) {
        return shim_return_minus_one(s, ctx);
    }
    if (csap_shims_arg(s, 1, &result) != 0) return -1;

    uint8_t zeros[144] = {0};
    if (csap_uc_mem_write(csap_shims_engine(s), result, zeros, sizeof(zeros)) != 0) return -1;

    uint8_t mode[2] = {0x80, 0x81};
    if (csap_uc_mem_write(csap_shims_engine(s), result + 4, mode, sizeof(mode)) != 0) return -1;

    const char* path = csap_shims_adi_path(s);
    uint64_t size = 0;
    if (path != NULL) {
        csap_shims_adi_file(s, path, &size);
    }
    if (csap_shims_write_u64(s, result + 96, size) != 0) return -1;

    return csap_shims_set_result(s, 0);
}

static int store_ftruncate(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t descriptor, length;
    if (csap_shims_arg(s, 0, &descriptor) != 0) return -1;
    if (descriptor != CSAP_ADI_FILE) {
        return shim_return_minus_one(s, ctx);
    }
    if (csap_shims_arg(s, 1, &length) != 0) return -1;
    if (length > (1ULL << 20)) {
        return shim_return_minus_one(s, ctx);
    }

    const char* path = csap_shims_adi_path(s);
    if (path == NULL || path[0] == '\0') {
        return shim_return_minus_one(s, ctx);
    }

    uint64_t current_size = 0;
    const uint8_t* current = csap_shims_adi_file(s, path, &current_size);
    if (current_size > length) current_size = length;

    if (csap_shims_set_adi_file(s, path, current, current_size) != 0) return -1;

    uint64_t offset = csap_shims_adi_offset(s);
    if (offset > current_size) {
        csap_shims_set_adi_offset(s, current_size);
    }

    return csap_shims_set_result(s, 0);
}

static int store_pthread_once(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t control, initializer, value;
    if (csap_shims_arg(s, 0, &control) != 0) return -1;
    if (csap_shims_arg(s, 1, &initializer) != 0) return -1;

    if (csap_shims_read_u64(s, control, &value) != 0) return -1;
    if (value == 0 || value == 0x4f4e4345ULL) {
        return csap_shims_set_result(s, 0);
    }
    if (csap_shims_write_u64(s, control, 0x4f4e4345ULL) != 0) return -1;

    return csap_shims_invoke_callback(s, initializer);
}

static int store_proc_pid_path(csap_shims_t* s, void* ctx) {
    (void)ctx;
    const char* path = "/System/Library/PrivateFrameworks/CommerceKit.framework/"
                       "Versions/A/Resources/commerce";
    uint64_t buffer, size;
    if (csap_shims_arg(s, 1, &buffer) != 0) return -1;
    if (csap_shims_arg(s, 2, &size) != 0) return -1;

    size_t length = strlen(path) + 1;
    if (buffer == 0 || size < (uint64_t)length) {
        return shim_return_minus_one(s, ctx);
    }
    if (csap_uc_mem_write(csap_shims_engine(s), buffer, path, length) != 0) return -1;

    return csap_shims_set_result(s, (uint64_t)(length - 1));
}

static int store_dispatch_once(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t predicate, block, value;
    if (csap_shims_arg(s, 0, &predicate) != 0) return -1;
    if (csap_shims_arg(s, 1, &block) != 0) return -1;

    if (csap_shims_read_u64(s, predicate, &value) != 0) return -1;
    if (value == UINT64_MAX) {
        return csap_shims_set_result(s, 0);
    }
    if (csap_shims_write_u64(s, predicate, UINT64_MAX) != 0) return -1;

    uint64_t initializer;
    if (csap_shims_read_u64(s, block + 16, &initializer) != 0) return -1;

    if (csap_uc_reg_write(csap_shims_engine(s), CSAP_ARM64_REG_X0, block) != 0) return -1;
    return csap_shims_invoke_callback(s, initializer);
}

static int store_callback_complete(csap_shims_t* s, void* ctx) {
    (void)ctx;
    return csap_shims_complete_callback(s);
}

static int store_read(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t descriptor, buffer, requested;
    if (csap_shims_arg(s, 0, &descriptor) != 0) return -1;
    if (csap_shims_arg(s, 1, &buffer) != 0) return -1;
    if (csap_shims_arg(s, 2, &requested) != 0) return -1;

    if (descriptor == CSAP_ADI_FILE) {
        if (requested > CSAP_MAX_GUEST_TRANSFER) return -1;

        uint64_t length = 0;
        const char* path = csap_shims_adi_path(s);
        const uint8_t* data = (path != NULL) ? csap_shims_adi_file(s, path, &length) : NULL;
        uint64_t offset = csap_shims_adi_offset(s);
        if (offset > length) offset = length;

        uint64_t remaining = length - offset;
        uint64_t size = requested < remaining ? requested : remaining;

        if (size > 0) {
            if (csap_uc_mem_write(csap_shims_engine(s), buffer, data + offset, size) != 0) {
                return -1;
            }
            csap_shims_set_adi_offset(s, offset + size);
        }
        return csap_shims_set_result(s, size);
    }

    if (descriptor != CSAP_COREFP_FILE) {
        return shim_return_minus_one(s, ctx);
    }

    if (requested > CSAP_MAX_GUEST_TRANSFER) return -1;

    uint64_t icxs_size = csap_shims_icxs_size(s);
    uint64_t offset = csap_shims_icxs_offset(s);
    if (offset > icxs_size) offset = icxs_size;
    uint64_t remaining = icxs_size - offset;
    uint64_t size = requested < remaining ? requested : remaining;

    if (size > 0) {
        const uint8_t* icxs = csap_shims_icxs(s);
        if (csap_uc_mem_write(csap_shims_engine(s), buffer, icxs + offset, size) != 0) return -1;
        csap_shims_set_icxs_offset(s, offset + size);
    }

    return csap_shims_set_result(s, size);
}

static int store_write(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t descriptor, buffer, requested;
    if (csap_shims_arg(s, 0, &descriptor) != 0) return -1;
    if (descriptor != CSAP_ADI_FILE) {
        return shim_return_minus_one(s, ctx);
    }
    if (csap_shims_arg(s, 1, &buffer) != 0) return -1;
    if (csap_shims_arg(s, 2, &requested) != 0) return -1;
    if (requested > CSAP_MAX_GUEST_TRANSFER) return -1;

    const char* path = csap_shims_adi_path(s);
    if (path == NULL || path[0] == '\0') {
        return shim_return_minus_one(s, ctx);
    }

    uint64_t current_size = 0;
    const uint8_t* current = csap_shims_adi_file(s, path, &current_size);
    uint64_t offset = csap_shims_adi_offset(s);
    uint64_t end = offset + requested;

    uint8_t* state = calloc(end > 0 ? (size_t)end : 1, 1);
    if (state == NULL) return -1;
    if (current != NULL && current_size > 0) {
        uint64_t copy = current_size < end ? current_size : end;
        memcpy(state, current, (size_t)copy);
    }
    if (requested > 0) {
        if (csap_uc_mem_read(csap_shims_engine(s), buffer, state + offset, requested) != 0) {
            free(state);
            return -1;
        }
    }

    int status = csap_shims_set_adi_file(s, path, state, end);
    free(state);
    if (status != 0) return -1;

    csap_shims_set_adi_offset(s, end);
    return csap_shims_set_result(s, requested);
}

static int store_unlink(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char path[512];
    if (read_string_arg(s, 0, path, sizeof(path)) != 0) return -1;

    if (!csap_shims_is_adi_state_path(path)) {
        return shim_return_minus_one(s, ctx);
    }

    csap_shims_remove_adi_file(s, path);
    csap_shims_set_adi_offset(s, 0);
    return csap_shims_set_result(s, 0);
}

static int store_sysctlbyname(csap_shims_t* s, void* ctx) {
    (void)ctx;
    char name[256];
    if (read_string_arg(s, 0, name, sizeof(name)) != 0) return -1;

    uint64_t output, length_address;
    if (csap_shims_arg(s, 1, &output) != 0) return -1;
    if (csap_shims_arg(s, 2, &length_address) != 0) return -1;

    uint8_t value[32];
    uint64_t length = 0;

    if (strcmp(name, "kern.monotonicclock") == 0 ||
        strcmp(name, "hw.ncpu") == 0 ||
        strcmp(name, "hw.logicalcpu") == 0 ||
        strcmp(name, "hw.physicalcpu") == 0 ||
        strcmp(name, "hw.optional.arm64") == 0) {
        value[0] = 1; value[1] = 0; value[2] = 0; value[3] = 0;
        length = 4;
    } else if (strcmp(name, "hw.memsize") == 0) {
        uint64_t memory = 8ULL << 30;
        memcpy(value, &memory, 8);
        length = 8;
    } else if (strcmp(name, "hw.machine") == 0) {
        memcpy(value, "arm64", 6);
        length = 6;
    } else if (strcmp(name, "hw.model") == 0) {
        memcpy(value, "MacBookPro13,3", 15);
        length = 15;
    } else if (strcmp(name, "kern.osversion") == 0) {
        memcpy(value, "16G29", 6);
        length = 6;
    } else {
        return shim_return_minus_one(s, ctx);
    }

    if (length_address != 0) {
        uint64_t requested = 0;
        if (csap_shims_read_u64(s, length_address, &requested) != 0) return -1;
        if (output != 0 && requested < length) {
            return shim_return_minus_one(s, ctx);
        }
        if (output != 0) {
            if (csap_uc_mem_write(csap_shims_engine(s), output, value, length) != 0) return -1;
        }
        if (csap_shims_write_u64(s, length_address, length) != 0) return -1;
    }

    return csap_shims_set_result(s, 0);
}

static int store_sysconf(csap_shims_t* s, void* ctx) {
    (void)ctx;
    uint64_t name;
    if (csap_shims_arg(s, 0, &name) != 0) return -1;

    switch (name) {
        case 29:  // _SC_PAGESIZE
            return csap_shims_set_result(s, 0x1000);
        case 57:
        case 58:  // _SC_NPROCESSORS_CONF, _SC_NPROCESSORS_ONLN
            return csap_shims_set_result(s, 1);
        case 200: // _SC_PHYS_PAGES
            return csap_shims_set_result(s, CSAP_HEAP_SIZE / 0x1000);
        default:
            return shim_return_minus_one(s, ctx);
    }
}

// ==================== 注册 ====================

static int register_x86_services(csap_shims_t* s) {
    const char* zero1[] = {"_CFBundleGetMainBundle", "_CFDataGetBytePtr", "_CFDataGetLength",
                           "_CFStringGetLength", "_CFStringGetMaximumSizeForEncoding",
                           "_CFUUIDCreateString", "_IORegistryEntryFromPath",
                           "_IORegistryEntrySearchCFProperty", "_IOServiceMatching",
                           "_getenv", "_pthread_self"};
    add_alias(s, zero1, 11, shim_return_zero);

    const char* zero2[] = {"_CFRelease", "_IOObjectRelease", "_close", "_close$UNIX2003",
                           "_pthread_mutex_lock", "_pthread_mutex_unlock",
                           "_pthread_rwlock_init", "_pthread_rwlock_init$UNIX2003",
                           "_pthread_rwlock_unlock", "_pthread_rwlock_unlock$UNIX2003",
                           "_pthread_rwlock_wrlock", "_pthread_rwlock_wrlock$UNIX2003"};
    add_alias(s, zero2, 12, shim_return_zero);

    const char* zero3[] = {"_CFStringCreateWithCStringNoCopy"};
    add_alias(s, zero3, 1, shim_return_zero);

    const char* fake[] = {"_CFDictionaryGetValue", "_DADiskCopyDescription",
                          "_DADiskCreateFromBSDName", "_DASessionCreate",
                          "_IORegistryEntryCreateCFProperty"};
    add_alias(s, fake, 5, shim_return_fake_handle);

    const char* minus1[] = {"_fcntl", "_fcntl$UNIX2003", "_lstat$INODE64",
                            "_statfs", "_statfs$INODE64", "_sysctl"};
    add_alias(s, minus1, 6, shim_return_minus_one);

    add_alias(s, (const char*[]){"_CFStringCreateWithCString"}, 1, shim_cf_string_create);
    add_alias(s, (const char*[]){"_CFStringGetCString"}, 1, shim_cf_string_get_cstring);
    add_alias(s, (const char*[]){"_IOIteratorNext"}, 1, shim_io_iterator_next);
    add_alias(s, (const char*[]){"_IORegistryEntryGetParentEntry"}, 1,
              shim_io_registry_entry_get_parent);
    add_alias(s, (const char*[]){"_IOServiceGetMatchingServices"}, 1,
              shim_io_service_get_matching_services);
    add_alias(s, (const char*[]){"_IOServiceGetMatchingService"}, 1, shim_return_uint32_max);
    add_alias(s, (const char*[]){"_OSAtomicCompareAndSwap32Barrier"}, 1, shim_compare_and_swap32);
    add_alias(s, (const char*[]){"___error"}, 1, shim_error_pointer);
    add_alias(s, (const char*[]){"_abort", "___stack_chk_fail", "dyld_stub_binder"}, 3, shim_abort);
    add_alias(s, (const char*[]){"_arc4random"}, 1, shim_arc4random);
    add_alias(s, (const char*[]){"_dlopen"}, 1, shim_dlopen);
    add_alias(s, (const char*[]){"_dlsym"}, 1, shim_dlsym);
    add_alias(s, (const char*[]){"_gettimeofday"}, 1, shim_gettimeofday);
    add_alias(s, (const char*[]){"_objc_msgSend"}, 1, shim_objc_msg_send);
    add_alias(s, (const char*[]){"_open", "_open$UNIX2003"}, 2, shim_open);
    add_alias(s, (const char*[]){"_pthread_once"}, 1, shim_pthread_once);
    add_alias(s, (const char*[]){"_read", "_read$UNIX2003"}, 2, shim_read);
    add_alias(s, (const char*[]){"_sysctlbyname"}, 1, shim_sysctlbyname);

    uint8_t zero8[8] = {0};
    uint64_t errno_addr = csap_shims_add_data(s, "guest.errno", zero8, 8);
    csap_shims_set_errno_addr(s, errno_addr);

    uint8_t stack_chk_guard[8] = {0xA5, 0x71, 0x3C, 0xD9, 0x86, 0x42, 0xEF, 0x10};
    csap_shims_add_data(s, "___stack_chk_guard", stack_chk_guard, 8);

    const char* data_names[] = {
        "_kCFAllocatorDefault", "_kCFAllocatorNull",
        "_kDADiskDescriptionVolumeUUIDKey", "_kIOMasterPortDefault"
    };
    for (int i = 0; i < 4; i++) {
        csap_shims_add_data(s, data_names[i], zero8, 8);
    }

    return 0;
}

static int register_store_services(csap_shims_t* s) {
    // 纯返回值服务
    add_alias(s, (const char*[]){
        "_CFBundleGetMainBundle", "_CFDataGetBytePtr", "_CFDataGetLength",
        "_CFStringGetLength", "_CFStringGetMaximumSizeForEncoding", "_CFUUIDCreateString",
        "_IORegistryEntryFromPath", "_IORegistryEntrySearchCFProperty", "_getenv",
        "_pthread_self",
    }, 10, shim_return_zero);

    add_alias(s, (const char*[]){
        "_CFDictionaryGetValue", "_CFFileDescriptorCreate", "_CFFileDescriptorCreateRunLoopSource",
        "_CFMachPortCreateRunLoopSource", "_CFRunLoopGetCurrent", "_CFRunLoopGetMain",
        "_CFURLCreateFromFileSystemRepresentation", "_DADiskCopyDescription",
        "_DADiskCreateFromBSDName", "_DASessionCreate", "_IORegistryEntryCreateCFProperty",
        "_dispatch_get_global_queue", "_dispatch_queue_create",
        "_dispatch_queue_create_with_target", "_os_transaction_create", "_xpc_connection_create",
    }, 16, shim_return_fake_handle);

    add_alias(s, (const char*[]){
        "_CFRelease", "_CFFileDescriptorEnableCallBacks", "_CFFileDescriptorInvalidate",
        "_CFFileSecuritySetMode", "_CFRunLoopAddSource", "_CFURLCopyResourcePropertyForKey",
        "_CFURLSetResourcePropertyForKey", "_CSBackupIsItemExcluded",
        "_CSBackupSetItemExcluded", "_IOObjectRelease", "_IOLockLock", "_IOLockUnlock",
        "_IOLockWakeup", "_IORWLockRead", "_IORWLockWrite", "_IORWLockUnlock",
        "_lck_mtx_lock", "_lck_mtx_unlock", "_lck_rw_lock_exclusive",
        "_lck_rw_unlock_exclusive", "_chmod", "_close", "_close$UNIX2003", "_fchmod",
        "_fcntl", "_fcntl$UNIX2003", "_kevent", "_lockf", "_mkdir", "_pthread_mutex_lock",
        "_pthread_mutex_unlock", "_pthread_rwlock_init", "_pthread_rwlock_init$UNIX2003",
        "_pthread_rwlock_destroy", "_pthread_rwlock_rdlock", "_pthread_rwlock_unlock",
        "_pthread_rwlock_unlock$UNIX2003", "_pthread_rwlock_wrlock",
        "_pthread_rwlock_wrlock$UNIX2003", "_pthread_set_qos_class_self_np",
        "_CFRunLoopStop", "_getpid", "_getuid", "_notify_post", "_ptrace", "_sched_yield",
        "_signal", "_umask", "_os_release", "_xpc_connection_activate",
        "_xpc_connection_cancel", "_xpc_connection_resume", "_xpc_connection_set_target_queue",
        "_xpc_dictionary_set_bool", "_xpc_dictionary_set_int64",
        "_xpc_dictionary_set_string", "_xpc_dictionary_set_uint64",
        "_xpc_dictionary_set_value", "_xpc_release", "_xpc_retain", "_xpc_transaction_begin",
        "_xpc_transaction_end",
    }, 63, shim_return_zero);

    add_alias(s, (const char*[]){"_IOLog", "_IOLogv"}, 2, shim_return_zero);
    add_alias(s, (const char*[]){"_notify_register_check"}, 1, store_notify_register_check);
    add_alias(s, (const char*[]){"_notify_check"}, 1, store_notify_check);
    add_alias(s, (const char*[]){"_notify_get_state"}, 1, store_notify_get_state);
    add_alias(s, (const char*[]){"_notify_cancel"}, 1, shim_return_zero);
    add_alias(s, (const char*[]){"_atexit"}, 1, shim_return_zero);
    add_alias(s, (const char*[]){"_CFRunLoopRun"}, 1, store_cf_run_loop_run);
    add_alias(s, (const char*[]){"_CFMachPortCreateWithPort"}, 1, store_cf_mach_port_create_with_port);
    add_alias(s, (const char*[]){"_CFMachPortGetPort"}, 1, shim_return_one);
    add_alias(s, (const char*[]){"_SecTaskCreateWithAuditToken",
                                 "_SecTaskCopyValueForEntitlement"}, 2, shim_return_fake_handle);
    add_alias(s, (const char*[]){"_CFStringCreateWithCString"}, 1, store_cf_string_create);
    add_alias(s, (const char*[]){"_CFStringCreateWithCStringNoCopy"}, 1,
              store_cf_string_create_no_copy);
    add_alias(s, (const char*[]){"_CFStringGetCString"}, 1, store_cf_string_get_cstring);
    add_alias(s, (const char*[]){"_CFGetTypeID", "_CFNumberGetTypeID"}, 2, shim_return_one);
    add_alias(s, (const char*[]){"_CFStringGetTypeID"}, 1, shim_return_two);
    add_alias(s, (const char*[]){"_CFDictionaryGetTypeID"}, 1, shim_return_three);
    add_alias(s, (const char*[]){"_CFNumberGetValue"}, 1, store_cf_number_get_value);
    add_alias(s, (const char*[]){"___chkstk_darwin", "____chkstk_darwin"}, 2, shim_return_unchanged);
    add_alias(s, (const char*[]){"__ZN9IOService15serviceMatchingEPKcP12OSDictionary"}, 1,
              shim_return_unchanged);
    add_alias(s, (const char*[]){"__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec"},
              1, store_wait_for_kernel_service);
    add_alias(s, (const char*[]){"__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmm"},
              1, store_new_kernel_buffer_descriptor);
    add_alias(s, (const char*[]){"__ZN18IOMemoryDescriptor16withAddressRangeEyyjP4task"},
              1, store_new_kernel_buffer_descriptor_at);
    add_alias(s, (const char*[]){"_IOIteratorNext"}, 1, shim_io_iterator_next);
    add_alias(s, (const char*[]){"_IOConnectCallStructMethod"}, 1,
              store_io_connect_call_struct_method);
    add_alias(s, (const char*[]){"_IORegistryEntryGetParentEntry"}, 1,
              store_io_registry_entry_get_parent_entry);
    add_alias(s, (const char*[]){"_IOServiceGetMatchingServices"}, 1,
              store_io_service_get_matching_services);
    add_alias(s, (const char*[]){"_IOServiceGetMatchingService"}, 1, shim_return_one);
    add_alias(s, (const char*[]){"_IOServiceMatching"}, 1, shim_return_fake_handle);
    add_alias(s, (const char*[]){"_IOMainPort"}, 1, store_io_main_port);
    add_alias(s, (const char*[]){"_IOServiceOpen"}, 1, store_io_service_open);
    add_alias(s, (const char*[]){"_OSAtomicCompareAndSwap32Barrier"}, 1, shim_compare_and_swap32);
    add_alias(s, (const char*[]){"___error"}, 1, shim_error_pointer);
    add_alias(s, (const char*[]){"_abort", "___stack_chk_fail", "dyld_stub_binder"}, 3, shim_abort);
    add_alias(s, (const char*[]){"_arc4random"}, 1, shim_arc4random);
    add_alias(s, (const char*[]){"_random"}, 1, store_random31);
    add_alias(s, (const char*[]){"_arc4random_uniform"}, 1, store_arc4random_uniform);
    add_alias(s, (const char*[]){"_read_random", "_kernel_read_random"}, 2, store_read_random);
    add_alias(s, (const char*[]){"_audit_token_to_au32"}, 1, store_audit_token_to_au32);
    add_alias(s, (const char*[]){"_audit_token_to_euid"}, 1, shim_return_zero);
    add_alias(s, (const char*[]){"_basename"}, 1, store_basename);
    add_alias(s, (const char*[]){"_bootstrap_look_up"}, 1, store_bootstrap_look_up);
    add_alias(s, (const char*[]){"_bootstrap_check_in"}, 1, store_bootstrap_check_in);
    add_alias(s, (const char*[]){"_mach_msg_rpc_from_kernel_proper"}, 1,
              store_mach_msg_rpc_from_kernel);
    add_alias(s, (const char*[]){"_mach_msg", "_mach_msg2_internal"}, 2, store_mach_msg);
    add_alias(s, (const char*[]){"_mach_msg_destroy", "_mach_msg_destroy_from_kernel_proper",
                                 "_mach_port_deallocate", "_mig_dealloc_reply_port",
                                 "_mig_deallocate", "_mig_put_reply_port"}, 6, shim_return_zero);
    add_alias(s, (const char*[]){"_mig_get_reply_port"}, 1, shim_return_one);
    add_alias(s, (const char*[]){"_dispatch_once"}, 1, store_dispatch_once);
    add_alias(s, (const char*[]){"_dlopen"}, 1, store_dlopen);
    add_alias(s, (const char*[]){"_dlsym"}, 1, store_dlsym);
    add_alias(s, (const char*[]){"_statfs", "_statfs$INODE64"}, 2, shim_return_minus_one);
    add_alias(s, (const char*[]){"_fstat"}, 1, store_fstat);
    add_alias(s, (const char*[]){"_ftruncate"}, 1, store_ftruncate);
    add_alias(s, (const char*[]){"_gettimeofday"}, 1, store_gettimeofday);
    add_alias(s, (const char*[]){"_clock_get_calendar_microtime"}, 1,
              store_clock_get_calendar_microtime);
    add_alias(s, (const char*[]){"_time"}, 1, store_current_time);
    add_alias(s, (const char*[]){"_gethostuuid"}, 1, store_gethostuuid);
    add_alias(s, (const char*[]){"_objc_msgSend"}, 1, store_objc_msg_send);
    add_alias(s, (const char*[]){"_open", "_open$UNIX2003"}, 2, store_open);
    add_alias(s, (const char*[]){"_lstat", "_lstat$INODE64", "_stat", "_stat$INODE64"}, 4,
              store_lstat);
    add_alias(s, (const char*[]){"_pthread_once"}, 1, store_pthread_once);
    add_alias(s, (const char*[]){"_proc_pidpath"}, 1, store_proc_pid_path);
    add_alias(s, (const char*[]){"_read", "_read$UNIX2003"}, 2, store_read);
    add_alias(s, (const char*[]){"_write"}, 1, store_write);
    add_alias(s, (const char*[]){"_unlink"}, 1, store_unlink);
    add_alias(s, (const char*[]){"_sysctl"}, 1, shim_return_minus_one);
    add_alias(s, (const char*[]){"_sysctlbyname"}, 1, store_sysctlbyname);
    add_alias(s, (const char*[]){"_sysconf"}, 1, store_sysconf);
    add_alias(s, (const char*[]){"_xpc_dictionary_get_data"}, 1, store_xpc_dictionary_get_data);
    add_alias(s, (const char*[]){"_xpc_dictionary_set_data"}, 1, store_xpc_dictionary_set_data);
    add_alias(s, (const char*[]){"_xpc_connection_create_mach_service"}, 1,
              store_xpc_connection_create_mach_service);
    add_alias(s, (const char*[]){"_xpc_connection_send_message_with_reply_sync"}, 1,
              store_xpc_connection_send_message_with_reply_sync);
    add_alias(s, (const char*[]){"_xpc_connection_set_event_handler"}, 1,
              store_xpc_connection_set_event_handler);
    add_alias(s, (const char*[]){"_xpc_dictionary_create_empty"}, 1,
              store_xpc_dictionary_create_empty);
    add_alias(s, (const char*[]){"_xpc_dictionary_create_reply"}, 1,
              store_xpc_dictionary_create_reply);
    add_alias(s, (const char*[]){"_xpc_dictionary_get_audit_token"}, 1,
              store_xpc_dictionary_get_audit_token);
    add_alias(s, (const char*[]){"_xpc_dictionary_send_reply"}, 1,
              store_xpc_dictionary_send_reply);
    add_alias(s, (const char*[]){"_xpc_get_type"}, 1, store_xpc_get_type);
    add_alias(s, (const char*[]){"_kqueue"}, 1, store_kqueue);
    add_alias(s, (const char*[]){"_os_log_type_enabled"}, 1, shim_return_one);
    add_alias(s, (const char*[]){"_os_log_impl", "__os_log_impl"}, 2, shim_return_zero);

    // 数据区域
    uint8_t zero8[8] = {0};
    uint64_t errno_addr = csap_shims_add_data(s, "guest.errno", zero8, 8);
    csap_shims_set_errno_addr(s, errno_addr);

    uint8_t stack_chk_guard[8] = {0xA5, 0x71, 0x3C, 0xD9, 0x86, 0x42, 0xEF, 0x10};
    csap_shims_add_data(s, "___stack_chk_guard", stack_chk_guard, 8);

    const char* data_names[] = {
        "_NDR_record", "_kCFAllocatorDefault", "_kCFAllocatorNull",
        "_kDADiskDescriptionVolumeUUIDKey", "_kIOMasterPortDefault",
    };
    for (int i = 0; i < 5; i++) {
        csap_shims_add_data(s, data_names[i], zero8, 8);
    }

    uint64_t fake_handle = CSAP_FAKE_HANDLE;
    csap_shims_add_data(s, "_kCFBooleanFalse", &fake_handle, 8);
    csap_shims_add_data(s, "_kCFBooleanTrue", &fake_handle, 8);

    uint64_t xpc_type = CSAP_XPC_DICT_TYPE;
    csap_shims_add_data(s, "__xpc_type_dictionary", &xpc_type, 8);
    xpc_type = CSAP_XPC_DICT_TYPE + 1;
    csap_shims_add_data(s, "__xpc_type_error", &xpc_type, 8);
    xpc_type = CSAP_XPC_DICT_TYPE + 2;
    csap_shims_add_data(s, "__xpc_error_connection_invalid", &xpc_type, 8);

    if (csap_shims_add_function(s, "callback.complete", store_callback_complete, NULL) == 0) {
        return -1;
    }

    return 0;
}

int csap_shims_register_platform_services(csap_shims_t* s) {
    if (s == NULL) return -1;
    return csap_shims_is_arm64(s) ? register_store_services(s) : register_x86_services(s);
}
